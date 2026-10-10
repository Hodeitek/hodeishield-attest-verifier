#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Hodeitek S.L.
# =============================================================================
# tests/image-assets.sh - the image job must cover every file release.yml puts
# in SHA256SUMS.
#
# v1.4.0 added keys-statement.json to SHA256SUMS; image.yml downloaded a fixed
# list that lacked it, and `sha256sum -c` failed on the release. The release
# path never runs on a pull request, so this checks it without a release:
#   a. the file list is read from release.yml's `sha256sum ... > SHA256SUMS`;
#   b. image.yml gets its files from .github/scripts/fetch-release-assets.sh
#      and names none of them itself;
#   c. that script, run with a stubbed gh and cosign on a fake SHA256SUMS that
#      lists exactly those files, downloads and verifies every one and its
#      bundle, and SHA256SUMS first;
#   d. it refuses bad names (../x, -x, a/b, .x, a..b, an absolute path), a
#      malformed line, a list without verify-attestation.sh, and a SHA256SUMS
#      that cosign rejects, before it downloads anything else.
# Offline: the stubs only copy fixture files. Needs bash and coreutils.
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RELEASE="$ROOT/.github/workflows/release.yml"
IMAGE="$ROOT/.github/workflows/image.yml"
FETCH="$ROOT/.github/scripts/fetch-release-assets.sh"

fail() { printf 'not ok - %s\n' "$*" >&2; exit 1; }
ok() { printf 'ok - %s\n' "$*"; }

# ---- a. what release.yml lists ---------------------------------------------
lines="$(grep -E '^[[:space:]]*sha256sum [^|]*> SHA256SUMS[[:space:]]*$' "$RELEASE" || true)"
[ "$(printf '%s\n' "$lines" | grep -c .)" -eq 1 ] \
  || fail "expected exactly one 'sha256sum ... > SHA256SUMS' line in release.yml"
read -ra words <<<"$(printf '%s' "$lines" | sed -E 's/^[[:space:]]*sha256sum //; s/[[:space:]]*> SHA256SUMS[[:space:]]*$//')"
files=()
for w in "${words[@]}"; do
  [[ "$w" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || fail "release.yml lists a name this test cannot read: $w"
  files+=("$w")
done
[ "${#files[@]}" -ge 2 ] || fail "release.yml lists fewer than 2 files"
printf '%s\n' "${files[@]}" | grep -qx verify-attestation.sh || fail "release.yml does not list verify-attestation.sh"
ok "release.yml lists: ${files[*]}"

# release.yml's two per-file loops (sign, verify as a reader) must cover every
# listed file plus SHA256SUMS: a file without a bundle breaks the image job.
want="$(printf '%s\n' "${files[@]}" SHA256SUMS | sort)"
loops="$(grep -E '^[[:space:]]*for f in .*; do[[:space:]]*$' "$RELEASE" || true)"
[ "$(printf '%s\n' "$loops" | grep -c .)" -eq 2 ] \
  || fail "expected exactly two 'for f in ...; do' loops in release.yml"
while IFS= read -r loop; do
  got="$(printf '%s' "$loop" | sed -E 's/^[[:space:]]*for f in //; s/; do[[:space:]]*$//' | tr ' ' '\n' | sort)"
  [ "$got" = "$want" ] || fail "a release.yml loop does not list exactly the SHA256SUMS files plus SHA256SUMS: $loop"
done <<<"$loops"
ok "both release.yml loops cover the SHA256SUMS files and SHA256SUMS"

# ---- b. image.yml derives its list from SHA256SUMS -------------------------
grep -qE '^[[:space:]]+bash \.github/scripts/fetch-release-assets\.sh dist$' "$IMAGE" \
  || fail "image.yml does not run .github/scripts/fetch-release-assets.sh dist (a comment does not count)"
for f in "${files[@]}"; do
  if [ "$f" != verify-attestation.sh ] && grep -qF "$f" "$IMAGE" "$FETCH"; then
    fail "$f is named in image.yml or the fetch script: the list must come from SHA256SUMS"
  fi
done
grep -qF 'cosign verify-blob' "$FETCH" || fail "the fetch script does not verify with cosign"
ok "image.yml takes its files from the fetch script, which reads them from SHA256SUMS"

# ---- c, d. the script, offline ---------------------------------------------
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
mkdir "$tmp/bin"

# gh: "gh release download TAG ... --pattern P ..." copies fixtures/P, and logs P.
cat >"$tmp/bin/gh" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
[ "$1 $2" = "release download" ] || { echo "stub gh: unexpected $*" >&2; exit 9; }
shift 3
dir=''
pats=()
while [ $# -gt 0 ]; do
  case "$1" in
    --dir) dir="$2"; shift 2 ;;
    --pattern) pats+=("$2"); shift 2 ;;
    --repo) shift 2 ;;
    --clobber) shift ;;
    *) echo "stub gh: unexpected argument $1" >&2; exit 9 ;;
  esac
done
matched=0
for p in "${pats[@]}"; do
  echo "$p" >>"$STUB_LOG/downloads"
  # As the real gh: a pattern that matches no asset is skipped, and only a
  # download where nothing matched at all is an error.
  [ -f "$STUB_FIXTURES/$p" ] || continue
  cp "$STUB_FIXTURES/$p" "$dir/$p"
  matched=1
done
[ "$matched" -eq 1 ] || { echo "stub gh: no assets match the patterns" >&2; exit 1; }
STUB
# cosign: "cosign verify-blob --bundle B ... FILE" succeeds if B and FILE exist.
cat >"$tmp/bin/cosign" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
[ "$1" = verify-blob ] || { echo "stub cosign: unexpected $*" >&2; exit 9; }
bundle=''; idn=''
args=("$@")
for ((i = 1; i < ${#args[@]}; i++)); do
  case "${args[i]}" in
    --bundle) bundle="${args[i+1]}" ;;
    --certificate-identity) idn="${args[i+1]}" ;;
  esac
done
file="${args[${#args[@]}-1]}"
[ "$idn" = "$EXPECT_IDENTITY" ] || { echo "stub cosign: wrong identity $idn" >&2; exit 9; }
[ -f "$bundle" ] && [ -f "$file" ] || { echo "stub cosign: missing $bundle or $file" >&2; exit 1; }
[ -z "${COSIGN_REJECT:-}" ] || [ "$file" != "$COSIGN_REJECT" ] || { echo "stub cosign: rejected $file" >&2; exit 1; }
echo "$file" >>"$STUB_LOG/verified"
STUB
chmod +x "$tmp/bin/gh" "$tmp/bin/cosign"

# run_case NAME SUMS_CONTENT -> sets rc, out; fixtures hold every listed file.
run_case() {
  local name="$1" sums="$2"
  local case_dir="$tmp/$name"
  rm -rf "$case_dir"
  mkdir -p "$case_dir/fix" "$case_dir/log"
  printf '%s' "$sums" >"$case_dir/fix/SHA256SUMS"
  : >"$case_dir/fix/SHA256SUMS.sigstore.json"
  for f in "${files[@]}" x a b; do
    printf 'content of %s\n' "$f" >"$case_dir/fix/$f"
    : >"$case_dir/fix/$f.sigstore.json"
  done
  # MISSING_ASSET: a fixture (a bundle) that the release does not have.
  [ -z "${MISSING_ASSET:-}" ] || rm -f "$case_dir/fix/$MISSING_ASSET"
  rc=0
  out="$(cd "$case_dir" && env PATH="$tmp/bin:$PATH" STUB_FIXTURES="$case_dir/fix" STUB_LOG="$case_dir/log" \
    EXPECT_IDENTITY=https://example.test/id COSIGN_REJECT="${COSIGN_REJECT:-}" \
    TAG=v0.0.0 GITHUB_REPOSITORY=example/repo RELEASE_IDENTITY=https://example.test/id \
    bash "$FETCH" "$case_dir/dist" 2>&1)" || rc=$?
  CASE_DIR="$case_dir"
}
hash64="$(printf '%064d' 0)"
sums_for() { local s='' n; for n in "$@"; do s+="$hash64  $n"$'\n'; done; printf '%s' "$s"; }

# good: the real list. sha256sum -c is real, so give each file its true hash.
good=''
mkdir -p "$tmp/good/fix"
for f in "${files[@]}"; do
  printf 'content of %s\n' "$f" >"$tmp/good/fix/$f"
  good+="$(sha256sum "$tmp/good/fix/$f" | cut -d' ' -f1)  $f"$'\n'
done
run_case good "$good"
[ "$rc" -eq 0 ] || fail "a good list was refused (exit $rc): $out"
for f in "${files[@]}"; do
  grep -qxF "$f" "$CASE_DIR/log/downloads" || fail "$f was not downloaded"
  grep -qxF "$f.sigstore.json" "$CASE_DIR/log/downloads" || fail "$f.sigstore.json was not downloaded"
  grep -qxF "$f" "$CASE_DIR/log/verified" || fail "$f was not verified with cosign"
done
[ "$(head -n1 "$CASE_DIR/log/verified")" = SHA256SUMS ] || fail "SHA256SUMS was not the first thing verified"
ok "a good list downloads and verifies every listed file and its bundle"

# A listed file whose hash is wrong must fail (sha256sum -c).
run_case wronghash "$(sums_for "${files[@]}")"
[ "$rc" -ne 0 ] || fail "a wrong hash was accepted"
ok "a wrong hash is refused"

# SHA256SUMS rejected by cosign: nothing else is downloaded.
COSIGN_REJECT=SHA256SUMS run_case badsig "$good"
[ "$rc" -ne 0 ] || fail "a SHA256SUMS that cosign rejects was accepted"
[ "$(wc -l <"$CASE_DIR/log/downloads")" -eq 2 ] || fail "files were downloaded before SHA256SUMS was verified"
ok "a SHA256SUMS that fails cosign stops the job before any other download"

# A listed file whose bundle cosign rejects.
COSIGN_REJECT="${files[${#files[@]}-1]}" run_case badbundle "$good"
[ "$rc" -ne 0 ] || fail "a rejected bundle was accepted"
ok "a listed file whose bundle fails cosign is refused"

# A listed file whose bundle is not in the release: gh skips the pattern, so
# the script itself must notice (cosign finds no bundle).
MISSING_ASSET="${files[${#files[@]}-1]}.sigstore.json" run_case nobundle "$good"
[ "$rc" -ne 0 ] || fail "a listed file with no bundle in the release was accepted"
ok "a listed file whose bundle is missing from the release is refused"

refuse() { # label sums
  run_case refuse "$2"
  [ "$rc" -ne 0 ] || fail "$1 was accepted"
  [ "$(wc -l <"$CASE_DIR/log/downloads")" -eq 2 ] || fail "$1: files were downloaded before the list was refused"
  ok "$1 is refused before any file is downloaded"
}
for bad in '../x' '-x' 'a/b' '.x' 'a..b' '/etc/passwd' 'x y' 'x;y'; do
  refuse "the name '$bad'" "$(sums_for verify-attestation.sh)$hash64  $bad"$'\n'
done
refuse "a malformed line" "$(sums_for verify-attestation.sh)not a checksum line"$'\n'
refuse "a one-space separator" "$(sums_for verify-attestation.sh)$hash64 b"$'\n'
refuse "a binary-mode marker" "$(sums_for verify-attestation.sh)$hash64 *b"$'\n'
refuse "an empty list" ""
refuse "a list without verify-attestation.sh" "$(sums_for a b)"
