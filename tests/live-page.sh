#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Hodeitek S.L.
# =============================================================================
# tests/live-page.sh — check that the published page serves the latest release's
# signed bundle, file for file.
#
# For the latest release it
#   1. downloads SHA256SUMS and verify-page-<tag>.tar.gz with their Sigstore
#      bundles, verifies both with cosign against release.yml at that tag, and
#      checks the archive's SHA-256 against SHA256SUMS;
#   2. checks the archive as pages.yml does before it deploys (no absolute
#      name, no ".." component, only plain files and folders, index.html at the
#      root) and that its MANIFEST.sha256 matches every file in it;
#   3. fetches every file MANIFEST.sha256 lists from PAGE_ORIGIN, and requires
#      the listed SHA-256; the served MANIFEST.sha256 must be the bundle's own.
#
# The module pins of this checkout (tools/mldsa-wasm/expected.sha256) are not
# used: they may already be newer than the latest release. What is checked is
# that the site serves exactly what the release signed.
#
# A static host cannot be listed: a file served beyond those the manifest names
# cannot be detected from outside.
#
# As in tests/live.sh, an outage (no connection, timeout, HTTP 5xx or 429 after
# retries) is NOT a finding: it is a warning and the script exits 0. So is a
# latest release that predates the page bundle (before v1.6.1). Everything
# else fails: a 404, a file that differs, a signature that does not verify.
#
# Needs: curl, python3, tar, gzip, coreutils, cosign. Without cosign it skips
# with a warning, unless GITHUB_ACTIONS is set, where it fails.
#
# Env: PAGE_ORIGIN (default https://verify.hodeishield.com)
#      GITHUB_TOKEN (optional, for the GitHub API rate limit)
# =============================================================================
set -uo pipefail

PAGE_ORIGIN="${PAGE_ORIGIN:-https://verify.hodeishield.com}"
REPO='Hodeitek/hodeishield-attest-verifier'
REPO_API="https://api.github.com/repos/$REPO"
OIDC_ISSUER='https://token.actions.githubusercontent.com'
# The first release with a page bundle.
FIRST_PAGE_VERSION='1.6.1'

T="$(mktemp -d)"; chmod 700 "$T"
trap 'rm -rf -- "$T"' EXIT

gha() { if [ -n "${GITHUB_ACTIONS:-}" ]; then printf '::%s title=live page check::%s\n' "$1" "$2"; fi; }
skip() {
  printf 'WARN  %s — skipped, not a verification result.\n' "$1"
  gha warning "$1 (skipped: not a verification result)"
  exit 0
}
fail() {
  printf 'FAIL  %s\n' "$1" >&2
  gha error "$1"
  exit 1
}
ok() { printf 'ok    %s\n' "$1"; }

# version_ge A B — true when A >= B (both X.Y.Z).
version_ge() {
  [ "$(printf '%s\n%s\n' "$1" "$2" | sort -t. -k1,1n -k2,2n -k3,3n | head -n1)" = "$2" ]
}

# json_str KEY FILE — the top-level string member KEY of the JSON object in FILE,
# or nothing when it is absent, not a string, or the file is not JSON.
json_str() {
  python3 -c 'import json, sys
try:
    v = json.load(open(sys.argv[2])).get(sys.argv[1])
except Exception:
    v = None
if isinstance(v, str):
    print(v)' "$1" "$2" 2>/dev/null || true
}

# get OUT URL [AUTH...] — prints the HTTP code; 000 when nothing came back.
get() {
  local out="$1" url="$2"; shift 2
  curl -sS --proto '=https' --max-time 30 --retry 3 --retry-delay 5 --retry-connrefused \
    -L -o "$out" -w '%{http_code}' "$@" "$url" 2>"$T/curl.err" || true
}

# classify WHAT CODE — 200 passes; an outage skips; anything else fails.
classify() {
  case "$2" in
    200) return 0 ;;
    000|429|5??) skip "$1: HTTP $2 (outage)" ;;
    *) fail "$1: HTTP $2" ;;
  esac
}

for tool in curl python3 tar gzip sha256sum; do
  command -v "$tool" >/dev/null 2>&1 || fail "$tool is not installed"
done
if ! command -v cosign >/dev/null 2>&1; then
  if [ -n "${GITHUB_ACTIONS:-}" ]; then fail "cosign is not installed on the runner"; fi
  skip "cosign is not installed here"
fi

# --- 1. the latest release and its signed bundle -----------------------------
GH_AUTH=()
if [ -n "${GITHUB_TOKEN:-}" ]; then GH_AUTH=(-H "Authorization: Bearer $GITHUB_TOKEN"); fi
code="$(get "$T/release.json" "$REPO_API/releases/latest" -H 'Accept: application/vnd.github+json' "${GH_AUTH[@]}")"
case "$code" in
  200) ;;
  404) skip 'the repository has no published release yet' ;;
  *) skip "could not read the latest release (HTTP $code: outage)" ;;
esac
TAG="$(json_str tag_name "$T/release.json")"
[[ "$TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "the latest release has an unreadable tag: '$TAG'"
if ! version_ge "${TAG#v}" "$FIRST_PAGE_VERSION"; then
  skip "the latest release $TAG predates the page bundle (the first is v$FIRST_PAGE_VERSION)"
fi
BUNDLE="verify-page-$TAG.tar.gz"
IDENTITY="https://github.com/$REPO/.github/workflows/release.yml@refs/tags/$TAG"
printf 'latest release %s: checking %s against %s\n' "$TAG" "$BUNDLE" "$PAGE_ORIGIN"

mkdir "$T/rel"
for f in SHA256SUMS SHA256SUMS.sigstore.json "$BUNDLE" "$BUNDLE.sigstore.json"; do
  classify "release asset $f" "$(get "$T/rel/$f" "https://github.com/$REPO/releases/download/$TAG/$f")"
done
for f in SHA256SUMS "$BUNDLE"; do
  cosign verify-blob --bundle "$T/rel/$f.sigstore.json" \
      --certificate-identity "$IDENTITY" --certificate-oidc-issuer "$OIDC_ISSUER" \
      "$T/rel/$f" >"$T/cosign.out" 2>&1 \
    || { cat "$T/cosign.out" >&2; fail "the Sigstore signature of $f does not verify for release.yml at $TAG"; }
done
ok "SHA256SUMS and $BUNDLE are signed by release.yml at $TAG"
want="$(awk -v n="$BUNDLE" '$2 == n { print $1 }' "$T/rel/SHA256SUMS")"
[[ "$want" =~ ^[0-9a-f]{64}$ ]] || fail "$BUNDLE is not listed (once) in SHA256SUMS"
got="$(sha256sum "$T/rel/$BUNDLE" | cut -d' ' -f1)"
[ "$got" = "$want" ] || fail "$BUNDLE has sha256 $got; SHA256SUMS lists $want"
ok "$BUNDLE is sha256 $want, as SHA256SUMS lists"

# --- 2. the archive, as pages.yml checks it before it deploys ----------------
tar -tzf "$T/rel/$BUNDLE" > "$T/names" || fail "$BUNDLE cannot be listed"
tar -tzvf "$T/rel/$BUNDLE" > "$T/long" || fail "$BUNDLE cannot be listed"
if grep -Eq '(^|/)\.\.(/|$)|^/|[[:cntrl:]]' "$T/names"; then
  fail "$BUNDLE has an absolute path, a '..' component or a control character in a name"
fi
if grep -v '^[-d]' "$T/long" > "$T/odd"; then
  cat "$T/odd" >&2
  fail "$BUNDLE has entries that are not plain files or folders"
fi
mkdir "$T/page"
tar -xzf "$T/rel/$BUNDLE" -C "$T/page" --no-same-owner --no-same-permissions \
  || fail "$BUNDLE cannot be unpacked"
[ -f "$T/page/index.html" ] || fail "$BUNDLE has no index.html at its root"
[ -f "$T/page/MANIFEST.sha256" ] || fail "$BUNDLE has no MANIFEST.sha256"
(cd "$T/page" && sha256sum --quiet --strict -c MANIFEST.sha256) >"$T/manifest.out" 2>&1 \
  || { cat "$T/manifest.out" >&2; fail "the MANIFEST.sha256 inside $BUNDLE does not match its files"; }
n="$(wc -l < "$T/page/MANIFEST.sha256")"
ok "$BUNDLE: plain names, only files and folders, index.html at the root, MANIFEST.sha256 matches its $n files"

# --- 3. what the site serves -------------------------------------------------
mkdir "$T/served"
code="$(get "$T/served/MANIFEST.sha256" "$PAGE_ORIGIN/MANIFEST.sha256")"
classify "$PAGE_ORIGIN/MANIFEST.sha256" "$code"
cmp -s "$T/served/MANIFEST.sha256" "$T/page/MANIFEST.sha256" \
  || fail "$PAGE_ORIGIN/MANIFEST.sha256 is not the MANIFEST.sha256 of $BUNDLE"
bad=0
while read -r sum path; do
  [[ "$sum" =~ ^[0-9a-f]{64}$ ]] || fail "MANIFEST.sha256 has a line that is not 'sha256  path': $sum $path"
  case "$path" in /*|*..*) fail "MANIFEST.sha256 names an unsafe path: $path" ;; esac
  code="$(get "$T/served/file" "$PAGE_ORIGIN/$path")"
  classify "$PAGE_ORIGIN/$path" "$code"
  served="$(sha256sum "$T/served/file" | cut -d' ' -f1)"
  if [ "$served" != "$sum" ]; then
    printf 'FAIL  %s/%s is sha256 %s; the bundle has %s\n' "$PAGE_ORIGIN" "$path" "$served" "$sum" >&2
    bad=$((bad + 1))
  fi
done < "$T/page/MANIFEST.sha256"
[ "$bad" -eq 0 ] || fail "$bad file(s) served at $PAGE_ORIGIN differ from $BUNDLE"
code="$(get "$T/served/root" "$PAGE_ORIGIN/")"
classify "$PAGE_ORIGIN/" "$code"
cmp -s "$T/served/root" "$T/page/index.html" || fail "$PAGE_ORIGIN/ is not the index.html of $BUNDLE"
ok "$PAGE_ORIGIN serves the $n files of $BUNDLE as signed, and its MANIFEST.sha256; / is its index.html"
