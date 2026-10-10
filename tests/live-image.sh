#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Hodeitek S.L.
# =============================================================================
# tests/live-image.sh — verify and run the latest release's signed image.
#
# For the latest release's tag (the one tests/live.sh resolves) it
#   1. resolves the digest of ghcr.io/hodeitek/hodeishield-attest-verifier:TAG
#      from the registry, anonymously, and from then on uses IMAGE@sha256:...
#      only (the tag is never run);
#   2. verifies the signature with cosign exactly as README.md ("A signed
#      image") tells a reader to, and the SBOM attestation with
#      `gh attestation verify`, as README.md says;
#   3. runs README.md's production example inside the image, with the same
#      flags as tests/live.sh, and requires exit 0 and the same verdict: the
#      posture example (VERIFIED) and the --status-list example (GOOD).
#
# The one distinction this script exists to keep, as in tests/live.sh:
#
#   * The release predating images, or the network or a service being
#     unavailable (no connection, timeout, HTTP 5xx or 429 after retries), is
#     NOT a finding. It is a warning and the script exits 0.
#     The cut is made by version, never by "the pull failed": images exist for
#     v1.4.1 and later (v1.4.0 and earlier have none).
#   * Everything else fails. In particular a registry answer of 401, 403 or 404
#     for a release that has an image is a finding (the image is missing or the
#     package is private), as is a signature or attestation that does not
#     verify, a digest that is not the one signed for that tag, a verdict other
#     than the expected one, and a version inside the image that is not the
#     release's.
#
# Needs: curl, jq, docker, cosign, gh (GH_TOKEN or GITHUB_TOKEN for gh). Without
# cosign or gh here it skips with a warning, as tests/live.sh does, unless
# GITHUB_ACTIONS is set, where a missing tool fails.
#
# Env: LIVE_ORIGIN (default https://app.hodeishield.com)
#      LIVE_SLUG   (default talmaren-payments; README.md must use the same slug)
# =============================================================================
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ORIGIN="${LIVE_ORIGIN:-https://app.hodeishield.com}"
SLUG="${LIVE_SLUG:-talmaren-payments}"
BASE="$ORIGIN/api/public/attest"
REPO_API='https://api.github.com/repos/Hodeitek/hodeishield-attest-verifier'
IMAGE_REPO='hodeitek/hodeishield-attest-verifier'
IMAGE="ghcr.io/$IMAGE_REPO"
OIDC_ISSUER='https://token.actions.githubusercontent.com'
# The first release with an image.
FIRST_IMAGE_VERSION='1.4.1'

T="$(mktemp -d)"; chmod 700 "$T"
trap 'rm -rf -- "$T"' EXIT

gha() { if [ -n "${GITHUB_ACTIONS:-}" ]; then printf '::%s title=live image check::%s\n' "$1" "$2"; fi; }
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

# need TOOL — a missing tool is a skip here, a failure in CI.
need() {
  if command -v "$1" >/dev/null 2>&1; then return 0; fi
  if [ -n "${GITHUB_ACTIONS:-}" ]; then fail "$1 is not installed on the runner"; fi
  skip "$1 is not installed here"
}
for tool in curl jq docker; do
  command -v "$tool" >/dev/null 2>&1 || fail "$tool is not installed"
done

# The README example, this check and tests/live.sh must name the same subject,
# and README.md must give the cosign command this script runs.
grep -qF "/api/public/attest/$SLUG " "$ROOT/README.md" \
  || fail "README.md does not use the live example /api/public/attest/$SLUG"
grep -qF -- "--expect-slug $SLUG --expect-issuer $ORIGIN" "$ROOT/README.md" \
  || fail "README.md's image example does not use --expect-slug $SLUG --expect-issuer $ORIGIN"
grep -qF -- "--certificate-identity \"https://github.com/Hodeitek/hodeishield-attest-verifier/.github/workflows/image.yml@refs/tags/<TAG>\"" "$ROOT/README.md" \
  || fail "README.md's cosign command does not use the certificate identity this check uses"
grep -qF -- "--certificate-oidc-issuer $OIDC_ISSUER" "$ROOT/README.md" \
  || fail "README.md's cosign command does not use the OIDC issuer this check uses"

# --- 1. the latest release, and the version cut ------------------------------
GH_AUTH=()
if [ -n "${GITHUB_TOKEN:-}" ]; then GH_AUTH=(-H "Authorization: Bearer $GITHUB_TOKEN"); fi
code="$(curl -sS --max-time 20 --retry 3 --retry-delay 5 -o "$T/release.json" -w '%{http_code}' \
          -H 'Accept: application/vnd.github+json' "${GH_AUTH[@]}" "$REPO_API/releases/latest" 2>/dev/null)" || code=000
case "$code" in
  200) ;;
  404) skip 'the repository has no published release yet' ;;
  *) skip "could not read the latest release (HTTP $code: outage)" ;;
esac
TAG="$(jq -r '.tag_name // empty' "$T/release.json" 2>/dev/null || true)"
VERSION="${TAG#v}"
[[ "$TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "the latest release has an unreadable tag: '$TAG'"
if ! version_ge "$VERSION" "$FIRST_IMAGE_VERSION"; then
  skip "the latest release $TAG predates images (the first is v$FIRST_IMAGE_VERSION)"
fi
printf 'latest release %s: it has an image, checking it\n' "$TAG"

# --- 2. the digest of the tag, from the registry -----------------------------
# registry_status NAME CODE — classify a registry answer. 401, 403 and 404 are
# not an outage: for a release that has an image they mean it is missing or
# private.
registry_status() {
  case "$2" in
    200) return 0 ;;
    000|'') skip "could not reach ghcr.io for $1 (outage)" ;;
    429|5??) skip "ghcr.io answered HTTP $2 for $1 (outage)" ;;
    401|403) fail "ghcr.io answered HTTP $2 for $1: $IMAGE:$TAG is private or not readable anonymously, but $TAG has an image" ;;
    404) fail "ghcr.io answered HTTP 404 for $1: no image $IMAGE:$TAG, but $TAG has an image" ;;
    *) fail "ghcr.io answered HTTP $2 for $1 — expected 200" ;;
  esac
}
CURL_TRY=(--max-time 20 --retry 3 --retry-delay 5 --retry-connrefused)
code="$(curl -sS "${CURL_TRY[@]}" -o "$T/token.json" -w '%{http_code}' \
          "https://ghcr.io/token?service=ghcr.io&scope=repository:$IMAGE_REPO:pull" 2>/dev/null)" || code=000
registry_status 'the anonymous pull token' "$code"
TOKEN="$(jq -r '.token // empty' "$T/token.json" 2>/dev/null || true)"
[ -n "$TOKEN" ] || fail 'ghcr.io gave no anonymous pull token'
code="$(curl -sS "${CURL_TRY[@]}" -o /dev/null -D "$T/manifest.headers" -w '%{http_code}' \
          -H "Authorization: Bearer $TOKEN" \
          -H 'Accept: application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json, application/vnd.docker.distribution.manifest.list.v2+json' \
          "https://ghcr.io/v2/$IMAGE_REPO/manifests/$TAG" 2>/dev/null)" || code=000
registry_status "the manifest of $TAG" "$code"
DIGEST="$(tr -d '\r' < "$T/manifest.headers" | sed -n 's/^[Dd]ocker-[Cc]ontent-[Dd]igest:[[:space:]]*//p' | head -n1)"
[[ "$DIGEST" =~ ^sha256:[0-9a-f]{64}$ ]] || fail "ghcr.io gave no usable digest for $IMAGE:$TAG ('$DIGEST')"
REF="$IMAGE@$DIGEST"
ok "$IMAGE:$TAG is $DIGEST (from here on only $REF is used)"

# is_outage FILE — the tool's own output names a network or service problem.
is_outage() {
  grep -qiE 'i/o timeout|timeout awaiting|context deadline exceeded|connection (refused|reset)|no such host|temporary failure in name resolution|tls handshake timeout|unexpected eof|network is unreachable|status code (429|5[0-9][0-9])|service unavailable|bad gateway|gateway time-?out|toomanyrequests' "$1"
}
# check_tool LABEL FILE RC — a failed tool is an outage if it says so, else a result.
check_tool() {
  if [ "$3" -eq 0 ]; then return 0; fi
  cat "$2"
  if is_outage "$2"; then skip "$1: the service looks unavailable"; fi
  fail "$1 failed (exit $3)"
}

# --- 3. signature and SBOM attestation, as README.md tells a reader ----------
need cosign
cosign verify "$REF" \
  --certificate-identity "https://github.com/Hodeitek/hodeishield-attest-verifier/.github/workflows/image.yml@refs/tags/$TAG" \
  --certificate-oidc-issuer "$OIDC_ISSUER" > "$T/cosign.out" 2>&1
check_tool "cosign verify of $REF" "$T/cosign.out" $?
ok "cosign verifies $REF as signed by image.yml at refs/tags/$TAG"

need gh
if [ -z "${GH_TOKEN:-}" ] && [ -n "${GITHUB_TOKEN:-}" ]; then export GH_TOKEN="$GITHUB_TOKEN"; fi
if [ -z "${GH_TOKEN:-}" ]; then
  if [ -n "${GITHUB_ACTIONS:-}" ]; then fail 'no GH_TOKEN for gh attestation verify'; fi
  skip 'no GH_TOKEN for gh attestation verify'
fi
gh attestation verify "oci://$REF" --repo Hodeitek/hodeishield-attest-verifier > "$T/gh.out" 2>&1
check_tool "gh attestation verify of $REF" "$T/gh.out" $?
ok "the SBOM attestation of $REF verifies"

# --- 4. run README.md's example inside the image -----------------------------
fetch() {
  local out="$T/data/$1" rc
  code="$(curl -sS "${CURL_TRY[@]}" -o "$out" -w '%{http_code}' "$2" 2>"$T/$1.err")"
  rc=$?
  case "$code" in
    200) return 0 ;;
    000|'') skip "could not reach $2 (curl exit $rc: $(tr '\n' ' ' < "$T/$1.err"))" ;;
    429|5??) skip "$2 answered HTTP $code" ;;
    *) fail "$2 answered HTTP $code — expected 200" ;;
  esac
}
# The image runs as a non-root user: the directory it reads must be readable.
mkdir "$T/data"; chmod 755 "$T/data"
fetch att.json          "$BASE/$SLUG"
fetch jwks.json         "$BASE/keys"
fetch status.json       "$BASE/status"
fetch status-keys.json  "$BASE/status-keys"
chmod 644 "$T"/data/*.json

docker pull "$REF" > "$T/pull.out" 2>&1
rc=$?
if [ "$rc" -ne 0 ]; then
  cat "$T/pull.out"
  if grep -qiE 'denied|unauthorized|not found|manifest unknown' "$T/pull.out"; then
    fail "docker pull $REF failed (exit $rc), but the registry gave its manifest: the image is not readable"
  fi
  skip "docker pull $REF failed (exit $rc): the registry looks unavailable"
fi

# image_run LABEL WANT_EXIT PATTERN -- verifier args... — offline, read-only.
image_run() {
  local label="$1" want="$2" pattern="$3" got; shift 4
  docker run --rm --pull never --network none -e NO_COLOR=1 -v "$T/data":/work:ro "$REF" "$@" > "$T/out" 2>&1
  got=$?
  cat "$T/out"
  [ "$got" -eq "$want" ] || fail "$label: the image exited $got, expected $want"
  grep -qF -- "$pattern" "$T/out" || fail "$label: no '$pattern' in the output"
  printf 'ok    %s (exit %s)\n\n' "$label" "$got"
}

docker run --rm --pull never --network none "$REF" --version > "$T/version.out" 2>&1
[ "$(tr -d '\r' < "$T/version.out")" = "verify-attestation.sh $VERSION" ] \
  || fail "the image reports '$(tr '\n' ' ' < "$T/version.out")', expected 'verify-attestation.sh $VERSION' for $TAG"
ok "the script inside reports version $VERSION"

COMMON=(--attestation att.json --jwks jwks.json --expect-slug "$SLUG" --expect-issuer "$ORIGIN")
image_run "posture attestation for $SLUG verifies in the image" 0 'VERIFIED' -- "${COMMON[@]}"
image_run "$SLUG is not revoked per the live status list, in the image" 0 \
  'GOOD — not revoked, per a verified status list' -- \
  "${COMMON[@]}" --status-list --status status.json --status-keys status-keys.json
