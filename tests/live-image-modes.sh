#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Hodeitek S.L.
# =============================================================================
# tests/live-image-modes.sh — the skip-or-fail logic of tests/live-image.sh.
#
# tests/live-image.sh can only run end to end against a published image. This
# runs it offline with stubbed curl, docker, cosign and gh, and checks the one
# distinction it exists to keep:
#   a. a release that predates images (< 1.4.1, by version) skips with a
#      warning, exit 0, and touches neither the registry nor docker;
#   b. 401, 403 and 404 from the registry for a release with an image FAIL;
#      an unreachable registry, 429 and 5xx are a warning, exit 0;
#   c. the version order is numeric (1.4.10 and 1.10.0 are after 1.4.1);
#   d. a good run uses IMAGE@sha256:... only (never the tag), with the
#      certificate identity of README.md, and runs both README examples;
#   e. a cosign or gh failure is a failure, unless its output names an outage;
#      a wrong verdict, exit code or version inside the image fails.
# Offline: the stubs only print. Needs bash, coreutils and jq.
# =============================================================================
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$ROOT/tests/live-image.sh"
T="$(mktemp -d)"; chmod 700 "$T"
trap 'rm -rf -- "$T"' EXIT
mkdir "$T/bin"
LOG="$T/calls.log"
DIGEST="sha256:$(printf 'ab%.0s' {1..32})"

# --- stubs -------------------------------------------------------------------
cat > "$T/bin/curl" <<'EOF'
#!/usr/bin/env bash
out=; hdr=; url=
while [ $# -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift 2 ;;
    -D) hdr="$2"; shift 2 ;;
    -w|-H|--max-time|--retry|--retry-delay) shift 2 ;;
    -*) shift ;;
    *) url="$1"; shift ;;
  esac
done
echo "curl $url" >> "$LOG"
case "$url" in
  https://api.github.com/*) code="$STUB_API_CODE"; body="{\"tag_name\":\"$STUB_TAG\"}" ;;
  https://ghcr.io/token*) code="$STUB_TOKEN_CODE"; body='{"token":"t"}' ;;
  https://ghcr.io/v2/*)
    code="$STUB_MANIFEST_CODE"; body=
    if [ -n "$hdr" ]; then printf 'HTTP/2 %s\r\nDocker-Content-Digest: %s\r\n' "$code" "$STUB_DIGEST" > "$hdr"; fi ;;
  *) code="$STUB_DATA_CODE"; body='{}' ;;
esac
if [ -n "$out" ] && [ "$out" != /dev/null ]; then printf '%s' "$body" > "$out"; fi
if [ "$code" = 000 ]; then echo 000; exit 6; fi
echo "$code"
EOF
cat > "$T/bin/docker" <<'EOF'
#!/usr/bin/env bash
echo "docker $*" >> "$LOG"
case "$1" in
  pull) printf '%s\n' "$STUB_PULL_MSG"; exit "$STUB_PULL_RC" ;;
  run)
    case " $* " in
      *" --version "*) echo "verify-attestation.sh $STUB_IMG_VERSION"; exit 0 ;;
      *" --status-list "*) printf '%s\n' "$STUB_STATUS_OUT"; exit "$STUB_STATUS_RC" ;;
      *) printf '%s\n' "$STUB_RUN_OUT"; exit "$STUB_RUN_RC" ;;
    esac ;;
esac
EOF
cat > "$T/bin/cosign" <<'EOF'
#!/usr/bin/env bash
echo "cosign $*" >> "$LOG"
printf '%s\n' "$STUB_COSIGN_MSG"; exit "$STUB_COSIGN_RC"
EOF
cat > "$T/bin/gh" <<'EOF'
#!/usr/bin/env bash
echo "gh $*" >> "$LOG"
printf '%s\n' "$STUB_GH_MSG"; exit "$STUB_GH_RC"
EOF
chmod +x "$T"/bin/*

PASSED=0; FAILED=0
pass() { printf 'ok - %s\n' "$1"; PASSED=$((PASSED + 1)); }
nok() { printf 'not ok - %s\n' "$1"; sed 's/^/    # /' "$T/out"; FAILED=$((FAILED + 1)); }

# scenario NAME WANT_RC OUT_PATTERN [VAR=value ...] — run the script with stubs.
# Leaves the stubs' call log in $LOG.
scenario() {
  local name="$1" want="$2" pattern="$3" got; shift 3
  : > "$LOG"
  env PATH="$T/bin:$PATH" LOG="$LOG" GH_TOKEN=x GITHUB_ACTIONS= \
    STUB_API_CODE=200 STUB_TAG=v1.4.1 STUB_TOKEN_CODE=200 STUB_MANIFEST_CODE=200 \
    STUB_DIGEST="$DIGEST" STUB_DATA_CODE=200 STUB_PULL_RC=0 STUB_PULL_MSG=pulled \
    STUB_COSIGN_RC=0 STUB_COSIGN_MSG=verified STUB_GH_RC=0 STUB_GH_MSG=verified \
    STUB_RUN_RC=0 STUB_RUN_OUT=VERIFIED STUB_STATUS_RC=0 \
    STUB_STATUS_OUT='GOOD — not revoked, per a verified status list' STUB_IMG_VERSION='' \
    "$@" bash "$SCRIPT" > "$T/out" 2>&1
  got=$?
  if [ "$got" -ne "$want" ]; then nok "$name (exit $got, expected $want)"; return 1; fi
  if ! grep -qF -- "$pattern" "$T/out"; then nok "$name (no '$pattern' in the output)"; return 1; fi
  pass "$name"
}
# no_call PATTERN NAME — the last scenario never made a call matching PATTERN.
no_call() {
  if grep -qe "$1" "$LOG"; then nok "$2"; sed 's/^/    # log: /' "$LOG"; else pass "$2"; fi
}
had_call() {
  if grep -qe "$1" "$LOG"; then pass "$2"; else nok "$2"; sed 's/^/    # log: /' "$LOG"; fi
}

# --- a. releases that predate images skip, by version ------------------------
for tag in v1.4.0 v1.3.9 v0.9.9 v1.0.0; do
  scenario "$tag predates images: warning, exit 0" 0 'predates images' STUB_TAG="$tag" \
    && no_call 'ghcr.io\|^docker\|^cosign' "$tag: neither the registry nor docker was touched"
done

# --- b. the registry: not found, private and unreadable fail; outages skip ---
for c in 401 403 404; do
  scenario "manifest HTTP $c for a release with an image fails" 1 "HTTP $c" STUB_MANIFEST_CODE=$c \
    && no_call '^docker\|^cosign' "manifest $c: nothing was run"
done
scenario 'token HTTP 403 fails' 1 'HTTP 403' STUB_TOKEN_CODE=403
scenario 'token HTTP 401 fails' 1 'HTTP 401' STUB_TOKEN_CODE=401
for c in 000 429 500 502 503 504; do
  scenario "manifest HTTP $c is an outage: warning, exit 0" 0 'outage' STUB_MANIFEST_CODE=$c
  scenario "token HTTP $c is an outage: warning, exit 0" 0 'outage' STUB_TOKEN_CODE=$c
done
scenario 'manifest HTTP 418 fails (not an outage)' 1 'HTTP 418' STUB_MANIFEST_CODE=418
scenario 'a digest that is not sha256:<64 hex> fails' 1 'no usable digest' STUB_DIGEST=sha256:abc
scenario 'the GitHub API unreachable: warning, exit 0' 0 'could not read the latest release' STUB_API_CODE=000
scenario 'the GitHub API 503: warning, exit 0' 0 'could not read the latest release' STUB_API_CODE=503
scenario 'no release yet: warning, exit 0' 0 'no published release' STUB_API_CODE=404
scenario 'an unreadable tag fails' 1 'unreadable tag' STUB_TAG=latest
scenario 'a tag with a suffix fails' 1 'unreadable tag' STUB_TAG=v1.4.1-rc1

# --- c. the version order is numeric -----------------------------------------
for tag in v1.4.1 v1.4.10 v1.5.0 v1.10.0 v2.0.0; do
  scenario "$tag has an image: it is checked" 0 "ok    posture attestation" STUB_TAG="$tag" STUB_IMG_VERSION="${tag#v}" \
    && had_call '^cosign' "$tag: cosign ran"
done

# --- d. a good run -----------------------------------------------------------
scenario 'a good run' 0 'ok    posture attestation' STUB_IMG_VERSION=1.4.1
had_call "^cosign verify ghcr.io/hodeitek/hodeishield-attest-verifier@$DIGEST --certificate-identity https://github.com/Hodeitek/hodeishield-attest-verifier/.github/workflows/image.yml@refs/tags/v1.4.1 --certificate-oidc-issuer https://token.actions.githubusercontent.com\$" 'cosign verify: the digest, README.md identity and issuer'
had_call "^gh attestation verify oci://ghcr.io/hodeitek/hodeishield-attest-verifier@$DIGEST --repo Hodeitek/hodeishield-attest-verifier\$" 'gh attestation verify: the digest'
had_call '^docker pull ghcr.io/hodeitek/hodeishield-attest-verifier@sha256:' 'docker pull by digest'
no_call 'hodeishield-attest-verifier:v' 'the tag is never given to docker or cosign'
no_call '^docker run.*hodeishield-attest-verifier[^@]' 'docker run uses the digest only'
had_call '--expect-slug talmaren-payments --expect-issuer https://app.hodeishield.com' 'the README flags'
had_call '--status-list --status status.json --status-keys status-keys.json' 'the status-list example'
had_call '--network none' 'the image runs without network'

# --- e. results are failures, outages are not --------------------------------
scenario 'cosign verify fails: FAIL' 1 'cosign verify' STUB_COSIGN_RC=1 STUB_COSIGN_MSG='Error: none of the expected identities matched'
no_call '^docker' 'cosign failed: the image was not run'
scenario 'cosign verify: no signatures found: FAIL' 1 'cosign verify' STUB_COSIGN_RC=1 STUB_COSIGN_MSG='Error: no signatures found'
scenario 'cosign verify: network timeout: warning, exit 0' 0 'looks unavailable' STUB_COSIGN_RC=1 STUB_COSIGN_MSG='Get "https://rekor.sigstore.dev": dial tcp: i/o timeout'
scenario 'gh attestation verify fails: FAIL' 1 'gh attestation verify' STUB_GH_RC=1 STUB_GH_MSG='Error: no attestations found'
no_call '^docker' 'attestation failed: the image was not run'
scenario 'gh attestation verify: HTTP 503: warning, exit 0' 0 'looks unavailable' STUB_GH_RC=1 STUB_GH_MSG='HTTP 503: status code 503'
scenario 'docker pull denied: FAIL' 1 'not readable' STUB_PULL_RC=1 STUB_PULL_MSG='Error response from daemon: denied'
scenario 'docker pull timeout: warning, exit 0' 0 'looks unavailable' STUB_PULL_RC=1 STUB_PULL_MSG='net/http: TLS handshake timeout'
scenario 'production unreachable: warning, exit 0' 0 'answered HTTP 503' STUB_DATA_CODE=503
scenario 'production example 404 fails' 1 'HTTP 404' STUB_DATA_CODE=404
scenario 'posture example exits 1 in the image: FAIL' 1 'exited 1, expected 0' STUB_RUN_RC=1 STUB_RUN_OUT='VERIFICATION FAILED' STUB_IMG_VERSION=1.4.1
scenario 'posture example exits 0 without VERIFIED: FAIL' 1 "no 'VERIFIED'" STUB_RUN_OUT='nothing' STUB_IMG_VERSION=1.4.1
scenario 'status example exits 1 (revoked): FAIL' 1 'exited 1, expected 0' STUB_STATUS_RC=1 STUB_IMG_VERSION=1.4.1
scenario 'status example without GOOD: FAIL' 1 "no 'GOOD" STUB_STATUS_OUT=unknown STUB_IMG_VERSION=1.4.1
scenario 'the image reports another version: FAIL' 1 "expected 'verify-attestation.sh 1.4.1'" STUB_IMG_VERSION=1.4.0

printf '\n%s passed, %s failed\n' "$PASSED" "$FAILED"
[ "$FAILED" -eq 0 ]
