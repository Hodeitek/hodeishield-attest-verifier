#!/usr/bin/env bash
# =============================================================================
# tests/live.sh — verify the README's live example against production.
#
# Fetches the public example attestation, the attestation key set, the
# revocation status list and the status key set from LIVE_ORIGIN, then runs the
# verifier on them exactly as the README tells a reader to.
#
# The one distinction this script exists to keep:
#
#   * The network, or the service, being unavailable (no connection, timeout,
#     HTTP 5xx or 429 after retries) is NOT a finding about the verifier or the
#     document. It is reported as a warning and the script exits 0.
#   * Everything else fails: the example subject not existing (HTTP 404 — the
#     README would be teaching a dead command), a document that does not verify
#     (exit 1), a check that could not run on a controlled toolchain (exit 2),
#     a revocation status of revoked (1) or unknown (3).
#
# Env: LIVE_ORIGIN (default https://app.hodeishield.com)
#      LIVE_SLUG   (default talmaren-payments — a demo organisation with
#                   fictitious data; README.md must use the same slug)
# =============================================================================
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERIFIER="$ROOT/scripts/attest/verify-attestation.sh"
ORIGIN="${LIVE_ORIGIN:-https://app.hodeishield.com}"
SLUG="${LIVE_SLUG:-talmaren-payments}"
BASE="$ORIGIN/api/public/attest"

T="$(mktemp -d)"; chmod 700 "$T"
trap 'rm -rf -- "$T"' EXIT

gha() { if [ -n "${GITHUB_ACTIONS:-}" ]; then printf '::%s title=live check::%s\n' "$1" "$2"; fi; }
outage() {
  printf 'WARN  %s — treated as an outage, not a verification result.\n' "$1"
  gha warning "$1 (outage: not a verification result)"
  exit 0
}
fail() {
  printf 'FAIL  %s\n' "$1" >&2
  gha error "$1"
  exit 1
}

# The README example and this check must name the same subject, or one of them
# is testing something nobody reads.
grep -qF "/api/public/attest/$SLUG " "$ROOT/README.md" \
  || fail "README.md does not use the live example /api/public/attest/$SLUG"

# fetch NAME URL — retries transient errors; classifies what is left.
fetch() {
  local out="$T/$1" code rc
  code="$(curl -sS --max-time 20 --retry 3 --retry-delay 5 --retry-connrefused \
            -o "$out" -w '%{http_code}' "$2" 2>"$T/$1.err")"
  rc=$?
  case "$code" in
    200) return 0 ;;
    000|'') outage "could not reach $2 (curl exit $rc: $(tr '\n' ' ' < "$T/$1.err"))" ;;
    429|5??) outage "$2 answered HTTP $code" ;;
    *) fail "$2 answered HTTP $code — expected 200" ;;
  esac
}

fetch att.json          "$BASE/$SLUG"
fetch jwks.json         "$BASE/keys"
fetch status.json       "$BASE/status"
fetch status-keys.json  "$BASE/status-keys"

# run LABEL WANT_EXIT -- verifier args...
run() {
  local label="$1" want="$2" got; shift 3
  NO_COLOR=1 bash "$VERIFIER" "$@" > "$T/out" 2>&1
  got=$?
  cat "$T/out"
  if [ "$got" -ne "$want" ]; then
    fail "$label: verifier exit $got, expected $want (1 = check failed/revoked, 2 = could not check, 3 = revocation unknown)"
  fi
  printf 'ok    %s (exit %s)\n\n' "$label" "$got"
}

COMMON=(--attestation "$T/att.json" --jwks "$T/jwks.json"
        --expect-slug "$SLUG" --expect-issuer "$ORIGIN")

run "posture attestation for $SLUG verifies" 0 -- "${COMMON[@]}"
run "$SLUG is not revoked per the live status list" 0 -- "${COMMON[@]}" \
  --status-list --status "$T/status.json" --status-keys "$T/status-keys.json"
