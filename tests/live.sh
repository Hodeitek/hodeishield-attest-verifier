#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Hodeitek S.L.
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

# run LABEL WANT_EXIT -- verifier args... (RUN_VERIFIER, when set, is the script run)
run() {
  local label="$1" want="$2" got; shift 3
  NO_COLOR=1 bash "${RUN_VERIFIER:-$VERIFIER}" "$@" > "$T/out" 2>&1
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

# The key anchor, after a release that publishes a key statement (v1.4.0 and
# later): download the latest release's keys-statement.json and its bundle and
# run the verifier on the production example with --anchor-file. It needs cosign
# and the network. It SKIPS, with a warning, when cosign is missing here, when
# GitHub cannot be reached, or when the latest release has no statement yet (the
# releases before v1.4.0 do not). Anything else is a result: exit 0 is expected,
# so a live key that the released statement does not list fails this check.
anchor_skip() {
  printf 'WARN  anchor step skipped: %s\n' "$1"
  gha warning "anchor step skipped: $1"
  exit 0
}
command -v cosign >/dev/null 2>&1 || anchor_skip 'cosign is not installed here'
REPO_API='https://api.github.com/repos/Hodeitek/hodeishield-attest-verifier'
GH_AUTH=()
if [ -n "${GITHUB_TOKEN:-}" ]; then GH_AUTH=(-H "Authorization: Bearer $GITHUB_TOKEN"); fi
code="$(curl -sS --max-time 20 --retry 3 --retry-delay 5 -o "$T/release.json" -w '%{http_code}' \
          -H 'Accept: application/vnd.github+json' "${GH_AUTH[@]}" "$REPO_API/releases/latest" 2>/dev/null)" || code=000
case "$code" in
  200) ;;
  404) anchor_skip 'the repository has no published release yet' ;;
  *) anchor_skip "could not read the latest release (HTTP $code)" ;;
esac
STMT_URLS="$(python3 -I -c '
import json, sys
a = {x["name"]: x["browser_download_url"] for x in json.load(open(sys.argv[1])).get("assets", [])}
if "keys-statement.json" in a and "keys-statement.json.sigstore.json" in a:
    print(a["keys-statement.json"]); print(a["keys-statement.json.sigstore.json"])
' "$T/release.json" 2>/dev/null || true)"
[ -n "$STMT_URLS" ] || anchor_skip 'the latest release has no keys-statement.json yet'
# Anti-rollback: --anchor-file refuses a statement from a release older than the
# verifier itself. Between a version bump and its release (a pull request, dev),
# the verifier under test is newer than the latest release, so it must refuse that
# release's statement; the live coverage then comes from the latest release's own
# verifier. Equal (the released state): the verifier under test does it directly.
TAG="$(python3 -I -c 'import json, sys; print(json.load(open(sys.argv[1])).get("tag_name", ""))' "$T/release.json" 2>/dev/null || true)"
REL_VERSION="${TAG#v}"
[[ "$REL_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "the latest release has an unreadable tag: '$TAG'"
SCRIPT_VERSION="$(sed -n 's/^VERIFIER_VERSION="\(.*\)"$/\1/p' "$VERIFIER")"
[[ "$SCRIPT_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "VERIFIER_VERSION of the script under test is unreadable: '$SCRIPT_VERSION'"
if [ "$SCRIPT_VERSION" = "$REL_VERSION" ]; then
  ANCHOR_MODE=equal
elif [ "$(printf '%s\n%s\n' "$SCRIPT_VERSION" "$REL_VERSION" | sort -t. -k1,1n -k2,2n -k3,3n | tail -1)" = "$SCRIPT_VERSION" ]; then
  ANCHOR_MODE=newer
else
  # A branch older than the latest release: nothing it can check here would say
  # anything about the release, so it fails and says to update the branch.
  fail "the script under test is v$SCRIPT_VERSION, older than the latest release $TAG: update this branch"
fi

# download_assets DIR URL... — only from this repository's releases.
download_assets() {
  local dir="$1" url; shift
  mkdir -p "$dir"
  for url in "$@"; do
    case "$url" in
      https://github.com/Hodeitek/hodeishield-attest-verifier/releases/download/*) ;;
      *) fail "the latest release names an asset outside this repository's releases: $url" ;;
    esac
    curl -fsSL --max-time 30 --retry 3 --retry-delay 5 -o "$dir/$(basename "$url")" "$url" \
      || anchor_skip "could not download $(basename "$url")"
  done
}
mapfile -t stmt_urls <<< "$STMT_URLS"
[ "${#stmt_urls[@]}" -eq 2 ] || fail "expected the statement and its bundle, got ${#stmt_urls[@]} assets"
download_assets "$T/anchor" "${stmt_urls[@]}"

if [ "$ANCHOR_MODE" = equal ]; then
  run "the production key is listed in the latest release's key statement" 0 -- "${COMMON[@]}" \
    --anchor-file "$T/anchor/keys-statement.json"
  exit 0
fi

# (a) The verifier under test refuses a statement older than itself.
NO_COLOR=1 bash "$VERIFIER" "${COMMON[@]}" --anchor-file "$T/anchor/keys-statement.json" --json > "$T/out" 2>&1
got=$?
cat "$T/out"
reason="$(python3 -I -c 'import json, sys; print(json.load(open(sys.argv[1])).get("reason", ""))' "$T/out" 2>/dev/null || true)"
if [ "$got" -ne 2 ] || [ "$reason" != anchor_statement_older ]; then
  fail "the verifier refuses a key statement older than itself (anti-rollback): exit $got, reason '$reason', expected exit 2 and anchor_statement_older"
fi
printf 'ok    the verifier refuses a key statement older than itself (anti-rollback) (exit 2, anchor_statement_older)\n\n'

# (b) The latest release's verifier, from its assets, with the statement.
mapfile -t release_urls < <(python3 -I -c '
import json, sys
a = {x["name"]: x["browser_download_url"] for x in json.load(open(sys.argv[1])).get("assets", [])}
if "verify-attestation.sh" in a and "SHA256SUMS" in a:
    print(a["verify-attestation.sh"]); print(a["SHA256SUMS"])
' "$T/release.json" 2>/dev/null || true)
[ "${#release_urls[@]}" -eq 2 ] || fail "the latest release $TAG has no verify-attestation.sh and SHA256SUMS assets"
download_assets "$T/released" "${release_urls[@]}"
want_sum="$(awk '$2 == "verify-attestation.sh" { print $1 }' "$T/released/SHA256SUMS")"
have_sum="$(sha256sum "$T/released/verify-attestation.sh" | awk '{ print $1 }')"
if [ -z "$want_sum" ] || [ "$want_sum" != "$have_sum" ]; then
  fail "the released verify-attestation.sh ($have_sum) does not match SHA256SUMS ($want_sum)"
fi
RUN_VERIFIER="$T/released/verify-attestation.sh" \
  run "the production key is listed in the latest release's key statement (checked with the $TAG verifier)" 0 -- "${COMMON[@]}" \
  --anchor-file "$T/anchor/keys-statement.json"
