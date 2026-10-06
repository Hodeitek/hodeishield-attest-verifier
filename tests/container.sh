#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Hodeitek S.L.
# =============================================================================
# tests/container.sh — run the README's container command, verbatim.
#
# README.md ("Run it without installing anything") gives two `docker run`
# commands: the posture check, after the `<!-- container-route -->` marker, and
# the same with --status-list (revocation), after `<!-- container-route-status -->`.
# This script extracts each block (the fence right after its marker) and runs it
# as written, so the README cannot drift from what works. Only the leading
# `docker` word is replaced, by $ENGINE, to exercise Podman with the same text.
#
# Cases:
#   a. the image digest is the same in README.md and every workflow;
#   b. live: the production example verifies (exit 0, VERIFIED) and, with the
#      status list, is not revoked (exit 0, GOOD). An outage is a warning and
#      skips this case; a 404 fails, as in tests/live.sh;
#   c. offline: a document minted under a throwaway key verifies (exit 0), and
#      the same document with one signed field changed is rejected (exit 1,
#      "SIGNATURE DOES NOT VERIFY"); under a minted status list that revokes
#      nothing it is GOOD (exit 0), under one that revokes its key it is
#      REVOKED (exit 1). No production dependency.
#
# Env: ENGINE      docker (default) or podman
#      LIVE_ORIGIN default https://app.hodeishield.com
#      LIVE_SLUG   default talmaren-payments (the README's slug)
# Needs: docker or podman, curl, bash. Minting needs OpenSSL >= 3.5, so it runs
# inside the same pinned image as the README command.
# =============================================================================
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENGINE="${ENGINE:-docker}"
ORIGIN="${LIVE_ORIGIN:-https://app.hodeishield.com}"
SLUG="${LIVE_SLUG:-talmaren-payments}"
BASE="$ORIGIN/api/public/attest"
DIGEST_RE='debian:trixie-slim@sha256:[0-9a-f]{64}'

T="$(mktemp -d)"; chmod 700 "$T"
trap 'rm -rf -- "$T"' EXIT

gha() { if [ -n "${GITHUB_ACTIONS:-}" ]; then printf '::%s title=container route::%s\n' "$1" "$2"; fi; }
fail() { printf 'FAIL  %s\n' "$1" >&2; gha error "$1"; exit 1; }
warn() { printf 'WARN  %s\n' "$1"; gha warning "$1"; }
ok()   { printf 'ok    %s\n' "$1"; }

case "$ENGINE" in docker|podman) ;; *) fail "ENGINE must be docker or podman, got '$ENGINE'" ;; esac
command -v "$ENGINE" >/dev/null 2>&1 || fail "$ENGINE is not installed"

# --- the README blocks, verbatim ---------------------------------------------
# extract MARKER OUT — the bash fence right after <!-- MARKER --> in README.md.
extract() {
  awk -v m="<!-- $1 -->" '
    found && !inb && /^```bash[[:space:]]*$/ { inb = 1; next }
    found && inb && /^```[[:space:]]*$/ { exit }
    $0 == m { found = 1; next }
    found && inb { print }
  ' "$ROOT/README.md" > "$2"
  [ -s "$2" ] || fail "no code block after <!-- $1 --> in README.md"
  head -n1 "$2" | grep -q '^docker ' || fail "the <!-- $1 --> block does not start with 'docker '"
  if [ "$ENGINE" != docker ]; then
    sed -i "1s/^docker /$ENGINE /" "$2"
  fi
}
BLOCK="$T/block.sh";        extract container-route        "$BLOCK"
STATUS_BLOCK="$T/status.sh"; extract container-route-status "$STATUS_BLOCK"

# run_block DIR OUTFILE [BLOCK] — run a block with DIR as the working directory.
run_block() { ( cd "$1" && NO_COLOR=1 bash "${3:-$BLOCK}" ) > "$2" 2>&1; }

# stage DIR — a minimal copy of the repository: what the block runs.
stage() { mkdir -p "$1" && cp -R "$ROOT/scripts" "$1/"; }

# --- a. digest consistency ---------------------------------------------------
FILES=(README.md .github/workflows/ci.yml .github/workflows/live.yml .github/workflows/container.yml)
for f in "${FILES[@]}"; do
  grep -Eq "$DIGEST_RE" "$ROOT/$f" || fail "no pinned debian:trixie-slim digest in $f"
done
n="$(cd "$ROOT" && grep -Eho "$DIGEST_RE" "${FILES[@]}" | sort -u | wc -l)"
[ "$n" -eq 1 ] || fail "the pinned image digest differs between README.md and the workflows ($n distinct); change them in the same commit"
IMAGE="$(grep -Eho "$DIGEST_RE" "$ROOT/README.md" | sort -u)"
ok "one image digest in README.md and the workflows"

# --- b. live -----------------------------------------------------------------
fetch() {
  local out="$1" url="$2" code rc
  code="$(curl -sS --max-time 20 --retry 3 --retry-delay 5 --retry-connrefused \
            -o "$out" -w '%{http_code}' "$url" 2>"$out.err")"
  rc=$?
  case "$code" in
    200) return 0 ;;
    000|'') warn "could not reach $url (curl exit $rc) — outage, live case skipped"; return 1 ;;
    429|5??) warn "$url answered HTTP $code — outage, live case skipped"; return 1 ;;
    *) fail "$url answered HTTP $code — expected 200" ;;
  esac
}

live() {
  local d="$T/live" rc
  stage "$d"
  fetch "$d/att.json" "$BASE/$SLUG" || return 0
  fetch "$d/jwks.json" "$BASE/keys" || return 0
  run_block "$d" "$T/live.out"; rc=$?
  cat "$T/live.out"
  [ "$rc" -eq 0 ] || fail "live: README command exited $rc, expected 0"
  grep -q 'VERIFIED' "$T/live.out" || fail "live: no VERIFIED in the output"
  ok "live: README command verifies the production example (exit 0)"
  fetch "$d/status.json" "$BASE/status" || return 0
  fetch "$d/status-jwks.json" "$BASE/status-keys" || return 0
  run_block "$d" "$T/live-status.out" "$STATUS_BLOCK"; rc=$?
  cat "$T/live-status.out"
  [ "$rc" -eq 0 ] || fail "live: README --status-list command exited $rc, expected 0"
  grep -qF 'GOOD — not revoked, per a verified status list' "$T/live-status.out" \
    || fail "live: no GOOD verdict in the --status-list output"
  ok "live: README --status-list command finds the production example not revoked (exit 0)"
}
live

# --- c. offline rejection ----------------------------------------------------
# Mint inside the pinned image: OpenSSL >= 3.5 is not on every host.
# shellcheck disable=SC2016  # expanded inside the container, on purpose
MINTER='
set -e
apt-get update -qq >/dev/null
apt-get install -y -qq --no-install-recommends openssl python3 >/dev/null
M="python3 /repo/tests/lib/mint.py"
$M keygen --out /tmp/k.pem --jwks /out/jwks.json >/dev/null
GEN="$(date -u +%Y-%m-%dT%H:%M:%S.000Z)"
EXP="$(date -u -d "+10 minutes" +%Y-%m-%dT%H:%M:%S.000Z)"
$M attest --key /tmp/k.pem --out /out/att.json --slug "$SLUG" --iss "$ISS" \
  --generated-at "$GEN" --expires-at "$EXP" \
  --framework iso27001=substantial --framework nis2=basic >/dev/null
$M keygen --out /tmp/s.pem --jwks /out/status-jwks.json >/dev/null
KID="$(python3 -c "import json; print(json.load(open(\"/out/jwks.json\"))[\"keys\"][0][\"kid\"])")"
NEXT="$(date -u -d "+1 hour" +%Y-%m-%dT%H:%M:%S.000Z)"
$M status --key /tmp/s.pem --iss "$ISS" --issued-at "$GEN" --next-update "$NEXT" \
  --seq 1 --out /out/status-empty.json >/dev/null
$M status --key /tmp/s.pem --iss "$ISS" --issued-at "$GEN" --next-update "$NEXT" \
  --seq 2 --revoke-kid="$KID" --out /out/status-revoked.json >/dev/null
python3 - <<PY
import json
d = json.load(open("/out/att.json"))
d["attestation"]["claims"]["overallBand"] = "advanced"
json.dump(d, open("/out/att-tampered.json", "w"))
PY
chmod a+r /out/*
'
MINTDIR="$T/mint"; mkdir -p "$MINTDIR"
if ! "$ENGINE" run --rm -e SLUG="$SLUG" -e ISS="$ORIGIN" \
     -v "$ROOT":/repo:ro -v "$MINTDIR":/out "$IMAGE" bash -c "$MINTER" > "$T/mint.out" 2>&1; then
  cat "$T/mint.out"
  fail "offline: could not mint the throwaway document in the container"
fi

# The block expects att.json and jwks.json in the working directory.
stage "$T/valid";    cp "$MINTDIR/att.json"          "$T/valid/att.json";    cp "$MINTDIR/jwks.json" "$T/valid/"
stage "$T/tampered"; cp "$MINTDIR/att-tampered.json" "$T/tampered/att.json"; cp "$MINTDIR/jwks.json" "$T/tampered/"

run_block "$T/valid" "$T/valid.out"; rc=$?
cat "$T/valid.out"
[ "$rc" -eq 0 ] || fail "offline: untampered minted document exited $rc, expected 0"
grep -q 'VERIFIED' "$T/valid.out" || fail "offline: no VERIFIED for the untampered document"
ok "offline: untampered minted document verifies (exit 0)"

run_block "$T/tampered" "$T/tampered.out"; rc=$?
cat "$T/tampered.out"
[ "$rc" -eq 1 ] || fail "offline: tampered document exited $rc, expected 1"
grep -qF 'SIGNATURE DOES NOT VERIFY' "$T/tampered.out" \
  || fail "offline: tampered document was rejected, but not for a signature failure"
ok "offline: a changed signed field is rejected (exit 1, SIGNATURE DOES NOT VERIFY)"

# Revocation: the same minted document under two minted status lists.
for list in empty revoked; do
  cp "$MINTDIR/status-$list.json" "$T/valid/status.json"
  cp "$MINTDIR/status-jwks.json"  "$T/valid/status-jwks.json"
  run_block "$T/valid" "$T/status-$list.out" "$STATUS_BLOCK"; rc=$?
  cat "$T/status-$list.out"
  case "$list" in
    empty)
      [ "$rc" -eq 0 ] || fail "offline: --status-list with a list that revokes nothing exited $rc, expected 0"
      grep -qF 'GOOD — not revoked, per a verified status list' "$T/status-$list.out" \
        || fail "offline: no GOOD verdict under a list that revokes nothing"
      ok "offline: --status-list, a list that revokes nothing is GOOD (exit 0)" ;;
    revoked)
      [ "$rc" -eq 1 ] || fail "offline: --status-list with the key revoked exited $rc, expected 1"
      grep -qF 'REVOKED — via key' "$T/status-$list.out" \
        || fail "offline: no REVOKED verdict under a list that revokes the key"
      ok "offline: --status-list, a list that revokes the key is REVOKED (exit 1)" ;;
  esac
done
