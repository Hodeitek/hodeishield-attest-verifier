#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Hodeitek S.L.
# =============================================================================
# tests/container.sh — run the README's container command, verbatim.
#
# README.md ("Run it without installing anything") gives one `docker run`
# command. This script extracts that block (the fence right after the
# `<!-- container-route -->` marker) and runs it as written, so the README
# cannot drift from what works. Only the leading `docker` word is replaced,
# by $ENGINE, to exercise Podman with the same text.
#
# Cases:
#   a. the image digest is the same in README.md and every workflow;
#   b. live: the production example verifies (exit 0, VERIFIED). An outage is a
#      warning and skips this case; a 404 fails, as in tests/live.sh;
#   c. offline: a document minted under a throwaway key verifies (exit 0), and
#      the same document with one signed field changed is rejected (exit 1,
#      "SIGNATURE DOES NOT VERIFY"), with no production dependency.
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

# --- the README block, verbatim ---------------------------------------------
BLOCK="$T/block.sh"
awk '
  found && !inb && /^```bash[[:space:]]*$/ { inb = 1; next }
  found && inb && /^```[[:space:]]*$/ { exit }
  /^<!-- container-route -->[[:space:]]*$/ { found = 1; next }
  found && inb { print }
' "$ROOT/README.md" > "$BLOCK"
[ -s "$BLOCK" ] || fail "no code block after <!-- container-route --> in README.md"
head -n1 "$BLOCK" | grep -q '^docker ' || fail "the README block does not start with 'docker '"
if [ "$ENGINE" != docker ]; then
  sed -i "1s/^docker /$ENGINE /" "$BLOCK"
fi

# run_block DIR OUTFILE — run the block with DIR as the working directory.
run_block() { ( cd "$1" && NO_COLOR=1 bash "$BLOCK" ) > "$2" 2>&1; }

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
