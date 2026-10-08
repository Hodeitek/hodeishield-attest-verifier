#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Hodeitek S.L.
# =============================================================================
# tests/keys-drift.sh - a rotation alarm. Reads the live key sets and compares
# them with docs/security/keys.json. Read-only.
#
# Recomputes each kid from the `pub` bytes (as the README does, never trusting
# the published kid) and fails if
#   * a live kid is absent from keys.json under the role of the endpoint it
#     was served from, or
#   * a live key carries hs_retired_at and keys.json retired_at disagrees.
#
# An unreachable or failing service is a warning, exit 0, as in tests/live.sh.
# Env: LIVE_ORIGIN (default https://app.hodeishield.com)
# =============================================================================
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ORIGIN="${LIVE_ORIGIN:-https://app.hodeishield.com}"
BASE="$ORIGIN/api/public/attest"

T="$(mktemp -d)"; chmod 700 "$T"
trap 'rm -rf -- "$T"' EXIT

for path in keys status-keys; do
  code="$(curl -sS --max-time 20 --retry 3 --retry-delay 5 --retry-connrefused \
            -o "$T/$path.json" -w '%{http_code}' "$BASE/$path" 2>/dev/null)" || code=000
  case "$code" in
    200) ;;
    000|''|429|5??)
      printf 'WARN  %s/%s answered %s - treated as an outage, not a drift result.\n' "$BASE" "$path" "$code"
      [ -z "${GITHUB_ACTIONS:-}" ] || printf '::warning title=keys drift::%s unavailable (HTTP %s)\n' "$path" "$code"
      exit 0 ;;
    *) printf 'FAIL  %s/%s answered HTTP %s - expected 200\n' "$BASE" "$path" "$code" >&2; exit 1 ;;
  esac
done

python3 -I - "$ROOT/docs/security/keys.json" "$T/keys.json" attestation "$T/status-keys.json" status-list <<'PY'
import base64, hashlib, json, sys

statement = json.load(open(sys.argv[1], encoding="utf-8"))
known = {k["kid"]: k for k in statement["keys"]}
errors = []

def kid_of(pub):
    raw = base64.urlsafe_b64decode(pub + "=" * (-len(pub) % 4))
    d = hashlib.sha256(b"hodei-shield.attest.kid.v1" + raw).digest()[:16]
    return base64.urlsafe_b64encode(d).decode().rstrip("=")

args = sys.argv[2:]
for path, role in zip(args[0::2], args[1::2]):
    try:
        live = json.load(open(path, encoding="utf-8"))["keys"]
        kids = [(kid_of(k["pub"]), k) for k in live]
    except (ValueError, KeyError, TypeError) as e:
        errors.append("the live %s key set cannot be read: %s" % (role, e))
        continue
    for kid, k in kids:
        s = known.get(kid)
        if s is None or s["role"] != role:
            errors.append("live %s kid %s is not in keys.json under that role" % (role, kid))
        elif "hs_retired_at" in k and s.get("retired_at") != k["hs_retired_at"]:
            errors.append("%s: live hs_retired_at %r, keys.json retired_at %r"
                          % (kid, k["hs_retired_at"], s.get("retired_at")))
    print("ok    %s: %s" % (role, ", ".join(kid for kid, _ in kids)))

if errors:
    for e in errors:
        print("FAIL  " + e, file=sys.stderr)
        print("::error title=keys drift::" + e)
    sys.exit(1)
PY
