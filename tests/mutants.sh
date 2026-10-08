#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Hodeitek S.L.
# =============================================================================
# tests/mutants.sh — prove the published vectors catch a verifier whose
# signature check does nothing.
#
# It builds a MUTANT copy of the verifier in a temporary directory: the two
# `openssl pkeyutl -verify` calls (attestation and status list) are made to
# always succeed, by one targeted text substitution each. It first asserts the
# substitutions really changed the file, so that if the source moves this test
# fails loudly instead of silently becoming a no-op.
#
# Then, for every case of tests/vectors/v1/vectors.json marked
# "signature_only": true (every other check passes; only the signature check
# stands between the document and acceptance):
#   - the reference verifier must give the expected failure, and
#   - the mutant must ACCEPT it (exit 0: VERIFIED, or GOOD for a status list).
# That is what proves a case is signature-only. Finally it runs the whole
# vector set against the mutant (tests/vectors.sh) and reports how many cases
# the mutant fails; every signature_only case must be among them.
#
# Needs: bash >= 4, OpenSSL >= 3.5, python3, jq. No network.
#   bash tests/mutants.sh
#   VERIFIER=/path/to/copy bash tests/mutants.sh
# =============================================================================
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERIFIER="${VERIFIER:-$ROOT/scripts/attest/verify-attestation.sh}"
VDIR="$ROOT/tests/vectors/v1"

T="$(mktemp -d)"; chmod 700 "$T"
trap 'rm -rf -- "$T"' EXIT

MUTANT="$T/verify-attestation-mutant.sh"

echo '# mutants: build the signature-disabled mutant'
if ! python3 -I - "$VERIFIER" "$MUTANT" <<'PY'
import sys
src, dst = sys.argv[1:3]
text = open(src, encoding="utf-8").read()
subs = [
    ('if openssl pkeyutl -verify -pubin -inkey "$WORKDIR/pub.pem" -rawin',
     'if true || openssl pkeyutl -verify -pubin -inkey "$WORKDIR/pub.pem" -rawin',
     "attestation signature check"),
    ('if openssl pkeyutl -verify -pubin -inkey "$WORKDIR/status_pub.pem" -rawin',
     'if true || openssl pkeyutl -verify -pubin -inkey "$WORKDIR/status_pub.pem" -rawin',
     "status-list signature check"),
]
for old, new, what in subs:
    n = text.count(old)
    if n != 1:
        print("not ok - the %s line was found %d times, expected exactly 1; the verifier "
              "changed, update tests/mutants.sh" % (what, n))
        sys.exit(1)
    text = text.replace(old, new)
open(dst, "w", encoding="utf-8").write(text)
print("ok - 2 verification calls made to always succeed")
PY
then
  exit 1
fi
if cmp -s "$VERIFIER" "$MUTANT"; then
  echo 'not ok - the mutant is identical to the verifier; the substitution did nothing'
  exit 1
fi

# One record per signature_only case, NUL-separated:
#   id, exit, match, n_args, args...
if ! python3 -I - "$VDIR/vectors.json" > "$T/cases.bin" <<'PY'
import json, sys
m = json.load(open(sys.argv[1], encoding="utf-8"))
out = sys.stdout.buffer
for c in m["cases"]:
    if not c.get("signature_only"):
        continue
    e = c["expect"]
    for x in [c["id"], str(e["exit"]), e["match"], str(len(c["args"]))] + c["args"]:
        out.write(x.encode("utf-8") + b"\0")
PY
then
  echo 'not ok - could not read vectors.json'
  exit 1
fi

echo '# mutants: signature_only cases (reference rejects, mutant accepts)'
cd "$VDIR" || exit 1
TOTAL=0; FOOLED=0; BAD=0
while IFS= read -r -d '' id; do
  IFS= read -r -d '' want
  IFS= read -r -d '' match
  IFS= read -r -d '' nargs
  args=()
  for ((i = 0; i < nargs; i++)); do IFS= read -r -d '' x; args+=("$x"); done
  TOTAL=$((TOTAL + 1))

  NO_COLOR=1 bash "$VERIFIER" "${args[@]}" > "$T/ref.out" 2>&1 < /dev/null
  ref=$?
  NO_COLOR=1 bash "$MUTANT" "${args[@]}" > "$T/mut.out" 2>&1 < /dev/null
  mut=$?

  why=''
  if [ "$ref" -ne "$want" ]; then
    why="reference exit $ref, expected $want"
  elif ! grep -qF -- "$match" "$T/ref.out"; then
    why="reference did not print: $match"
  elif [ "$mut" -ne 0 ]; then
    why="mutant exit $mut, expected 0: another check rejects this case, so it is not signature-only"
  elif ! grep -qE 'VERIFIED — this document was signed|GOOD — not revoked' "$T/mut.out"; then
    why="mutant exit 0 but printed neither VERIFIED nor GOOD"
  fi
  if [ -n "$why" ]; then
    printf 'not ok - %s (%s)\n' "$id" "$why"
    BAD=$((BAD + 1))
  else
    printf 'ok - %s (reference exit %s, mutant exit 0)\n' "$id" "$ref"
    FOOLED=$((FOOLED + 1))
  fi
done < "$T/cases.bin"

echo
if [ "$TOTAL" -eq 0 ]; then
  echo 'not ok - vectors.json has no signature_only case'
  exit 1
fi

echo '# mutants: the whole vector set against the mutant'
VERIFIER="$MUTANT" bash "$ROOT/tests/vectors.sh" > "$T/all.out" 2>&1
SUMMARY="$(grep -E '^# vectors v1: [0-9]+ passed, [0-9]+ failed' "$T/all.out" | tail -1)"
VPASS="$(printf '%s' "$SUMMARY" | sed -n 's/.*: \([0-9]*\) passed.*/\1/p')"
VFAIL="$(printf '%s' "$SUMMARY" | sed -n 's/.* passed, \([0-9]*\) failed.*/\1/p')"
if [ -z "$VPASS" ] || [ -z "$VFAIL" ]; then
  echo 'not ok - could not read the vector summary for the mutant'
  sed 's/^/    # /' "$T/all.out" | tail -20
  exit 1
fi
VALL=$((VPASS + VFAIL))
printf '# mutants: the mutant fails %d of %d vectors\n' "$VFAIL" "$VALL"
if [ "$VFAIL" -lt "$TOTAL" ]; then
  echo "not ok - the mutant fails $VFAIL vectors, fewer than the $TOTAL signature_only cases"
  BAD=$((BAD + 1))
fi

printf '# mutants: signature_only cases fooling the mutant: %d of %d, problems: %d\n' "$FOOLED" "$TOTAL" "$BAD"
[ "$BAD" -eq 0 ] && [ "$FOOLED" -eq "$TOTAL" ]
