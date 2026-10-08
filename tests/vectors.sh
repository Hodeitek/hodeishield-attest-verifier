#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Hodeitek S.L.
# =============================================================================
# tests/vectors.sh — run the published test vectors against the verifier.
#
# tests/vectors/v1/ is a static, committed set of documents, keys and expected
# outcomes (see its README.md). This runner:
#
#   1. checks every file in v1/ against SHA256SUMS (a vector that changed is a
#      failure, not a surprise), then
#   2. runs every case in vectors.json from inside v1/ as
#        NO_COLOR=1 bash "$VERIFIER" <args...>
#      and asserts the exit code, the `match` line of the reference script's
#      output, any `absent` lines, and (when recorded) the canonical sha-256.
#
# Needs: bash >= 4, OpenSSL >= 3.5, python3 (standard library only; it reads the
# manifest), and jq (the verifier itself needs it for --status-list). No network,
# except for the cases marked "requires": ["cosign"] (the --anchor-file cases
# built on real Sigstore bundles): they need cosign 3.1.3 or later and the network
# (cosign may refresh its trust root from the Sigstore TUF repository). A case
# whose requirement is absent is reported as SKIPPED, never as passed.
#   bash tests/vectors.sh
#   VERIFIER=/path/to/copy bash tests/vectors.sh
# =============================================================================
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERIFIER="${VERIFIER:-$ROOT/scripts/attest/verify-attestation.sh}"
VDIR="$ROOT/tests/vectors/v1"

T="$(mktemp -d)"; chmod 700 "$T"
trap 'rm -rf -- "$T"' EXIT

PASSED=0; FAILED=0; SKIPPED=0

# Whether the requirement $1 of a case is available here.
have_requirement() {
  case "$1" in
    cosign)
      local v=''
      command -v cosign >/dev/null 2>&1 || return 1
      v="$(cosign version 2>/dev/null | awk '$1 == "GitVersion:" { print $2; exit }' || true)"
      python3 -c '
import re, sys
m = re.fullmatch(r"v?([0-9]{1,6})\.([0-9]{1,6})\.([0-9]{1,6})(-.*)?", sys.argv[1])
n = tuple(int(x) for x in m.groups()[:3]) if m else (0, 0, 0)
sys.exit(0 if n > (3, 1, 3) or (n == (3, 1, 3) and not m.group(4)) else 1)
' "$v"
      ;;
    *) return 1 ;;
  esac
}

echo '# vectors v1: SHA256SUMS'
if ! python3 - "$VDIR" <<'PY'
import hashlib, os, sys
root = sys.argv[1]
listed = {}
for line in open(os.path.join(root, "SHA256SUMS"), encoding="utf-8"):
    h, _, rel = line.rstrip("\n").partition("  ")
    listed[rel] = h
bad = 0
for rel, h in sorted(listed.items()):
    p = os.path.join(root, rel)
    if not os.path.isfile(p):
        print("not ok - listed file is missing: " + rel); bad += 1
    elif hashlib.sha256(open(p, "rb").read()).hexdigest() != h:
        print("not ok - file changed since SHA256SUMS: " + rel); bad += 1
for dp, _, fns in os.walk(root):
    for fn in fns:
        rel = os.path.relpath(os.path.join(dp, fn), root)
        if rel != "SHA256SUMS" and rel not in listed:
            print("not ok - file not in SHA256SUMS: " + rel); bad += 1
if bad:
    sys.exit(1)
print("ok - %d files match SHA256SUMS" % len(listed))
PY
then
  echo '# vectors v1: SHA256SUMS does not match; not running the cases'
  exit 1
fi

# One record per case, NUL-separated fields:
#   id, exit, code, match, canonical, status_canonical, n_absent, n_args, n_req,
#   absent..., args..., requires...
if ! python3 - "$VDIR/vectors.json" > "$T/cases.bin" <<'PY'
import json, sys
m = json.load(open(sys.argv[1], encoding="utf-8"))
out = sys.stdout.buffer
for c in m["cases"]:
    e = c["expect"]
    absent = e.get("absent", [])
    f = [c["id"], str(e["exit"]), e["code"], e["match"],
         c.get("canonical_sha256", ""), c.get("status_canonical_sha256", ""),
         str(len(absent)), str(len(c["args"])), str(len(c.get("requires", [])))] + absent + c["args"] + c.get("requires", [])
    for x in f:
        out.write(x.encode("utf-8") + b"\0")
PY
then
  echo 'not ok - could not read vectors.json'
  exit 1
fi

echo '# vectors v1: cases'
cd "$VDIR" || exit 1
while IFS= read -r -d '' id; do
  IFS= read -r -d '' want
  IFS= read -r -d '' code
  IFS= read -r -d '' match
  IFS= read -r -d '' canon
  IFS= read -r -d '' scanon
  IFS= read -r -d '' nabs
  IFS= read -r -d '' nargs
  IFS= read -r -d '' nreq
  absent=(); args=(); reqs=()
  for ((i = 0; i < nabs; i++)); do IFS= read -r -d '' x; absent+=("$x"); done
  for ((i = 0; i < nargs; i++)); do IFS= read -r -d '' x; args+=("$x"); done
  for ((i = 0; i < nreq; i++)); do IFS= read -r -d '' x; reqs+=("$x"); done

  missing=''
  for x in "${reqs[@]+"${reqs[@]}"}"; do
    have_requirement "$x" || missing="${missing:+$missing, }$x"
  done
  if [ -n "$missing" ]; then
    printf 'skipped - %s [%s] (needs %s, not available here)\n' "$id" "$code" "$missing"
    SKIPPED=$((SKIPPED + 1))
    continue
  fi

  out="$T/out.$((PASSED + FAILED + SKIPPED))"
  NO_COLOR=1 bash "$VERIFIER" "${args[@]}" > "$out" 2>&1 < /dev/null
  got=$?
  why=''
  if [ "$got" -ne "$want" ]; then
    why="exit $got, expected $want"
  elif ! grep -qF -- "$match" "$out"; then
    why="exit $got as expected, but no line containing: $match"
  else
    for a in "${absent[@]+"${absent[@]}"}"; do
      if grep -qF -- "$a" "$out"; then why="output contains: $a"; break; fi
    done
    if [ -z "$why" ] && [ -n "$canon" ] && ! grep -qF -- "sha-256: $canon" "$out"; then
      why="canonical sha-256 $canon not printed"
    fi
    if [ -z "$why" ] && [ -n "$scanon" ] && ! grep -qF -- "sha-256: $scanon" "$out"; then
      why="status-list canonical sha-256 $scanon not printed"
    fi
  fi
  if [ -n "$why" ]; then
    printf 'not ok - %s [%s] (%s)\n' "$id" "$code" "$why"
    sed 's/^/    # /' "$out"
    FAILED=$((FAILED + 1))
  else
    printf 'ok - %s (exit %s, %s)\n' "$id" "$got" "$code"
    PASSED=$((PASSED + 1))
  fi
done < "$T/cases.bin"

echo
printf '# vectors v1: %d passed, %d failed, %d skipped\n' "$PASSED" "$FAILED" "$SKIPPED"
[ "$FAILED" -eq 0 ] && [ "$PASSED" -gt 0 ]
