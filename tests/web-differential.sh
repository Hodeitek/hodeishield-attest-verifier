#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Hodeitek S.L.
# =============================================================================
# tests/web-differential.sh - the page's verifier logic and the real script, on
# the same arguments, must give the same exit code, verdict and reason code.
#
#   bash tests/web-differential.sh [--wasm DIR]
#
# The cases are in tests/web/differential/cases.json: inputs on which the page once
# gave a weaker verdict than the script (a duplicate member nested in the protected
# header, an integer of more than 4,300 digits, the refusals of the script's reader
# of the status list) and a genuine document with a direction-override character
# in its organisation name. The 118 vectors of tests/vectors/v1 are run by
# tests/web-vectors.sh and are not repeated here.
#
# Needs what the script needs (bash, OpenSSL >= 3.5, python3) and Node. --wasm is the
# output of tools/mldsa-wasm/build.sh; without it the module is built first.
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WASM_DIR="${WASM_DIR:-}"
while [ $# -gt 0 ]; do
  case "$1" in
    --wasm) WASM_DIR="${2:?}"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
command -v node >/dev/null 2>&1 || { echo "node is needed (no npm packages)" >&2; exit 2; }

WORK="$(mktemp -d)"
trap 'rm -rf -- "$WORK"' EXIT
if [ -z "$WASM_DIR" ]; then
  WASM_DIR="$WORK/wasm"
  bash "$ROOT/tools/mldsa-wasm/build.sh" "$WASM_DIR" > "$WORK/wasm.log" 2>&1 || { tail -20 "$WORK/wasm.log" >&2; exit 1; }
fi
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-1792000000}" bash "$ROOT/tools/verify-page/build.sh" "$WASM_DIR" "$WORK/page" > /dev/null
bash "$ROOT/tools/verify-page/check.sh" "$WORK/page" > /dev/null
node "$ROOT/tests/web/differential/run.mjs" "$WORK/page"
