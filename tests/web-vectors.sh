#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Hodeitek S.L.
# =============================================================================
# tests/web-vectors.sh - the in-browser verifier against tests/vectors/v1, in
# real headless browsers, on the page as it is shipped.
#
#   bash tests/web-vectors.sh [--wasm DIR] [--browsers chrome,firefox] [--keep]
#
# --wasm DIR   the output of tools/mldsa-wasm/build.sh (mldsa_wasm.wasm and
#              mldsa_wasm.js). Without it the module is built first (needs docker
#              and network access, a minute or two).
# --browsers   which of chrome and firefox to run (default both: Google Chrome
#              and Firefox must be installed; both are on ubuntu-latest).
# --keep       keep the assembled page and print where it is.
#
# What it does: assembles the page exactly as the release bundle does
# (tools/verify-page/build.sh), checks its manifest, then for each browser runs
# tests/web/run.mjs twice: from http://127.0.0.1 and from disk (file://), as a
# downloaded copy is used. Every one of the 118 cases must give the verdict, exit
# code and reason code of the case, with the fixed "now" of the case (--now). The
# page's own controls are driven too (files, paste, drop, languages) and the
# result is read from data attributes, never from the text. The three
# --anchor-file cases need cosign, which the page does not have: the page must say
# "could not check" (exit 2), and one reason code differs by design (see
# docs/security/browser-verifier.md). Safari is not tested.
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WASM_DIR="${WASM_DIR:-}"
BROWSERS="chrome,firefox"
KEEP=0
while [ $# -gt 0 ]; do
  case "$1" in
    --wasm)     WASM_DIR="${2:?}"; shift 2 ;;
    --browsers) BROWSERS="${2:?}"; shift 2 ;;
    --keep)     KEEP=1; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
command -v node >/dev/null 2>&1 || { echo "node is needed (no npm packages)" >&2; exit 2; }

WORK="$(mktemp -d)"
trap 'if [ "$KEEP" -eq 0 ]; then rm -rf -- "$WORK"; else echo "# page kept in $WORK/page"; fi' EXIT

if [ -z "$WASM_DIR" ]; then
  echo '# building the ML-DSA-65 module (tools/mldsa-wasm/build.sh)'
  WASM_DIR="$WORK/wasm"
  bash "$ROOT/tools/mldsa-wasm/build.sh" "$WASM_DIR" > "$WORK/wasm.log" 2>&1 || { tail -20 "$WORK/wasm.log" >&2; exit 1; }
  cat "$WASM_DIR/SHA256SUMS"
fi

echo '# vectors v1: the files match SHA256SUMS'
( cd "$ROOT/tests/vectors/v1" && sha256sum --quiet -c SHA256SUMS ) || { echo 'not ok - the vectors changed since SHA256SUMS' >&2; exit 1; }

echo '# assembling the page as the release bundle does'
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-1792000000}" bash "$ROOT/tools/verify-page/build.sh" "$WASM_DIR" "$WORK/page" > /dev/null
bash "$ROOT/tools/verify-page/check.sh" "$WORK/page" || exit 1

rc=0
IFS=, read -r -a LIST <<< "$BROWSERS"
for b in "${LIST[@]}"; do
  case "$b" in
    chrome)
      command -v "${CHROME:-google-chrome}" >/dev/null 2>&1 || { echo 'not ok - Google Chrome is not installed' >&2; rc=1; continue; } ;;
    firefox)
      command -v "${FIREFOX:-firefox}" >/dev/null 2>&1 || { echo 'not ok - Firefox is not installed' >&2; rc=1; continue; } ;;
    *) echo "unknown browser: $b" >&2; exit 2 ;;
  esac
  for mode in http file; do
    out="$WORK/$b-$mode.out"
    code=0
    node "$ROOT/tests/web/run.mjs" --browser "$b" --mode "$mode" --page "$WORK/page" > "$out" || code=$?
    grep -E '^(#|not ok)' "$out" || true
    [ "$code" -eq 0 ] || rc=1
  done
done
echo
if [ "$rc" -eq 0 ]; then echo '# web vectors: all browsers passed'; else echo '# web vectors: FAILED'; fi
exit "$rc"
