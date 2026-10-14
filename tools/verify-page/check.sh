#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Hodeitek S.L.
# =============================================================================
# tools/verify-page/check.sh - check an assembled page (the output of build.sh, or
# an unpacked verify-page-<tag>.tar.gz) against what is pinned.
#
#   bash tools/verify-page/check.sh PAGE_DIR
#
# 1. MANIFEST.sha256 matches every file, and lists every file but itself;
# 2. mldsa/mldsa_wasm.wasm and mldsa/mldsa_wasm.js are the bytes pinned in
#    tools/mldsa-wasm/expected.sha256;
# 3. mldsa/mldsa_wasm.b64.js, the file the page actually runs, is byte for byte
#    what tools/verify-page/b64js.sh makes from that pinned .wasm (the pin covers
#    the module the page uses, not only the file next to it, and nothing can be
#    added to it).
# Needs bash, coreutils and python3.
# =============================================================================
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
DIR="${1:?usage: check.sh PAGE_DIR}"
# VERIFY_PAGE_EXPECTED is for the tests of this script only (a stand-in module).
EXPECTED="${VERIFY_PAGE_EXPECTED:-$ROOT/tools/mldsa-wasm/expected.sha256}"

T="$(mktemp -d)"
trap 'rm -rf -- "$T"' EXIT
( cd "$DIR" && sha256sum --quiet -c MANIFEST.sha256 ) || { echo "not ok - a file does not match MANIFEST.sha256" >&2; exit 1; }
( cd "$DIR" && find . -type f ! -name MANIFEST.sha256 | sed 's|^\./||' | LC_ALL=C sort ) > "$T/files"
sed -E 's/^[0-9a-f]{64}  //' "$DIR/MANIFEST.sha256" > "$T/listed"
cmp -s "$T/files" "$T/listed" || { echo "not ok - MANIFEST.sha256 does not list exactly the files of the page" >&2; exit 1; }
echo "ok - MANIFEST.sha256 lists and matches every file"

( cd "$DIR/mldsa" && sha256sum --quiet -c "$EXPECTED" ) || { echo "not ok - the module is not the pinned one (tools/mldsa-wasm/expected.sha256)" >&2; exit 1; }
echo "ok - mldsa_wasm.wasm and mldsa_wasm.js are the pinned bytes"

# The file the page runs, compared byte for byte with what b64js.sh makes from the
# pinned module (the module's hash was checked just above): nothing can be appended
# to it, and no second module can be added.
bash "$HERE/b64js.sh" "$DIR/mldsa/mldsa_wasm.wasm" > "$T/b64.js"
cmp -s "$T/b64.js" "$DIR/mldsa/mldsa_wasm.b64.js" || { echo "not ok - mldsa_wasm.b64.js is not exactly what the pinned module makes" >&2; exit 1; }
echo "ok - mldsa_wasm.b64.js, the file the page runs, is exactly the pinned module (byte for byte)"
