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
# 3. mldsa/mldsa_wasm.b64.js, the file the page actually runs, decodes to exactly
#    those pinned .wasm bytes (the pin covers the module the page uses, not only
#    the file next to it).
# Needs bash, coreutils and python3.
# =============================================================================
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
DIR="${1:?usage: check.sh PAGE_DIR}"
EXPECTED="$ROOT/tools/mldsa-wasm/expected.sha256"

T="$(mktemp -d)"
trap 'rm -rf -- "$T"' EXIT
( cd "$DIR" && sha256sum --quiet -c MANIFEST.sha256 ) || { echo "not ok - a file does not match MANIFEST.sha256" >&2; exit 1; }
( cd "$DIR" && find . -type f ! -name MANIFEST.sha256 | sed 's|^\./||' | LC_ALL=C sort ) > "$T/files"
sed -E 's/^[0-9a-f]{64}  //' "$DIR/MANIFEST.sha256" > "$T/listed"
cmp -s "$T/files" "$T/listed" || { echo "not ok - MANIFEST.sha256 does not list exactly the files of the page" >&2; exit 1; }
echo "ok - MANIFEST.sha256 lists and matches every file"

( cd "$DIR/mldsa" && sha256sum --quiet -c "$EXPECTED" ) || { echo "not ok - the module is not the pinned one (tools/mldsa-wasm/expected.sha256)" >&2; exit 1; }
echo "ok - mldsa_wasm.wasm and mldsa_wasm.js are the pinned bytes"

python3 -I - "$DIR/mldsa" "$EXPECTED" <<'PY' || { echo "not ok - mldsa_wasm.b64.js does not decode to the pinned module" >&2; exit 1; }
import base64, hashlib, re, sys
d, expected = sys.argv[1], sys.argv[2]
pin = {}
for line in open(expected, encoding="ascii"):
    h, _, n = line.rstrip("\n").partition("  ")
    pin[n] = h
js = open(d + "/mldsa_wasm.b64.js", encoding="ascii").read()
m = re.search(r'^globalThis\.HV_MLDSA_WASM_B64="([A-Za-z0-9+/=]*)";$', js, re.M)
assert m, "no module in mldsa_wasm.b64.js"
assert len(re.findall(r"HV_MLDSA_WASM_B64", js)) == 1, "more than one module in mldsa_wasm.b64.js"
raw = base64.b64decode(m.group(1), validate=True)
assert hashlib.sha256(raw).hexdigest() == pin["mldsa_wasm.wasm"], "the decoded module is not the pinned one"
PY
echo "ok - mldsa_wasm.b64.js, the file the page runs, decodes to the pinned module"
