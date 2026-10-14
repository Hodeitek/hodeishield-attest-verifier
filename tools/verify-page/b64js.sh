#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Hodeitek S.L.
# =============================================================================
# tools/verify-page/b64js.sh - print mldsa_wasm.b64.js for a module.
#
#   bash tools/verify-page/b64js.sh mldsa_wasm.wasm > mldsa_wasm.b64.js
#
# The page runs the module from this script, not from the .wasm file, so that it
# needs no request and also works opened from disk. build.sh writes it with this
# script, and check.sh writes it again from the pinned module and compares the two
# byte for byte, so that nothing can be added to the file the page runs.
# =============================================================================
set -euo pipefail
WASM="${1:?usage: b64js.sh mldsa_wasm.wasm}"
printf '// SPDX-License-Identifier: Apache-2.0\n'
printf '// Copyright 2026 Hodeitek S.L.\n'
printf '//\n'
printf '// The bytes of mldsa_wasm.wasm as base64, made by tools/verify-page/b64js.sh. Not edited by hand:\n'
printf '// decode it and compare with mldsa_wasm.wasm, or with a build of tools/mldsa-wasm.\n'
printf 'globalThis.HV_MLDSA_WASM_B64="%s";\n' "$(base64 -w0 "$WASM")"
