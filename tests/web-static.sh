#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Hodeitek S.L.
# =============================================================================
# tests/web-static.sh - static checks of the in-browser verifier page (web/):
#   - tests/web/static.mjs: the Content-Security-Policy is the strict one and
#     nothing in the markup or the code goes round it;
#   - tests/web/locales.mjs: the six interface languages keep the same keys and
#     say something of their own.
# Reads files only. Needs Node (no npm packages).
#   bash tests/web-static.sh
# =============================================================================
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
command -v node >/dev/null 2>&1 || { echo "node is needed (no npm packages)" >&2; exit 2; }
rc=0
echo '# web page: static checks'
node "$ROOT/tests/web/static.mjs" || rc=1
echo '# web page: interface languages'
node "$ROOT/tests/web/locales.mjs" || rc=1
exit "$rc"
