#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Hodeitek S.L.
# =============================================================================
# tools/verify-page/build.sh - assemble the in-browser verifier page, and
# optionally pack it as the release bundle verify-page-<tag>.tar.gz.
#
#   SOURCE_DATE_EPOCH=<seconds> bash tools/verify-page/build.sh WASM_DIR OUT_TREE [OUT.tar.gz]
#
# WASM_DIR   the output of tools/mldsa-wasm/build.sh (mldsa_wasm.wasm and
#            mldsa_wasm.js). Nothing built is kept in the repository.
# OUT_TREE   a directory that does not exist yet; the page is assembled in it:
#              web/*                         as in the repository
#              mldsa/mldsa_wasm.wasm         the module, unchanged
#              mldsa/mldsa_wasm.js           the Emscripten loader, unchanged
#              mldsa/mldsa_wasm.b64.js       the same module bytes as base64 in a
#                                            script, so the page needs no request
#                                            and also works opened from disk
#              MANIFEST.sha256               SHA-256 of every other file
# OUT.tar.gz the release bundle, if a name is given: sorted names, owner 0:0,
#            fixed modes, mtime SOURCE_DATE_EPOCH, gzip -n. The same inputs
#            give the same bytes.
#
# SOURCE_DATE_EPOCH is required: the output must not depend on the clock.
# =============================================================================
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
WASM_DIR="${1:?usage: build.sh WASM_DIR OUT_TREE [OUT.tar.gz]}"
TREE="${2:?usage: build.sh WASM_DIR OUT_TREE [OUT.tar.gz]}"
TARBALL="${3:-}"
: "${SOURCE_DATE_EPOCH:?SOURCE_DATE_EPOCH must be set (the bundle must not depend on the clock)}"
[[ "$SOURCE_DATE_EPOCH" =~ ^[0-9]{1,12}$ ]] || { echo "SOURCE_DATE_EPOCH is not a number" >&2; exit 2; }

for f in mldsa_wasm.wasm mldsa_wasm.js; do
  if [ ! -f "$WASM_DIR/$f" ] || [ -L "$WASM_DIR/$f" ]; then
    echo "missing $WASM_DIR/$f (build it with tools/mldsa-wasm/build.sh)" >&2
    exit 2
  fi
done
[ ! -e "$TREE" ] || { echo "$TREE already exists" >&2; exit 2; }
if [ -n "$TARBALL" ] && [ -e "$TARBALL" ]; then echo "$TARBALL already exists" >&2; exit 2; fi

# The page, as committed. Regular files and directories only.
if [ -n "$(find "$ROOT/web" ! -type f ! -type d -print -quit)" ]; then
  echo "web/ holds something that is not a regular file or a directory" >&2; exit 2
fi
mkdir -p "$TREE"
( cd "$ROOT/web" && tar -cf - . ) | ( cd "$TREE" && tar -xf - --no-same-owner --no-same-permissions )

mkdir "$TREE/mldsa"
cp "$WASM_DIR/mldsa_wasm.wasm" "$WASM_DIR/mldsa_wasm.js" "$TREE/mldsa/"
{
  printf '// SPDX-License-Identifier: Apache-2.0\n'
  printf '// Copyright 2026 Hodeitek S.L.\n'
  printf '//\n'
  printf '// The bytes of mldsa_wasm.wasm as base64, made by tools/verify-page/build.sh. Not edited by hand:\n'
  printf '// decode it and compare with mldsa_wasm.wasm, or with a build of tools/mldsa-wasm.\n'
  printf 'globalThis.HV_MLDSA_WASM_B64="%s";\n' "$(base64 -w0 "$WASM_DIR/mldsa_wasm.wasm")"
} > "$TREE/mldsa/mldsa_wasm.b64.js"

# Fixed modes, so the bytes of the archive do not depend on the umask.
find "$TREE" -type d -exec chmod 0755 {} +
find "$TREE" -type f -exec chmod 0644 {} +

# The manifest: every file but itself, sorted by name, in sha256sum's format.
TMP="$(mktemp -d)"
trap 'rm -rf -- "$TMP"' EXIT
( cd "$TREE" && find . -type f -print | LC_ALL=C sort | sed 's|^\./||' \
    | while IFS= read -r f; do sha256sum -- "$f"; done > "$TMP/MANIFEST.sha256" )
cp "$TMP/MANIFEST.sha256" "$TREE/MANIFEST.sha256"
chmod 0644 "$TREE/MANIFEST.sha256"
[ -f "$TREE/index.html" ] || { echo "index.html is not at the root of the page" >&2; exit 2; }

if [ -n "$TARBALL" ]; then
  ( cd "$TREE" && find . -mindepth 1 -print | LC_ALL=C sort > "$TMP/list" )
  ( cd "$TREE" && tar --no-recursion --files-from="$TMP/list" --format=gnu \
      --owner=0 --group=0 --numeric-owner --mtime="@$SOURCE_DATE_EPOCH" -cf - ) | gzip -n -9 > "$TARBALL"
  sha256sum "$TARBALL"
fi
