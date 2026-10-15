#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Hodeitek S.L.
# =============================================================================
# tools/verify-page/reader-check.sh - check a verify-page-<tag>.tar.gz the way a
# reader would use it, before it is signed into a release.
#
#   bash tools/verify-page/reader-check.sh BUNDLE.tar.gz
#
# 1. index.html is at the root of the archive;
# 2. no name is absolute or holds a ".." component;
# 3. every entry is a plain file or a folder (no link, no device);
# 4. unpacked, it passes tools/verify-page/check.sh (manifest and pinned module).
# The listings are written to files and read from there: under pipefail,
# `tar | grep -q` fails when grep stops reading before tar has finished, which
# refused a good bundle and let a bad one through (the v1.6.0 tag).
# Needs bash, tar, gzip, coreutils and python3.
# =============================================================================
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUNDLE="${1:?usage: reader-check.sh BUNDLE.tar.gz}"
fail() { printf 'not ok - %s\n' "$*" >&2; exit 1; }

if [ ! -f "$BUNDLE" ] || [ -L "$BUNDLE" ]; then fail "$BUNDLE is not a plain file"; fi

T="$(mktemp -d)"
trap 'rm -rf -- "$T"' EXIT

tar -tzf "$BUNDLE" > "$T/names" || fail "the bundle cannot be listed"
tar -tzvf "$BUNDLE" > "$T/long" || fail "the bundle cannot be listed"

grep -qx './index.html' "$T/names" || fail "index.html is not at the root of the bundle"
if grep -Eq '(^|/)\.\.(/|$)|^/' "$T/names"; then fail "the bundle has an absolute path or a '..' component"; fi
if grep -v '^[-d]' "$T/long" > "$T/odd"; then
  cat "$T/odd" >&2
  fail "the bundle has entries that are not plain files or folders"
fi

mkdir "$T/unpacked"
tar -xzf "$BUNDLE" -C "$T/unpacked" --no-same-owner --no-same-permissions --touch
bash "$HERE/check.sh" "$T/unpacked"
printf 'ok - %s: index.html at the root, plain names, only files and folders, manifest and module as pinned\n' "$(basename "$BUNDLE")"
