#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Hodeitek S.L.
# =============================================================================
# tests/web-bundle.sh - the page bundle (verify-page-<tag>.tar.gz, built by
# tools/verify-page/build.sh) is reproducible and has the shape pages.yml needs.
#
#   bash tests/web-bundle.sh [WASM_DIR]
#
# Without WASM_DIR two stand-in files take the place of the module (the packaging
# does not depend on their content); with it, the real module built by
# tools/mldsa-wasm/build.sh is used.
#
# Checked:
#   - the same inputs give the same bytes when built twice, in other directories,
#     with another umask, at another time (the build uses only SOURCE_DATE_EPOCH);
#   - another SOURCE_DATE_EPOCH gives other bytes (the date is really used);
#   - index.html is at the root; names are sorted; owner and group are 0; files
#     are 0644 and folders 0755; every mtime is SOURCE_DATE_EPOCH; only files and
#     folders; no absolute path and no ".." in a name; gzip has no name and no time;
#   - MANIFEST.sha256 lists every file but itself, and every hash matches;
#   - mldsa/mldsa_wasm.b64.js carries exactly the bytes of mldsa/mldsa_wasm.wasm;
#   - a missing SOURCE_DATE_EPOCH or a missing module is refused.
# Needs bash, tar (GNU), gzip, coreutils and python3.
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD="$ROOT/tools/verify-page/build.sh"
fail() { printf 'not ok - %s\n' "$*" >&2; exit 1; }
ok() { printf 'ok - %s\n' "$*"; }

T="$(mktemp -d)"
trap 'rm -rf -- "$T"' EXIT

WASM="${1:-}"
if [ -z "$WASM" ]; then
  WASM="$T/wasm"; mkdir "$WASM"
  head -c 4096 /dev/zero | tr '\0' 'w' > "$WASM/mldsa_wasm.wasm"
  printf 'var Module=function(){};\n' > "$WASM/mldsa_wasm.js"
fi

SDE=1792000000
mkdir -p "$T/a" "$T/b/deeper/still" "$T/c"
SOURCE_DATE_EPOCH=$SDE bash "$BUILD" "$WASM" "$T/a/tree" "$T/a/bundle.tar.gz" > /dev/null
sleep 2
( umask 077; SOURCE_DATE_EPOCH=$SDE TMPDIR="$T" bash "$BUILD" "$WASM" "$T/b/deeper/still/tree" "$T/b/bundle.tar.gz" > /dev/null )
cmp "$T/a/bundle.tar.gz" "$T/b/bundle.tar.gz" || fail "two builds of the same inputs gave different bytes"
sum="$(sha256sum "$T/a/bundle.tar.gz" | cut -d' ' -f1)"
ok "two builds (other directories, other umask, two seconds apart) are identical: sha256 $sum"

SOURCE_DATE_EPOCH=$((SDE + 86400)) bash "$BUILD" "$WASM" "$T/c/tree" "$T/c/bundle.tar.gz" > /dev/null
if cmp -s "$T/a/bundle.tar.gz" "$T/c/bundle.tar.gz"; then fail "another SOURCE_DATE_EPOCH gave the same bytes"; fi
ok "another SOURCE_DATE_EPOCH gives other bytes"

# the listing
tar -tzf "$T/a/bundle.tar.gz" > "$T/names"
grep -qx './index.html' "$T/names" || fail "index.html is not at the root of the bundle"
LC_ALL=C sort -c "$T/names" || fail "the names are not sorted"
if grep -Eq '(^|/)\.\.(/|$)|^/|[[:cntrl:]]' "$T/names"; then fail "a name is absolute, holds .. or a control character"; fi
if tar -tzvf "$T/a/bundle.tar.gz" | grep -v '^[-d]' | grep -q .; then fail "the bundle holds something that is not a file or a folder"; fi
ok "index.html is at the root; names are sorted and plain; only files and folders"

python3 -I - "$T/a/bundle.tar.gz" "$SDE" <<'PY' || fail "owner, mode or time of an entry is not the fixed one"
import sys, tarfile
path, sde = sys.argv[1], int(sys.argv[2])
bad = []
with tarfile.open(path) as t:
    for m in t.getmembers():
        want = 0o755 if m.isdir() else 0o644
        if (m.uid, m.gid, m.uname, m.gname) != (0, 0, "", "") and (m.uid, m.gid) != (0, 0):
            bad.append(m.name + " owner")
        if m.mode != want: bad.append("%s mode %o" % (m.name, m.mode))
        if m.mtime != sde: bad.append("%s mtime %d" % (m.name, m.mtime))
if bad:
    print("\n".join(bad)); sys.exit(1)
PY
head -c 10 "$T/a/bundle.tar.gz" | od -An -tx1 | tr -d ' \n' | grep -q '^1f8b0[0-9a-f]00000000' \
  || fail "the gzip header carries a flag, a name or a time (use gzip -n)"
ok "owner 0:0, modes 0644 and 0755, every mtime is SOURCE_DATE_EPOCH, gzip -n"

# the manifest
mkdir "$T/x"
tar -xzf "$T/a/bundle.tar.gz" -C "$T/x" --no-same-owner --no-same-permissions --warning=no-timestamp
( cd "$T/x" && sha256sum --quiet -c MANIFEST.sha256 ) || fail "a hash in the manifest does not match"
( cd "$T/x" && find . -type f ! -name MANIFEST.sha256 | sed 's|^\./||' | LC_ALL=C sort ) > "$T/files"
sed -E 's/^[0-9a-f]{64}  //' "$T/x/MANIFEST.sha256" > "$T/listed"
cmp "$T/files" "$T/listed" || fail "the manifest does not list exactly the files of the bundle (without itself), in sorted order"
ok "MANIFEST.sha256 lists all $(wc -l < "$T/listed" | tr -d ' ') other files, and every hash matches"

# the module as base64 is the module
python3 -I - "$T/x/mldsa" <<'PY' || fail "mldsa_wasm.b64.js does not carry the bytes of mldsa_wasm.wasm"
import base64, re, sys
d = sys.argv[1]
js = open(d + "/mldsa_wasm.b64.js", encoding="ascii").read()
m = re.search(r'^globalThis\.HV_MLDSA_WASM_B64="([A-Za-z0-9+/=]*)";$', js, re.M)
assert m and base64.b64decode(m.group(1), validate=True) == open(d + "/mldsa_wasm.wasm", "rb").read()
PY
ok "mldsa_wasm.b64.js carries exactly the bytes of mldsa_wasm.wasm"

# refusals
if ( unset SOURCE_DATE_EPOCH; bash "$BUILD" "$WASM" "$T/n1" > /dev/null 2>&1 ); then fail "a build without SOURCE_DATE_EPOCH was accepted"; fi
mkdir "$T/empty"
if ( SOURCE_DATE_EPOCH=$SDE bash "$BUILD" "$T/empty" "$T/n2" > /dev/null 2>&1 ); then fail "a build without the module was accepted"; fi
ok "a missing SOURCE_DATE_EPOCH and a missing module are refused"

# check.sh: the pinned module, the file the page runs, and the manifest. The pin is
# made here from the module of this run (VERIFY_PAGE_EXPECTED is for this test only).
( cd "$WASM" && sha256sum mldsa_wasm.wasm mldsa_wasm.js ) > "$T/expected.sha256"
CHECK="$ROOT/tools/verify-page/check.sh"
export VERIFY_PAGE_EXPECTED="$T/expected.sha256"
bash "$CHECK" "$T/x" > /dev/null || fail "check.sh refused the untouched page"
ok "check.sh accepts the untouched page"
remanifest() {
  ( cd "$1" && find . -type f ! -name MANIFEST.sha256 | sed 's|^\./||' | LC_ALL=C sort | while IFS= read -r f; do sha256sum -- "$f"; done > "$T/m" )
  cp "$T/m" "$1/MANIFEST.sha256"
}
# a second module appended to the file the page runs, and the manifest made again
cp -r "$T/x" "$T/evil1"
printf 'globalThis["HV_MLDSA_"+"WASM_B64"]="AGFzbQEAAAA=";\n' >> "$T/evil1/mldsa/mldsa_wasm.b64.js"
remanifest "$T/evil1"
if bash "$CHECK" "$T/evil1" > /dev/null 2>&1; then fail "check.sh accepted a second module appended to mldsa_wasm.b64.js"; fi
# another module in place of the real one inside the script
cp -r "$T/x" "$T/evil2"
{ head -n 5 "$T/x/mldsa/mldsa_wasm.b64.js"; printf 'globalThis.HV_MLDSA_WASM_B64="AGFzbQEAAAA=";\n'; } > "$T/evil2/mldsa/mldsa_wasm.b64.js"
remanifest "$T/evil2"
if bash "$CHECK" "$T/evil2" > /dev/null 2>&1; then fail "check.sh accepted another module in mldsa_wasm.b64.js"; fi
# the .wasm itself changed
cp -r "$T/x" "$T/evil3"
printf 'x' >> "$T/evil3/mldsa/mldsa_wasm.wasm"
remanifest "$T/evil3"
if bash "$CHECK" "$T/evil3" > /dev/null 2>&1; then fail "check.sh accepted a changed mldsa_wasm.wasm"; fi
# a file changed and the manifest not made again
cp -r "$T/x" "$T/evil4"
printf '\n' >> "$T/evil4/index.html"
if bash "$CHECK" "$T/evil4" > /dev/null 2>&1; then fail "check.sh accepted a file that the manifest does not match"; fi
# a file added that the manifest does not list
cp -r "$T/x" "$T/evil5"
printf 'x' > "$T/evil5/extra.js"
if bash "$CHECK" "$T/evil5" > /dev/null 2>&1; then fail "check.sh accepted a file the manifest does not list"; fi
ok "check.sh refuses: a module appended to or replaced in mldsa_wasm.b64.js (manifest made again), a changed .wasm, a changed file, an unlisted file"
