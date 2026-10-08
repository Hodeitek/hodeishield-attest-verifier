#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Hodeitek S.L.
# =============================================================================
# tests/version-consistency.sh - VERIFIER_VERSION must agree with CHANGELOG.md
# (and, on a release, with the tag).
#
# --anchor-file refuses a key statement from a release older than the script's
# own VERIFIER_VERSION, so that number must be the version this script is
# released as. Static: reads the script and the changelog, runs nothing else.
#
#   bash tests/version-consistency.sh            normal CI
#   bash tests/version-consistency.sh --tag v1.4.0   a release (tag push)
#   --script PATH, --changelog PATH              other files (for the tests)
#
# Normal: VERIFIER_VERSION equals the version of the top section when that is a
# dated heading "## vX.Y.Z - YYYY-MM-DD"; when the top section is "## Unreleased"
# it is strictly greater than the newest dated heading.
# Release: VERIFIER_VERSION equals the tag without its "v", and the changelog has
# the dated heading "## v<that> - YYYY-MM-DD".
# Needs bash and python3 (standard library only).
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$ROOT/scripts/attest/verify-attestation.sh"
CHANGELOG="$ROOT/CHANGELOG.md"
TAG=''
while [ $# -gt 0 ]; do
  case "$1" in
    --tag)       TAG="${2:?}"; shift 2 ;;
    --script)    SCRIPT="${2:?}"; shift 2 ;;
    --changelog) CHANGELOG="${2:?}"; shift 2 ;;
    *) printf 'unknown argument: %s\n' "$1" >&2; exit 2 ;;
  esac
done

python3 -I - "$SCRIPT" "$CHANGELOG" "$TAG" <<'PY'
import re, sys

script, changelog, tag = sys.argv[1:4]
ver_re = r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"

def tup(s):
    return tuple(int(x) for x in s.split("."))

m = [re.fullmatch(r'VERIFIER_VERSION="(.*)"', l.rstrip("\n"))
     for l in open(script, encoding="utf-8")]
m = [x for x in m if x]
if len(m) != 1:
    sys.exit("not ok - expected exactly one VERIFIER_VERSION=\"...\" line in %s, found %d" % (script, len(m)))
version = m[0].group(1)
if not re.fullmatch(ver_re, version):
    sys.exit("not ok - VERIFIER_VERSION %r is not N.N.N" % version)

top, dated = None, []
for l in open(changelog, encoding="utf-8"):
    l = l.rstrip("\n")
    if not l.startswith("## "):
        continue
    d = re.fullmatch(r"## v(%s) - ([0-9]{4}-[0-9]{2}-[0-9]{2})" % ver_re, l)
    if d:
        dated.append(d.group(1))
        top = top or ("dated", d.group(1))
    elif l == "## Unreleased":
        top = top or ("unreleased", None)
    elif l != "## Compatibility":
        sys.exit("not ok - unexpected heading in the changelog: %s" % l)
if top is None or not dated:
    sys.exit("not ok - the changelog has no dated version heading")
newest = max(dated, key=tup)

if tag:
    t = re.fullmatch(r"v(%s)" % ver_re, tag)
    if not t:
        sys.exit("not ok - %r is not a release tag vN.N.N" % tag)
    if version != t.group(1):
        sys.exit("not ok - VERIFIER_VERSION is %s, the tag is %s: the release commit must set it" % (version, tag))
    if version not in dated:
        sys.exit("not ok - the changelog has no dated heading '## v%s - YYYY-MM-DD'" % version)
    print("ok - release %s: VERIFIER_VERSION and the dated changelog heading agree" % tag)
elif top[0] == "unreleased":
    if tup(version) <= tup(newest):
        sys.exit("not ok - the top section is Unreleased, so VERIFIER_VERSION %s must be greater than the newest release v%s"
                 % (version, newest))
    print("ok - Unreleased: VERIFIER_VERSION %s is greater than the newest release v%s" % (version, newest))
else:
    if version != top[1]:
        sys.exit("not ok - the top section is v%s, VERIFIER_VERSION is %s" % (top[1], version))
    print("ok - VERIFIER_VERSION %s is the version of the top changelog section" % version)
PY
