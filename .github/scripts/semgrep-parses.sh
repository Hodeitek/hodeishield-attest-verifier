#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Hodeitek S.L.
# =============================================================================
# semgrep-parses.sh - fail if Semgrep's bash parser cannot parse
# a script completely.
#
#   semgrep-parses.sh FILE...
#
# Needs semgrep on the PATH (ci.yml installs a pinned version) and python3.
#
# Semgrep exits 0 on a file it cannot parse and puts the problem in the "errors"
# array of its JSON output (a syntax error, or PartialParsing when it dropped the
# lines it could not read), so the exit status says nothing. The check looks at
# the JSON: every file must be in paths.scanned and no error may be reported.
# The pattern matches nothing: only the parse is wanted. A pattern that matches
# every statement, such as $X, ends in "Too many matches" on a long script.
# No network, no login, no metrics, no version check.
# =============================================================================
set -euo pipefail

[ $# -ge 1 ] || { echo "usage: semgrep-parses.sh FILE..." >&2; exit 2; }
work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT

for f in "$@"; do
  rc=0
  # shellcheck disable=SC2016 # $X is a Semgrep metavariable, not a shell variable
  semgrep --lang bash -e 'semgrep_parse_check_never_matches $X' \
    --json --metrics=off --disable-version-check --quiet \
    -- "$f" > "$work/out.json" 2> "$work/err.txt" || rc=$?
  if [ "$rc" -ne 0 ]; then
    echo "::error file=$f::semgrep exited $rc"
    cat "$work/err.txt" >&2
    exit 1
  fi
  python3 -I - "$work/out.json" "$f" <<'PY'
import json, sys
out, f = sys.argv[1:3]
d = json.load(open(out))
errors = d.get("errors", [])
scanned = d.get("paths", {}).get("scanned", [])
if f not in scanned:
    print("::error file=%s::semgrep did not scan the file (scanned: %s)" % (f, scanned))
    sys.exit(1)
if errors:
    for e in errors:
        print("::error file=%s::semgrep: %s: %s" % (f, e.get("type"), str(e.get("message", ""))[:300].replace("\n", " ")))
    sys.exit(1)
print("ok - semgrep --lang bash parses %s completely" % f)
PY
done
