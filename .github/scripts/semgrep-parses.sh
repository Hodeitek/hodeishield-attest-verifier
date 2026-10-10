#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Hodeitek S.L.
# =============================================================================
# semgrep-parses.sh - fail if Semgrep's bash parser cannot parse
# a script completely.
#
#   semgrep-parses.sh FILE...
#
# Needs python3, and either docker with SEMGREP_IMAGE set to a Semgrep image
# (ci.yml pins one by digest; it runs with no network, the file mounted read-only)
# or, without SEMGREP_IMAGE, a semgrep on the PATH.
#
# Semgrep exits 0 on a file it cannot parse and puts the problem in the "errors"
# array of its JSON output (a syntax error, or PartialParsing when it dropped the
# lines it could not read), so the exit status says nothing. The check looks at
# the JSON: every file must be in paths.scanned and no error may be reported.
# The pattern matches nothing: only the parse is wanted. A pattern that matches
# every statement, such as $X, ends in "Too many matches" on a long script.
# No login, no metrics, no version check. Whatever fails to run, or leaves no valid
# JSON, fails the check.
# =============================================================================
set -euo pipefail

[ $# -ge 1 ] || { echo "usage: semgrep-parses.sh FILE..." >&2; exit 2; }
work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT

for f in "$@"; do
  rc=0
  target="$f"
  run=(semgrep)
  if [ -n "${SEMGREP_IMAGE:-}" ]; then
    abs="$(cd "$(dirname -- "$f")" && pwd -P)"
    target="/src/$(basename -- "$f")"
    run=(docker run --rm --network none -v "$abs:/src:ro" -w /src
      -e SEMGREP_ENABLE_VERSION_CHECK=0 -e SEMGREP_SEND_METRICS=off "$SEMGREP_IMAGE" semgrep)
  fi
  # shellcheck disable=SC2016 # $X is a Semgrep metavariable, not a shell variable
  "${run[@]}" --lang bash -e 'semgrep_parse_check_never_matches $X' \
    --json --metrics=off --disable-version-check --quiet \
    -- "$target" > "$work/out.json" 2> "$work/err.txt" || rc=$?
  if [ "$rc" -ne 0 ]; then
    echo "::error file=$f::semgrep exited $rc"
    cat "$work/err.txt" >&2
    exit 1
  fi
  python3 -I - "$work/out.json" "$target" "$f" <<'PY'
import json, sys
out, f, shown = sys.argv[1:4]
d = json.load(open(out))
errors = d.get("errors", [])
scanned = d.get("paths", {}).get("scanned", [])
if f not in scanned:
    print("::error file=%s::semgrep did not scan the file (scanned: %s)" % (shown, scanned))
    sys.exit(1)
if errors:
    for e in errors:
        print("::error file=%s::semgrep: %s: %s" % (shown, e.get("type"), str(e.get("message", ""))[:300].replace("\n", " ")))
    sys.exit(1)
print("ok - semgrep --lang bash parses %s completely" % shown)
PY
done
