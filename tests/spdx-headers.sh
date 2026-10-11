#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Hodeitek S.L.
# =============================================================================
# tests/spdx-headers.sh - every tracked shell script, workflow and Dockerfile
# must carry the licence header.
#
# Checked files, from `git ls-files`:
#   *.sh; files with no extension whose first line is a bash or sh shebang
#   (.githooks/commit-msg); .github/workflows/*.yml; Dockerfile and Dockerfile.*.
# Not checked:
#   tests/vectors/ (test data: its bytes are hashed in SHA256SUMS and signed, so
#   a comment would change them); .github/ISSUE_TEMPLATE/*.yml (issue forms, not
#   workflows); documents, JSON and Python.
# The header is the two comment lines the other files carry, directly after the
# shebang when there is one, else at the top of the file:
#   # SPDX-License-Identifier: Apache-2.0
#   # Copyright 2026 Hodeitek S.L.
#
#   bash tests/spdx-headers.sh                     the tracked files
#   --root DIR --files LIST                        another tree and a file list
#                                                  (one relative path per line;
#                                                  for the tests)
# Static: reads files, runs nothing else. Needs bash and git (not with --files).
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIST=''
while [ $# -gt 0 ]; do
  case "$1" in
    --root)  ROOT="${2:?}"; shift 2 ;;
    --files) LIST="${2:?}"; shift 2 ;;
    *) printf 'unknown argument: %s\n' "$1" >&2; exit 2 ;;
  esac
done

SPDX='# SPDX-License-Identifier: Apache-2.0'
COPY_RE='^# Copyright [0-9]{4} Hodeitek S\.L\.$'

if [ -n "$LIST" ]; then
  mapfile -t TRACKED < "$LIST"
else
  mapfile -t TRACKED < <(git -C "$ROOT" ls-files)
fi

checked=0
bad=0
for f in "${TRACKED[@]}"; do
  case "$f" in
    tests/vectors/*|.github/ISSUE_TEMPLATE/*) continue ;;
  esac
  base="${f##*/}"
  [ -f "$ROOT/$f" ] || continue
  first=''
  IFS= read -r first < "$ROOT/$f" || true
  case "$base" in
    *.sh|Dockerfile|Dockerfile.*) ;;
    *.*) case "$f" in .github/workflows/*.yml) ;; *) continue ;; esac ;;
    *) case "$first" in '#!'*/bash*|'#!'*/sh*|'#!'*' bash'*|'#!'*' sh'*) ;; *) continue ;; esac ;;
  esac
  checked=$((checked + 1))
  skip=0
  case "$first" in '#!'*) skip=1 ;; esac
  l1=''; l2=''
  { for ((i = 0; i < skip; i++)); do IFS= read -r _ || true; done
    IFS= read -r l1 || true; IFS= read -r l2 || true; } < "$ROOT/$f"
  if [ "$l1" != "$SPDX" ]; then
    printf 'not ok - %s: line %s is not "%s"\n' "$f" "$((skip + 1))" "$SPDX"; bad=$((bad + 1))
  elif ! [[ "$l2" =~ $COPY_RE ]]; then
    printf 'not ok - %s: line %s is not "# Copyright <year> Hodeitek S.L."\n' "$f" "$((skip + 2))"; bad=$((bad + 1))
  fi
done

if [ "$checked" -eq 0 ]; then
  printf 'not ok - no shell script, workflow or Dockerfile found to check\n'; exit 1
fi
if [ "$bad" -ne 0 ]; then
  printf '%s of %s files lack the licence header\n' "$bad" "$checked"; exit 1
fi
printf 'ok - %s shell scripts, workflows and Dockerfiles carry the licence header\n' "$checked"
