#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Hodeitek S.L.
# =============================================================================
# tests/test-deps-parity.sh - the release tag runs the suite as pull requests do.
#
#   bash tests/test-deps-parity.sh [CI_YML RELEASE_YML]
#
# release.yml runs the offline suite again before it signs anything, but only on
# a v* tag, so no pull request runs that job. The v1.4.1 tag failed tests that
# needed curl, which only ci.yml's test job installed (#84). This check runs on
# every pull request and fails, naming what differs, unless both test jobs:
#   - install their packages with .github/scripts/install-test-deps.sh, and
#     have no apt-get install of their own;
#   - pass it every extra package that ci.yml's job passes (release.yml may pass
#     more, such as shellcheck);
#   - run tests/run.sh with VERIFIER_REQUIRE_LATIN1: "1";
#   - run in the same container image (one digest bump must change both).
#
# Needs bash and python3. Offline.
# =============================================================================
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CI_YML="${1:-$ROOT/.github/workflows/ci.yml}"
RELEASE_YML="${2:-$ROOT/.github/workflows/release.yml}"

python3 - "$CI_YML" "$RELEASE_YML" <<'EOF'
import re, sys

INSTALL = ".github/scripts/install-test-deps.sh"

def tests_job(path):
    """The lines of the job whose key is `tests:` under `jobs:`, without comments."""
    lines = open(path, encoding="utf-8").read().splitlines()
    out, inside = [], False
    for line in lines:
        if re.fullmatch(r"  tests:\s*", line):
            inside = True
            continue
        if inside and re.match(r"  \S", line):
            break
        if inside and not line.lstrip().startswith("#"):
            out.append(line)
    return out

def check(name, path):
    job = tests_job(path)
    problems = []
    if not job:
        return None, ["%s has no `tests` job" % name]
    calls = [l for l in job if re.match(r"\s*run:\s*bash\s+" + re.escape(INSTALL) + r"(\s|$)", l)]
    if len(calls) != 1:
        problems.append("%s's test job runs %s %d times, expected once" % (name, INSTALL, len(calls)))
    if any(re.search(r"\bapt-get\s+install\b", l) for l in job):
        problems.append("%s's test job has an apt-get install of its own; add the package to %s" % (name, INSTALL))
    if not any(re.fullmatch(r'\s*VERIFIER_REQUIRE_LATIN1:\s*"1"\s*', l) for l in job):
        problems.append('%s\'s test job does not set VERIFIER_REQUIRE_LATIN1: "1" for tests/run.sh' % name)
    extra = set(calls[0].split(INSTALL, 1)[1].split()) if len(calls) == 1 else set()
    image = [l.split(":", 1)[1].strip() for l in job if re.match(r"    container:\s*\S", l)]
    return (extra, image[0] if len(image) == 1 else None), problems

ci, problems = check("ci.yml", sys.argv[1])
rel, rel_problems = check("release.yml", sys.argv[2])
problems += rel_problems
if ci is not None and rel is not None:
    missing = sorted(ci[0] - rel[0])
    if missing:
        problems.append("release.yml's test job does not install what ci.yml's does: %s" % " ".join(missing))
    if ci[1] is None or ci[1] != rel[1]:
        problems.append("the test jobs do not run in the same container: ci.yml %s, release.yml %s" % (ci[1], rel[1]))

if problems:
    for p in problems:
        print("not ok - " + p)
    sys.exit(1)
print("ok - ci.yml and release.yml run the suite in the same container, install the test packages with %s, and release.yml lacks none of ci.yml's" % INSTALL)
EOF
