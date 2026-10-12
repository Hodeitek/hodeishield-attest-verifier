#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Hodeitek S.L.
# =============================================================================
# install-test-deps.sh - install what the offline test suite needs, in the
# Debian container of a test job.
#
#   install-test-deps.sh [EXTRA_PACKAGE...]
#
# ci.yml's and release.yml's test jobs both run this, so the release tag runs
# the suite with exactly the packages every pull request ran it with. When
# release.yml kept its own package list, the v1.4.1 tag failed tests that
# needed curl, which only ci.yml installed (#84). Add a package the suite needs
# here, not in a workflow; tests/test-deps-parity.sh fails if a test job
# installs packages of its own.
#
# It also makes the en_US.ISO-8859-1 locale, for the test that the verdict does
# not depend on the locale (VERIFIER_REQUIRE_LATIN1=1 makes tests/run.sh
# require it).
#
# No jq: --status-list needs nothing but python3, and the suite runs without it.
# =============================================================================
set -euo pipefail

apt-get update -qq
apt-get install -y -qq --no-install-recommends \
  openssl python3 curl ca-certificates gettext-base locales "$@"

# localedef exits 1 on a mere warning; whether the locale exists is what counts.
localedef -c -i en_US -f ISO-8859-1 en_US.ISO-8859-1 || true
test "$(LC_ALL=en_US.ISO-8859-1 locale charmap)" = ISO-8859-1
