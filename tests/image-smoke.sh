#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Hodeitek S.L.
# =============================================================================
# tests/image-smoke.sh IMAGE — positive checks on a built container image.
#
# CI only (needs docker and jq). Run by .github/workflows/image.yml on a pull
# request and before a release image is pushed. It checks that the image
#   a. prints --help and exits 0,
#   b. does not run as root,
#   c. verifies the published positive vector `valid-detached` (exit 0,
#      VERIFIED), with tests/vectors/v1 mounted read-only.
# Rejection cases stay in tests/run.sh, which runs against the script itself.
# =============================================================================
set -uo pipefail

IMAGE="${1:?usage: tests/image-smoke.sh IMAGE}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VEC="$ROOT/tests/vectors/v1"

fail() { printf 'FAIL  %s\n' "$1" >&2; exit 1; }
ok()   { printf 'ok    %s\n' "$1"; }

command -v docker >/dev/null 2>&1 || fail "docker is not installed"
command -v jq >/dev/null 2>&1 || fail "jq is not installed"

docker run --rm "$IMAGE" --help >/dev/null || fail "--help did not exit 0"
ok "--help exits 0"

uid="$(docker run --rm --entrypoint id "$IMAGE" -u)" || fail "could not read the container user id"
[ "$uid" != 0 ] || fail "the image runs as root"
ok "runs as uid $uid, not root"

mapfile -t args < <(jq -r '.cases[] | select(.id == "valid-detached") | .args[]' "$VEC/vectors.json")
[ "${#args[@]}" -gt 0 ] || fail "vector valid-detached not found in vectors.json"
out="$(docker run --rm -v "$VEC":/work:ro "$IMAGE" "${args[@]}" 2>&1)"; rc=$?
printf '%s\n' "$out"
[ "$rc" -eq 0 ] || fail "vector valid-detached exited $rc, expected 0"
grep -q 'VERIFIED' <<<"$out" || fail "vector valid-detached: no VERIFIED in the output"
ok "vector valid-detached verifies (exit 0)"
