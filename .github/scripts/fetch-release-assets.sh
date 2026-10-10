#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Hodeitek S.L.
# =============================================================================
# .github/scripts/fetch-release-assets.sh - download a release's assets and
# verify them, taking the list of files from the release's own SHA256SUMS.
#
#   fetch-release-assets.sh DIR
#
# Env: TAG, GITHUB_REPOSITORY, RELEASE_IDENTITY (the certificate identity of
# release.yml for this tag), GH_TOKEN for gh. Needs gh, cosign, sha256sum.
#
# The list is discovered, not written here: release.yml decides what SHA256SUMS
# lists, and a list kept in two places drifts (v1.4.0 added a third file and the
# image job, which knew only two, failed). Order matters:
#   1. SHA256SUMS is verified with cosign BEFORE anything is read from it;
#   2. each name is checked to be a plain file name, since it is used as a path
#      and as a gh --pattern;
#   3. every listed file and its bundle are downloaded, checked against
#      SHA256SUMS, and verified with cosign against the same identity.
# verify-attestation.sh must be listed: the image is built from it.
# Used by .github/workflows/image.yml; tests/image-assets.sh runs it offline.
# =============================================================================
set -euo pipefail

dir="${1:?usage: fetch-release-assets.sh DIR}"
: "${TAG:?}" "${GITHUB_REPOSITORY:?}" "${RELEASE_IDENTITY:?}"

mkdir "$dir"
cd "$dir"

verify() {
  cosign verify-blob --bundle "${1}.sigstore.json" \
    --certificate-identity "$RELEASE_IDENTITY" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    "$1"
}

gh release download "$TAG" --repo "$GITHUB_REPOSITORY" --dir . \
  --pattern SHA256SUMS \
  --pattern SHA256SUMS.sigstore.json
verify SHA256SUMS

# "<64 hex>  <name>" and nothing else. The name starts with a letter or digit
# (no dot, no dash) and has no slash, so it cannot leave this directory or be
# read as an option.
names=()
found=0
while IFS= read -r line || [ -n "$line" ]; do
  if [[ ! "$line" =~ ^[0-9a-f]{64}\ \ ([A-Za-z0-9][A-Za-z0-9._-]*)$ ]]; then
    echo "malformed line in SHA256SUMS: $line" >&2
    exit 1
  fi
  name="${BASH_REMATCH[1]}"
  if [[ "$name" == *..* || "$name" == SHA256SUMS* ]]; then
    echo "refusing the name in SHA256SUMS: $name" >&2
    exit 1
  fi
  [ "$name" = verify-attestation.sh ] && found=1
  names+=("$name")
done < SHA256SUMS
[ "${#names[@]}" -gt 0 ] || { echo "SHA256SUMS lists no files" >&2; exit 1; }
[ "$found" -eq 1 ] || { echo "verify-attestation.sh is not listed in SHA256SUMS" >&2; exit 1; }

args=()
for name in "${names[@]}"; do
  args+=(--pattern "$name" --pattern "${name}.sigstore.json")
done
gh release download "$TAG" --repo "$GITHUB_REPOSITORY" --dir . "${args[@]}"

sha256sum -c SHA256SUMS
for name in "${names[@]}"; do
  verify "$name"
done
