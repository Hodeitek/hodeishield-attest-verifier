# Changelog

Changes to the verifier and its published material, newest first. Each release
page on GitHub has the full notes, the script's sha256 and the signature
bundles; see [Verifying a release](README.md#verifying-a-release).

## Compatibility

Every release so far verifies `attest.attestation.v1` documents and
`attest.statuslist.v1` status lists, and no other format version. Only the
latest release is supported, as [SECURITY.md](SECURITY.md) says.

## Unreleased

Documentation and repository metadata only; `scripts/` is unchanged since
v1.2.1.

### Added
- Issue form for "the verifier cannot run or cannot check", and a contact link
  to private vulnerability reporting.
- Links to the guides on docs.hodeishield.com, and a pointer to hodeishield.com
  for organisations that want to publish their own attestations.
- README and verification document §6: what the key fingerprint to pin is (the
  `kid`), and a command that computes it from a downloaded `jwks.json`.
- This changelog.

### Changed
- Verification document brought up to date with v1.2.1 (ML-DSA capability gate,
  the `EXPIRED` verdict).
- CONTRIBUTING: "Issues" (when a fixed issue is closed) and "Design" (shared
  vocabulary for designing a change).

## v1.2.1 - 2026-10-06

`verify-attestation.sh` changes. sha256
`16dcf76978f0556e259385f676699a8bf11abaa94288ae1cc05ddf596b1ce7d0`.

### Fixed
- LibreSSL was reported as an ML-DSA capable OpenSSL. The toolchain gate now
  checks that `openssl version` names OpenSSL, that it is at least 3.5, and that
  it offers ML-DSA-65; each failure says why and exits 2. Exit codes and
  verdicts are unchanged for supported toolchains.

### Changed
- Renovate configuration removed; container image digests and the cosign
  version are bumped by hand in periodic reviews.

### Tests
- New assertions for a LibreSSL version string and an OpenSSL without ML-DSA-65,
  and a CI job running the verifier with real LibreSSL.

## v1.2.0 - 2026-10-06

`verify-attestation.sh` byte-identical to v1.1.0.

### Added
- `tests/vectors/v1/`: 101 fixed test vectors for `attest.attestation.v1` and
  `attest.statuslist.v1`, with test-only keys.
- `tests/mutants.sh`: shows that a verifier with the signature check disabled
  is caught by the 24 `signature_only` vectors.

## v1.1.0 - 2026-10-06

### Changed
- A genuine attestation that is only expired ends with `EXPIRED - the
  signature is valid, but this attestation expired on <expiresAt>`. The exit
  code is still 1; any other failure still ends with `VERIFICATION FAILED`.

### Added
- README: share the link rather than the file; run the verifier in a container
  without installing anything (Docker or Podman), including `--status-list`.
- CONTRIBUTING states that the working language is English.
- Container route workflow and `tests/container.sh`.

## v1.0.1 - 2026-09-29

### Security
- Any JSON member that appears more than once in the same object is rejected
  (`duplicate_key`). No verdict changed, since duplicates already resolved to
  the signed value, but the output could mislead a reader keeping the first
  copy. Attestation, `--claims` file and protected header: exit 1. Key
  document: exit 2. Status list, its key set and header: exit 3.
- The attestation key is selected from the JWKS as JSON, by `kid`.

### Tests
- `tests/run.sh` grows to 57 cases.

## v1.0.0 - 2026-09-29

First public release.

### Security
- The verifier judges only what the signature covers; a member the signature
  does not cover is rejected (`unsigned_member`).

### Added
- `scripts/attest/verify-attestation.sh`, the offline verifier, with
  `--status-list` revocation checking.
- CI (shellcheck, offline suite, old-OpenSSL exit code), a daily live check
  against production, and releases with `SHA256SUMS` and Sigstore keyless
  bundles.
