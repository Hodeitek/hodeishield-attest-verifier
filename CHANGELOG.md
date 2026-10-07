# Changelog

Changes to the verifier and its published material, newest first. Each release
page on GitHub has the full notes, the script's sha256 and the signature
bundles; see [Verifying a release](README.md#verifying-a-release).

## Compatibility

Every release so far verifies `attest.attestation.v1` documents and
`attest.statuslist.v1` status lists, and no other format version. A change to
either format that older verifiers cannot read is announced at least 90 days
before it takes effect. Only the latest release is supported, as
[SECURITY.md](SECURITY.md) says.

## Unreleased

`scripts/attest/verify-attestation.sh` changes, so there will be a new sha256 at
release.

### Security
- Every value taken from a document, key set or status list is printed with
  control characters (newline, carriage return, ESC) and any non-ASCII byte as a
  visible `\xHH` escape. Before, an edited document could carry a nonce, `iss`,
  `jti`, date or member name that forged lines such as an "Attested content"
  block or a `VERIFIED` verdict on stdout, above the real `FAIL` lines on stderr
  (the exit code was not affected).

### Fixed
- A verified document with a non-ASCII framework label no longer ends in an
  error when Python's stdout is not UTF-8 (`PYTHONIOENCODING=ascii`); a display
  problem cannot change the verdict.
- `--expect-kid` validates its value in the C locale, so an accented letter is a
  usage error (exit 2) under a UTF-8 locale instead of a failed check.
- The `UNKNOWN` verdict text no longer says a list "you could not fetch" is
  unknown: a list that could not be fetched is exit 2, and `UNKNOWN` (exit 3) is
  a list that was obtained but does not verify, or cannot settle the subject.

### Changed
- **Output change.** The overall band, the frameworks and the other claims about
  the organisation are no longer printed before the checks have finished. They
  appear in an "Attested content" block just before the verdict, and only when
  the document verifies (exit 0, or `GOOD` in `--status-list` mode). A document
  that is tampered, expired, revoked, of unknown status or that could not be
  checked prints `attested content withheld: this document did not verify`
  instead. The full posture JSON, which was printed every time, is now printed
  only with `--raw`, and under the same rule. A script that read the band or
  the posture JSON from the output of a failed run no longer finds it; exit
  codes are unchanged.
- `--help` prints a short usage (the options, the exit codes, where to read
  more) instead of the whole header comment of the script.
- The messages no longer point to a design document that is not public. The
  status-list header and the `UNKNOWN` verdict point to
  `docs/security/attest-verification.md` §7.1, which has a new paragraph,
  "Unknown is not good".
- Verification document §7.1: the "Unknown is not good" paragraph, and a note
  that the sample output in §4.3 predates the attested-content change.
- CONTRIBUTING: "Issues" (when a fixed issue is closed) and "Design" (shared
  vocabulary for designing a change).
- Verification document brought up to date with v1.2.1 (ML-DSA capability gate,
  the `EXPIRED` verdict).

### Added
- `--raw`: also print the full signed posture JSON, for a document that verifies.
- `--expect-kid KID`: require that the key that signed the attestation has this
  kid, compared with the kid recomputed from the key bytes. Repeat it to pin two
  kids through a rotation overlap. A mismatch is a failed check (exit 1,
  `unexpected_kid`); a value that is not the shape of a kid is a usage error
  (exit 2). It is not `--check-kid`, which looks a kid up in a status list, and
  it does not apply to the status-list signing key.
- Documentation corrections: the Compatibility section gives the real exit codes
  for an unknown format version (2 for an attestation, 3 for a status list);
  "Unknown is not good" says a fetch failure is exit 2; "What the output shows"
  lists exactly what a run that does not verify still prints.
- README: a Compatibility section (format versions per verifier version, the
  90-day notice, latest release only), "What the output shows", and
  `--expect-kid` in "Pinning the key".
- Tests for all of the above, including a check that no output refers to a
  document that is not public.
- Issue form for "the verifier cannot run or cannot check", and a contact link
  to private vulnerability reporting.
- Links to the guides on docs.hodeishield.com, and a pointer to hodeishield.com
  for organisations that want to publish their own attestations.
- README and verification document §6: what the key fingerprint to pin is (the
  `kid`), and a command that computes it from a downloaded `jwks.json`.
- This changelog.

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
