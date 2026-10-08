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

### Added
- [`docs/security/keys.json`](docs/security/keys.json), the machine-readable
  list of the issuer's signing keys (schema `hodeishield.keys.statement.v1`),
  kept identical to `docs/security/keys.md` by a CI check. Releases from the
  next one publish it as `keys-statement.json`, in `SHA256SUMS` and signed with
  Sigstore (`keys-statement.json.sigstore.json`).
- [A decision record for the key anchor](docs/security/key-anchor.md): the
  signed statement, checked by a coming `--anchor-file` option, with "anchor
  could not be checked" as exit 2. The option is not in the script yet.
- A daily check that the live key sets contain no key, and no retirement time,
  that `keys.json` does not list.

### Changed
- §6 item 2 of the verification document no longer says the Web PKI is the only
  channel for the attestation key: from the release that carries the key
  statement there is a second one, signed by this repository's release workflow.

### Documentation
- [An evaluation of Rust ML-DSA-65 implementations](docs/security/rust-mldsa-evaluation.md)
  for a port of the verifier: version, stability, verification API, audits,
  FIPS 140-3, C or pure Rust, and WebAssembly for each candidate, with a
  recommendation and a date to look again. It does not run any candidate
  against the test vectors; that stays open and will be done in CI.

## v1.3.0 - 2026-10-08

`verify-attestation.sh` changes. sha256
`0e7d4a27f2834a69a7173731a7589bca6566355cedce11dfc9a4b71c25745552`.

### Security
- Every value taken from a document, key set or status list is printed with
  control characters (newline, carriage return, ESC) and any non-ASCII byte as a
  visible `\xHH` escape. Before, an edited document could carry a nonce, `iss`,
  `jti`, date or member name that forged lines such as an "Attested content"
  block or a `VERIFIED` verdict on stdout, above the real `FAIL` lines on stderr
  (the exit code was not affected). This affected every release from v1.0.0 to
  v1.2.1.

### Added
- Retired-key enforcement. A key in a key set may carry `hs_retired_at`, an RFC
  3339 UTC time with seconds (exactly `YYYY-MM-DDTHH:MM:SSZ`). For the
  attestation key set, a document whose signed `generatedAt` is at or after it
  fails as `retired_key` (exit 1, `VERIFICATION FAILED`, not `EXPIRED`), an
  earlier one passes with a line saying the key is retired, and a malformed
  value makes the key set invalid (exit 2). For the status-list key set, a list
  issued at or after the retirement of its key is unknown (exit 3), and so is a
  malformed value. The instants are compared exactly, to the millisecond. A
  retired key that is not the selected one has no effect, and `--pub-b64url`,
  which has no JWK, is not affected. Earlier versions ignore the member.
- Nine test vectors for it (`retired-key-*`, `retired-other-key-*` and
  `status-retired-key-*`) appended to `tests/vectors/v1/`, with the new codes
  `retired_key`, `jwks_retired_at_malformed`, `status_unknown_retired_key` and
  `status_unknown_retired_at_malformed`; no existing vector changed.
- Five more test vectors for key sets that cannot be read one way
  (`jwks-duplicate-kid`, `jwks-keys-not-array`, `status-keys-duplicate-kid`,
  `status-keys-not-array`, `status-keys-entry-not-object`). The set now has 115
  cases; the first 101 are unchanged.
- `docs/security/keys.md`: the versioned list of the current signing keys (the
  attestation key and the status-list key), how to check them yourself, and the
  rotation policy. The README "Pinning the key" section points to it.
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
- A key set that is not an array of objects under `keys`, or that has two keys
  with the same `kid`, is invalid: exit 2 for `--jwks`, unknown (exit 3) for
  `--status-keys`. Before, the first entry won, so a retirement marker could be
  dodged by ordering, and a status key set with `keys` as an object or with a
  non-object entry was read inconsistently (or made `jq` exit 5).
- `--pub-b64url` together with `--jwks` is a usage error (exit 2). Before, the
  key set was silently ignored and the run could exit 0 on a path that did not
  exist.
- The unknown-kid message no longer says a retired key leaves the published key
  set at the end of its overlap; by policy, a retired key stays published and is
  marked with `hs_retired_at`.
- Verification document §7: a retired key stays in the published key set, marked
  as retired, instead of leaving it at the end of its overlap. A document signed
  by a retired key is acceptable only if its `generatedAt` is before the
  retirement time, and a compromise is handled by status-list revocation, not by
  retirement. §6 item 2 points to `docs/security/keys.md`.
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
- Verification document §7.1: the "Unknown is not good" paragraph, a note
  that the sample output in §4.3 predates the attested-content change, and two
  passages that named a non-public design document no longer do.
- CONTRIBUTING: "Issues" (when a fixed issue is closed) and "Design" (shared
  vocabulary for designing a change).
- Verification document brought up to date with v1.2.1 (ML-DSA capability gate,
  the `EXPIRED` verdict).

### Tests
- The mutant check can be skipped locally with `VERIFIER_SKIP_MUTANTS=1`, which
  allows contributors to run the suite without building the signature-disabled
  verifier. CI always runs the mutant check and fails if the variable is set in
  a GitHub Actions environment.

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
