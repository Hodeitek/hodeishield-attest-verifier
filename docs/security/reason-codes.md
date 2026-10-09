# Reason codes

Every check the verifier makes has a stable, machine-readable reason code. The
codes are part of the public interface **from v1.4.0**: they are only ever
added, never renamed or removed, so a program can rely on them.

The text output does not print the codes. With `--json` the verifier emits
them: each entry of `checks`, and `reason`, the code that decided the exit
code, are codes from this file (see
[json-output.md](json-output.md)).

## How to read the table

- **Result**: `pass` (a check held), `warn` (a note, not a failure) or `fail`.
- **Exit**: the exit code a failing check leads to. `0` for a pass or a warning
  (except the revocation warnings that leave the status unknown: `3`), `1`
  verification failed or revoked, `2` could not check, `3` status unknown.
- **Mode**: `attestation` (the default), `status-list` (`--status-list`), or
  `both` (a check on the document that also runs when a status list is
  checked with it, or a usage or environment problem).
- **Vectors**: the cases of `tests/vectors/v1/vectors.json` whose `expect.code`
  is this code. A code with no vector is covered by `tests/run.sh` or by no
  published case yet.
- Codes named in the manifest keep the name it gives them. Where a document
  breaks several rules, the code of the verdict is the one `expect.code` names;
  the list of checks has every one that ran.

Command-line errors found while reading the arguments (an unknown option, a
missing value, a malformed `--expect-kid`, `--check-kid`, `--min-seq`,
`--max-age-seconds`, `--max-age-days` or `--now`, an
option of the status-list mode without `--status-list`) happen before any check
runs. They are not entries of `checks`; with `--json` their `reason` is
`usage` (below) and `message` has the text.

`tests/run.sh` fails if a code used in `scripts/attest/verify-attestation.sh` is
missing from this file, or a code in the vectors manifest is one the script
cannot emit.

## Usage and environment

| Code | Meaning | Result | Exit | Mode | Vectors |
|---|---|---|---|---|---|
| `usage` | An argument error, found before any check ran. Only ever the `reason` of a `--json` result, never an entry of `checks`. | fail | 2 | both |  |
| `status_source_missing` | `--status-list` without `--status`. | fail | 2 | both |  |
| `status_keys_source_missing` | `--status-list` without `--status-keys`. | fail | 2 | status-list |  |
| `status_list_nothing_to_check` | `--status-list` with no document, `--check-kid` or `--check-subject`. | fail | 2 | status-list |  |
| `expect_kid_needs_attestation` | `--expect-kid` without `--attestation` or `--jws`. | fail | 2 | both |  |
| `attestation_missing` | Neither `--attestation` nor `--jws` was given. | fail | 2 | attestation |  |
| `jws_unreadable` | The `--jws` file cannot be read. | fail | 2 | both |  |
| `attestation_unreadable` | The `--attestation` file cannot be read. | fail | 2 | both |  |
| `key_source_missing` | Neither `--jwks` nor `--pub-b64url` was given. | fail | 2 | both |  |
| `claims_unreadable` | The `--claims` file cannot be read. | fail | 2 | both |  |
| `pub_b64url_with_jwks` | `--pub-b64url` combined with `--jwks`. | fail | 2 | both |  |
| `posture_with_claims` | `--posture` combined with `--claims` or `--attestation`. | fail | 2 | both |  |
| `openssl_missing` | `openssl` is not installed. | fail | 2 | both |  |
| `openssl_not_openssl` | The `openssl` found is not OpenSSL (for example LibreSSL). | fail | 2 | both |  |
| `openssl_version_unparseable` | The OpenSSL version string cannot be read. | fail | 2 | both |  |
| `openssl_too_old` | OpenSSL is older than 3.5. | fail | 2 | both |  |
| `openssl_mldsa65_missing` | This OpenSSL does not offer ML-DSA-65. | fail | 2 | both |  |
| `openssl_mldsa65_available` | OpenSSL offers ML-DSA-65. | pass | 0 | both |  |
| `python3_missing` | `python3` is needed for this step and is not installed. | fail | 2 | both |  |
| `jq_missing` | `jq` is not installed. | fail | 2 | status-list |  |
| `tools_present` | `python3` and `jq` are present. | pass | 0 | status-list |  |
| `curl_missing` | `curl` is needed to fetch a URL and is not installed. | fail | 2 | status-list |  |
| `spki_tool_missing` | Neither `xxd` nor `python3` is available to build the key header. | fail | 2 | both |  |
| `fetch_failed` | Fetching a `--status` or `--status-keys` URL failed. | fail | 2 | status-list |  |
| `fetch_cleartext_loopback` | Warning: a URL is fetched over cleartext HTTP from loopback. | warn | 0 | status-list |  |
| `fetch_cleartext_http` | Warning: a status list is fetched over cleartext HTTP. | warn | 0 | status-list |  |
| `status_keys_cleartext_refused` | The status key set was given as a cleartext HTTP URL (refused). | fail | 2 | status-list |  |
| `file_unreadable` | A `--status` or `--status-keys` file cannot be read. | fail | 2 | status-list |  |

## Reading the document and the JWS

| Code | Meaning | Result | Exit | Mode | Vectors |
|---|---|---|---|---|---|
| `attestation_unparseable` | The `--attestation` file is not an attestation document. | fail | 2 | both |  |
| `attestation_signature_missing` | The attestation has no `signature` member. | fail | 2 | both |  |
| `posture_bare_refused` | `--posture` holds a bare posture, which the signature does not cover. | fail | 2 | both |  |
| `posture_unrecognised` | The `--posture` file is not recognisable. | fail | 2 | both |  |
| `claims_posture_missing` | The claims JSON has no usable `posture` object. | fail | 2 | both |  |
| `jws_not_compact` | Not a compact JWS (two dots expected). | fail | 2 | both |  |
| `jws_too_many_dots` | More than two dots (a JSON-serialised JWS). | fail | 2 | both |  |
| `jws_detached` | Detached JWS: the payload segment is empty. | pass | 0 | both |  |
| `jws_attached` | Attached JWS: the payload segment carries the canonical bytes. | pass | 0 | both |  |
| `jws_detached_needs_claims` | A detached JWS needs `--claims` or `--attestation`. | fail | 2 | both |  |
| `header_not_base64url` | The protected header is not base64url. | fail | 2 | both |  |
| `signature_not_base64url` | The signature is not base64url. | fail | 2 | both |  |
| `signature_size_valid` | The signature is 3309 bytes. | pass | 0 | both |  |
| `signature_size_invalid` | The signature is not 3309 bytes. | fail | 1 | both | 2: `sig-truncated-3308`, `sig-extended-3310` |
| `header_alg_valid` | `alg` is `ML-DSA-65`. | pass | 0 | both |  |
| `header_alg_invalid` | `alg` is anything else. | fail | 1 | both | 5: `header-alg-none`, `alg-ml-dsa-44`, `alg-ml-dsa-87`, ... |
| `header_typ_valid` | `typ` is `application/attest+jws`. | pass | 0 | both |  |
| `header_typ_invalid` | `typ` is anything else. | fail | 1 | both |  |
| `header_crit_absent` | The header has no `crit`. | pass | 0 | both |  |
| `header_members_valid` | The header is exactly `alg`, `kid`, `typ`. | pass | 0 | both |  |
| `header_not_allowed` | The header carries `crit` or a member beyond `alg`, `kid`, `typ`. | fail | 1 | both | 3: `header-extra-member`, `header-crit`, `dup-header-member` |
| `payload_not_base64url` | The attached payload is not base64url. | fail | 2 | both |  |
| `payload_not_envelope` | The attached payload does not decode to an attestation envelope. | fail | 1 | both | 1: `attached-garbage-payload` |
| `payload_embedded` | The payload embedded in the JWS is used. | pass | 0 | both |  |
| `payload_matches_claims` | The embedded payload equals the bytes re-derived from the claims. | pass | 0 | both |  |
| `payload_claims_mismatch` | The embedded payload differs from the claims JSON supplied. | fail | 1 | both |  |
| `canonicalise_failed` | The claims JSON cannot be canonicalised. | fail | 2 | both |  |
| `canonicalise_posture_failed` | The nested posture cannot be canonicalised. | fail | 2 | both |  |
| `canonical_rederived` | The canonical envelope bytes were re-derived from the claims. | pass | 0 | both |  |
| `opaque_bytes` | Warning: no claims JSON, so opaque bytes are verified. | warn | 0 | both |  |

## Key set and key

| Code | Meaning | Result | Exit | Mode | Vectors |
|---|---|---|---|---|---|
| `jwks_unreadable` | The `--jwks` file cannot be read. | fail | 2 | both |  |
| `not_strict_json` | The key set is not strict JSON (UTF-8, no BOM, one value). | fail | 2 | both | 1: `jwks-trailing-text` |
| `jwks_duplicate_key` | The key set repeats a member. | fail | 2 | both | 1: `dup-jwks-member` |
| `jwks_keys_not_array` | `keys` is not an array of objects. | fail | 2 | both | 1: `jwks-keys-not-array` |
| `jwks_duplicate_kid` | Two keys carry the same kid. | fail | 2 | both | 1: `jwks-duplicate-kid` |
| `unknown_kid` | No key in the set carries the header kid. | fail | 2 | both | 1: `unknown-kid` |
| `jwks_key_selected` | A key was selected by kid. | pass | 0 | both |  |
| `jwks_retired_at_malformed` | `hs_retired_at` of the selected key is malformed. | fail | 2 | both | 1: `retired-key-malformed` |
| `public_key_not_base64url` | The public key is not base64url. | fail | 2 | both |  |
| `public_key_size_valid` | The public key is 1952 bytes. | pass | 0 | both |  |
| `public_key_size_invalid` | The public key is not 1952 bytes. | fail | 1 | both |  |
| `kid_derivable` | The kid derives from the key bytes. | pass | 0 | both |  |
| `kid_mismatch` | The header kid does not derive from the key bytes, or `claims.kid` differs from the header kid. | fail | 1 | both | 4: `kid-mismatch`, `header-kid-not-derived-from-key`, `claims-kid-differs-from-header-kid`, ... |
| `kid_pinned` | The key kid is one pinned with `--expect-kid`. | pass | 0 | both |  |
| `unexpected_kid` | The key kid is not one pinned with `--expect-kid`. | fail | 1 | both |  |
| `public_key_rejected` | OpenSSL rejected the reconstructed public key. | fail | 2 | both |  |
| `public_key_loaded` | The key loaded as an ML-DSA-65 public key. | pass | 0 | both |  |
| `claims_kid_matches` | `claims.kid` equals the header kid. | pass | 0 | both |  |
| `signature_valid` | The ML-DSA-65 signature verifies. | pass | 0 | both |  |
| `signature_invalid` | The signature does not verify. | fail | 1 | both | 20: `tampered-field`, `tampered-signature`, `reordered-header`, ... |

## Freshness and retirement

| Code | Meaning | Result | Exit | Mode | Vectors |
|---|---|---|---|---|---|
| `not_yet_valid` | `generatedAt` is in the future beyond the skew allowance. | fail | 1 | both | 1: `not-yet-valid` |
| `too_old` | Older than `--max-age-seconds` (genuine but stale). | fail | 1 | both | 1: `too-old` |
| `fresh` | Within the freshness window. | pass | 0 | both |  |
| `date_unparseable` | A date (`generatedAt`, `expiresAt`) is not an RFC 3339 time. | fail | 1 | both | 1: `unparseable-date` |
| `generated_at_missing` | No `generatedAt`. | fail | 1 | both |  |
| `retired_key` | Signed by a retired key, generated at or after the retirement (or not provable). | fail | 1 | both | 2: `retired-key-at`, `retired-key-pinned` |
| `retired_key_document_predates` | The key is retired, but the document predates it. | pass | 0 | both |  |
| `expired` | `expiresAt` has passed (genuine but stale). | fail | 1 | both | 5: `expired`, `expired-says-signature-valid`, `expired-names-fetch-command`, ... |
| `not_expired` | `expiresAt` has not passed. | pass | 0 | both |  |
| `ttl_exceeded` | The validity window is above the 3600 s ceiling. | fail | 1 | both | 1: `ttl-exceeded` |
| `ttl_within_ceiling` | The validity window is within the ceiling. | pass | 0 | both |  |
| `missing_expiry` | No `expiresAt`. | fail | 1 | both | 1: `missing-expiry` |
| `slug_match` | The slug is the expected one. | pass | 0 | both |  |
| `slug_mismatch` | The slug is not the expected one. | fail | 1 | both | 5: `wrong-slug`, `expired-wrong-slug`, `decoy-slug-reads-signed-slug`, ... |
| `freshness_unchecked` | Warning: no claims JSON, so freshness is not checked. | warn | 0 | both |  |

## The anchor (`--anchor-file`)

[key-anchor.md](key-anchor.md) describes the option. **A statement that does not
verify, or cannot be checked, is exit 2 by design ("anchor could not be
checked"), never exit 1.** A statement that does not verify says nothing about
the attestation itself, just as a wrong key document does not (`unknown_kid`,
`jwks_duplicate_key`): it is not evidence that the attestation is forged, and
the run never ends in `VERIFIED`. Only a statement that verifies and does not
list the key is a failed check. The cause of a verification failure (the
identity does not match, the signature is invalid or the statement was altered,
the bundle is unreadable, the trust root could not be obtained) is in the text of
`anchor_unverified`; it is one code, not several. A retired key used after its
retirement is the existing `retired_key`, compared with the statement's
`retired_at` as well as the key set's `hs_retired_at`.

**Anti-rollback.** The release tag is read from the verified certificate (a
bundle that is not exactly v0.3 is refused first, `anchor_bundle_unsupported`,
and cosign is asked a second time for the exact identity read, so the
certificate is the one it verified) and compared, number by number, with the version of the script. A statement from an
older release is refused (`anchor_statement_older`), and a tag that cannot be
read strictly is refused too (`anchor_tag_unreadable`), both exit 2 and both
before the statement is read, because any older statement that was genuinely
signed would otherwise be accepted. A reader who runs an OLD verifier can still be served a statement as old as that verifier's own version. That is why only the latest release is supported ([SECURITY.md](../../SECURITY.md)), and why `--status-list`, which revokes a compromised key unconditionally, remains the path for a key compromise.

| Code | Meaning | Result | Exit | Mode | Vectors |
|---|---|---|---|---|---|
| `anchor_bundle_without_file` | `--anchor-bundle` without `--anchor-file`. | fail | 2 | both |  |
| `anchor_cosign_unavailable` | cosign is missing, older than 3.1.3, or its version cannot be read. | fail | 2 | both |  |
| `anchor_bundle_unsupported` | The bundle is not exactly a Sigstore bundle v0.3 (strict JSON, the v0.3 `mediaType`, exactly `mediaType`, `verificationMaterial` and `messageSignature`, one `certificate`, `tlogEntries`). Checked before cosign runs: cosign reads any other bundle in its legacy format, and then verifies a certificate other than the one the release tag is read from. | fail | 2 | both |  |
| `anchor_unverified` | cosign did not verify the statement (identity, signature, bundle or trust root), or did not verify it a second time under the exact identity read from the certificate, or that certificate does not carry this repository's numeric ID (Source Repository Identifier, OID 1.3.6.1.4.1.57264.1.15, `1340684886`), or the statement or bundle cannot be read. | fail | 2 | both | 2: `anchor-tampered-statement`, `anchor-wrong-identity` |
| `anchor_tag_unreadable` | The release tag of the verified certificate identity cannot be read: no tag, a pre-release, build metadata, a leading zero, not `vN.N.N`, or an identity that is not this repository's release workflow. | fail | 2 | both |  |
| `anchor_statement_older` | The statement is from a release older than this verifier (`VERIFIER_VERSION`), compared numerically. Checked before the content is read. | fail | 2 | both | 1: `anchor-statement-older-than-verifier` |
| `anchor_malformed` | The verified statement is not strict JSON, has a duplicate member, or is not a well-formed `hodeishield.keys.statement.v1`. | fail | 2 | both |  |
| `anchor_verified` | cosign verified the statement under the fixed identity. | pass | 0 | both |  |
| `anchor_issuer_matches` | `iss` is the issuer the statement names. | pass | 0 | attestation |  |
| `anchor_issuer_mismatch` | `iss` is not the issuer the statement names (an empty `iss` included). | fail | 1 | attestation |  |
| `anchor_kid_absent` | The kid recomputed from the key bytes is not listed. | fail | 1 | both |  |
| `anchor_role_mismatch` | The kid is listed with a role other than `attestation`. | fail | 1 | both |  |
| `anchor_retired_mismatch` | The statement's `retired_at` and the key set's `hs_retired_at` disagree. | fail | 1 | attestation |  |
| `anchor_kid_listed` | The statement lists the kid as an attestation key. | pass | 0 | both |  |
| `anchor_status_kid_absent` | The status-list key's recomputed kid is not listed. | fail | 3 | status-list |  |
| `anchor_status_role_mismatch` | The status-list kid is listed with a role other than `status-list`. | fail | 3 | status-list |  |
| `anchor_status_retired_mismatch` | The statement's `retired_at` and the status key set's `hs_retired_at` disagree. | fail | 3 | status-list |  |
| `anchor_status_kid_listed` | The statement lists the kid as a status-list key. | pass | 0 | status-list |  |

## Claims

| Code | Meaning | Result | Exit | Mode | Vectors |
|---|---|---|---|---|---|
| `doc_version_valid` | `docVersion` is `attest.attestation.v1`. | pass | 0 | both |  |
| `unsupported_version` | `docVersion` is anything else. | fail | 1 | both |  |
| `duplicate_key` | The document repeats a member. | fail | 1 | both | 7: `dup-posture-members`, `dup-claims-in-attestation`, `dup-claims-top-level`, ... |
| `members_signed` | Every member is covered by the signature. | pass | 0 | both |  |
| `unsigned_member` | The document carries a member the signature does not cover. | fail | 1 | both | 5: `decoy-slug-unsigned-member`, `decoy-timestamps-expired`, `unsigned-member-top-level`, ... |
| `nul_byte` | A signed string the checks compare (`slug`, `generatedAt`, `expiresAt`, `iss`, `kid`, `jti`, `nonce`, `docVersion`, `overallBand`, `visibility`) holds a NUL byte, so no comparison can read it exactly; it is shown with each NUL as `\x00`. | fail | 1 | both |  |
| `iss_empty` | `iss` is the empty string: the document names no issuer. With `--anchor-file` it is also `anchor_issuer_mismatch`. | fail | 1 | both |  |
| `issuer_match` | `iss` is the expected issuer. | pass | 0 | both |  |
| `issuer_mismatch` | `iss` is not the expected issuer. | fail | 1 | both | 2: `other-issuer`, `attached-issuer-mismatch` |
| `issuer_unpinned` | Warning: no `--expect-issuer`. | warn | 0 | both |  |
| `nonce_match` | The nonce is the expected one (or null as required). | pass | 0 | both |  |
| `nonce_mismatch` | The nonce is not the expected one. | fail | 1 | both | 2: `nonce-mismatch`, `attached-nonce-mismatch` |
| `nonce_unchecked` | Warning: the document has a nonce and `--expect-nonce` was not given. | warn | 0 | both |  |
| `overall_band_valid` | `overallBand` equals the weakest attested band. | pass | 0 | both |  |
| `overall_band_mismatch` | `overallBand` is not the weakest attested band. | fail | 1 | both | 1: `overall-band-overclaim` |
| `redaction_valid` | A gated posture is redacted as required. | pass | 0 | both |  |
| `redaction_violation` | A gated posture carries coverage, heartbeat or overall band. | fail | 1 | both | 1: `gated-redaction-leak` |
| `verified` | The verdict: every check held. | pass | 0 | attestation | 8: `valid-detached`, `valid-jws-claims`, `nonce-match`, ... |

## Status list (a failure leaves the status unknown)

| Code | Meaning | Result | Exit | Mode | Vectors |
|---|---|---|---|---|---|
| `status_unknown_not_strict_json` | The status list or key set is not strict JSON. | fail | 3 | status-list | 1: `status-bom` |
| `status_unknown_duplicate_key` | The status list or key set repeats a member. | fail | 3 | status-list | 1: `status-dup-member` |
| `status_shape_valid` | The document is `{statusList, signature}`. | pass | 0 | status-list |  |
| `status_unknown_malformed_document` | The document is not `{statusList, signature}`. | fail | 3 | status-list |  |
| `status_doc_version_valid` | `docVersion` is `attest.statuslist.v1`. | pass | 0 | status-list |  |
| `status_unknown_unsupported_version` | `docVersion` is anything else. | fail | 3 | status-list |  |
| `status_unknown_not_compact_jws` | `signature` is not a three-segment compact JWS. | fail | 3 | status-list |  |
| `status_unknown_too_many_dots` | `signature` has too many dots. | fail | 3 | status-list |  |
| `status_unknown_signature_not_detached` | The payload segment is not empty. | fail | 3 | status-list |  |
| `status_jws_detached` | The payload segment is empty, as required. | pass | 0 | status-list |  |
| `status_unknown_header_not_base64url` | The protected header is not base64url. | fail | 3 | status-list |  |
| `status_unknown_signature_not_base64url` | The signature is not base64url. | fail | 3 | status-list |  |
| `status_signature_size_valid` | The signature is 3309 bytes. | pass | 0 | status-list |  |
| `status_unknown_signature_size` | The signature is not 3309 bytes. | fail | 3 | status-list | 2: `status-sig-truncated-3308`, `status-sig-extended-3310` |
| `status_unknown_header_not_object` | The header is not a JSON object. | fail | 3 | status-list |  |
| `status_unknown_header_not_strict_json` | The header is not strict JSON. | fail | 3 | status-list |  |
| `status_unknown_header_duplicate_key` | The header repeats a member. | fail | 3 | status-list |  |
| `status_unknown_unsupported_crit` | The header carries `crit`. | fail | 3 | status-list |  |
| `status_header_crit_absent` | The header has no `crit`. | pass | 0 | status-list |  |
| `status_header_members_valid` | The header is exactly `alg`, `kid`, `typ`. | pass | 0 | status-list |  |
| `status_unknown_header_not_allowed` | The header has other members. | fail | 3 | status-list |  |
| `status_header_alg_valid` | `alg` is `ML-DSA-65`. | pass | 0 | status-list |  |
| `status_unknown_unsupported_alg` | `alg` is anything else. | fail | 3 | status-list | 2: `status-alg-ml-dsa-44`, `status-alg-eddsa` |
| `status_header_typ_valid` | `typ` is `application/attest-status+jws`. | pass | 0 | status-list |  |
| `status_unknown_unexpected_typ` | `typ` is anything else. | fail | 3 | status-list |  |
| `status_unknown_keys_not_array` | The status key set's `keys` is not an array of objects. | fail | 3 | status-list | 2: `status-keys-not-array`, `status-keys-entry-not-object` |
| `status_unknown_duplicate_kid` | The status key set has two keys with one kid. | fail | 3 | status-list | 1: `status-keys-duplicate-kid` |
| `status_key_selected` | A status key was selected by kid. | pass | 0 | status-list |  |
| `status_unknown_retired_at_malformed` | `hs_retired_at` of the status key is malformed. | fail | 3 | status-list | 1: `status-retired-key-malformed` |
| `status_unknown_unknown_kid` | The list's kid is not in the status key set. | fail | 3 | status-list | 1: `status-wrong-key` |
| `status_unknown_public_key_not_base64url` | The status public key is not base64url. | fail | 3 | status-list |  |
| `status_public_key_size_valid` | The status public key is 1952 bytes. | pass | 0 | status-list |  |
| `status_unknown_public_key_size` | The status public key is not 1952 bytes. | fail | 3 | status-list |  |
| `status_kid_derivable` | The kid derives from the status key bytes. | pass | 0 | status-list |  |
| `status_unknown_kid_mismatch` | The kid does not derive from the key bytes, or `statusList.kid` differs from the header kid. | fail | 3 | status-list |  |
| `status_public_key_loaded` | The status key loaded. | pass | 0 | status-list |  |
| `status_unknown_public_key_rejected` | OpenSSL rejected the status public key. | fail | 3 | status-list |  |
| `status_canonical_rederived` | The canonical bytes were re-derived from `statusList`. | pass | 0 | status-list |  |
| `status_unknown_nul_byte` | A string of the status list or its header that the checks compare (`kid`, `iss`, `alg`, `typ`, `docVersion`, `issuedAt`, `nextUpdate`, a subject's `notBefore`) holds a NUL byte. | fail | 3 | status-list |  |
| `status_unknown_encoding_failed` | The canonical encoder refused the list. | fail | 3 | status-list |  |
| `status_unknown_truncated_invalid` | `truncated` is not a boolean. | fail | 3 | status-list | 1: `status-truncated-not-boolean` |
| `status_signature_valid` | The status list signature verifies. | pass | 0 | status-list |  |
| `status_unknown_bad_signature` | The status list signature does not verify. | fail | 3 | status-list | 9: `status-stripped-revocation`, `sigonly-status-seq`, `sigonly-status-nextupdate-plus-1s`, ... |
| `status_kid_matches` | `statusList.kid` equals the header kid. | pass | 0 | status-list |  |
| `status_issuer_match` | The list `iss` is the expected issuer. | pass | 0 | status-list |  |
| `status_unknown_issuer_mismatch` | The list `iss` is not the expected issuer. | fail | 3 | status-list |  |
| `status_unknown_date_unparseable` | `issuedAt` or `nextUpdate` is not RFC 3339, or cannot be compared with a key retirement. | fail | 3 | status-list |  |
| `status_not_future` | `issuedAt` is not in the future. | pass | 0 | status-list |  |
| `status_unknown_not_yet_valid` | `issuedAt` is in the future beyond the skew allowance. | fail | 3 | status-list |  |
| `status_validity_within_ceiling` | `nextUpdate - issuedAt` is within the ceiling. | pass | 0 | status-list |  |
| `status_unknown_validity_exceeded` | `nextUpdate - issuedAt` is above the ceiling. | fail | 3 | status-list |  |
| `status_not_stale` | `nextUpdate` has not passed. | pass | 0 | status-list |  |
| `status_unknown_stale` | `nextUpdate` has passed. | fail | 3 | status-list | 1: `status-stale` |
| `status_retired_key_list_predates` | The status key is retired, but the list predates it. | pass | 0 | status-list |  |
| `status_unknown_retired_key` | The list was issued at or after the retirement of its key. | fail | 3 | status-list | 1: `status-retired-key-at` |
| `status_not_rolled_back` | `seq` is not below `--min-seq`. | pass | 0 | status-list |  |
| `status_unknown_rolled_back` | `seq` is below `--min-seq`. | fail | 3 | status-list | 1: `status-rolled-back` |
| `status_not_self_revoking` | The list does not revoke its own key. | pass | 0 | status-list |  |
| `status_unknown_self_revocation` | The list revokes its own signing key. | fail | 3 | status-list |  |

## Revocation check

| Code | Meaning | Result | Exit | Mode | Vectors |
|---|---|---|---|---|---|
| `status_unknown_list_unverified` | Warning: the list did not verify, so it is not applied. | warn | 3 | status-list |  |
| `status_unknown_no_subject` | Warning: no kid or subject to look up. | warn | 3 | status-list |  |
| `status_unknown_generated_at_missing` | Warning: the subject is listed, but there is no `generatedAt` to compare with `notBefore`. | warn | 3 | status-list |  |
| `status_unknown_subject_dates_unparseable` | Warning: `generatedAt` or `notBefore` is not RFC 3339. | warn | 3 | status-list |  |
| `status_unknown_truncated` | Warning: the subject is not found, but the list is truncated. | warn | 3 | status-list |  |
| `good` | The verdict: not revoked, per a verified list. | pass | 0 | status-list | 3: `status-good`, `status-good-after-withdrawal`, `status-retired-key-before` |
| `revoked_key` | The verdict: the key is in the list. | fail | 1 | status-list | 2: `status-revoked-key`, `status-expired-under-revoking-list` |
| `revoked_subject` | The verdict: the subject is withdrawn from a date after the document. | fail | 1 | status-list | 2: `status-revoked-subject`, `status-attached-jws-revoked` |
