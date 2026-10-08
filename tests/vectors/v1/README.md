# Test vectors v1

Fixed inputs and expected outcomes for the formats `attest.attestation.v1`
(posture attestation) and `attest.statuslist.v1` (revocation status list), for
anyone writing their own verifier: a browser tool, another language, an
integration. If your implementation reaches the same verdict on every case, it
agrees with the reference script `scripts/attest/verify-attestation.sh` on
everything these vectors cover.

## TEST-ONLY keys: never trust them

`keys/` holds throwaway ML-DSA-65 keys, **public and private**, so that anyone
can regenerate or extend the set. They sign nothing real. Anything signed by
them is a fixture. Never add them to a trust store, a key allow-list or a
JWKS you publish, and never treat a document signed by them as genuine.

| File | Role |
|---|---|
| `keys/test-only-issuer.pem`, `keys/test-only-issuer-jwks.json` | attestation signing key and its public JWKS |
| `keys/test-only-other.pem`, `keys/test-only-other-jwks.json` | an unrelated key (unknown-kid and mislabelled-key cases) |
| `keys/test-only-status.pem`, `keys/test-only-status-jwks.json` | status-list signing key, disjoint from the attestation key, and its public key set |

## Layout

- `vectors.json`: the manifest, one entry per case.
- `attestations/`, `jws/`, `claims/`: input documents (full attestations,
  compact JWS in detached and attached form, bare claims objects).
- `jwks/`: key-document variants (mislabelled, duplicated member, trailing text,
  keys marked with `hs_retired_at`).
- `status-lists/`: signed status lists, valid and manipulated.
- `SHA256SUMS`: sha-256 of every file in this directory except itself.

## The manifest

`vectors.json` has `format`, `statusListFormat`, `vectorsVersion`, and `cases`.
Each case:

| Field | Meaning |
|---|---|
| `id` | stable kebab-case identifier, never reused |
| `description` | what the case shows |
| `args` | the verifier's arguments as an array. Paths are relative to this directory; run the verifier from here. Every case passes a fixed `--now EPOCH`, so none depends on the wall clock |
| `expect.exit` | `0` verified or good, `1` failed or revoked, `2` could not check, `3` revocation status unknown |
| `expect.code` | short stable snake_case outcome or reason, our own naming, for implementations that do not parse the reference script's English |
| `expect.match` | exact substring the reference script prints for this case. Specific to its English output; skip it in your own tests |
| `expect.absent` | (optional) substrings the reference output must not contain, to keep verdicts that exit alike from being confused (for example "expired" versus "forged") |
| `canonical_sha256` | (valid documents) sha-256 of the canonical envelope bytes the signature is over, printed by the script in section [4]. Use it to debug your encoder |
| `status_canonical_sha256` | same, for the status list's canonical bytes |
| `signature_only` | (optional, `true`) every check other than the signature check passes for this document, so only the signature check stands between it and acceptance. See "Signature-only vectors" below |

### Running another implementation

**Exit code plus `expect.code` is the contract.** For each case run your
verifier with `args` from this directory and check it reaches `expect.exit` for
the reason `expect.code` names. The `code` values are:

- `0`: `verified`, `good`
- `1`: `signature_invalid`, `signature_size_invalid`, `expired`, `too_old`, `not_yet_valid`, `ttl_exceeded`,
  `date_unparseable`, `missing_expiry`, `issuer_mismatch`, `slug_mismatch`,
  `nonce_mismatch`, `overall_band_mismatch`, `kid_mismatch`, `header_not_allowed`,
  `header_alg_invalid`, `unsigned_member`, `duplicate_key`, `payload_not_envelope`,
  `redaction_violation`, `revoked_key`, `revoked_subject`, `retired_key`
- `2`: `unknown_kid`, `jwks_duplicate_key`, `not_strict_json`, `jwks_retired_at_malformed`,
  `jwks_duplicate_kid`, `jwks_keys_not_array`
- `3`: `status_unknown_*` (`bad_signature`, `unknown_kid`, `stale`, `rolled_back`,
  `truncated_invalid`, `duplicate_key`, `not_strict_json`, `signature_size`,
  `unsupported_alg`, `retired_key`, `retired_at_malformed`, `duplicate_kid`,
  `keys_not_array`)

Where one document breaks several rules at once (a decoy inside an expired
document, say), `code` names the verdict the reference gives; the case
description says which.

The reference runner is `tests/vectors.sh` (`VERIFIER=/path/to/script bash
tests/vectors.sh`). It checks `SHA256SUMS` first, then runs each case as
`NO_COLOR=1 bash "$VERIFIER" args...` from this directory.

## Signature-only vectors

Some manipulations are rejected by checks that run **independently of the
signature**: the signature size (3309 bytes), `alg` must be `ML-DSA-65`, the
`kid` must be derivable from the key bytes, `claims.kid` must equal the header
`kid`, the header member set. Those vectors are valuable, but they cannot tell
you whether your signature check works: a verifier whose signature check always
passes still rejects them, by design (defence in depth). They are the plain
cases, without the flag.

The cases marked `"signature_only": true` are different: every other check
passes, and only the ML-DSA verification stands between the document and exit
0 (or `good`). The reference rejects each one with `SIGNATURE DOES NOT VERIFY`
(exit 1) or, for a status list, `bad_signature` (exit 3). If your verifier
accepts any of them, its signature check is not doing its job. They cover:

- a signed value changed so that nothing else notices (`orgName`,
  `lastCheckedAt`, `generatedAt`, `expiresAt`, a framework label, code or
  non-weakest band, `jti`, an added `nonce`; for a status list `seq`,
  `issuedAt`, `nextUpdate`), and the same through `--jws` plus `--claims`;
- signature bytes flipped at the start, middle and end, length kept at 3309;
- a document signed with another key but presented under the issuer's kid
  (header and `claims.kid`), for attestations and status lists;
- a valid signature transplanted from another genuine document (same key,
  same header) onto this document's claims;
- the kid switched consistently to the other key's kid, a key set holding both
  keys, and the signature still by the issuer key.

The structural cases (signature one byte short or long, `alg` set to
ML-DSA-44, ML-DSA-87, EdDSA or empty, a header kid the key bytes do not derive,
`claims.kid` different from the header kid) are plain cases that each assert the
specific reason the reference prints.

`tests/mutants.sh` enforces this: it builds a copy of the reference verifier
with the two `openssl pkeyutl -verify` calls forced to succeed, then checks that
every `signature_only` case is rejected by the reference and accepted by that
copy. A case that some other check also rejects would fail there, so the flag
cannot be applied loosely. The test keys that sign these documents are
`TEST-ONLY` (see above); `tests/lib/mint.py` has test-only options
(`--declare-kid`, `--header-kid`, `--claims-kid`) to make a document name a key
other than the one that signed it, which no real issuer does.

## The vectors are the committed bytes

ML-DSA signing is randomised: running `tests/lib/gen_vectors.py` again does
**not** reproduce these files. The generator is committed so the set can be
audited and extended, not to regenerate it. It refuses to overwrite existing
files unless given `--force`, and `--extend` adds only new files and cases.

## Evolution policy

- `v1/` is **append-only**. New cases get new ids; ids are never reused or
  renumbered.
- The expected outcome of an existing case never changes, except to fix a bug
  in the vector itself. Such a fix is recorded in the change log below with the
  date and the reason.
- A new format version (for example `attest.attestation.v2`) gets a new sibling
  directory (`v2/`). `v1/` stays for as long as the verifier accepts v1
  documents.
- How format versions are introduced and retired is the versioning policy in
  [#20](https://github.com/Hodeitek/hodeishield-attest-verifier/issues/20).

## Change log

- 2026-10-06: v1 published.
- 2026-10-06: added 37 cases and their files (nothing existing changed): 24
  `signature_only` cases (new manifest field, see above) that only the signature
  check rejects, for attestations and status lists, and 13 structural signature
  cases (signature size, `alg`, kid derivation, `claims.kid`). New codes:
  `signature_size_invalid`, `status_unknown_signature_size`,
  `status_unknown_unsupported_alg`. `tests/lib/mint.py` gained test-only kid
  options and `tests/mutants.sh` was added. Only the manifest and this
  README (which describe the new cases) changed; every key, document and other
  file keeps its `SHA256SUMS` line byte for byte.
- 2026-10-07: added 9 cases and their files (nothing existing changed) for the
  `hs_retired_at` member of a JWK, which marks a key as retired. A key set
  marks a key as `2026-07-31T18:53:58Z`: a document generated at
  `18:53:57.999Z` verifies, one generated at `18:53:58.000Z` fails
  (`retired_key`), a malformed value is a key set that cannot be used
  (`jwks_retired_at_malformed`, exit 2), and a retired key that is not the
  selected one changes nothing. The same for the status list's key set: a list
  issued at or after the retirement is unknown (`status_unknown_retired_key`),
  as is a malformed value (`status_unknown_retired_at_malformed`). New codes:
  `retired_key`, `jwks_retired_at_malformed`, `status_unknown_retired_key`,
  `status_unknown_retired_at_malformed`. The manifest and this README changed;
  every other file keeps its `SHA256SUMS` line byte for byte.
- 2026-10-08: added 5 cases and their files (nothing existing changed) for key
  sets that cannot be read one way: two keys with the same kid, and `keys`
  that is not an array of objects. For the attestation key set the outcome is
  exit 2 (`jwks_duplicate_kid`, `jwks_keys_not_array`); for the status key set
  it is exit 3 (`status_unknown_duplicate_kid`, `status_unknown_keys_not_array`).
  The manifest and this README changed; every other file keeps its `SHA256SUMS`
  line byte for byte.
