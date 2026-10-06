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
- `jwks/`: key-document variants (mislabelled, duplicated member, trailing text).
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

### Running another implementation

**Exit code plus `expect.code` is the contract.** For each case run your
verifier with `args` from this directory and check it reaches `expect.exit` for
the reason `expect.code` names. The `code` values are:

- `0`: `verified`, `good`
- `1`: `signature_invalid`, `expired`, `too_old`, `not_yet_valid`, `ttl_exceeded`,
  `date_unparseable`, `missing_expiry`, `issuer_mismatch`, `slug_mismatch`,
  `nonce_mismatch`, `overall_band_mismatch`, `kid_mismatch`, `header_not_allowed`,
  `header_alg_invalid`, `unsigned_member`, `duplicate_key`, `payload_not_envelope`,
  `redaction_violation`, `revoked_key`, `revoked_subject`
- `2`: `unknown_kid`, `jwks_duplicate_key`, `not_strict_json`
- `3`: `status_unknown_*` (`bad_signature`, `unknown_kid`, `stale`, `rolled_back`,
  `truncated_invalid`, `duplicate_key`, `not_strict_json`)

Where one document breaks several rules at once (a decoy inside an expired
document, say), `code` names the verdict the reference gives; the case
description says which.

The reference runner is `tests/vectors.sh` (`VERIFIER=/path/to/script bash
tests/vectors.sh`). It checks `SHA256SUMS` first, then runs each case as
`NO_COLOR=1 bash "$VERIFIER" args...` from this directory.

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
