# Decision record: an anchor for the issuer's signing keys

- Status: Accepted
- Date: 2026-10-08
- Scope: how a reader can check the issuer's keys by a channel other than the
  issuer's web host.

## Context

A reader fetches the key set from `https://app.hodeishield.com` over HTTPS. The
only thing that binds that key set to the issuer is the Web PKI and DNS
(§6 item 2 of [the verification document](attest-verification.md)). A
compromised web host, or a TLS man in the middle with a certificate the reader's
trust store accepts, could serve a different key set together with attestations
signed by it, and every check in the verifier would pass.

[keys.md](keys.md) lists the current keys by `kid` and `--expect-kid` compares
against a `kid` the reader pinned. That is a second place to compare against,
but a reader has to copy the `kid` by hand, and nothing says the copy came from
anyone other than whoever served it.

## Options considered

- A. A key statement published as a release asset and signed keyless by the
  release workflow. Chosen.
- B. A full Sigstore verification inside the script. Rejected: it is new,
  security-critical cryptographic code in a script meant to be read in one
  sitting, and it needs the Sigstore trust root kept up to date for as long as
  the script is used.
- C. The script reads the statement without verifying its signature. Rejected:
  it adds a file to trust and no assurance about where it came from.
- DNSSEC. Rejected: a script in bash cannot validate it without trusting the
  resolver it asks.
- A well-known URI on a second domain. Rejected: it relies on the same Web PKI,
  so it does not add an independent channel.
- A transparency log of the key set kept by the issuer. Rejected for now: it
  needs infrastructure on the issuer's side. It may come later.

## Decision

Option A.

Each release publishes the key statement `keys-statement.json`, the file
[keys.json](keys.json) of the tagged commit. It is listed in `SHA256SUMS` and is
signed with the same keyless cosign step, at the same pinned cosign version, as
the other release assets, which produces `keys-statement.json.sigstore.json`.
The Sigstore identity is the one of the other assets:

- certificate identity
  `https://github.com/Hodeitek/hodeishield-attest-verifier/.github/workflows/release.yml@refs/tags/vX.Y.Z`
- OIDC issuer `https://token.actions.githubusercontent.com`

### The statement

A JSON object with exactly these members and no others. There is no free text.

| Member   | Value                                                            |
| -------- | ---------------------------------------------------------------- |
| `schema` | `hodeishield.keys.statement.v1`                                  |
| `issuer` | the issuer origin, `https://app.hodeishield.com`                 |
| `keys`   | an array of key objects, one per key, retired keys included      |

A key object:

| Member         | Value                                                                                         |
| -------------- | --------------------------------------------------------------------------------------------- |
| `kid`          | the key identifier, as in [§4.2 of the verification document](attest-verification.md#42-the-kid-is-checked-not-trusted) |
| `role`         | `attestation` or `status-list`                                                                |
| `status`       | `active` or `retired`                                                                         |
| `published_at` | the URL of the key set that carries the key                                                   |
| `active_since` | the date the key became active, `YYYY-MM-DD`. Omitted when it is not known (the retired key) |
| `retired_at`   | RFC 3339 UTC with seconds, `YYYY-MM-DDTHH:MM:SSZ`, the same value as the key set's `hs_retired_at`. Present for retired keys only |

`keys.md` and `keys.json` say the same thing; CI fails if they differ
(`tests/keys-consistency.sh`).

### What a reader runs

Download `keys-statement.json` and `keys-statement.json.sigstore.json` from the
release and check them as the other assets
([Verifying a release](../../README.md#verifying-a-release)):

```bash
cosign verify-blob --bundle keys-statement.json.sigstore.json \
  --certificate-identity "https://github.com/Hodeitek/hodeishield-attest-verifier/.github/workflows/release.yml@refs/tags/<TAG>" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  keys-statement.json
```

From v1.4.0 the verifier takes the statement itself:

```bash
bash verify-attestation.sh --attestation att.json --jwks jwks.json \
  --expect-slug <slug> --expect-issuer https://app.hodeishield.com \
  --anchor-file keys-statement.json
```

The bundle is read from `keys-statement.json.sigstore.json` next to the
statement, or from the file given with `--anchor-bundle`. The option is in the
script from v1.4.0. It behaves as follows:

- It runs `cosign verify-blob` on the statement and its bundle:

  ```bash
  cosign verify-blob --bundle BUNDLE \
    --certificate-identity-regexp '^https://github\.com/Hodeitek/hodeishield-attest-verifier/\.github/workflows/release\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    STATEMENT
  ```

  The identity is a regular expression fixed in the script that accepts this
  repository's release workflow at a tag `vN.N.N` and nothing else, with the
  issuer above. The reader does not choose the identity: there is no option and
  no environment variable for it. The script verifies and parses one private
  copy of the statement, so the file cannot change between the two.
- cosign may contact the Sigstore TUF repository to refresh its trust root, so
  the option can need network access even though the rest of the verifier does
  not.
- It needs cosign, version 3.1.3 or later (the version `release.yml` pins),
  compared numerically. cosign is an optional dependency, needed only for this
  option. Everything else the verifier does is unchanged and does not need it.
- **Exit 2, by design, when the anchor cannot be checked.** Without cosign, with
  an older one, or if the statement does not verify for any reason (a tampered
  statement, a signing identity that is not this repository's release workflow,
  an invalid signature, an unreadable or malformed bundle, a trust root that
  cannot be obtained), or if what cosign verified is not a well-formed
  statement, the run ends with exit 2, "anchor could not be checked". It is not
  exit 1, and it is never reported as a pass. The reason is the one that applies
  to a wrong key document elsewhere in the verifier: a statement that does not
  verify says nothing about the attestation itself, so it is not evidence that
  the attestation is forged, and the run never ends in `VERIFIED`. The message
  says which cause was found (cosign reports all of them with exit 1, so the
  script reads what cosign printed; when it matches nothing the message is
  "cosign could not verify the statement"), and shows cosign's own diagnostics
  with every value escaped and every path cut to a file name.
- The statement is read strictly: valid UTF-8 JSON, no duplicate member, the
  schema `hodeishield.keys.statement.v1`, only the documented members,
  `retired_at` in the exact `YYYY-MM-DDTHH:MM:SSZ` form and present for retired
  keys only. Anything else is exit 2 (`anchor_malformed`).
- Membership is asked once the key has been selected and its `kid` recomputed
  from the key bytes, never of a label. The statement must list the attestation
  key that signed the document under the role `attestation`, with a retirement
  that is the same instant as the key set's `hs_retired_at` (both absent, or
  both present and equal), and its `issuer` must be the document's `iss`. A
  retirement the statement carries applies to the document like the key set's:
  a document generated at or after it fails the ordinary `retired_key` check.
  In `--status-list` mode the status-list key is asked the same way with the
  role `status-list`. A statement that verifies and does not satisfy these is a
  failed check (exit 1; for the status-list key, status unknown, exit 3), not a
  "could not check".
- With `--pub-b64url` there is no JWK, but the `kid` is still recomputed from
  the key bytes, so the statement is asked about it. There is no key set and so
  no `hs_retired_at` to compare; the statement's `retired_at`, if any, still
  applies to the document's `generatedAt`.

`--anchor-file` arrives in v1.4.0. Earlier releases carry no statement, so there
is nothing to check them against; a reader of an earlier release keeps
[keys.md](keys.md) and `--expect-kid`.

### The reason codes

The codes are in [reason-codes.md](reason-codes.md#the-anchor---anchor-file).
`anchor_cosign_unavailable`, `anchor_unverified` and `anchor_malformed` are exit
2. `anchor_kid_absent`, `anchor_role_mismatch`, `anchor_retired_mismatch` and
`anchor_issuer_mismatch` are exit 1; the retirement itself is the existing
`retired_key`. The three `anchor_status_*` failures are exit 3.

## Consequences

It protects against a compromised web host, or a TLS man in the middle, serving
a key set whose key is not one the issuer published through this repository: the
`kid` of the signing key must be in a statement signed by this repository's
release workflow.

It does not protect against:

- a compromised release pipeline or GitHub account, which can sign a statement
  with a different key. The tags are signed and the release is published by
  hand from a draft, which makes that harder but not impossible.
- a compromised issuer key. That is handled by revocation (§7 and §7.1 of the
  verification document), not by this statement.

A rotation changes `keys.md` and `keys.json` in the same signed commit and
reaches readers with the next release. A release made before a rotation does not
list the new key, so a reader on an older release sees "failed" for a key that
is genuine and updates the verifier. A daily check (`tests/keys-drift.sh`, in
the live workflow) fails if the live key sets contain a kid that `keys.json`
does not list under the right role, or a retirement time that disagrees, so a
rotation that did not reach this repository is noticed.
