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
statement, or from the file given with `--anchor-bundle`. The exact names of the
options are those of the release that ships them; its `--help` is authoritative.
The option behaves as follows:

- It runs `cosign verify-blob` on the statement and its bundle. The certificate
  identity is a regular expression fixed in the script that accepts this
  repository's release workflow at a tag `vN.N.N` and nothing else, with the
  issuer above. The reader does not choose the identity.
- It needs cosign, version 3.1.3 or later. cosign is an optional dependency,
  needed only for this option. Everything else the verifier does is unchanged
  and does not need it.
- Without cosign, with an older one, or if the verification cannot be performed
  for any reason (an unreadable file, no bundle, no network where cosign needs
  it), the run ends with exit 2, "anchor could not be checked". It is never
  reported as a pass and never as a failure of the document.
- The statement must list the attestation key that signed the document, and, in
  `--status-list` mode, the status-list key, each under the right `role`, with a
  retirement consistent with the `hs_retired_at` of the key set. A statement
  that does not is a failed check (exit 1), not a "could not check".

`--anchor-file` arrives in v1.4.0. Earlier releases carry no statement, so there
is nothing to check them against; a reader of an earlier release keeps
[keys.md](keys.md) and `--expect-kid`.

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
