![HodeiShield Attest Verifier, by Hodeitek](.github/banner.png)

# Verify a HodeiShield attestation yourself

[![Live check against production](https://github.com/Hodeitek/hodeishield-attest-verifier/actions/workflows/live.yml/badge.svg?branch=main)](https://github.com/Hodeitek/hodeishield-attest-verifier/actions/workflows/live.yml)
[![CI](https://github.com/Hodeitek/hodeishield-attest-verifier/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Hodeitek/hodeishield-attest-verifier/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/Hodeitek/hodeishield-attest-verifier?display_name=tag)](https://github.com/Hodeitek/hodeishield-attest-verifier/releases)
[![Licence: Apache-2.0](https://img.shields.io/badge/licence-Apache--2.0-blue)](LICENSE)

The offline verifier for [HodeiShield](https://app.hodeishield.com) posture
attestations, published by [Hodeitek](https://hodeitek.com).

This repository exists so that you do **not** have to take Hodeitek's word for a
signed compliance-posture attestation. It contains a verifier you can read and
run yourself, and the documentation that explains exactly what a `VERIFIED`
result does and does not mean.

Nothing here needs credentials, an account, or our cooperation.

**What you are verifying.** A posture attestation is a short document, signed by
HodeiShield, stating how far an organisation has got with frameworks such as
ISO 27001 or NIS2 at a given moment. You would usually receive one from a
supplier, from their Trust Center on HodeiShield, or attached to a security
questionnaire. This tool tells you whether that document is genuine, unaltered,
current and about the organisation you think; §6 of the documentation says what
it cannot tell you.

---

## The short version

The attestation and the signing key are served by
[app.hodeishield.com](https://app.hodeishield.com). `-f` makes `curl` fail on an
HTTP error instead of saving the error page as `att.json`.

```bash
curl -fsS https://app.hodeishield.com/api/public/attest/talmaren-payments -o att.json
curl -fsS https://app.hodeishield.com/api/public/attest/keys              -o jwks.json

bash scripts/attest/verify-attestation.sh \
  --attestation att.json --jwks jwks.json \
  --expect-slug talmaren-payments --expect-issuer https://app.hodeishield.com
```

`talmaren-payments` is a demonstration organisation with fictitious data, kept
so that you can try the tool. It is not a promise: a demo subject can be
retired, and then the endpoint answers 404. Substitute the slug of whichever
organisation's attestation you were given. Always pass `--expect-issuer`; the
document names its own issuer, and only you can say which one you trust.

## What you need installed

| | |
|---|---|
| `bash` ≥ 4 | This is bash, not POSIX `sh`. |
| **`openssl` ≥ 3.5** | ML-DSA (FIPS 204) support landed in 3.5. Check with `openssl list -signature-algorithms \| grep -i ml-dsa`. If that prints nothing, upgrade — a failure there is a limit of your tooling, not evidence against the document. |
| **`python3`** | Required in practice. The endpoint serves a *detached* JWS, so the signed bytes must be re-derived from the JSON you can read. Standard library only. |
| `curl` | Only to fetch the two files above. Verification itself is offline. |
| `jq` | Only for `--status-list` (revocation checking). |

`xxd` is used when present and is not required.

## Exit codes — the distinction matters

Posture mode (the default, as above):

| Code | Meaning |
|---|---|
| **0** | Verified. The signature holds and every requested check passed. |
| **1** | **Check failed.** Something did not hold. Do not rely on the document. |
| **2** | **Could not check.** Missing tool, unreadable input, unknown key. This is *not* a statement about the document — do not read it as failure. |

`--status-list` mode (revocation, see below):

| Code | Meaning |
|---|---|
| **0** | Good. If a document was given, its posture checks passed **and** it is not revoked. |
| **1** | **Revoked**, or the posture check of the document you gave failed. |
| **2** | **Could not check.** Bad flags, a missing tool, or a status list that could not be fetched or read. |
| **3** | **Unknown.** The list was obtained but does not verify, is stale, was rolled back, or names its own signer. This is neither "good" nor "revoked". |

Never test `$? -ne 0` and treat the result as one outcome. In `--status-list`
mode that collapses "revoked" (1), "could not check" (2) and "unknown" (3) into
the same branch, and the one you most need to tell apart from a clean result is
the one you would lose. Conflating these is the single most common way to
misread a verifier. They are kept apart deliberately, everywhere in the script.

### Revocation

A signed status list says whether the key that signed a document, or the
organisation it was issued for, has been withdrawn. It is a separate document
with a separate key set, and it is optional: checking it only adds information.
Verify the attestation and its revocation status in one run:

```bash
curl -fsS https://app.hodeishield.com/api/public/attest/status      -o status.json
curl -fsS https://app.hodeishield.com/api/public/attest/status-keys -o status-jwks.json

bash scripts/attest/verify-attestation.sh --status-list \
  --status status.json --status-keys status-jwks.json \
  --attestation att.json --jwks jwks.json \
  --expect-slug talmaren-payments --expect-issuer https://app.hodeishield.com
```

`--jwks` and `--status-keys` are different key sets and are never
interchangeable. What the list can and cannot tell you is in
[§7.1 of the verification document](docs/security/attest-verification.md#71-checking-key-or-subject-revocation-yourself).

## Convince yourself it can fail

A verifier that has only ever printed `PASS` has told you nothing. Each of these
must exit 1, and you should run them before trusting a `VERIFIED`:

```bash
# 1. Tamper with a signed field.
python3 -c "import json;d=json.load(open('att.json'));\
d['attestation']['claims']['overallBand']='advanced';\
json.dump(d,open('att-tampered.json','w'))"
bash scripts/attest/verify-attestation.sh --attestation att-tampered.json \
  --jwks jwks.json --expect-slug talmaren-payments ; echo "exit=$?"   # 1

# 2. Ask for the wrong subject.
bash scripts/attest/verify-attestation.sh --attestation att.json \
  --jwks jwks.json --expect-slug not-talmaren-payments ; echo "exit=$?" # 1

# 3. Add a member the signature does not cover.
python3 -c "import json;d=json.load(open('att.json'));\
d['attestation']['claims']['note']='not signed';\
json.dump(d,open('att-extra.json','w'))"
bash scripts/attest/verify-attestation.sh --attestation att-extra.json \
  --jwks jwks.json --expect-slug talmaren-payments ; echo "exit=$?"   # 1
```

The third case fails as `unsigned_member`: the signature covers a fixed set of
members, so anything else in the JSON is a statement nobody signed, and the
verifier rejects it rather than ignoring it.

`docs/security/attest-verification.md` §4.7 adds more, including a
header-reordering case and an issuer substitution. To run the full offline
rejection suite (keys generated at test time, no network), use
`bash tests/run.sh`.

## What a `VERIFIED` proves — and what it does not

Read **[§6 of the verification document](docs/security/attest-verification.md#6-what-a-verified-attestation-proves--and-what-it-does-not)**
before relying on any result. It is the section that matters most, and it is
longer than the commands on purpose.

The short form, so it is on this page too:

**It proves** that the document was signed by the holder of the published key,
that not one bit has changed since, that the timestamps inside it were not
altered after signing (the key holder can sign any timestamp — see §6), and that
the signature is post-quantum (ML-DSA-65, FIPS 204).

**It does not prove** that the claims inside are true. The maturity bands are
*our* scoring of evidence supplied by the organisation — a signed document
containing a wrong claim is a signed wrong claim. It does not prove the key
belongs to Hodeitek (you are trusting the Web PKI for that one binding — pin the
fingerprint). It does not prove anything about accredited certification bodies.
And §6 item 8 states, without softening, that the signing key is held in
software rather than in an HSM, and what that means for you.

## Where this comes from, and what is redacted

- `scripts/attest/verify-attestation.sh` is the same script we keep, byte for
  byte, at the same path in Hodeitek's private repository, where CI checks that
  the two copies never diverge. The HodeiShield service itself does not run
  this script: it verifies with its own TypeScript implementation of the same
  format, which is why an independent implementation you can read is worth
  having. Every release
  publishes a `SHA256SUMS` for the script and a Sigstore keyless signature
  bundle; see [Verifying a release](#verifying-a-release).
- `docs/security/attest-verification.md` is a **redacted public edition** of an
  internal document. The redactions are itemised at the bottom of that file, so
  you can judge them rather than take them on faith. No limitation was removed,
  shortened or softened; §3 (verifying an unrelated transport root CA) is
  omitted because it depends on files you do not have.
- References in the script's comments to paths like `app/src/lib/attest/…` are
  **provenance** — they say where a constant or a rule came from. They are not
  steps you are expected to follow. The same holds for references to
  `docs/architecture/specs/…` (the revocation design document) in the script's
  comments and in some of its messages: that document is not public. §7 of the
  public document covers what a verifier needs.

## Verifying a release

Download these four files from the GitHub release you are using:
`verify-attestation.sh`, `SHA256SUMS`, `SHA256SUMS.sigstore.json` and
`verify-attestation.sh.sigstore.json`. Then:

```bash
sha256sum -c SHA256SUMS

cosign verify-blob --bundle verify-attestation.sh.sigstore.json \
  --certificate-identity "https://github.com/Hodeitek/hodeishield-attest-verifier/.github/workflows/release.yml@refs/tags/<TAG>" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  verify-attestation.sh

cosign verify-blob --bundle SHA256SUMS.sigstore.json \
  --certificate-identity "https://github.com/Hodeitek/hodeishield-attest-verifier/.github/workflows/release.yml@refs/tags/<TAG>" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  SHA256SUMS
```

Replace `<TAG>` with the release tag. This proves that the file was built from
that tag of this repository by its release workflow, and that the signing was
logged in Rekor. The tag itself is signed; GitHub shows it as Verified. It does **not** prove the verifier is correct. Read it; that is
the reason it is a short, single, readable script.

## Tests and CI

- `shellcheck` runs on the shell scripts.
- `bash tests/run.sh` runs the offline acceptance suite: every case mints its own
  documents with a throwaway key and asserts both the exit code and the reason
  printed. It needs bash, OpenSSL ≥ 3.5, `python3` and `jq`, and no network.
- A job checks that, with an OpenSSL too old for ML-DSA, the verifier exits 2
  ("could not check"), never 1.
- On every push, pull request and once a day (the "Live check" badge above),
  `bash tests/live.sh` runs the verifier against the production
  `talmaren-payments` attestation and the status list, exactly as above. A network outage is reported as a warning; a document
  that does not verify, a revoked or unknown status, or a 404 on the example is a
  failure.

## Reporting a problem

If any check here fails, or if you find a discrepancy between what a document
claims and what you can independently establish:

**security@hodeitek.com** — include the artefact, the exact command, and the
full output. A verification failure you can reproduce is a security report and
we will treat it as one.

## Licence

Apache License 2.0. It is a verifier; you should be free to read it, run it,
modify it and integrate it into your own due-diligence tooling without asking.

## About

- [app.hodeishield.com](https://app.hodeishield.com) — HodeiShield; where the attestations, keys and status list are served.
- [hodeitek.com](https://hodeitek.com) — Hodeitek, who publishes this repository.
