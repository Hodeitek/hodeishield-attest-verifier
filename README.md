# Verify a HodeiShield attestation yourself

This repository exists so that you do **not** have to take Hodeitek's word for a
signed compliance-posture attestation. It contains the verifier we run
ourselves, and the documentation that explains exactly what a `VERIFIED` result
does and does not mean.

Nothing here needs credentials, an account, or our cooperation.

---

## The short version

```bash
curl -sS https://app.hodeishield.com/api/public/attest/meridian -o att.json
curl -sS https://app.hodeishield.com/api/public/attest/keys     -o jwks.json

bash scripts/attest/verify-attestation.sh \
  --attestation att.json --jwks jwks.json \
  --expect-slug meridian --expect-issuer https://app.hodeishield.com
```

`meridian` is a live public subject you can use to try the tool. Substitute the
slug of whichever organisation's attestation you were given.

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

| Code | Meaning |
|---|---|
| **0** | Verified. The signature holds and every requested check passed. |
| **1** | **Check failed.** Something did not hold. Do not rely on the document. |
| **2** | **Could not check.** Missing tool, unreadable input, unknown key. This is *not* a statement about the document — do not read it as failure. |

Conflating 1 and 2 is the single most common way to misread a verifier. They are
kept apart deliberately, everywhere in the script.

## Convince yourself it can fail

A verifier that has only ever printed `PASS` has told you nothing. Both of these
must exit non-zero, and you should run them before trusting a `VERIFIED`:

```bash
# 1. Tamper with a signed field.
python3 -c "import json;d=json.load(open('att.json'));\
d['attestation']['claims']['overallBand']='advanced';\
json.dump(d,open('att-tampered.json','w'))"
bash scripts/attest/verify-attestation.sh --attestation att-tampered.json \
  --jwks jwks.json --expect-slug meridian ; echo "exit=$?"   # 1

# 2. Ask for the wrong subject.
bash scripts/attest/verify-attestation.sh --attestation att.json \
  --jwks jwks.json --expect-slug notmeridian ; echo "exit=$?" # 1
```

`docs/security/attest-verification.md` §4.7 adds more, including a
header-reordering case and an issuer substitution.

## What a `VERIFIED` proves — and what it does not

Read **[§6 of the verification document](docs/security/attest-verification.md#6-what-a-verified-attestation-proves--and-what-it-does-not)**
before relying on any result. It is the section that matters most, and it is
longer than the commands on purpose.

The short form, so it is on this page too:

**It proves** that the document was signed by the holder of the published key,
that not one bit has changed since, that the timestamps inside it cannot have
been back-dated, and that the signature is post-quantum (ML-DSA-65, FIPS 204).

**It does not prove** that the claims inside are true. The maturity bands are
*our* scoring of evidence supplied by the organisation — a signed document
containing a wrong claim is a signed wrong claim. It does not prove the key
belongs to Hodeitek (you are trusting the Web PKI for that one binding — pin the
fingerprint). It does not prove anything about accredited certification bodies.
And §6 item 8 states, without softening, that the signing key is held in
software rather than in an HSM, and what that means for you.

## Where this comes from, and what is redacted

- `scripts/attest/verify-attestation.sh` is **byte-identical** to the file we
  run in Hodeitek's private repository at the same path. Verify that claim by
  asking us for the hash and comparing.
- `docs/security/attest-verification.md` is a **redacted public edition** of an
  internal document. The redactions are itemised at the bottom of that file, so
  you can judge them rather than take them on faith. No limitation was removed,
  shortened or softened; §3 (verifying an unrelated transport root CA) is
  omitted because it depends on files you do not have.
- References in the script's comments to paths like `app/src/lib/attest/…` are
  **provenance** — they say where a constant or a rule came from. They are not
  steps you are expected to follow.

## Reporting a problem

If any check here fails, or if you find a discrepancy between what a document
claims and what you can independently establish:

**security@hodeitek.com** — include the artefact, the exact command, and the
full output. A verification failure you can reproduce is a security report and
we will treat it as one.

## Licence

Apache License 2.0. It is a verifier; you should be free to read it, run it,
modify it and integrate it into your own due-diligence tooling without asking.
