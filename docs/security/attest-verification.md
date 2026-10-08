# Verifying HodeiShield attestations

**Public edition.** This is the redacted, externally-publishable edition of an
internal Hodeitek document. What was removed, and why, is listed at the bottom
under **"What this edition leaves out"**. Nothing was softened: every limitation
the internal edition states about what these attestations *do not prove* is
reproduced here in full.

**Audience: you, outside Hodeitek.** A customer checking a supplier's claim, a
security team validating a Trust Center badge, an evaluator asking to be shown
the artefact rather than told about it.

Nothing here requires our cooperation. Every check runs offline, against
material you already hold, using OpenSSL and a few common tools (§2). If a step needs you to trust us for
anything other than "this key is Hodeitek's", we have written it down as a gap
rather than glossed over it.

- [1. Two independent artefacts](#1-two-independent-artefacts-do-not-confuse-them)
- [2. What you need](#2-what-you-need)
- [3. Verifying the post-quantum root CA](#3-verifying-the-post-quantum-root-ca) — *omitted from this edition, see below*
- [4. Verifying a posture attestation, offline](#4-verifying-a-posture-attestation-offline)
- [5. Proving the toolchain to yourself first](#5-proving-the-toolchain-to-yourself-first)
- [6. What a verified attestation proves — and what it does not](#6-what-a-verified-attestation-proves--and-what-it-does-not)
- [7. Key rotation, revocation and what to do with an old document](#7-key-rotation-revocation-and-what-to-do-with-an-old-document)
- [8. Why Cloudflare is not in this picture](#8-why-cloudflare-is-not-in-this-picture)
- [9. Cryptographic choices, stated plainly](#9-cryptographic-choices-stated-plainly)
- [10. Reporting a problem](#10-reporting-a-problem)

Section numbering is kept identical to the internal edition on purpose: the
verifier prints "read §6 before relying on it", and that pointer has to land on
the section it means.

---
## 1. Two independent artefacts. Do not confuse them.

HodeiShield publishes two post-quantum things. They are unrelated, and a great
deal of the value of this document is in keeping them apart.

|                                         | **A. AOP post-quantum root CA**                                                                              | **B. ATTEST document-signing key**                                                                      |
| --------------------------------------- | ------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------- |
| What it is                              | A self-signed X.509 CA certificate                                                                           | A bare ML-DSA-65 key pair — no certificate, no CA, no chain                                             |
| Algorithm                               | ML-DSA-65 (FIPS 204)                                                                                         | ML-DSA-65 (FIPS 204)                                                                                    |
| Where it lives                          | In our deployment manifests, and as the second certificate in our origin CA bundle                            | Public half at `GET /api/public/attest/keys`; private half is a 32-byte seed held in software — see §6, item 8, which does not soften it |
| What it is for                          | Mutual TLS on the Cloudflare→origin hop                                                                      | Signing posture attestation documents                                                                   |
| Does it sign attestations?              | **No. Never.**                                                                                               | Yes. That is its only job.                                                                              |
| Does it vouch for any compliance claim? | **No.**                                                                                                      | Yes — that is the claim you are checking                                                                |
| Is it in the live TLS path today?       | **No.** Origin-pull uses the classical ECDSA P-256 root, which is the _first_ certificate in the same bundle | n/a                                                                                                     |

> **The transport CA does not vouch for attestation documents.**
> There is no chain from A to B and there is not meant to be. If someone shows
> you the post-quantum CA as evidence that an attestation is genuine, that is a
> non sequitur — politely reject it. Artefact A demonstrates that we have a
> real, verifiable ML-DSA-65 certificate; it demonstrates nothing about any
> particular document.

### 1.1 An honest note about artefact A

The post-quantum root CA is real, cryptographically valid, and committed — §3 of the internal edition
shows how to check it, and that section is not reproduced here (see below). But be clear about its status: it
is **provisioned, not load-bearing**. The production origin-pull path uses the
classical ECDSA P-256 root, because Cloudflare cannot currently deliver an
ML-DSA client certificate on origin-pull for this zone (the constraint is on
Cloudflare's side, not ours). Our origin verifies ML-DSA client certificates correctly; the
blocker is on the edge side. When Cloudflare ships it, the change is a
certificate swap, not an engineering project.

So: the certificate is genuine, and the fact that it is not yet in the live
transport path is stated here rather than left for you to discover.

---

## 2. What you need

| Requirement       | Why                                                                                                                                                                |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **OpenSSL ≥ 3.5** | ML-DSA (FIPS 204) support landed in 3.5. Older builds cannot parse these artefacts at all, and LibreSSL (the `openssl` on macOS) has no ML-DSA whatever its version number. Before anything else the verifier checks that its `openssl` is OpenSSL, is 3.5 or later and lists ML-DSA-65 in `openssl list -signature-algorithms`; otherwise it stops with exit 2, "not ML-DSA capable". A failure there is a tooling limit, not evidence against the artefact. |
| **`bash` ≥ 4**   | `verify-attestation.sh` is bash, not POSIX `sh`. No Node, no npm, no HodeiShield code.                                                                             |
| **`python3`**     | Needed on the path the endpoint actually serves. `GET /api/public/attest/<slug>` returns a **detached** JWS, so the canonical bytes have to be re-derived from the JSON you can read — which is the point, and which needs a JSON parser and the encoder of §4.5. Standard library only. |
| **`jq`**          | Required by the script only for `--status-list` (§7.1). The §4.6 by-hand path uses it throughout, so that path needs **OpenSSL, `python3` and `jq`**, plus `xxd` or `python3` to turn one hex constant into bytes. It does not work with OpenSSL alone. |
| Network access    | Only to _fetch_ the public key and the document. Verification itself is offline.                                                                                   |

```console
$ openssl version
OpenSSL 3.5.6 7 Apr 2026 (Library: OpenSSL 3.5.6 7 Apr 2026)

$ openssl list -signature-algorithms | grep -i ml-dsa
  ML-DSA-44 @ default
  ML-DSA-65 @ default
  ML-DSA-87 @ default
```

Without `python3` the verifier stops at step [0] with `exit 2` and the message
`python3 is needed to read the claims JSON and re-derive the canonical envelope
bytes.` — exit **2** is "could not check", never "check failed"; see the exit
codes in the repository README.

If the second command does not list ML-DSA-65, stop and upgrade OpenSSL.
Debian/Ubuntu ship 3.5+ from trixie/24.10 onward; on macOS, `brew install
openssl@3` and put its `bin` ahead of the system LibreSSL. If you cannot
install it, the repository README's container route runs the same script in a
digest-pinned Debian 13 image and needs only Docker or Podman on your machine.

---

## 3. Verifying the post-quantum root CA

**Omitted from this public edition.** This section verifies artefact **A** — the
AOP post-quantum root CA used for the Cloudflare→origin mTLS hop — against
certificate files that ship inside Hodeitek's private repository. Without those
files the section cannot be followed, so reproducing it here would be a set of
commands you could not run.

It is omitted for that reason and no other. Artefact A signs no attestation and
vouches for no compliance claim (§1); nothing in §4 depends on it. If you are
doing supplier due diligence and want that section, ask — see §10.

---
## 4. Verifying a posture attestation, offline

### 4.0 The shape of the thing

A HodeiShield posture attestation has **two parts that travel together**:

1. **The claims, as JSON.** Human-readable. Who vouches (`iss`), which key
   (`kid`), a unique document id (`jti`), your challenge if you issued one
   (`nonce`), the derived `overallBand`, and — nested at `claims.posture` — the
   thing you actually want to know: which organisation, which frameworks, which
   maturity bands, computed when.
2. **A detached JWS.** `BASE64URL(protected) || '..' || BASE64URL(signature)` —
   RFC 7515 Appendix F. The payload segment is **empty**; the signature covers
   a deterministic binary re-encoding of **the whole claims object**.

That split is deliberate, and it is in your favour. You verify the signature
over bytes **you re-derive yourself** from the JSON you can read. There is no
step where you are asked to trust that an opaque blob says what a nearby
human-readable document claims it says — if they disagree, verification fails.

> **The one thing people get wrong.** The signed bytes are the **attestation
> envelope** `hodei-shield.attest.attestation.v1` (fields E1..E7), *not* the bare
> posture. The posture is nested inside it, verbatim, as field E7 — the frozen
> `hodei-shield.attest.posture.v1` bytes (fields F1..F8). Both encodings are
> specified in §4.4 and you need both: the inner one produces E7, the outer one
> produces the bytes the signature is over. Re-deriving only the posture makes a
> perfectly genuine attestation fail to verify, which is exactly the bug this
> document and `verify-attestation.sh` shipped with until 2026-07-30.
>
> Practically: **verify against `claims`, never against `claims.posture` alone.**
> The posture on its own is not enough — `iss`, `kid`, `jti`, `nonce` and
> `overallBand` are all inside the signature too, and `jti` is a random UUID
> nobody can reconstruct.

**The signature covers a closed set of members, and nothing else.** The
canonical encoders of §4.4 read exactly these members and skip any other: in
`claims`, `docVersion`, `iss`, `kid`, `jti`, `nonce`, `overallBand` and
`posture`; in the posture, `version`, `slug`, `orgName`, `visibility`,
`generatedAt`, `expiresAt`, `lastCheckedAt` and `frameworks`; in each framework
entry, `code`, `label` and `band`. A JSON member outside those sets is not signed,
so a document that carries one is showing you a fact nobody signed, while the
signature over the members that *are* covered still verifies. A conforming
verifier therefore **rejects** such a document; `verify-attestation.sh` reports
`unsigned_member`, listing the offending paths, and fails. §4.6 step 5a does the
same by hand, and §4.7 experiment D is a test you can run.

**A member may appear only once.** JSON leaves duplicate member names undefined,
and parsers disagree about which copy they keep: `python3` and `jq` keep the
last, other tools the first. The signed value can be only one of them, so a
document that repeats a member — anywhere, including the `attestation` wrapper,
or `claims` both beside and inside it — is rejected as `duplicate_key`, and the
"every member … is covered by the signature" line is not printed for it. Before
v1.0.1 the verdict was already decided on the last copy, the signed one, but the
first copy could be printed under a PASS line; that output is what changed. The
same rule applies to the key documents (a duplicated member there is exit 2) and
to the status list (unknown, exit 3).

An **attached** form also exists (`protected.payload.signature`, the canonical
envelope bytes embedded) for contexts where carrying two files is awkward. Both
verify the same way; the tooling here handles either, and cross-checks them
against each other when you supply both. Given an attached JWS **alone**, the
script decodes the embedded envelope back into the claims it encodes and holds
them to every check a detached document gets: freshness, `--expect-slug`,
`--expect-issuer`, `--expect-nonce` and revocation. A payload that does not
decode as the envelope is "could not check" (exit 2), never a pass. The
signature is over `protected.payload` in both forms, so anyone holding a
detached document can re-serialise it as attached; neither form is weaker.

The protected header is a **closed set** of exactly three members:

```json
{
  "alg": "ML-DSA-65",
  "kid": "roeFReafBOA_WF3cqfilHA",
  "typ": "application/attest+jws"
}
```

| Member | Value                    | Why you should check it                                                                                                                                                                                                                                                                                         |
| ------ | ------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `alg`  | `ML-DSA-65`              | The IANA-permanent identifier from [RFC 9964](https://www.rfc-editor.org/rfc/rfc9964.html), a published Proposed Standard. Not provisional, not a vendor extension. **Compare it as a constant — never let a document choose the algorithm you verify under.** `alg: "none"` is the oldest JWS attack there is. |
| `kid`  | 22 base64url chars       | Names which key signed. Derivable from the key bytes (§4.2), so a key document cannot mislabel itself.                                                                                                                                                                                                          |
| `typ`  | `application/attest+jws` | RFC 8725 §3.11 explicit typing. It stops an attestation being replayed into any other JWS-consuming surface.                                                                                                                                                                                                    |

A `crit` member, or any fourth member, is a rejection: the verifier reports
`malformed_document` (the header members it found, against exactly `alg,kid,typ`)
and fails, for a posture attestation and for a status list alike. If we ever need
to add a header field, that is a new `typ` and a new document version, not a
silent extension.

> **Correction, 2026-07-30.** Between 2026-07-29 and 2026-07-30 this section and
> `scripts/attest/verify-attestation.sh` documented and implemented only the
> **inner posture** encoding, while the issuer signed the **envelope**. Anyone
> following the published procedure got `SIGNATURE DOES NOT VERIFY` on a
> perfectly genuine attestation. The error was found by driving the published
> tool against a live document during a key-rotation drill
> (`docs/operations/attest-key-rotation-drill-2026-07-30.md`); it had never
> worked, because the envelope and the verifier shipped in the same commit and
> the verifier was only ever tested against fixtures built on the same wrong
> assumption. Everything below is now produced by running the shipped tool
> against live, unmodified endpoint output. If you built a verifier from the
> earlier text, §4.7 experiment C is the one-command check for whether you
> inherited the bug.
>
> **Status note, 2026-07-30.** The signing and verification library
> (`app/src/lib/attest/`) is implemented and is the source of truth for
> everything in this section.
> All three public routes are implemented: the JWK Set at
> `/api/public/attest/keys`, the signed document at
> `/api/public/attest/<slug>`, and the convenience verifier at
> `/api/public/attest/verify`. A deployment with no signing key
> configured answers the key set with a truthful, cacheable `{"keys": []}` and
> the document route with `503 attest_unavailable` — that is "this deployment
> signs nothing", not "the endpoint does not exist".

### 4.1 Get the two inputs

```bash
# 1. The signing key. An RFC 7517 JWK Set, served anonymously, no auth, CORS-open.
#    Cached `public, max-age=300, stale-while-revalidate=3600`.
curl -fsS https://app.hodeishield.com/api/public/attest/keys -o jwks.json

# 2. The attestation itself, fetched from the URL you were given, right before
#    verifying. A document lives at most one hour, so a file forwarded by email
#    or attached to a questionnaire will usually fail the freshness check.
curl -fsS https://app.hodeishield.com/api/public/attest/<slug> -o att.json
```

`att.json` carries both halves in one file, and the reference verifier takes it
as-is:

```json
{
  "attestation": {
    "claims": { "docVersion": "attest.attestation.v1", "iss": "…", "kid": "…",
                "jti": "…", "nonce": null, "overallBand": "in_progress",
                "posture": { "version": "attest.posture.v1", "…": "…" } },
    "signature": "eyJhbGciOiJNTC1EU0EtNjUi…",
    "digest": "05c4681633cea1ff…"
  },
  "verification": { "jwksUrl": "…", "signingBytes": "hodei-shield.attest.attestation.v1", "…": "…" }
}
```

`digest` is SHA-256 of the signing bytes. It is a **content id**, not an
authentication check — comparing a digest proves nothing about who produced it.
It is useful for one thing: confirming your re-encoder agrees with ours before
you go looking for a signature bug. `verification.signingBytes` names the domain
separator of the encoding the signature covers, and it says
`hodei-shield.attest.attestation.v1` — the envelope, not the posture.

If you were handed the two halves separately, they are
`.attestation.signature` (the compact JWS) and `.attestation.claims` (the signed
document).

`jwks.json` is a JWK Set of RFC 9964 `AKP` ("Algorithm Key Pair") keys:

```json
{
  "keys": [
    {
      "kty": "AKP",
      "alg": "ML-DSA-65",
      "pub": "G6eg_1aw7Yi6_tMuVcW5QSryYOTB0-hPibLwrKfp…",
      "kid": "roeFReafBOA_WF3cqfilHA",
      "use": "sig"
    }
  ]
}
```

A key set can list more than one key (§7); the production set carried two when
these examples were captured, and the one shown is the one that signed the
document used throughout §4. Always select by `kid`.

`pub` is base64url of the **raw 1952-byte FIPS 204 `pkEncode` public key** — no
SPKI wrapper, no PEM, no `priv` member (there is no code path in the platform
that could add one).

### 4.2 The `kid` is checked, not trusted

```
kid = BASE64URL( SHA-256( UTF8("hodei-shield.attest.kid.v1") || publicKey )[0..16] )
```

Recompute it from the key bytes. A JWK that names a `kid` it cannot derive is
either mislabelled or hostile, and the tooling rejects it either way. The
domain separator keeps a `kid` from ever colliding with a posture digest over
the same input.

```bash
{ printf 'hodei-shield.attest.kid.v1'; cat pub.raw; } \
  | openssl dgst -sha256 -binary \
  | head -c 16 | openssl base64 -A | tr '+/' '-_' | tr -d '='
```

```
roeFReafBOA_WF3cqfilHA
```

### 4.3 The short version

```bash
scripts/attest/verify-attestation.sh \
  --attestation att.json --jwks jwks.json \
  --expect-slug talmaren-payments --expect-issuer https://app.hodeishield.com
```

If you hold the two halves separately, pass them separately — same check:

```bash
scripts/attest/verify-attestation.sh \
  --jws att.jws --claims att.claims.json --jwks jwks.json \
  --expect-slug talmaren-payments --expect-issuer https://app.hodeishield.com
```

`talmaren-payments` is a demonstration organisation with fictitious data. Real
output, run on 2026-09-29 against the unmodified document served by
`/api/public/attest/talmaren-payments` — not a fixture (colour codes off,
`NO_COLOR=1`). Every value below, including the `kid`, `jti` and digest, is from
that run; a fresh fetch has a new `jti`, `generatedAt` and digest:

```
HodeiShield posture attestation — offline verification

[0] Environment
  PASS  OpenSSL 3.5.7 offers ML-DSA-65

[1] Structure
  PASS  detached JWS (RFC 7515 Appendix F): payload segment is empty
  PASS  signature is 3309 bytes — the ML-DSA-65 size

[2] Header
        {"alg":"ML-DSA-65","kid":"roeFReafBOA_WF3cqfilHA","typ":"application/attest+jws"}
  PASS  alg is ML-DSA-65 (RFC 9964, IANA-permanent)
  PASS  typ is application/attest+jws — cannot be replayed into another JWS surface
  PASS  no 'crit' header extension
  PASS  header is the closed set {alg, kid, typ}

[3] Public key
  PASS  selected the JWKS key whose kid is 'roeFReafBOA_WF3cqfilHA'
  PASS  public key is 1952 bytes — the ML-DSA-65 size
  PASS  kid 'roeFReafBOA_WF3cqfilHA' is derivable from these key bytes
  PASS  loaded as an ML-DSA-65 public key

[4] Payload — attestation envelope (E1..E7)
  PASS  re-derived 750 canonical envelope bytes from the claims JSON you can read
        of which E7 nests 548 bytes of hodei-shield.attest.posture.v1 (the posture itself)
        sha-256: 05c4681633cea1ff8c2bf236b881a0aefea0187066c3b5d57f81d84043f09f89
        (compare with attestation.digest as the endpoint published it — a content id,
         never an authentication check: the signature below is the check)
  PASS  claims.kid (E3) equals the protected-header kid — one key, named twice, agreeing

[5] Signature
  PASS  ML-DSA-65 signature verifies over protected.payload

[6] Freshness
        generatedAt: 2026-09-29T10:34:13.668Z  (age 2s)
  PASS  within the 3600s freshness window
        expiresAt:   2026-09-29T10:49:13.668Z
  PASS  not expired
  PASS  validity window 900s is within the issuer's 3600s ceiling
        lastCheckedAt: 2026-09-08T12:56:35.697Z  (freshness of the underlying data,
                       which can be older than generatedAt)
  PASS  posture is for slug 'talmaren-payments', as expected

[7] Attested claims
        docVersion:  attest.attestation.v1
        iss:         https://app.hodeishield.com
        kid:         roeFReafBOA_WF3cqfilHA
        jti:         3d9fbfe0-93a3-4f37-ac7a-39f78783c9ad
        nonce:       null  (no challenge — see --expect-nonce)
        overallBand: in_progress
  PASS  docVersion (E1) is attest.attestation.v1 — and it is inside the signature, so it cannot be rewritten on the wire
  PASS  every member of the claims JSON is covered by the signature
  PASS  iss (E2) is 'https://app.hodeishield.com', as expected
  PASS  overallBand (E6) 'in_progress' equals the weakest attested band — recomputed, not trusted

        posture (E7, the frozen v1 bytes):
        {
          "version": "attest.posture.v1",
          "slug": "talmaren-payments",
          "orgName": "Talmaren Payments",
          "visibility": "public",
          "generatedAt": "2026-09-29T10:34:13.668Z",
          "expiresAt": "2026-09-29T10:49:13.668Z",
          "lastCheckedAt": "2026-09-08T12:56:35.697Z",
          "frameworks": [
            {
              "code": "dora",
              "label": "DORA",
              "band": "substantial"
            },
            {
              "code": "ens",
              "label": "ENS",
              "band": "in_progress"
            },
            {
              "code": "gdpr",
              "label": "GDPR",
              "band": "substantial"
            },
            {
              "code": "iso27001",
              "label": "ISO27001",
              "band": "in_progress"
            },
            {
              "code": "iso42001",
              "label": "ISO42001",
              "band": "in_progress"
            },
            {
              "code": "nis2",
              "label": "NIS2",
              "band": "in_progress"
            },
            {
              "code": "soc2",
              "label": "SOC2",
              "band": "in_progress"
            }
          ]
        }

VERIFIED — this document was signed by the holder of the key above and
has not been altered since.

That is all it proves. It does not prove the claims inside are true, that
the key belongs to who you think, or that the document was meant to exist.
Read docs/security/attest-verification.md §6 before relying on it.
```

> **Note on the output above.** That run predates a change to what the script
> prints. Today the overall band and the frameworks are shown in an "Attested
> content" block just before the verdict, and only when the document verifies;
> the full posture JSON is printed only with `--raw`; and a document that does
> not verify prints `attested content withheld: this document did not verify`
> in their place. The checks and the verdict are unchanged.

**Always pass `--expect-issuer`.** `iss` decides whose key set is
authoritative, and a verifier that never checks it will happily accept a
perfectly valid document signed by somebody else's deployment of this software.
Without it the script still verifies, but prints a `WARN` that nothing pinned
`iss`. A demonstration subject can be retired, in which case its endpoint
answers 404; substitute the slug you were given.

### 4.4 The canonical encoding — what the signature actually covers

There are **two** encodings here, one nested inside the other, and you need both:

| | Domain separator | Fields | Role |
| --- | --- | --- | --- |
| **Envelope** | `hodei-shield.attest.attestation.v1` | **E1..E7** | **The signed bytes.** The JWS payload. |
| **Posture** | `hodei-shield.attest.posture.v1` | **F1..F8** | The frozen v1 posture. Nested verbatim as **E7**. |

If you implement only the posture encoder you will produce bytes the signature
was never over, and every genuine attestation will look forged. Start from the
envelope.

Both encodings are **deliberately not JSON**. Canonical-JSON schemes push the
determinism problem into number formatting, string escaping and key ordering,
all of which differ between implementations. These are positional, binary,
length-prefixed encodings with none of those degrees of freedom.

**Primitives** — identical for both encodings.

```
u64be(n)    8 bytes, unsigned 64-bit big-endian
bytes(b)    u64be(len(b)) || b                    ("length-prefixed field")
str(s)      bytes(UTF8(s))
opt_str(s)  0x00                                   when s is null
            0x01 || str(s)                         otherwise
u64(n)      bytes(u64be(n))   i.e. u64be(8) || u64be(n)
```

`u64` is length-prefixed too — redundant, but it makes _every_ field in the
stream length-prefixed, so no field boundary can slide into its neighbour.

#### 4.4.1 The envelope — `hodei-shield.attest.attestation.v1` (signed)

```
envelope := DOMAIN || E1 || E2 || … || E7

DOMAIN := the 34 raw bytes UTF8("hodei-shield.attest.attestation.v1")
          emitted WITHOUT a length prefix

E1 := str(docVersion)      MUST equal "attest.attestation.v1"
E2 := str(iss)             who vouches — the platform origin, not the tenant
E3 := str(kid)             the key that signed; MUST equal the JWS header kid
E4 := opt_str(jti)         unique per issuance (UUID v4). Never null in practice;
                           optional-encoded for forward compatibility.
E5 := opt_str(nonce)       your challenge, echoed verbatim, or null
E6 := opt_str(overallBand) the weakest attested band, or null
E7 := bytes(posture)       ← the F1..F8 bytes of §4.4.2, nested whole
```

Encode `E7` by running the posture encoder of §4.4.2 and wrapping its output in
one `bytes()` length prefix. It is not re-parsed or re-serialised on the way in:
those bytes *are* the v1 posture bytes, which is what lets a Rust verifier slice
E7 out of the stream and hand it to an existing v1 posture decoder unchanged.

**`kid` is signed twice, and that is deliberate.** Once here as E3, and once as
part of the JWS protected header, which is inside the JWS signing input. A
conforming verifier asserts the two agree (`verify-attestation.sh` reports
`kid_mismatch`), so a document cannot name one key in its body and be signed by
another.

**Why an envelope at all.** `AttestPosture` is a frozen cross-language wire
contract shared with our Rust endpoint agent; adding `jti`/`nonce`/`iss` to it
would be an in-place edit of a versioned format, which the versioning rule below
forbids. So the issuer signs an envelope that nests the frozen bytes as one
length-prefixed field. One signature, one payload, two formats that can version
independently.

**Envelope rules.** E1..E7 are positional, in exactly that order. Every string
is checked for valid UTF-8 with no unpaired surrogates and bounded length
(4096 bytes per field), by the same rules R5/R6 below. Any change to the field
list or order requires a `.v2` DOMAIN and a new `docVersion` — never an in-place
edit.

#### 4.4.2 The posture — `hodei-shield.attest.posture.v1` (nested at E7)

These are also the bytes the badge commitment of §4.9 hashes, so this encoder
earns its keep twice.

```
canonical := DOMAIN || F1 || F2 || … || F8

DOMAIN := the 30 raw bytes UTF8("hodei-shield.attest.posture.v1")
          emitted WITHOUT a length prefix

F1 := str(version)         MUST equal "attest.posture.v1"
F2 := str(slug)
F3 := str(orgName)
F4 := str(visibility)      "public" | "gated"
F5 := str(generatedAt)     RFC 3339, verbatim as supplied
F6 := opt_str(expiresAt)
F7 := opt_str(lastCheckedAt)
F8 := u64(frameworkCount) || FW[0] || FW[1] || … || FW[n-1]

FW[i] := str(code) || str(label) || str(band)
```

**Rules** — these govern the posture, and R1/R5/R6 govern the envelope too.

|        |                                                                                                                                                                                                                               |
| ------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **R1** | Fields are **positional**, in exactly that order. Key order in any JSON representation is irrelevant.                                                                                                                         |
| **R2** | Frameworks are sorted **ascending by the UTF-8 byte sequence** of `code` — memcmp order, _not_ locale order and _not_ UTF-16 code-unit order (they diverge above the BMP). Reshuffling the array cannot change the signature. |
| **R3** | Duplicate `code` values are **rejected**, not deduplicated. With duplicates the R2 sort is not a total order and two implementations could legitimately disagree on the byte stream.                                          |
| **R4** | Timestamps are hashed as the **exact strings supplied**. No normalising `Z` versus `+00:00`, no trimming fractional seconds. We emit UTC `Z` with milliseconds; you re-encode whatever string you received.                   |
| **R5** | Every string must be valid UTF-8 with no unpaired surrogates. An unpaired surrogate encodes to U+FFFD, which would map two _different_ inputs onto the _same_ bytes — a collision the signature would then bless. Rejected.   |
| **R6** | Field lengths are bounded, so an attacker-influenced field cannot turn signing into a memory event.                                                                                                                           |

**Versioning.** Any change to the field list, field order, framework record or
sort rule requires a new `DOMAIN` (`.v2`) and a new `version` string. v1 is
never edited in place: changing the domain separator makes old and new
signatures mutually unverifiable, which is exactly the safe outcome.

The domain separators also keep these signature spaces disjoint from every other
digest in the platform, and from each other — an attestation signature can never
be replayed as an ingest-envelope signature, and a bare posture encoding can
never be mistaken for a signed envelope, even with identical key material.

### 4.5 A complete independent implementation, in 35 lines

That spec is meant to be sufficient on its own. Here is a Python encoder written
from it, with no reference to our code. It is the encoder embedded in
`verify-attestation.sh` **without its hardening**: the script's copy additionally
enforces the 4096-byte cap on every string field, the 64-framework cap and the
type checks (posture must be an object, every field a string) that §4.4.1 and
rule R6 require, and it refuses a document that violates any of them. For a
document that satisfies those rules the two produce the same bytes; if you
implement your own verifier, include those checks. Note it implements **both**
formats: `posture_bytes` produces E7, `envelope_bytes` produces the bytes that
are signed.

```python
import json, struct, sys
ENVELOPE = b"hodei-shield.attest.attestation.v1"
POSTURE  = b"hodei-shield.attest.posture.v1"
def u64be(n): return struct.pack(">Q", n)
def bs(b):    return u64be(len(b)) + b
def st(s):
    if not isinstance(s, str): raise SystemExit("field must be a string")
    s.encode("utf-8", "strict")                 # R5 / E-rules
    return bs(s.encode("utf-8"))
def opt(s):   return b"\x00" if s is None else b"\x01" + st(s)
def u64(n):   return bs(u64be(n))

def posture_bytes(p):                            # F1..F8 — nested at E7
    if p["version"] != "attest.posture.v1":       raise SystemExit("bad version")
    if p["visibility"] not in ("public","gated"): raise SystemExit("bad visibility")
    fw = sorted(p["frameworks"], key=lambda f: f["code"].encode("utf-8"))   # R2
    codes = [f["code"] for f in fw]
    if len(set(codes)) != len(codes):             raise SystemExit("duplicate code")  # R3
    out = [POSTURE, st(p["version"]), st(p["slug"]), st(p["orgName"]),
           st(p["visibility"]), st(p["generatedAt"]),
           opt(p.get("expiresAt")), opt(p.get("lastCheckedAt")), u64(len(fw))]
    for f in fw: out += [st(f["code"]), st(f["label"]), st(f["band"])]
    return b"".join(out)

def envelope_bytes(c):                           # E1..E7 — THIS is what is signed
    if c["docVersion"] != "attest.attestation.v1": raise SystemExit("bad docVersion")
    nested = posture_bytes(c["posture"])         # E7 first: refuse a bad posture early
    return b"".join([ENVELOPE, st(c["docVersion"]), st(c["iss"]), st(c["kid"]),
                     opt(c.get("jti")), opt(c.get("nonce")), opt(c.get("overallBand")),
                     bs(nested)])

claims = json.load(open(sys.argv[1]))
what = sys.argv[2] if len(sys.argv) > 2 else "envelope"
sys.stdout.buffer.write(envelope_bytes(claims) if what == "envelope"
                        else posture_bytes(claims["posture"]))
```

Run it against the claims and compare the digest with what the platform
computed and published in the same response:

```bash
jq '.attestation.claims' att.json > claims.json

python3 canon.py claims.json > canon.bin              # the signed envelope
python3 canon.py claims.json posture > nested.bin     # just E7's contents
wc -c < canon.bin
wc -c < nested.bin
openssl dgst -sha256 canon.bin
jq -r '.attestation.digest' att.json
```

```
750
548
SHA2-256(canon.bin)= 05c4681633cea1ff8c2bf236b881a0aefea0187066c3b5d57f81d84043f09f89
05c4681633cea1ff8c2bf236b881a0aefea0187066c3b5d57f81d84043f09f89
```

That digest is byte-identical to the one the platform's TypeScript encoder
produced for the same document, and the platform published it next to the
signature without being asked. **Two independent implementations, written in
different languages from the same written spec, agree exactly.** That is the
evidence that this format is genuinely specified rather than
defined-by-implementation — and it is what makes third-party verification real
rather than nominal.

The 750/548 split is worth internalising: 548 of those bytes are the nested
posture, and 202 are the envelope around it. A verifier that produces 548 is
hashing the wrong document, however perfect its posture encoder.

### 4.6 The long version — verify by hand

You do not need our repository.

```bash
# A base64url decoder. JWS uses base64url without padding; OpenSSL wants
# standard base64 with padding.
b64url_decode() {
  local s="${1//-/+}"; s="${s//_//}"
  case $(( ${#s} % 4 )) in 2) s="$s==";; 3) s="$s=";; esac
  printf '%s' "$s" | openssl base64 -d -A
}
b64url_encode() { openssl base64 -A -in "$1" | tr '+/' '-_' | tr -d '='; }

# 0. Split the document into its two halves.
jq -r '.attestation.signature' att.json > att.jws
jq   '.attestation.claims'     att.json > claims.json

# 1. Split the compact JWS. For a detached JWS the middle segment is empty.
JWS=$(tr -d '[:space:]' < att.jws)
H=${JWS%%.*}; REST=${JWS#*.}; P=${REST%%.*}; S=${REST#*.}

# 2. Read the header and check `alg` and `typ` yourself.
b64url_decode "$H"
```

```
{"alg":"ML-DSA-65","kid":"roeFReafBOA_WF3cqfilHA","typ":"application/attest+jws"}
```

```bash
# 2b. The header is a closed set: exactly alg, kid, typ. Anything else — a fourth
#     member, or `crit` — is a rejection, whatever the signature says.
b64url_decode "$H" | jq -r 'keys | join(",")'       # must print: alg,kid,typ
HDR_KID=$(b64url_decode "$H" | jq -r '.kid')

# 3. Take the raw public key from the JWKS — the key whose kid is the header kid,
#    not every key's `pub`; a published key set can hold more than one. Then
#    confirm its length and that its kid is derivable from its bytes.
PUB_B64URL=$(jq -r --arg kid "$HDR_KID" '.keys[] | select(.kid == $kid) | .pub' jwks.json)
b64url_decode "$PUB_B64URL" > pub.raw
wc -c < pub.raw                                     # must be exactly 1952
{ printf 'hodei-shield.attest.kid.v1'; cat pub.raw; } | openssl dgst -sha256 -binary \
  | head -c 16 | openssl base64 -A | tr '+/' '-_' | tr -d '='   # must equal the header kid
```

```
1952
roeFReafBOA_WF3cqfilHA
```

```bash
# 4. OpenSSL loads SubjectPublicKeyInfo; the JWK carries the bare key. Prepend
#    the 22-byte ML-DSA-65 SPKI header (OID 2.16.840.1.101.3.4.3.12). These
#    bytes are a constant of the algorithm, not a HodeiShield value — derive
#    them yourself from any ML-DSA-65 key with `openssl pkey -pubout -outform DER`.
printf '308207b2300b0609608648016503040312038207a100' | xxd -r -p > pub.der
cat pub.raw >> pub.der
openssl pkey -pubin -inform DER -in pub.der -out pub.pem
openssl pkey -pubin -in pub.pem -noout -text | head -1
```

```
ML-DSA-65 Public-Key:
```

```bash
# 5a. Reject anything in claims.json that the signature does not cover (§4.0).
#     The encoder of §4.5 reads only the members below and skips the rest, so an
#     extra member would verify without being signed. Any output here means:
#     reject the document (verify-attestation.sh reports `unsigned_member`).
#     jq silently keeps the last of a duplicated member, so check the file as you
#     received it for duplicates first (§4.0); any output means reject it too:
#       python3 -c 'import json,sys
#       def h(p):
#           ks = [k for k, _ in p]
#           if len(set(ks)) != len(ks): print("duplicate member:", ks)
#           return dict(p)
#       json.load(open(sys.argv[1]), object_pairs_hook=h)' att.json
jq -r '
    (keys - ["docVersion","iss","kid","jti","nonce","overallBand","posture"]
       | map("claims." + .)),
    (.posture | (keys - ["version","slug","orgName","visibility","generatedAt",
                         "expiresAt","lastCheckedAt","frameworks"]
       | map("posture." + .))),
    (.posture.frameworks | to_entries[] | (.value | keys - ["code","label","band"])
       | map("posture.frameworks[]." + .))
    | .[]' claims.json                              # must print nothing
```

```bash
# 5. Re-derive the canonical ENVELOPE from the claims JSON (§4.5) — not from
#    claims.posture, which is only field E7 of it — then rebuild the JWS signing
#    input: ASCII( BASE64URL(protected) || "." || BASE64URL(payload) ).
#    The protected segment goes in EXACTLY as received — never re-serialise it
#    from the parsed header, or a sender could reorder the header JSON and have
#    you verify over bytes that differ from the ones signed.
python3 canon.py claims.json > canon.bin
wc -c < canon.bin                                   # 750 for the document above
printf '%s.%s' "$H" "$(b64url_encode canon.bin)" > signing_input.bin
b64url_decode "$S" > sig.bin
wc -c < sig.bin                                     # must be exactly 3309
```

```
750
3309
```

```bash
# 6. Verify. The ML-DSA context string is EMPTY — OpenSSL's default, and what
#    RFC 9964 mandates. Do not pass a context.
openssl pkeyutl -verify -pubin -inkey pub.pem -rawin -in signing_input.bin -sigfile sig.bin
```

```
Signature Verified Successfully
```

Only now read the claims as authoritative — after the signature checks out,
never before. The by-hand path stops at the signature: it does not check
freshness, `iss`, the nonce or the derived `overallBand` (§4.8 and the script
do), so do those yourself before relying on a document.

### 4.7 Convince yourself the check can fail

A verification procedure that always passes is not a verification procedure.
Four experiments, all worth running, all with real output from the document
above (run 2026-09-29, `NO_COLOR=1`; lines that do not bear on the point are
omitted, and nothing is added). The exit code of each is stated: run it and
check yours.

**A. A tampered claim must be caught (exit 1).** Upgrade the ISO 27001 band from
`in_progress` to `advanced` — exactly the lie a forged attestation would tell:

```bash
python3 - <<'EOF'
import json
d = json.load(open('att.json'))
for f in d['attestation']['claims']['posture']['frameworks']:
    if f['code'] == 'iso27001': f['band'] = 'advanced'      # the forgery
json.dump(d, open('att-tampered.json','w'), indent=2)
EOF

scripts/attest/verify-attestation.sh --attestation att-tampered.json --jwks jwks.json
echo "exit=$?"
```

```
[4] Payload — attestation envelope (E1..E7)
  PASS  re-derived 747 canonical envelope bytes from the claims JSON you can read
        of which E7 nests 545 bytes of hodei-shield.attest.posture.v1 (the posture itself)
        sha-256: 3143c82fa5737dd6fde9cdb56a173e6f58626fbfa4c17b8f29ccbf35a1e4c92a

[5] Signature
  FAIL  SIGNATURE DOES NOT VERIFY — the document was altered, or it was not signed by this key

VERIFICATION FAILED — 1 check(s) did not hold. Do not rely on this document.
exit=1
```

**B. A harmless reshuffle must _not_ be caught (exit 0).** Rule R2 sorts
frameworks by code, so reordering the array is a no-op. If this failed, the
format would be fragile and every re-serialisation through a JSON library would
be a false alarm:

```bash
python3 -c "
import json
d = json.load(open('att.json'))
d['attestation']['claims']['posture']['frameworks'].reverse()
json.dump(d, open('att-reordered.json','w'), indent=2)"

scripts/attest/verify-attestation.sh --attestation att-reordered.json --jwks jwks.json
echo "exit=$?"
```

```
[5] Signature
  PASS  ML-DSA-65 signature verifies over protected.payload
```

The exit code is 0 only while the document is still fresh (within the hour); the
signature line is the point of the experiment. Sensitive to meaning,
insensitive to representation. That is the property you want, and you have just
tested both halves of it.

**C. An envelope field must be caught too (exit 1)** — the experiment that
distinguishes a verifier which hashes the envelope from one which only hashes the
posture. Rewrite `iss`, the field that decides whose key set is authoritative,
leaving the posture untouched:

```bash
python3 -c "
import json
d = json.load(open('att.json'))
d['attestation']['claims']['iss'] = 'https://attacker.example'
json.dump(d, open('att-issuer.json','w'), indent=2)"

scripts/attest/verify-attestation.sh --attestation att-issuer.json --jwks jwks.json
echo "exit=$?"
```

```
  FAIL  SIGNATURE DOES NOT VERIFY — the document was altered, or it was not signed by this key
VERIFICATION FAILED — 1 check(s) did not hold. Do not rely on this document.
exit=1
```

`iss`, `kid`, `jti` and `nonce` live only in the envelope (E2..E5). A verifier
that re-derives just the posture would pass this experiment — silently accepting
a document whose issuer, key name and challenge had all been rewritten. **If your
own implementation passes A and B but not C, it is hashing E7 instead of E1..E7.**

**D. A member the signature does not cover must be caught (exit 1).** Add a
member that no encoder reads. The signature over the covered members still
verifies, which is exactly why a verifier must reject the document instead of
ignoring the extra member:

```bash
python3 -c "
import json
d = json.load(open('att.json'))
d['attestation']['claims']['note'] = 'not signed'
json.dump(d, open('att-extra.json','w'), indent=2)"

scripts/attest/verify-attestation.sh --attestation att-extra.json --jwks jwks.json
echo "exit=$?"
```

```
  PASS  ML-DSA-65 signature verifies over protected.payload
  FAIL  unsigned_member — the claims JSON carries members the signature does not cover:
          claims.note
VERIFICATION FAILED — 1 check(s) did not hold. Do not rely on this document.
exit=1
```

The same holds for an extra member inside `claims.posture` or inside a framework
entry (the paths are reported as `posture.<member>` and
`posture.frameworks[<i>].<member>`). If your own implementation prints
`VERIFIED` for D, it can be shown facts nobody signed.

If you want all of this, and more, as one command, `bash tests/run.sh` in this
repository runs the offline rejection suite with throwaway keys and
no network.

### 4.8 Freshness and replay

A signature is timeless; a compliance posture is not. Signature validity alone
does not make a document current.

| Field           | What to do with it                                                                                                                                                                                                                                                  |
| --------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `generatedAt`   | RFC 3339 instant the posture was computed. Reject anything older than your own tolerance; the reference verifier defaults to **1 hour** (`--max-age-seconds`), matching the issuer's hard TTL ceiling. Reject anything **more than 300 seconds in the future** as well: the reference verifier fails it as `not_yet_valid`, because otherwise a document dated a year ahead would stay "fresh" for a year. **MUST be present and parseable:** a missing `generatedAt`, or one that cannot be parsed as RFC 3339, is a failure, never a skipped check — a document whose age was not read has not had its age checked. |
| `expiresAt`     | After this, treat the document as stale by construction — re-fetch, do not accept "just this once". **MUST be present: reject a document without one.** We always set it, so a document lacking an expiry is not one of ours, and it must never be read as "never expires". Also reject `expiresAt - generatedAt > 1 hour` — that is above the ceiling we can issue, so it did not come from a conforming issuer whatever its signature says. |
| `lastCheckedAt` | Freshest genuine monitoring heartbeat behind the posture. **Can legitimately be older than `generatedAt`** — that gap is the honest signal of how stale the underlying _data_ is, as distinct from the document. `null` means no heartbeat is being claimed at all. |
| `slug`          | Binds the attestation to one trust center. Check it against the organisation you think you are evaluating. `--expect-slug` does this for you.                                                                                                                       |
| `visibility`    | `gated` postures are redacted by design — see §6.                                                                                                                                                                                                                   |

A genuine document that fails only on age or expiry still exits 1 in the
reference verifier: it is not one to rely on. Its last line tells it apart from
a forged or altered one: `EXPIRED — the signature is valid, but this
attestation expired on <expiresAt>.` (or `… was generated on <generatedAt>,
more than the <N>s you allow (--max-age-seconds) ago.`), followed by the `curl`
command that fetches a fresh copy. Every other failure ends with
`VERIFICATION FAILED — … Do not rely on this document.` The `EXPIRED` line
appears only when the signature verified and age or expiry was the only
failure.

#### The nonce — how to collapse the replay window to a single exchange

`expiresAt` alone leaves a window. Inside it, a genuine attestation can be
re-presented in a context it was not issued for and every signature check will
pass, because the document really is ours. If you need better than "issued
within the last hour", **issue your own challenge**:

```bash
# You invent the challenge. 8–128 base64url characters ([A-Za-z0-9_-]).
NONCE="$(openssl rand -base64 24 | tr '+/' '-_' | tr -d '=')"

curl -fsS "https://app.hodeishield.com/api/public/attest/<slug>?nonce=${NONCE}" \
  -o att.json

# The challenge comes back at claims.nonce, INSIDE the signed bytes.
# The reference verifier makes the comparison for you:
scripts/attest/verify-attestation.sh --attestation att.json --jwks jwks.json \
  --expect-nonce "$NONCE"
```

```
  PASS  nonce (E5) echoes your challenge verbatim — this document was minted for you, now
```

The nonce is field **E5 of the signing envelope** (§4.4.1), not a response header
and not a JSON field bolted on beside the signature — so it cannot be edited
onto an old document. A document echoing a challenge you invented thirty seconds
ago cannot have been fetched in April. `verifyPostureAttestation` enforces this
via its `expectedNonce` option, the `/verify` convenience endpoint reports
`nonceMatched` when you supply one, and `--expect-nonce` is the offline
equivalent. Present the same document to a verifier that challenged differently
and it is rejected, however well it verifies:

```
  PASS  ML-DSA-65 signature verifies over protected.payload
  FAIL  nonce_mismatch — you challenged with 'ZZZZ-a-different-challenge-ZZZZ', the document carries 'yGNc4hhzO8LSLe9-FFNup1xCeHQCO9_W'. A replayed or substituted document, however well it verifies.
```

Use `--expect-nonce ''` to assert the opposite — that a document carries **no**
challenge. If you pass no `--expect-nonce` and the document *does* carry a nonce,
nothing compared it, and the verifier says so with a warning:

```
  WARN  the document carries a nonce but you did not pass --expect-nonce, so nothing
  WARN  compared it. Only the party that invented the challenge can check it.
```

If the document carries no nonce and you pass no `--expect-nonce`, the verifier
prints `nonce: null  (no challenge — see --expect-nonce)` in its claims listing
and no warning: there was no challenge to leave uncompared. Either way, a
document you did not challenge gives you no replay protection beyond `expiresAt`.

Rules worth knowing before you rely on it:

| | |
| --- | --- |
| **Charset** | `^[A-Za-z0-9_-]{8,128}$`. A challenge outside it is **refused with `400 invalid_nonce`**, never trimmed or re-encoded — silently normalising your challenge would break your own comparison while still making us sign attacker-chosen bytes. |
| **Repeats** | `?nonce=a&nonce=b` is a `400`. "The first one wins" is a convention nobody agreed to. |
| **Caching** | A challenged response is `no-store, no-cache, must-revalidate, private`, decided on the PRESENCE of the parameter, never its validity. It is addressed to you alone and must never be served to a second party from a shared cache. |
| **Rate limit** | The challenged path is deliberately tighter than the anonymous one (5/min per IP vs 60/min), because it is uncacheable by design and every request costs a full live scoring run plus a signature. Challenge-response is a one-at-a-time exchange; this will not constrain honest use. |

**The residual, stated plainly.** We do **not** store issued nonces server-side,
and that is a deliberate design decision, not an omission (the reasoning is in
`app/src/app/api/public/attest/[slug]/route.ts`, "WHY THERE IS NO SERVER-SIDE
NONCE STORE"). We are the signer; you are the verifier; the challenge is yours.
So **you must correlate it yourself**: keep the challenge you issued, compare it
to `claims.nonce` on the document you got back, and reject a mismatch. We cannot
do that step for you, and a nonce you do not check is decoration.

There is likewise **no replay counter and no per-document revocation** (§7.5).
If you take the passive route and skip the challenge, narrow `expiresAt`
tolerance plus your own record of which document you received from whom are the
only mitigations, and both are yours to run.

### 4.9 Checking an embedded badge against the attestation

The embeddable Trust Center badge (`/api/public/badge/<slug>`) is an image. It
cannot authenticate itself — anyone can serve an SVG that says anything, and a
signature drawn inside a picture proves nothing about the picture. So the badge
does not claim to be evidence. It carries a **citation**: an 8-character
reference to the posture it is depicting, and the URL of the signed attestation
covering that same posture.

Read it off the badge (`Verified by HodeiShield · #a1b2c3d4`), or take it from
the response headers, which is what a machine should do:

```bash
curl -sI https://app.hodeishield.com/api/public/badge/<slug> | grep -i '^link:\|^x-attest'
```

```
link: <https://app.hodeishield.com/api/public/attest/<slug>>; rel="describedby"; type="application/json"
x-attest-commitment: a1b2c3d4…  (64 hex characters)
```

The reference is a domain-separated SHA-256 over the **inner posture bytes of
§4.4.2** — the F1..F8 encoding, *not* the signing envelope — with the two
issuance timestamps pinned:

```
commitment := SHA-256( "hodei-shield.trust-center.badge-ref.v1"
                       || canonical_posture( posture with
                            generatedAt = "1970-01-01T00:00:00.000Z",
                            expiresAt   = null ) )
```

The domain string is emitted as 38 raw bytes with no length prefix, exactly like
the two `DOMAIN`s of §4.4. Everything after it is `posture_bytes` from §4.5 —
the same function that produces E7 — so there is no third format to implement.
This is deliberately the *inner* encoding: the badge depicts the posture, and
the posture is what the reference must identify. `jti` changes on every fetch,
so an envelope-based reference could never match a cached image.

`generatedAt` and `expiresAt` are pinned because they belong to one _issuance_,
not to the posture: every fetch of the attestation endpoint mints new ones. A
reference derived from them would change on every fetch and could never match a
cached image, which is a check that always fails — worse than no check. Note
that `lastCheckedAt` is **not** pinned: it is content the badge draws, so when
monitoring runs, the reference legitimately moves.

Verify the attestation normally (§4.3), then:

```bash
# Reuse canon.py from §4.5 — in its `posture` mode — on a claims object whose
# posture has the two issuance fields pinned.
jq '{posture: (.attestation.claims.posture
      | .generatedAt = "1970-01-01T00:00:00.000Z" | .expiresAt = null)}' \
  att.json > timeless.json

{ printf 'hodei-shield.trust-center.badge-ref.v1'; python3 canon.py timeless.json posture; } \
  | openssl dgst -sha256 -r | cut -c1-8
```

Compare those 8 characters with the badge. **Equal** means the image is
depicting the posture we sign. **Different** means the image is stale — badges
are edge-cached for five minutes and may be served stale for longer — or that it
did not come from us at all. Either way the signed document wins; the image is
never authoritative, and the badge's own `<desc>` text says so.

Two consequences worth stating:

- The reference is **not** a signature, a MAC or a token, and nothing
  authenticates on it. It is a content identifier that makes "is this badge
  showing what you signed?" a question with an answer. Eight characters is sized
  for a human comparing two strings; the full 64-character commitment is in the
  `X-Attest-Commitment` header if you want it.
- A **gated** trust center's badge carries a reference too, and it is a pure
  function of the slug and organisation name — both printed on the badge in plain
  text. It is constant over time and identical for two gated centers with
  completely different posture, so it cannot be polled, differenced or otherwise
  used to infer anything the gate is withholding. See §6.

## 5. Proving the toolchain to yourself first

Before verifying anything of ours, verify that your OpenSSL does ML-DSA-65
correctly at all. This uses no HodeiShield material whatsoever:

```bash
openssl genpkey -algorithm ML-DSA-65 -out self.pem
printf 'hello post-quantum world' > msg.bin
openssl pkeyutl -sign   -inkey self.pem -rawin -in msg.bin -out sig.bin
wc -c < sig.bin                       # 3309
openssl pkey -in self.pem -pubout -out selfpub.pem
openssl pkeyutl -verify -pubin -inkey selfpub.pem -rawin -in msg.bin -sigfile sig.bin
```

```
3309
Signature Verified Successfully
```

If that works, the procedure in §4 is sound and any failure there is about our
artefacts, not your tools.

### 5.1 One bridge, not two implementations

We sign in TypeScript with [`@noble/post-quantum`](https://github.com/paulmillr/noble-post-quantum)
pinned to exactly `0.7.1` (verified against `app/package.json` on 2026-10-07;
earlier editions of this document said `0.6.1` and then `0.7.0`, both stale). Our Rust
endpoint agent signs with RustCrypto `ml-dsa`. Deliberately the same algorithm and the same byte contract, so
there is one cryptographic bridge to audit rather than two that might diverge.

We check that our TypeScript library and your OpenSSL agree. That check runs
from our own checkout, so it is **our** measurement, not one you can re-run —
the output below is reproduced so you can see what it asserts, and it was
captured while `0.6.1` was the pin. Treat it as our word; §5's first block, which
you *can* run, is the part that needs no trust:

```bash
scripts/attest/generate-attest-key.sh
```

```
[2] Public key
  PASS  derived via OpenSSL genpkey; SPKI DER 1974 B → raw 1952 B
  PASS  public key is 1952 bytes — matches the byte contract

[3] Cross-implementation check
  PASS  OpenSSL 3.5.6 and @noble/post-quantum 0.6.1 derive the identical
  PASS  1952-byte public key from this seed — one ML-DSA bridge, not two

[4] Sign / verify round-trip
  PASS  signature is 3309 bytes — matches the byte contract
  PASS  signature verifies under the derived public key (empty context)
```

Two independent FIPS 204 implementations, given the same 32-byte seed, produce
byte-identical 1952-byte public keys. That is the interoperability claim, tested
rather than asserted.

### 5.2 Byte contract

If you are writing your own verifier, these are the numbers:

| Item             | Size              | Encoding                                                                                                         |
| ---------------- | ----------------- | ---------------------------------------------------------------------------------------------------------------- |
| Public key       | **1952 bytes**    | raw FIPS 204 `pkEncode`; base64url in the JWK `pub` member                                                       |
| Signature        | **3309 bytes**    | raw, detached, no ASN.1 wrapper; base64url as the JWS third segment                                              |
| Private key seed | 32 bytes          | never transmitted; the expanded 4032-byte key is never used as the at-rest form                                  |
| Signing context  | **empty, always** | RFC 9964 mandates it. Passing a non-empty context produces signatures our Rust side structurally cannot verify.  |
| Signing input    | —                 | `ASCII(BASE64URL(protected) + "." + BASE64URL(payload))`, where `payload` is the canonical **envelope** bytes of §4.4.1 (E1..E7) — **not** the posture bytes, which are only field E7 |
| Protected header | 3 members         | closed set `alg` / `kid` / `typ`; a fourth member or a `crit` is a rejection (`malformed_document`)              |
| Detached form    | —                 | `BASE64URL(protected)                                                                                            |     | '..' |     | BASE64URL(signature)` — RFC 7515 Appendix F, empty payload segment |

**Do not expect byte-identical signatures across implementations.** noble
defaults to _hedged_ (randomised) signing; RustCrypto is deterministic. Both
produce valid signatures that the other verifies. Comparing signature bytes
between two implementations of the same key and message will legitimately
differ — compare _verification results_, never bytes.

---

## 6. What a verified attestation proves — and what it does not

This section matters more than the commands.

### Proves

1. **Integrity.** Not one bit of the header or payload changed after signing.
2. **Origin.** It was produced by whoever holds the private key matching the
   public key you verified against.
3. **A point in time, as far as integrity goes.** The `generatedAt` and
   `lastCheckedAt` values are the ones that were signed; they were not altered
   after signing. That is all it says about them: the holder of the signing key
   can sign **any** timestamp, including a false or a backdated one, and there is
   no external timestamp authority or log behind them (item 8 below says who can
   read that key). They can, of course, also have been _wrong_ when signed — see
   below. The same integrity guarantee applies to every envelope field: `iss`, `kid`, `jti` and your `nonce`
   are inside the signature (§4.4.1), so none of them can be rewritten on a
   document after the fact either — which is what makes challenge-response
   worth doing.
4. **Post-quantum resistance of the signature.** ML-DSA-65 is FIPS 204,
   NIST security category 3, believed resistant to cryptanalytically relevant
   quantum computers. A "harvest now, decrypt later" adversary cannot forge this
   signature later using a quantum computer — which classical ECDSA and RSA
   signatures cannot promise.

### Does **not** prove

1. **That the claims inside are true.** The signature attests that _HodeiShield
   asserted_ this posture. It does not audit the posture. The maturity bands
   come from our own scoring of evidence supplied by the organisation. A signed
   document containing a wrong claim is a signed wrong claim.
2. **That the key belongs to Hodeitek.** You fetched it over HTTPS from
   `app.hodeishield.com`, so you are trusting the Web PKI and DNS for that one
   binding. Up to v1.3.0 there is no other channel for the attestation key.
   From v1.4.0 a release carries a key statement signed with Sigstore, which
   names the keys by `kid` and can be checked with `--anchor-file` (see
   [the key anchor decision](key-anchor.md)). That is a second channel tied to
   this repository's release workflow, not a root of trust of the issuer: there
   is still no CA, no transparency log of the key set and no DNSSEC-anchored
   record. **Pin the key
   fingerprint on first use** and treat an unannounced change as an incident
   (§7). The fingerprint is the key's `kid`, derived from the public key bytes
   (§4.2); the verifier recomputes it and prints it, and a JWKS whose `kid`
   does not match its key is rejected. This is a real limitation and we are not going to dress it up.
3. **Anything about the certification bodies.** A `band: advanced` for ISO 27001
   is _our_ computed maturity band, not a certificate issued by an accredited
   certification body. If you need the certification itself, ask for the
   certificate and the accreditation, and check the certification body's own
   register. HodeiShield attestations are a freshness-and-integrity layer over
   posture data, not a substitute for accredited third-party audit.
4. **That the document was ever meant to exist.** There is no public
   append-only log of issued attestations, so a validly-signed document issued
   out of band is indistinguishable from a routine one. Signature verification
   proves origin, not authorisation.
5. **Non-revocation of the *individual document*.** There is no OCSP, no CRL,
   no status endpoint keyed to a single attestation's `jti` — that remains
   true, and it is a deliberate design choice rather than a gap still to be
   closed (§7 argues the arithmetic). If a posture collapses the minute after
   issuance, an unexpired attestation keeps verifying until it expires. That
   window is deliberately short — 15 minutes by default, 1 hour at the
   absolute ceiling — but it is a window. What is **no longer true** is "there
   is no revocation of any kind": since 2026-07-30 the platform can revoke the
   **signing key** that issued a document (unconditionally, any document that
   key ever signed) or the **subject** it was issued for (bounded to
   attestations generated before a chosen instant) — §7 documents both, with a
   procedure you can run yourself. Do not conflate the two: per-*document*
   revocation is still absent by design; per-*key* and per-*subject*
   revocation are not. A **per-document nonce does exist** and is the control
   that closes the unexpired-window problem specifically: challenge the issuer
   yourself and the document is bound to your exchange (§4.8). The residual is
   that we do not store nonces, so correlating your challenge with the echoed
   one is **your** step; skip it and you are back to the `expiresAt` window.
   There is no replay counter.
6. **A complete picture, when `visibility` is `gated`.** A gated trust center
   deliberately publishes less: the raw score is never public, and the maturity
   band is the only progress signal you get. A `gated` attestation is redacted
   by design, not incomplete by accident — but do not read `framework` coverage
   in a gated posture as the organisation's full estate.
7. **Anything about the transport.** The signature says nothing about the TLS
   used to deliver it, and vice versa (§1, §8).

### Not-proved, on the operational side

8. **Any form of protected key custody.** Stated without softening, because you
   would be entitled to assume otherwise and we would rather you did not:

   The signing key is a **32-byte seed held in software**, as a value in the
   application's secret store, and read into the application process at start-up.
   That is the whole mechanism.

   - It is **not** in an HSM.
   - It is **not** in a cloud KMS.
   - It is **not** Vault-backed, and it is not fronted by any external secrets
     manager. If you have seen such a component mentioned in our architecture
     material in connection with **this** key, that material describes an
     intended future state, not a running system.
   - The key is **exportable by design** — it is a string, and reading it is a
     read.

   **Who can read it today.** Anyone with administrative access to the platform
   on which the application runs, and the operator of the managed infrastructure
   underneath it. Encryption at rest is whatever that managed platform provides;
   we do not operate that layer and do not independently attest to it. *(The
   internal edition names the specific store, namespace and access paths. Those
   are withheld here — not because the risk is different, but because a list of
   exact targets helps only one kind of reader. The risk statement below is the
   internal one, unchanged.)*

   **The residual risk, plainly.** A single successful read of that value lets
   the holder forge a HodeiShield posture attestation for any tenant, at any
   time, that is **cryptographically indistinguishable** from a genuine one —
   because it would be genuine, in the only sense the signature can express.
   There is no second factor, no quorum and no signing service in front of the
   key. What bounds the damage is small and worth knowing exactly: the short
   signed lifetime (15 minutes typical, 1 hour ceiling — an attacker cannot mint
   a long-lived document), the per-document nonce if *you* challenge us (§4.8),
   and withdrawal of the key from the published set, which invalidates every
   document that key ever signed (§7, and note that a signed revocation status
   list has existed since 2026-07-30 — an earlier edition of this paragraph said
   there was none, and that was already out of date when it was written).

   **Mitigations that are actually in place:** role-based access control on the
   secret store; an admission policy that blocks a forged workload from mounting
   it; a rotation procedure with a publication overlap, so rotating does not
   invalidate outstanding documents; and the fact that the seed never leaves the
   process it is loaded into — it is held in a closure, is not a property of any
   object, and cannot be reached by serialization, logging or an error report.

   **Migration target and its trigger.** Non-exportable custody — a KMS/HSM-held
   key, or an external signing service so the seed never enters the application
   process — is planned but **not built**. The conditions that trigger it are
   recorded rather than left open-ended: a second person needing operational
   access to the seed, a contractual or certification commitment to
   non-exportable key custody, or the first customer who makes it a condition of
   relying on these attestations.

   If your own risk assessment requires hardware key custody before you rely on
   a third party's signed attestation, **this control does not meet that bar
   today.** Ask us; we will tell you the same thing in writing.

---
## 7. Key rotation, revocation and what to do with an old document

The attestation key rotates on a **12-month** cadence, and immediately on
suspected compromise. The current keys are listed in [`keys.md`](keys.md).

**Planned rotation** publishes both keys during a **90-day overlap**: the key
document lists two entries, new attestations carry the new `kid`, and documents
you already hold keep verifying while the old key is still within its validity.

**A retired key stays published.** It is not removed from the set when it is
retired; it is marked as retired, so documents signed before its retirement can
still be checked. A document signed by a retired key is acceptable only if its
`generatedAt` is before the retirement time. As policy, the key set marks a
retired key with the member `hs_retired_at`, an RFC 3339 UTC time with seconds
(`YYYY-MM-DDTHH:MM:SSZ`). Verifier v1.3.0 and later reject a document whose
`generatedAt` is at or after it (exit 1, `retired_key`; the instants are
compared exactly, milliseconds included), and a status list issued at or after
the retirement of its own key is unknown (exit 3). Earlier versions ignore the
member, so with them check that a document signed by a retired key has a
`generatedAt` before the retirement time listed in [`keys.md`](keys.md). The
one-hour validity ceiling means an attestation from a retired key cannot pass at
the current time: a backdated one has already expired, and a current one is dated
after the retirement. A status list can be valid for up to 24 hours plus a 300
second allowance, so one signed by a retired status key and issued just before
the retirement can still be accepted for that long; a compromise goes through
revocation, not retirement. With `--now` set to a past instant, a backdated document
is judged as of that instant.

The key document lists the ACTIVE signing key first, then every retired key,
deduplicated by `kid`. Two consequences for you:

- **Do not take `keys[0]` and stop.** Active-first is a contract, so `keys[0]`
  is what we are signing with right now — but a document you already hold may
  legitimately name a later entry. Resolve by `kid` across the whole set.
- **Do not cache a key set indefinitely, and do re-fetch on an unknown `kid`.**
  A new key appears in the set at the start of an overlap.

**Compromise is not handled by retirement.** A compromised key is revoked
through the status list: its `kid` is listed in `keys[]`, and every document it
ever signed stops verifying at once (§7.1). Retirement would not do that, since
a retired key's earlier documents stay acceptable. The old key is withdrawn
immediately with no overlap, because during an overlap an attacker holding the
leaked seed can forge attestations that verify. That is the intended behaviour.

If a HodeiShield attestation that previously verified suddenly does not:

1. Re-fetch `/api/public/attest/keys`. The `kid` in your
   document may simply be signed by a key that is now retired.
2. **Fetch `/api/public/attest/status` and run the §7.1 procedure below**
   against the `kid` (and, if you know it, the trust-center slug). This is the
   fastest way to learn *why* — `revoked` with a reason (exit 1), versus
   `unknown` because the list was fetched but does not verify (exit 3), versus
   "could not check" because no list could be fetched at all, which includes a
   deployment that publishes none (exit 2), versus `good` (in which case the
   failure is something else entirely and you should re-check §4).
3. Check this section and the Trust Center for a dated revocation notice naming
   the retired `kid` or the withdrawn subject. A revocation is announced; a
   silent disappearance is not.
4. If the `kid` is gone with no notice and the status list (if configured) does
   not explain it either — treat it as an incident and contact us (§10). Do not
   assume it is benign, and do not fall back to trusting the document
   unverified.

**What "revocation" means here today — and what it does not.** As of
2026-07-30 there is a signed, freshness-bounded **status list**, published at
`GET /api/public/attest/status` and verified against its **own**, separate key
set at `GET /api/public/attest/status-keys` — never the attestation key set at
`/keys`. The two key sets are disjoint by construction (a holder of
the attestation seed cannot sign a status list any conforming verifier
will even look at, and vice versa). It gives you two real primitives:

- **Key revocation, unconditional.** If the `kid` that signed your document
  appears in the list's `keys[]`, the document is **revoked** — full stop,
  regardless of what its own `generatedAt` claims. The rule does not compare
  timestamps on purpose: `generatedAt` is a field inside the bytes the
  (by hypothesis compromised) key signs, so trusting it would be decoration.
- **Subject-epoch revocation, bounded.** If your document's trust-center slug
  appears in the list's `subjects[]` with a `notBefore` **later** than your
  document's `generatedAt`, the document is **revoked**. This is a narrower,
  different-purpose primitive — us withdrawing one organisation's *past*
  attestations from a chosen instant, not a key-compromise response — and it
  is the only one of the two that legitimately reads a timestamp, precisely
  because this branch presumes the key itself is not the problem.

**What is still, deliberately, absent: per-document (`jti`) revocation.** You
still cannot recall the one mis-issued attestation without revoking either the
key or the subject it belongs to. Combined with the 1-hour `MAX_TTL_SECONDS`
ceiling, an isolated mis-issued document that does not warrant either of those
simply expires — that has not changed. The arithmetic: a per-`jti` entry
would be worth, at best, the remaining minutes of a document that was going
to die within the hour anyway, against a permanent cost (a durable write on
every anonymous fetch of an attestation, an enumerable issuance corpus).

**If you never fetch the status list, nothing about your position changes.**
A verifier who only performs the checks in §4, and who pinned the key
fingerprint on first use per §6 item 2, is exactly as well off today as before
this subsystem existed — still bound by the `expiresAt` window, still without
per-document recall. The status list is **strictly additive** for a verifier
willing to spend one more fetch; it neither weakens nor is required by the
offline guarantee described in §4 and §8.

**The notice table below has columns for key retirements only.** A subject
revocation — a different event, covered above — has no row to go in as this
table is currently shaped; treat its absence from the table as a known gap in
the table's layout, not as evidence no subject revocation has occurred. Check
`/api/public/attest/status` directly (via §7.1) for the authoritative,
machine-verifiable answer on either dimension.

### 7.1 Checking key or subject revocation yourself

This uses the `--status-list` mode of `scripts/attest/verify-attestation.sh` —
the same script §4 uses for posture verification, extended rather than
duplicated. Verified against the script as committed
(`app/src/lib/attest/status-list.ts` is the wire format it implements; if the
flags below ever diverge from `scripts/attest/verify-attestation.sh --help`,
trust the script).

**Standalone — you already have a `kid` or a slug from elsewhere:**

```bash
curl -fsS https://app.hodeishield.com/api/public/attest/status       -o status.json
curl -fsS https://app.hodeishield.com/api/public/attest/status-keys  -o status-jwks.json

scripts/attest/verify-attestation.sh --status-list \
  --status status.json --status-keys status-jwks.json \
  --check-kid "<the kid you are checking>"
```

(You can also pass `--status` / `--status-keys` as `http(s)://` URLs directly —
the script fetches them itself with `curl` — and add `--check-subject <slug>`
with `--check-generated-at <RFC3339>` to test the subject dimension too.)

**Combined — verify a document AND its revocation status in one run**, which is
the §7 step-2 workflow above and the recommended default when you hold the
attestation. `att.json` is the same file §4.1 fetches — from wherever you were
handed the document, or freshly from a live Trust Center:

```bash
NONCE="$(openssl rand -base64 24 | tr '+/' '-_' | tr -d '=')"
curl -fsS "https://app.hodeishield.com/api/public/attest/<slug>?nonce=${NONCE}" -o att.json

scripts/attest/verify-attestation.sh --status-list \
  --status status.json --status-keys status-jwks.json \
  --attestation att.json --jwks jwks.json \
  --expect-slug <slug> --expect-issuer https://app.hodeishield.com \
  --expect-nonce "$NONCE"
```

Real output from a run on 2026-09-29 against the production deployment, for
`talmaren-payments` (a demonstration organisation with fictitious data), with the
list at `seq` 1564 carrying no revoked key and no revoked subject. Only the last
section and the verdict are shown, exit 0; nothing is added:

```
[9] Revocation check
        subjectHash(talmaren-payments) = BrIFESLm9sK1SU_zjryKixn9vo58vbMKhKI4S_3nlKE

GOOD — kid roeFReafBOA_WF3cqfilHA is not revoked, subject talmaren-payments carries no earlier withdrawal (list seq 1564).

GOOD — not revoked, per a verified status list.

That is all it proves. It does not prove the claims inside are true, that the key
belongs to who you think, or that nothing else about the document is wrong. Read
docs/security/attest-verification.md §6 and §7 before relying on it.
```

and with the signing key itself on the list, the last lines have this form (the
reason is whichever the list carries: `key_compromise`, `superseded`,
`issuer_error`, `subject_withdrawn` or `unspecified`), with exit 1:

```
REVOKED — via key, reason "<reason>". Do not rely on this document.
```

Given both `--attestation` (or `--jws`/`--claims`) and `--status-list`, the
script runs the full §4 posture check first and then applies the status list to
the resulting `kid`, slug and `generatedAt` — you do not supply
`--check-kid`/`--check-subject` yourself in this mode; they are read from the
verified document. If the posture check fails, the run ends as a failure
(exit 1) whatever the list says: an inauthentic document is not rescued by not
being listed. Note `--jwks` and `--status-keys` are **different key sets** and the
script never resolves one against the other; passing the attestation JWKS as
`--status-keys` yields `unknown` (exit 3), not `good`.

**What "revoked" means exactly.** The two rules of §7 are applied in this order,
and the first that fires decides:

- **Key rule.** `kid` (the header kid of the document, or `--check-kid`) is
  listed in `keys[]` → revoked, with no timestamp compared.
- **Subject rule.** The slug (from the document, or `--check-subject`) is listed
  in `subjects[]` — matched by the hash `SHA-256("hodei-shield.attest.subject.v1"
  || slug)`, base64url — and the document's `generatedAt` is **strictly earlier**
  than the entry's `notBefore` → revoked. A `generatedAt` equal to or later than
  `notBefore` is not revoked by this rule: the entry withdraws attestations
  issued *before* that instant. If the subject is listed but no `generatedAt` is
  available, or `generatedAt` or `notBefore` cannot be parsed, the outcome is
  `unknown`, never `good`.
- If the list is marked `truncated` (entries were dropped to fit a cap) and the
  subject is not found, the outcome is `unknown` on the subject dimension:
  "not found" does not mean "not listed".

**Exit codes are distinct on purpose** — a caller scripting against this must
not be able to collapse "revoked", "we could not check" and "we could not tell"
into one outcome by checking `$? -ne 0`:

| Exit | Meaning |
| --- | --- |
| `0` | `good` — if a document was given, its posture checks passed (§4) **and** the list verifies and neither rule fired; if only `--check-kid` / `--check-subject` were given, the list verifies and neither rule fired |
| `1` | `revoked` — the key rule or the subject rule fired, **or** the posture check of the document you gave failed |
| `2` | **could not check** — usage or environment problem (bad flags, missing `curl`/`openssl`/`python3`/`jq`, an unreadable file), **or a `--status` / `--status-keys` source that could not be fetched** (the script stops with `error: failed to fetch …`). Says nothing about the subject. |
| `3` | `unknown` — the list was obtained but does not verify: bad signature, stale past `nextUpdate` (300 s skew allowance), rolled back (`--min-seq`), self-revoking, an unresolved or mislabelled `kid`, a malformed document; **or** the subject rule could not be decided (see above). The list's `iss` is compared to `--expect-issuer` **only if you pass it**; without it, a list from another issuer is not caught. **Not** evidence of anything either way — see the "if you never fetch" paragraph above. |

**Unknown is not good.** An `unknown` outcome (exit 3) means a status list was
obtained but could not be verified, or the subject rule could not be decided
from the list it has, so the verifier has **not** established that the key or
the subject is fine. (A list that could not be fetched at all is a different
case, exit 2: "could not check".) Treat `unknown` exactly as you would an
unreachable revocation authority: do not read it as "not revoked" and do not
carry on as if the check had passed. It is a distinct outcome, not a synonym for
`good` (exit 0) or for `revoked` (exit 1), which is why a script must not
collapse it into either by testing `$? -eq 0` or `$? -ne 0`. Re-fetch the status
list and the key set and run the check again; if it persists, follow the steps
in §7.

A `404 status_list_unavailable` from `/api/public/attest/status` means this
deployment publishes no list at all (unconfigured, or the publisher has never
run) — the honest, cacheable non-answer, distinct from an empty *signed* list
asserting "nothing is revoked". The script's `--status` fetch surfaces the 404
as "could not check" (exit 2: the fetch fails before any list exists to be
`unknown`); at that point you are simply back in the offline mode this document
has always described.

**Revocation notices** (none to date):

| Date | Retired `kid` | Trusted from → until | Reason                   |
| ---- | ------------- | -------------------- | ------------------------ |
| —    | —             | —                    | No key has been revoked. |

---

## 8. Why Cloudflare is not in this picture

Signing a document requires no Cloudflare involvement whatsoever. This is an
architectural requirement, not an accident, and it is worth being explicit about
because the two were previously entangled.

The post-quantum _transport_ story is blocked on someone else. Cloudflare cannot
currently deliver an ML-DSA client certificate on origin-pull for this zone —
origin-pull breaks — so production mTLS runs on a classical ECDSA P-256
certificate. Our origin verifies ML-DSA client certificates correctly; the constraint is at the
edge, and we do not control when it lifts.

Had attestation been built on that path, the entire post-quantum claim would
have inherited a third-party roadblock. It is not. The attestation signer:

- holds its own key pair, unrelated to any CA, any certificate and any chain;
- signs bytes in the application process, with no TLS involvement of any kind;
- is verified by you from a public key and an OpenSSL command, with no reference
  to how the document reached you.

Consequences you can check:

- You can verify an attestation **fully offline**, on a machine that has never
  spoken to Cloudflare or to us.
- The attestation is post-quantum **today**, while the transport is not.
- Rotating the attestation key needs no Cloudflare change, no certificate
  reissue and no edge coordination.
- If Cloudflare disappeared tomorrow, attestation verification would be
  unaffected.

The one residual dependency is _distribution_: you fetch the public key over
HTTPS from a Cloudflare-fronted hostname. That is a delivery-path dependency, not
a cryptographic one — which is exactly why §6 tells you to pin the key
fingerprint rather than re-trust the fetch each time.

---

## 9. Cryptographic choices, stated plainly

| Decision            | Choice                                           | Rationale                                                                                                                                          |
| ------------------- | ------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| Algorithm           | ML-DSA-65 (FIPS 204), NIST category 3            | Standardised, IANA-registered for JWS by RFC 9964, and the same primitive the Rust endpoint agent uses.                                            |
| JWS `alg`           | `"ML-DSA-65"`                                    | Permanent IANA identifier from RFC 9964, a published Proposed Standard. No provisional namespace.                                                  |
| JWK type            | `"AKP"`, `pub` = base64url(1952-byte key)        | RFC 9964. COSE equivalent is algorithm `-49`.                                                                                                      |
| Context string      | Always empty                                     | Mandated by RFC 9964; also the only thing the Rust `Signer` supports. A non-empty context would produce signatures our own agent could not verify. |
| Private key at rest | 32-byte KeyGen seed                              | Mirrors the Rust side; the 4032-byte expanded key is never the storage or wire form.                                                               |
| TS library          | `@noble/post-quantum`, pinned to exactly `0.7.1` | Pure TypeScript — no native addon, no WASM, no C or assembly in the trust path. Mirrors the agent's RustCrypto choice so there is one bridge.      |
| Rust library        | RustCrypto `ml-dsa` (pre-1.0)                    | Pure Rust, no `unsafe` FFI. `fips204` and `pqcrypto-*` were rejected as stale and as C/asm respectively.                                           |

### Known weakness, stated because you would find it anyway

**`@noble/post-quantum` is self-audited only.** The external Cure53 audit
of the noble family covers the ciphers and curves packages, **not** the
post-quantum module. RustCrypto `ml-dsa` is likewise pre-1.0 and unaudited. Both sides of our bridge therefore rest on pre-1.0, externally
unaudited implementations of a recently standardised algorithm.

We accept this deliberately: the alternative was a C or WASM binding, which
trades audit maturity for a much larger and less inspectable trust surface, or
running two different implementations, which doubles the risk instead of halving
it. The Rust agent documents the identical exception in its own security posture
document. It is a real risk, it is mirrored on both sides on purpose, and it is
written down rather than buried.

To be concrete about what that means for you: if a flaw were found in noble's
ML-DSA implementation, the realistic exposure is signature _forgeability_ or key
extraction through a side channel — not silent acceptance of bad documents on
your side, since you verify with OpenSSL, an entirely different implementation.
Verifying with OpenSSL rather than with our library is a meaningful part of why
this document tells you to do it that way.

---

## 10. Reporting a problem

If any check in this document fails — a fingerprint mismatch, a signature that
will not verify, a `kid` that vanished without a revocation notice, or a
discrepancy between what a document claims and what you can independently
establish:

**security@hodeitek.com**

Include the artefact, the exact command you ran, and its full output. A
verification failure you can reproduce is a security report and we will treat it
as one.

---

### Related documents

- [`scripts/attest/verify-attestation.sh`](../../scripts/attest/verify-attestation.sh)
  — §4 and §7, automated. **In this repository**, byte for byte the copy we
  keep in our private repository, where CI checks the two never diverge. The
  service itself verifies with its own TypeScript implementation, not with this
  script.

Referenced above but **not public**: the operator-side key-handling and rotation
runbook, the transport mTLS notes, the revocation design specification, the
key-generation script, and the issuer source under `app/src/lib/attest/`. They
live in Hodeitek's private repository. Where the text or the verifier points at
one of them, that pointer is provenance — it tells you where a rule came from —
and not a step you are expected to follow.

---

## What this edition leaves out

So that you can judge the redaction rather than take it on faith, here is the
complete list of what differs from the internal edition:

| # | Removed or changed | Why |
|---|---|---|
| 1 | **§3 in full** — verifying the post-quantum root CA | Depends on certificate files in the private repository. Unrunnable here, and it bears on no attestation claim (§1). |
| 2 | **§6 item 8** — the names of the secret store, namespace, environment variable, the enumerated access paths, and the file paths of the compensating controls | An exact target list. The risk statement, the "who can read it", the residual-risk paragraph and the "does not meet that bar today" conclusion are all kept. |
| 3 | **§1 table cell** — where the private half lives | Same reason as #2. |
| 4 | **Links to internal operator documents** (`k8s/**`, `docs/operations/**`, `docs/architecture/specs/**`) | Dead links for you; infrastructure layout for someone else. Named in prose above as provenance instead. |
| 5 | **Corrected, not removed:** the library pin (`0.6.1` / `0.7.0` → `0.7.1`), the claim that no Python is needed, and a stale "no revocation status list" clause | These were wrong or out of date in the internal edition. They are fixed here and the fixes are flagged in place. |

Nothing in the "does not prove" list was removed, shortened or reworded to read
better. If you find a claim in this edition that the internal edition states
more harshly, that is a defect — report it under §10.

