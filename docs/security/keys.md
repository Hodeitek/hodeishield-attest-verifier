# Current signing keys

This is the versioned list of the keys that sign HodeiShield attestations and
status lists. It is a second channel to compare against, not a root of trust:
see [How this file changes](#how-this-file-changes).

The same list is kept in machine-readable form in [keys.json](keys.json), and
each release from v1.4.0 publishes it as `keys-statement.json`, signed with
Sigstore. See [the key anchor decision](key-anchor.md).

A key is named by its `kid`, `BASE64URL(SHA-256("hodei-shield.attest.kid.v1" ||
raw ML-DSA-65 public key)[0..16])`, see
[§4.2 of the verification document](attest-verification.md#42-the-kid-is-checked-not-trusted).
The values below were measured on 2026-10-07 by recomputing each `kid` from the
`pub` bytes of the live key sets.

| kid                      | Role        | Status  | Published at                                                | Active since         | Retired              | Next rotation due |
| ------------------------ | ----------- | ------- | ----------------------------------------------------------- | -------------------- | -------------------- | ----------------- |
| `roeFReafBOA_WF3cqfilHA` | attestation | active  | `https://app.hodeishield.com/api/public/attest/keys`        | 2026-07-31 (~18:53 UTC) | -                 | about 2027-07-31  |
| `1_9j4Qa0yh0DaIWNdo5shw` | attestation | retired | `https://app.hodeishield.com/api/public/attest/keys`        | before 2026-07-31    | `2026-07-31T18:53:58Z` | -               |
| `ybyUZ2JKT6PFvTREXyU9_A` | status list | active  | `https://app.hodeishield.com/api/public/attest/status-keys` | 2026-07-31           | -                    | about 2027-07-31  |

The two key sets are separate and disjoint (§7 of the verification document).
`--expect-kid` applies to the attestation key only.

## Check it yourself

Download the key set and compute the kids from the key bytes. This is the same
command as in the README, "Pinning the key":

```bash
curl -fsS https://app.hodeishield.com/api/public/attest/keys -o jwks.json
python3 -I -c 'import sys,json,base64,hashlib;[print(base64.urlsafe_b64encode(hashlib.sha256(b"hodei-shield.attest.kid.v1"+base64.urlsafe_b64decode(k["pub"]+"="*(-len(k["pub"])%4))).digest()[:16]).decode().rstrip("=")) for k in json.load(open(sys.argv[1]))["keys"]]' jwks.json
```

Run against the attestation key set, it prints `roeFReafBOA_WF3cqfilHA` and
`1_9j4Qa0yh0DaIWNdo5shw`. Run against the status-list key set it prints
`ybyUZ2JKT6PFvTREXyU9_A`.

To have the verifier compare the signing key for you:

```bash
bash scripts/attest/verify-attestation.sh --attestation att.json --jwks jwks.json \
  --expect-slug <slug> --expect-issuer https://app.hodeishield.com \
  --expect-kid roeFReafBOA_WF3cqfilHA
```

During an overlap, when two attestation keys are active, repeat `--expect-kid`
once per key.

## Rotation policy

Both roles follow the same policy:

- A new key every 12 months.
- A 90-day overlap, during which the old and the new key are both published.
- A retired key stays in the published set, marked as retired, rather than being
  removed, so that documents signed before its retirement can still be checked.
- A compromised key is not handled by retirement. Its `kid` is listed in the
  status list's `keys[]`, which revokes everything it signed unconditionally
  (§7 and §7.1 of the verification document).

A document signed by a retired key is acceptable only if its `generatedAt` is
before the retirement time. For an attestation, no such document passes at the
current time: the verifier enforces a validity ceiling of one hour (`expiresAt`
minus `generatedAt`), so a document backdated to before the retirement has
already expired, and a current one is dated after it. A status list is
different: its validity (`nextUpdate` minus `issuedAt`) can be up to 24 hours,
plus a 300 second clock allowance, so a list signed by a retired status key and
issued just before the retirement can still be accepted for that long after it.
Retirement is not a response to compromise: a compromised key goes through
revocation (above), not retirement. With `--now` set to a past instant a
backdated document is judged as of that instant.

As policy, the key set marks a retired key with the member `hs_retired_at`, an
RFC 3339 UTC time with seconds (`YYYY-MM-DDTHH:MM:SSZ`). Verifier v1.3.0 and later reject a
document whose `generatedAt` is at or after it (exit 1, `retired_key`), and a
status list issued at or after the retirement of its key is unknown (exit 3).
A `hs_retired_at` in any other form makes the key set invalid (exit 2 for the
attestation key set, unknown for the status-list key set), and so does a key set
whose `keys` is not an array of objects or that lists the same `kid` twice. Earlier versions
ignore the member, so with them check yourself that a document signed by a
retired key has a `generatedAt` before the retirement time in the table above.

## How this file changes

This file changes only through a signed commit in a pull request, in the same
window as the key change. A rotation changes this file and [keys.json](keys.json)
in the same signed commit; CI fails if they differ, and a daily check fails if
the live key sets contain a key that keys.json does not list. Each change is listed in [CHANGELOG.md](../../CHANGELOG.md)
and in the release notes. The repository's signed tags and Sigstore-signed
releases (see [Verifying a release](../../README.md#verifying-a-release)) reach
you by a channel independent of the issuer's web host.

This does not make the file a root of trust. It lets you compare what the web
host serves with what a signed commit of this repository says. If the two
differ, treat it as an incident (§7 of the verification document).
