# Machine-readable output: `--json`

`--json` makes the verifier print **one JSON object on stdout and nothing
else**. The human text (the `PASS`, `WARN` and `FAIL` lines, the banners and
the verdict) is not printed, on stdout or on stderr. The exit code is the same
as without the option: 0 verified (good), 1 a check failed (revoked), 2 could
not check, 3 unknown (`--status-list` only).

```bash
bash scripts/attest/verify-attestation.sh --json \
  --attestation att.json --jwks jwks.json --expect-slug acme --expect-issuer https://issuer.example
echo "exit: $?"
```

Rules that hold for every run:

- `--json` is found before the arguments are read, wherever it appears, so an
  argument error is reported as JSON too.
- Every string goes through JSON encoding with `ensure_ascii`: the output is
  printable ASCII on one line, so a control character or an escape sequence in
  a document can never reach a terminal raw.
- `--help` and `--version` are the exception: with `--json` they print their
  usual text and exit 0.
- Read the exit code, or `exit_code` (always the same number), to decide.
  Everything else in the object explains it.
- Without `python3` (itself a reason for exit 2) a smaller object is written:
  the same top-level members, with `attested` null, `unverified` empty and
  `anchor` null, and a byte outside printable ASCII in `message` shown as
  `\u00XX`.

## The object

Schema name: `hodeishield.verifier.result.v1`.

| Member | Type | Meaning |
|---|---|---|
| `schema` | string | Always `hodeishield.verifier.result.v1`. |
| `verifier.version` | string | The version of the script that produced the object, as `--version` prints it. |
| `mode` | string | `attestation` (the default) or `status-list` (`--status-list`). |
| `exit_code` | integer | The exit code of the process: 0, 1, 2 or 3. |
| `verdict` | string | One of `verified`, `expired`, `failed`, `could_not_check` (attestation mode, and either mode for exit 2); `good`, `revoked`, `unknown` (`--status-list`); see below. |
| `reason` | string or null | The [reason code](reason-codes.md) that decided the exit code; see below. |
| `checks` | array | Every check that ran, in order; see below. |
| `attested` | object or null | What the signature covers, **only when `exit_code` is 0**; see below. |
| `unverified` | object | Values read from the document, **not established** unless `exit_code` is 0; see below. |
| `anchor` | object or null | The result of `--anchor-file`; null without it. |
| `message` | string | Present for an argument error and for a run that stopped with exit 2: the error text. Diagnostic only; its wording is not part of the interface. |

### `verdict` and `reason`

| `verdict` | `exit_code` | The text-mode verdict |
|---|---|---|
| `verified` | 0 | `VERIFIED` |
| `good` | 0 | `GOOD` (`--status-list`) |
| `expired` | 1 | `EXPIRED`: the signature is valid and the only failures are age or expiry |
| `failed` | 1 | `VERIFICATION FAILED` |
| `revoked` | 1 | `REVOKED` (`--status-list`) |
| `could_not_check` | 2 | An environment or usage problem, or an anchor that could not be checked |
| `unknown` | 3 | `UNKNOWN` (`--status-list`) |

`reason` is one of the codes in [reason-codes.md](reason-codes.md), plus `usage`
for an argument error. It is chosen like this:

- exit 0: `verified` or `good`;
- an argument error, before any check ran: `usage`;
- `revoked`: the `revoked_key` or `revoked_subject` check;
- `expired`: `expired` when the expiry check failed, otherwise the first failed
  check (`too_old`);
- otherwise the first failed check whose `exit_class` equals `exit_code`, not
  counting `too_old` and `expired` for `failed` (they decide only `expired`).

When a document breaks several rules `reason` is one of them and `checks` has
all of them. `reason` can be `null` only if the process ended in a way the
script did not plan (an interruption, for example).

### `checks`

```json
{"code": "signature_valid", "result": "pass", "exit_class": 0}
```

- `code`: a reason code.
- `result`: `pass`, `warn` or `fail`.
- `exit_class`: the exit code that check leads to: 0 for a pass or a warning,
  1 for a failed check, 2 for a problem that stops the run, 3 for a failed check
  of the status list, and 3 for a warning that leaves the status unknown.

The list is complete, including checks made in subshells. Two different checks
that share a code are two entries; a warning printed over several lines is one.
The place in the script that made a check is not part of the output.

### `attested`

`null` unless `exit_code` is 0, with or without `--raw`: the same rule as the
text mode, which prints the "Attested content" block only for a document that
verified (and, in `--status-list` mode, was `GOOD`). It is also null for a
`--status-list` run that checked a kid or a subject without a document.

When present:

| Member | Meaning |
|---|---|
| `overallBand` | The weakest attested band, or null. |
| `slug` | The subject (organisation) slug. |
| `visibility` | `public` or `gated`. |
| `generatedAt` | When the posture was generated. |
| `lastCheckedAt` | Freshness of the underlying data, or null. |
| `frameworks` | `[{"label", "code", "band"}, ...]`, in the document's order. |
| `posture` | Only with `--raw`: the full signed posture as a JSON object. |

### `unverified`

Values the verifier read from the document, for diagnosis: `docVersion`, `iss`,
`kid`, `jti`, `nonce`, `generatedAt`, `expiresAt` and `slug`. A member is
present when the text mode would have read it by then (so it is empty `{}`
for an argument error, and may lack `docVersion` and the others when the run
stopped early); it is null when the document does not carry it. Each is the
string the document carries, exactly (a trailing newline included), and the one
the checks compared, except that a NUL byte, which fails the run (`nul_byte`), is
shown as the four characters `\x00`.

**These values are not established by the verifier unless `exit_code` is 0.**
On any other exit they come from a document that may have been altered, or from
one that was never shown to be genuine. They are named `unverified` so that
nobody reads them as attested content. Use them to see why a run failed, never
to decide anything about the organisation. Even at exit 0 they are claims of
the issuer, which a verified signature proves were not altered; it does not
prove that they are true.

### `anchor`

Present (not null) when `--anchor-file` is used:

| Member | Meaning |
|---|---|
| `verified` | True when the key statement was verified with cosign and every check about it held: the key (and, in `--status-list` mode, the status-list key) is listed under the right role, with a matching retirement, and `iss` is the issuer the statement names. Each of those checks must have RUN: a run that stopped after the statement verified and before one of them (an unknown kid, a document that cannot be canonicalised, a status list that failed first) has `verified` false. |
| `release_tag` | The release the statement was signed for (read from the certificate, once cosign has verified it under that exact identity), for example `v1.4.0`; null if the statement was not verified far enough to read it. |
| `kids` | The keys asked about: `[{"kid", "role", "listed"}, ...]` with `role` `attestation` or `status-list`. `listed` is true when the statement lists that kid under that role. Empty when the statement could not be checked. |

## Stability

The schema is `v1`. Within `v1`:

- members are only ever **added**, never renamed, removed or given another
  meaning; a consumer must ignore members it does not know;
- new reason codes may appear in `checks` and `reason`; they are only added,
  as the reason codes are;
- a change that breaks either rule is a new schema name
  (`hodeishield.verifier.result.v2`), announced as the other format changes
  are.

The wording of `message` and the order of the members of an object are not
part of the interface.

## Examples

A verified document (`checks` shortened):

```json
{
  "schema": "hodeishield.verifier.result.v1",
  "verifier": {"version": "1.4.0"},
  "mode": "attestation",
  "exit_code": 0,
  "verdict": "verified",
  "reason": "verified",
  "checks": [
    {"code": "openssl_mldsa65_available", "result": "pass", "exit_class": 0},
    {"code": "signature_valid", "result": "pass", "exit_class": 0},
    {"code": "fresh", "result": "pass", "exit_class": 0},
    {"code": "verified", "result": "pass", "exit_class": 0}
  ],
  "attested": {
    "overallBand": "basic",
    "slug": "fixture-org",
    "visibility": "public",
    "generatedAt": "2026-01-01T00:00:00.000Z",
    "lastCheckedAt": "2026-01-01T00:00:00.000Z",
    "frameworks": [
      {"label": "ISO27001", "code": "iso27001", "band": "substantial"},
      {"label": "NIS2", "code": "nis2", "band": "basic"}
    ]
  },
  "unverified": {
    "docVersion": "attest.attestation.v1",
    "iss": "https://issuer.test",
    "kid": "U4ak4BB34tmbAwevvbToHw",
    "jti": "466c9169-c288-4fd8-89c4-830987e3795f",
    "nonce": null,
    "generatedAt": "2026-01-01T00:00:00.000Z",
    "expiresAt": "2026-01-01T00:15:00.000Z",
    "slug": "fixture-org"
  },
  "anchor": null
}
```

A document altered after signing (`checks` shortened; `attested` is null, even
with `--raw`):

```json
{
  "schema": "hodeishield.verifier.result.v1",
  "verifier": {"version": "1.4.0"},
  "mode": "attestation",
  "exit_code": 1,
  "verdict": "failed",
  "reason": "signature_invalid",
  "checks": [
    {"code": "openssl_mldsa65_available", "result": "pass", "exit_class": 0},
    {"code": "signature_invalid", "result": "fail", "exit_class": 1},
    {"code": "fresh", "result": "pass", "exit_class": 0},
    {"code": "overall_band_mismatch", "result": "fail", "exit_class": 1}
  ],
  "attested": null,
  "unverified": {
    "docVersion": "attest.attestation.v1",
    "iss": "https://issuer.test",
    "kid": "U4ak4BB34tmbAwevvbToHw",
    "jti": "466c9169-c288-4fd8-89c4-830987e3795f",
    "nonce": null,
    "generatedAt": "2026-01-01T00:00:00.000Z",
    "expiresAt": "2026-01-01T00:15:00.000Z",
    "slug": "fixture-org"
  },
  "anchor": null
}
```

An argument error:

```json
{
  "schema": "hodeishield.verifier.result.v1",
  "verifier": {"version": "1.4.0"},
  "mode": "attestation",
  "exit_code": 2,
  "verdict": "could_not_check",
  "reason": "usage",
  "checks": [],
  "attested": null,
  "unverified": {},
  "anchor": null,
  "message": "unknown argument: --bogus"
}
```

## Tests

`tests/run.sh` has a section for `--json`, and `bash tests/vectors.sh --json`
runs every published vector with `--json` and asserts that stdout is exactly
one JSON object, nothing is on stderr, `schema` and `exit_code` are right,
`reason` is the vector's `expect.code` (for a document that breaks several rules,
a code among its failed checks), and `attested` is null unless the exit code
is 0.
