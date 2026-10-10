<!--
SPDX-License-Identifier: Apache-2.0
Copyright 2026 Hodeitek S.L.
-->

# mldsa-vectors

A small Rust program that runs the ML-DSA-65 verify primitive of
[`aws-lc-rs`](https://crates.io/crates/aws-lc-rs) over the published test
vectors in `tests/vectors/v1` and checks that it reaches the same **signature
verdict** as the reference script `scripts/attest/verify-attestation.sh`. It
meets the last open criterion of
[issue #30](https://github.com/Hodeitek/hodeishield-attest-verifier/issues/30):
"any candidate must verify the same vectors as the bash script". The written
evaluation is [docs/security/rust-mldsa-evaluation.md](../../docs/security/rust-mldsa-evaluation.md).

## What it does not claim

- It checks the primitive's signature verdict, **not the whole verifier**. Every
  other check (freshness, slug, issuer, nonce, revocation, kid derivation,
  closed header set, duplicate members, the anchor) is not run here.
- It is **not the Rust port** (issue #29). It is a test harness; nothing in this
  directory is meant to be shipped or reused as a verifier.
- It does not re-implement the canonical encoders. The bytes a signature covers
  are produced by the reference script's own embedded Python encoders
  (`CANON_PY`, `CANON_STATUS_PY`): the program reads them out of the script
  text and runs them with `python3`, as the script does. A port still has to
  write and test its own encoders. Where the manifest has `canonical_sha256`
  (`status_canonical_sha256`), the program checks the bytes it got against it.
- A pass says nothing about the FIPS status or the audit status of `aws-lc-rs`;
  see the evaluation document.

## Run it

Needs a Rust toolchain, a C compiler (AWS-LC is built from source by
`aws-lc-sys`) and `python3`, from the repository root:

```sh
cargo build --locked --release --manifest-path tools/mldsa-vectors/Cargo.toml
tools/mldsa-vectors/target/release/mldsa-vectors tests/vectors/v1 scripts/attest/verify-attestation.sh
```

It prints one line per case (`ok`, `SKIP` with the reason, `FAIL`) and a count.
The exit code is 0 only if no case disagrees and at least `MIN_CHECKED` (a
constant in `src/main.rs`) cases were checked. A run that checks fewer fails, so
cases that silently turn into skips cannot hide a regression. Raise the floor
when vectors are added; never lower it.

The workflow `.github/workflows/mldsa-vectors.yml` runs it in the official Rust
image (pinned by version and digest) on changes to this directory, to
`tests/vectors/**` or to the workflow, and by hand.

## How a case is mapped to a verdict

The expected verdict comes from the manifest (`vectors.json`) and nothing else:

| The manifest says | The primitive must |
|---|---|
| `expect.exit` is `0` (`verified`, `good`) | accept the attestation signature, and for a status-list case also the status-list signature |
| `expect.code` is `signature_invalid` or `signature_size_invalid` | reject the attestation signature |
| `expect.code` is `status_unknown_bad_signature` or `status_unknown_signature_size` | reject the status-list signature |
| any other `expect.code`, but `expect.match` says "the signature is valid" (for example `EXPIRED`) | accept the attestation signature |
| anything else | nothing is asserted: the case is SKIPPED, with the code as the reason |

Cases with `--anchor-file` are skipped (cosign decides them). The other skipped
cases fail for a reason that is not the signature (kid, alg, header members,
duplicate members, key-set defects, freshness without a stated signature
verdict, revocation) so the manifest does not tell what the signature check says
about them. The size cases are rejected by the reference before it calls
OpenSSL; here they show that the primitive also refuses a signature of 3308 or
3310 bytes.

Signing input, as the script builds it (RFC 7515): `ASCII(BASE64URL(protected) ||
'.' || BASE64URL(payload))`, the protected segment exactly as received. For a
detached JWS the payload is the canonical envelope (or status-list) bytes
re-derived from the claims; for an attached JWS it is the segment itself. The
key is the entry of the case's key set (`--jwks`, or `--status-keys` for a
status list) whose `kid` equals the header `kid`; its `pub` member (base64url) is
the raw FIPS 204 public key. The ML-DSA context string is empty.

Result on 2026-10-11 (aws-lc-rs 1.18.1, aws-lc-sys 0.45.0): 118 cases, 47
checked and agreed (50 signature verdicts: 3 status-list cases also check the
attestation signature), 0 disagreed, 71 skipped (3 anchor, 68 with no
signature verdict in the manifest).

## Dependencies

Only stable (>= 1.0) crates are direct dependencies, pinned exactly in
`Cargo.toml`; `Cargo.lock` is committed and CI builds with `--locked`:

- `aws-lc-rs` 1.18.1, `default-features = false`, feature `aws-lc-sys` only (no
  `ring-io`, no `ring-sig-verify`, no `alloc`). ML-DSA-65 verification is
  `aws_lc_rs::signature::ML_DSA_65` with `UnparsedPublicKey`, in the stable
  module since 1.18.0. Its C backend `aws-lc-sys` is pre-1.0; the evaluation
  document records this.
- `serde_json` 1.0.151, `default-features = false`, feature `std`.
- `data-encoding` 2.11.1, `default-features = false`, feature `std` (strict
  base64url without padding; trailing bits are checked).

Every version in `Cargo.lock` was published on crates.io on or before
2026-10-04, at least seven days before the tool was written. When you update the lock, check
`created_at` of each version in the crates.io API
(`https://crates.io/api/v1/crates/<name>/<version>`). The rest of the lock is
the build-time chain of `aws-lc-sys` (`cc`, `cmake`, `pkg-config`, `dunce`,
`fs_extra`, ...) and the dependencies of `serde_json`; several are pre-1.0 and
none is used at run time to decide a verdict.
