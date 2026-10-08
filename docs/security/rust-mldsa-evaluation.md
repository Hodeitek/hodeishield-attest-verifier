# Rust ML-DSA-65 implementations for a port of the verifier

Checked on 2026-10-08. Every fact below was read from the primary source linked
next to it (crates.io API, docs.rs, the project's repository, the NIST CMVP
list as the vendor links it) on that date. Where a source did not say, this
page says "not confirmed" and does not infer. Tracks
[issue #30](https://github.com/Hodeitek/hodeishield-attest-verifier/issues/30).

## Summary

- The verifier checks ML-DSA-65 (FIPS 204) signatures with OpenSSL >= 3.5. A
  Rust port needs a Rust library that does the same.
- Policy: only stable (>= 1.0) dependencies in the trust path. Of the Rust
  libraries found, one is >= 1.0 and has ML-DSA-65 verification in its stable
  API: `aws-lc-rs` (stable since 1.18.0, 2026-08-07). It wraps C and assembly
  (AWS-LC), and it depends on `aws-lc-sys`, which is itself pre-1.0.
- The pure-Rust libraries (`ml-dsa`, `fips204`, `libcrux-ml-dsa`) are all
  pre-1.0. `ml-dsa` states it has never been independently audited.
- No external audit report of any candidate's ML-DSA code was found.
- No FIPS 140-3 certificate was confirmed to cover ML-DSA. The AWS-LC module
  version that includes ML-DSA is listed as "in process", not validated.
- Recommendation: no-go today; conditional go for a native binary on
  `aws-lc-rs`; no-go for WebAssembly. See "Recommendation".

## Table

| Crate | Latest (crates.io) | >= 1.0 | ML-DSA-65 verify in stable API | Audit / certification | Underlying code | wasm32-unknown-unknown | Maintenance |
|---|---|---|---|---|---|---|---|
| `ml-dsa` (RustCrypto) | 0.1.1, 2026-06-05 | no | yes (`VerifyingKey` + `Verifier`, no feature gate) | none; README: "never been independently audited" | pure Rust | built in CI; support not claimed | release 2026-06-05, commits to 2026-07 |
| `aws-lc-rs` | 1.18.1, 2026-09-01 | yes | yes, stable since 1.18.0 | no audit found; FIPS 140-3 for ML-DSA not confirmed (v4.0 module in process) | C and asm (AWS-LC) via `aws-lc-sys` 0.45 (pre-1.0) | not stated (`wasm32-unknown-emscripten` only) | release 2026-09-01 |
| `fips204` | 0.4.6, 2024-12-22 (repo is at 0.5.0, unpublished) | no | yes (`Verifier`) | none found | pure, safe Rust | browser demo in repo; support statement not found | repo commits 2026-10-06, no release since 2024-12 |
| `libcrux-ml-dsa` | 0.0.11, 2026-10-07 | no | yes (`ml_dsa_65` verify) | formal verification (hax/F*) of field, NTT, serialisation; no audit report found | Rust, portable plus AVX2 | not stated | release 2026-10-07, repo pushed 2026-10-08 |
| `pqcrypto-mldsa` | 0.1.2, 2025-08-05 | no | not checked (excluded) | none found | C (PQClean) | not stated | repository archived, "unmaintained" |
| `pqcrypto-dilithium` | 0.5.0, 2023-10-16 | no | not checked; 2023 release predates FIPS 204 | none found | C (PQClean) | not stated | archived with the rest |
| `oqs` (liboqs-rust) | 0.11.0, 2025-05-01 | no | yes (ML-DSA algorithms; README example uses `MlDsa44`) | none; liboqs README does not recommend production use | C (liboqs, mldsa-native) | not stated | repo commits 2026-09-28, last release 2025-05 |

## Per candidate

**`ml-dsa` (RustCrypto).** Pure Rust, `edition = "2024"`, MSRV 1.85. Verification
is `VerifyingKey<MlDsa65>` with the `Verifier` trait, in the crate root, with no
unstable module or feature. The README warns the code "has never been
independently audited". The changelog shows 0.1.0 on 2026-05-17 after a run of
release candidates, and recent fixes for constant-time issues and Wycheproof
failures (0.1.0 notes; commits of 2026-06 and 2026-07). The project's CI builds
the crate for `wasm32-unknown-unknown` (`.github/workflows/ml-dsa.yml`); that
is a build check, not a support statement. Pre-1.0, so it fails the policy.
Sources: [crates.io](https://crates.io/api/v1/crates/ml-dsa),
[docs.rs](https://docs.rs/ml-dsa/0.1.1/ml_dsa/),
[README](https://github.com/RustCrypto/signatures/blob/master/ml-dsa/README.md),
[changelog](https://github.com/RustCrypto/signatures/blob/master/ml-dsa/CHANGELOG.md),
[CI](https://github.com/RustCrypto/signatures/blob/master/.github/workflows/ml-dsa.yml).

**`aws-lc-rs`.** Version 1.18.0 (2026-08-07) release notes: "The ML-DSA
signature APIs are now stable". `ML_DSA_65` (verification) and
`ML_DSA_65_SIGNING` live in `aws_lc_rs::signature`, no `unstable` feature. In
1.13.0 (2025-04-01) they had been introduced under `unstable`. The
`unstable` feature still exists in `Cargo.toml`. Underneath is AWS-LC (C and
assembly); the crate depends on `aws-lc-sys` 0.45.0, which is pre-1.0, so
"stable" applies to the Rust API and not to the whole dependency chain. The
`fips` feature binds `aws-lc-fips-sys` 0.14.2. The release notes say the FIPS
4.0 module provides ML-DSA. AWS-LC's FIPS.md lists validated certificates for
v1.0, v2.0 and v3.1 (#4631, #5146, #5429, #4816, #5298, #5314) and lists v4.0
(static and dynamic) as submitted and in process. Whether any of the listed
certificates covers ML-DSA was not confirmed, and this page does not claim it.
Platform page lists `wasm32-unknown-emscripten`; `wasm32-unknown-unknown` is
not stated. Sources: [crates.io](https://crates.io/api/v1/crates/aws-lc-rs),
[releases](https://github.com/aws/aws-lc-rs/releases/tag/v1.18.0),
[docs.rs](https://docs.rs/aws-lc-rs/1.18.1/aws_lc_rs/signature/index.html),
[Cargo.toml](https://github.com/aws/aws-lc-rs/blob/main/aws-lc-rs/Cargo.toml),
[FIPS.md](https://github.com/aws/aws-lc/blob/main/crypto/fipsmodule/FIPS.md),
[platform support](https://aws.github.io/aws-lc-rs/platform_support.html).

**`fips204`.** Pure, safe Rust ("without any unsafe code"), `no_std` for key and
signature generation. The README says the API is stabilised, but the version is
0.x. crates.io has 0.4.6 from 2024-12-22; the repository's `Cargo.toml` says
0.5.0 and has commits as recent as 2026-10-06, so the published crate is
behind the repository. README mentions NIST ACVP vectors and a browser demo
under `wasm/`; no audit statement was found. Sources:
[crates.io](https://crates.io/api/v1/crates/fips204),
[README](https://github.com/integritychain/fips204/blob/main/README.md),
[repository](https://github.com/integritychain/fips204).

**`libcrux-ml-dsa`.** Rust, portable plus AVX2. The README marks field
arithmetic, NTT and serialisation as formally verified with hax and F*; the
workspace README says executables are not verified to be side-channel
resistant, and that all crates are pre-release (< 0.1) and to contact the
maintainers before production use. Changelog 0.0.9 (2026-05-13) fixes an
incorrect AVX2 `use_hint`. No audit report found; WebAssembly not stated for
this crate. Sources: [crates.io](https://crates.io/api/v1/crates/libcrux-ml-dsa),
[crate README](https://github.com/cryspen/libcrux/blob/main/libcrux-ml-dsa/README.md),
[changelog](https://github.com/cryspen/libcrux/blob/main/libcrux-ml-dsa/CHANGELOG.md),
[workspace README](https://github.com/cryspen/libcrux/blob/main/Readme.md). The
repository is now `celabshq/libcrux` (GitHub API, `cryspen/libcrux` redirects).

**`pqcrypto-mldsa`, `pqcrypto-dilithium`.** Bindings to C from PQClean. The
repository README says: "This project is unmaintained", that it will get no
security fixes and that new projects should not use it; it recommends RustCrypto
and others. Excluded. Sources: [README](https://github.com/rustpq/pqcrypto/blob/main/README.md),
[crates.io](https://crates.io/api/v1/crates/pqcrypto-mldsa).

**`oqs`.** Bindings to liboqs. liboqs states it is for prototyping and does not
recommend relying on it in production; ML-DSA comes from mldsa-native. The
`oqs` crate is 0.11.0, last released 2025-05-01. Sources:
[crates.io](https://crates.io/api/v1/crates/oqs),
[liboqs README](https://github.com/open-quantum-safe/liboqs/blob/main/README.md),
[liboqs-rust README](https://github.com/open-quantum-safe/liboqs-rust/blob/main/README.md).

**Others seen in a crates.io search for "ml-dsa".** `pqc-rs-ml-dsa` 1.0.0
(2026-09-28, 70 downloads, repository created 2026-07; its README says "has not
been independently audited"), `dilithium-rs` 0.4.1 (2026-08-31), `pqc-sig`
0.5.0 (2026-09-24). Too new, and unaudited or pre-1.0; not assessed further.
A 1.0 version number alone does not meet the intent of the policy.

## Recommendation

- **Native binary: conditional go on `aws-lc-rs` (>= 1.18.0), once the
  vectors check below passes in CI.** It is the only candidate that is >= 1.0
  with verification in the stable API. Two points the owner must accept or
  reject first: the C/asm code underneath, and `aws-lc-sys` being pre-1.0.
  Its FIPS status for ML-DSA is not confirmed and must not be cited.
- **WebAssembly: no-go.** No candidate states `wasm32-unknown-unknown` support
  and is also >= 1.0. Wait for one of: `ml-dsa` 1.0, or `aws-lc-rs`
  documenting `wasm32-unknown-unknown`.
- **Event that would change the first point:** a published AWS-LC FIPS module
  certificate that names ML-DSA, or an independent audit of a pure-Rust
  implementation (`ml-dsa` or `libcrux-ml-dsa`) reaching 1.0.
- **Look again on 2027-04-01** (the issue's milestone is H1 2027).

## Policy context

Project policy accepts only stable (>= 1.0) dependencies in the trust path.
[Section 9 of the verification document](attest-verification.md#9-cryptographic-choices-stated-plainly) already
records that the issuer side uses a pre-1.0, unaudited Rust ML-DSA library.
A verifier whose point is that the evaluator need not trust us should not add
a second one.

## How the vector criterion will be met

Issue #30 requires that any candidate verify the same vectors as the bash
script. That is not done here and is not checked on a developer machine:
`tests/vectors/v1` includes negative cases. It will be done in CI, as part of
the Rust port work (#29): the selected crate verifies every case in
`tests/vectors/v1` and must give the same outcome as the bash script for each
(accepted or rejected, and the same failure class). A single difference
rejects the candidate. This criterion stays open until that CI job exists and
passes.

## Not confirmed

- Any external audit report for any candidate's ML-DSA code.
- A FIPS 140-3 certificate that names ML-DSA (AWS-LC v4.0 is listed as in process).
- `wasm32-unknown-unknown` support as a stated claim by any project.
- The ML-DSA-65 API of `pqcrypto-*` and `oqs` at the docs.rs level; both are
  excluded for other reasons.
