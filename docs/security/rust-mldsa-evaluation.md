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

- **Native binary: conditional go on `aws-lc-rs` (>= 1.18.0). The vectors check
  passes (see "Result of the vector check").** It is the only candidate that is >= 1.0
  with verification in the stable API. Two points the owner must accept or
  reject first: the C/asm code underneath, and `aws-lc-sys` being pre-1.0.
  Its FIPS status for ML-DSA is not confirmed and must not be cited.
- **WebAssembly: no-go for `wasm32-unknown-unknown`** (the finding of
  2026-10-08; for the browser verifier of #25, see the addendum of 2026-10-13,
  which tests two other paths). No candidate states `wasm32-unknown-unknown` support
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

## Result of the vector check

Issue #30 requires that any candidate verify the same vectors as the bash
script. For `aws-lc-rs` this was run on 2026-10-11 by
[`tools/mldsa-vectors`](../../tools/mldsa-vectors/README.md), a small harness
(not the port, #29) that gives `aws_lc_rs::signature::ML_DSA_65` the signing
input and key of each case in `tests/vectors/v1` and compares its accept or
reject with the signature verdict the manifest states for the reference
script. With `aws-lc-rs` 1.18.1 (`aws-lc-sys` 0.45.0): 118 cases, 47 checked
and agreed, 0 disagreed, 71 skipped (3 anchor cases decided by cosign, and 68
whose reason for failing is not the signature, so the manifest states no
signature verdict). The 47 cover valid documents, tampered fields, flipped
signature bytes, a signature by another key, a transplanted signature, wrong
signature sizes, and status lists. The harness fails if any case disagrees or
if fewer than 47 are checked. It runs in CI (`.github/workflows/mldsa-vectors.yml`)
when the harness, the vectors or the script change.

This is a check of the primitive's signature verdict only. It is not a check of
the whole verifier, and it does not change the points under "Not confirmed". The
other candidates were not run: none of them meets the stability policy.

## Addendum 2026-10-13: ML-DSA-65 in the browser

Tracks [issue #25](https://github.com/Hodeitek/hodeishield-attest-verifier/issues/25)
(a static in-browser verifier that uses an ML-DSA-65 implementation different
from the issuer's). The sections above found no Rust library that documents
`wasm32-unknown-unknown`. Two other paths were not tested, and this addendum
tests them. Every result below was measured on 2026-10-13 and every version is
stated; claims from a project's own pages are linked.

### Method

Same pass criterion and case selection as "Result of the vector check". The
`tools/mldsa-vectors` harness was run natively once, unchanged in logic, with
one addition: besides comparing the verdicts it wrote out, for each checked
case, the public key, the signing input and the signature (hex), and the
verdict the manifest requires. That gives 50 signature verdicts in 47 checked
cases (118 cases in all; 3 anchor cases and 68 cases whose manifest entry states
no signature verdict are skipped, exactly as before). Each runtime below was
given those 50 inputs and had to return accept or reject as required. A case
passes only if all its signature verdicts agree. Nothing but the primitive
differs between runs, so the counts are comparable with the native run (47 of 47
checked cases, 0 disagreed). These runs check the primitive's signature verdict
only; they are not a check of a browser verifier, which does not exist yet.

A static page needs a secure context for WebCrypto. The browser runs were
served from `http://127.0.0.1` (a secure context) with fresh, default browser
profiles and no flags except `--headless` (Chrome: `--headless=new --no-sandbox
--disable-gpu`; Firefox: `--headless --no-remote`).

### Result

| Path | Runtime | Result | Cases | Signature verdicts |
|---|---|---|---|---|
| 1. AWS-LC on `wasm32-unknown-emscripten` | Node 24.15.0 | PASS | 47/47 | 50/50 |
| 1. AWS-LC on `wasm32-unknown-emscripten` | Chrome 155.0.8059.39, default settings | PASS | 47/47 | 50/50 |
| 1. AWS-LC on `wasm32-unknown-emscripten` | Firefox 153.4.0esr, default settings | PASS | 47/47 | 50/50 |
| 2. native WebCrypto `ML-DSA-65` | Chrome 155.0.8059.39, default settings | PASS | 47/47 | 50/50 |
| 2. native WebCrypto `ML-DSA-65` | Firefox 153.4.0esr, default settings | FAIL | 0/47 | 0/50 |
| 2. native WebCrypto `ML-DSA-65` | Node 24.15.0 (context only, not a pass) | would pass | 47/47 | 50/50 |
| 2. native WebCrypto `ML-DSA-65` | Safari | not tested | | |

No mismatch was found in any run that passed. The Firefox WebCrypto run
mismatched every case because every call failed (below).

### Path 1: AWS-LC on `wasm32-unknown-emscripten`

Builds and runs. Versions: `aws-lc-rs` 1.18.1 and `aws-lc-sys` 0.45.0 (the same
`Cargo.lock` as `tools/mldsa-vectors`, minus the two crates the wasm harness does
not use), Rust 1.97.1 (LLVM 22.1.6) with the `wasm32-unknown-emscripten`
target, Emscripten 6.0.12 installed from the `emsdk` repository.

Method. A minimal binary crate depending on `aws-lc-rs` with
`default-features = false, features = ["aws-lc-sys"]`, exporting one C function
that calls `UnparsedPublicKey::new(&ML_DSA_65, pk).verify(msg, sig)`. Built with
`cargo build --release --target wasm32-unknown-emscripten`, linker arguments
`-sEXPORTED_FUNCTIONS=_mldsa_verify,_malloc,_free -sEXPORTED_RUNTIME_METHODS=HEAPU8
-sMODULARIZE=1 -sENVIRONMENT=web,worker,node -sALLOW_MEMORY_GROWTH=1`. The build
compiles the C code of AWS-LC with `emcc`; no change to
`aws-lc-sys` was needed. Output: one `.wasm` file of 778,381 bytes and one
JavaScript loader of 56,046 bytes (default `-O3`; no attempt was made to
shrink them). The loader was run in Node and in both browsers; the browsers
loaded it from a page and called the export for each input.

What did not work first. With Emscripten 3.1.68, the version the Rust platform
page for this target names
([platform support](https://doc.rust-lang.org/rustc/platform-support/wasm32-unknown-emscripten.html)),
the C code of AWS-LC compiled but the final link failed in `wasm-opt`:
`Unknown option '--enable-bulk-memory-opt'`. Emscripten 6.0.12 (the version
`emsdk` listed as the recommended one on that day) links without error, with one
deprecation warning about `-sWASM_BIGINT` that Rust's link line passes. Use a
clean build directory when changing the Emscripten version: a cached build of the
C objects survives a change of `emcc`.

What this path means for a trust path. It keeps AWS-LC (C code, so it is the same
code base as the native option, with the open points above: `aws-lc-sys` is
pre-1.0 and the FIPS status for ML-DSA is not confirmed). It adds the
Emscripten toolchain and its generated JavaScript loader to what a reader must
trust and review, and a page that loads WebAssembly needs a
Content-Security-Policy that allows it (`'wasm-unsafe-eval'`). Whether two
builds of the module give the same bytes was not tested; #29 requires that.

### Path 2: native ML-DSA in WebCrypto

The WICG draft
[Modern Algorithms in the Web Cryptography API](https://wicg.github.io/webcrypto-modern-algos/)
defines `ML-DSA-65`, the key formats `raw-public`, `spki` and `jwk` (key type
`AKP`) and `SubtleCrypto.supports()`.

Chrome 155.0.8059.39, default settings, no flag: `SubtleCrypto.supports("verify",
"ML-DSA-65")` and `supports("importKey", "ML-DSA-65")` return `true`.
`importKey` succeeds with `raw-public`, with `spki` (the 1,952-byte key wrapped
in a SubjectPublicKeyInfo with OID 2.16.840.1.101.3.4.3.18) and with `jwk`
(`kty: "AKP"`). `crypto.subtle.verify({name: "ML-DSA-65"}, ...)` gave the
required verdict in 50 of 50 signature verdicts. This passes without any
experimental flag. Which cryptographic library Chrome uses for it was not
checked here. Only version 155 was tested, not the first version that ships it.

Firefox 153.4.0esr, default settings: `SubtleCrypto.supports` does not exist
(`undefined`). `importKey` with `raw-public` throws `SyntaxError: An invalid or
illegal string was specified` (the format is not accepted); with `spki` and with
`jwk` it throws `NotSupportedError: Operation is not supported`. All 50 verify
attempts therefore failed. No experimental setting was found: a search of the
`libxul.so` of this build for the strings `ML-DSA`, `mldsa` and `dilithium` found
none (the same library does contain ML-KEM preference text), while the NSS library
shipped with it does contain ML-DSA. That does not prove that no preference
exists; it shows that the browser engine of this build has no ML-DSA name in it.
Fail.

Node 24.15.0 (OpenSSL 3.5.5, `process.versions.openssl`) supports `ML-DSA-65` in
`crypto.subtle` with `raw-public` and prints an `ExperimentalWarning`; 50 of 50
verdicts and 47 of 47 cases agree. It is recorded as context only: it is backed
by OpenSSL, the library the reference script uses, so it is not an independent
implementation for the purpose of #25 (see the
[Node documentation](https://nodejs.org/docs/latest-v24.x/api/webcrypto.html)).

Safari: not tested (not available for this evaluation).

Consequence for a public page. A page that relies on native WebCrypto verifies in
Chrome 155 and fails in Firefox 153 ESR, so it cannot be the only verification
path. It could be used as a second, independent check next to path 1 or only
where `SubtleCrypto.supports("verify", "ML-DSA-65")` is true; that is a design
decision for #25, not a result of this test.

### Updated recommendation for #25

- Path 1 passes the criterion on every runtime tested (Node, Chrome 155,
  Firefox 153 ESR): 47 of 47 checked cases. The technical blocker recorded above
  ("no candidate documents `wasm32-unknown-unknown`") is removed for #25 by this
  route, so #25 does not have to stay on hold for lack of an implementation.
- The remaining questions are decisions, not findings: whether `aws-lc-sys`
  (pre-1.0) and an Emscripten-generated loader are acceptable in the trust path
  under the policy above; a reproducible build of the module (not tested); and
  the size of the artefact (about 830 KB before compression). The decision on
  #25 therefore stays with the maintainers; this document does not make it.
- Path 2 does not pass (Firefox 153 ESR fails, Safari not tested). Native
  WebCrypto is not a substitute for path 1 today. Re-check when Firefox ships
  `ML-DSA` in WebCrypto.
- #29 (a shared Rust core for the CLI and the browser) is not affected: the
  addendum tested only the signature primitive, not the canonical encoders,
  freshness, revocation or any other check of the verifier.

### Reproducing

Run `tools/mldsa-vectors` natively with a small patch that writes out the inputs
(not committed). Build the harness crate described above with the pinned
versions. Serve a directory with the loader, the `.wasm`, the inputs and the page
from `127.0.0.1`, and open it with the browsers listed, with a new profile each.
For path 2 call `crypto.subtle.importKey("raw-public", pk, {name: "ML-DSA-65"},
false, ["verify"])` and `crypto.subtle.verify({name: "ML-DSA-65"}, key, sig, msg)`.

## Not confirmed

- Any external audit report for any candidate's ML-DSA code.
- A FIPS 140-3 certificate that names ML-DSA (AWS-LC v4.0 is listed as in process).
- `wasm32-unknown-unknown` support as a stated claim by any project.
- The ML-DSA-65 API of `pqcrypto-*` and `oqs` at the docs.rs level; both are
  excluded for other reasons.
- Added 2026-10-13: whether two builds of the Emscripten module of `aws-lc-rs`
  give the same bytes; any Safari result; which library Chrome uses for ML-DSA
  in WebCrypto; the first Chrome version that ships it; whether Firefox has a
  preference that enables ML-DSA in WebCrypto (none was found in the 153 ESR
  build).
