<!--
SPDX-License-Identifier: Apache-2.0
Copyright 2026 Hodeitek S.L.
-->

# mldsa-wasm

The ML-DSA-65 verify primitive of [`aws-lc-rs`](https://crates.io/crates/aws-lc-rs)
as a WebAssembly module for the browser, and the recipe that builds it
reproducibly. It is the module for
[issue #25](https://github.com/Hodeitek/hodeishield-attest-verifier/issues/25);
the evaluation behind it is the "Addendum 2026-10-13" of
[docs/security/rust-mldsa-evaluation.md](../../docs/security/rust-mldsa-evaluation.md).

It checks the signature primitive only. It is not the verifier: freshness,
issuer, revocation and the canonical encoders are not in it.

## Export

`mldsa_verify(pk, pk_len, msg, msg_len, sig, sig_len) -> i32`: 1 if `sig` is a
valid ML-DSA-65 signature of `msg` under the raw public key `pk` (1,952 bytes),
0 in every other case. `_malloc` and `_free` are exported, and `HEAPU8`, so the
caller can place the three byte strings in the module's memory.

## Build

```
bash tools/mldsa-wasm/build.sh OUT_DIR
```

Needs docker (or `DOCKER=podman`) and network access to crates.io and
static.rust-lang.org. It writes `mldsa_wasm.wasm`, `mldsa_wasm.js` (the
Emscripten loader) and `SHA256SUMS` to `OUT_DIR`.

Pinned:

| What | Pin |
|---|---|
| Base image | `emscripten/emsdk:6.0.12@sha256:77638e6c215a65f25a704c0c831d5c2463a8c0468a58c6cb82489dbe621dfa05` (Emscripten 6.0.12) |
| rustup | 1.28.2, SHA-256 `20a06e644b0d9bd2fbdbfd52d42540bdde820ea7df86e92e533c073da0cdd43c` checked in the Dockerfile |
| Rust | 1.97.1, target `wasm32-unknown-emscripten` |
| Crates | `Cargo.lock` (`aws-lc-rs` 1.18.1, `aws-lc-sys` 0.45.0), built with `--locked`; the registry checksums in the lock are verified by cargo |

The build runs in a fresh container each time: empty cargo home, empty target
directory, empty Emscripten cache; the sources are mounted read-only. Paths are
mapped to fixed names for rustc (`--remap-path-prefix`) and for the C compiler
(`-ffile-prefix-map`), `codegen-units` is 1, and `SOURCE_DATE_EPOCH`, `TZ` and
`LC_ALL` are fixed.

## Checking that it is reproducible

Build twice, with the sources at a different path in the container and as a
different user, and compare:

```
bash tools/mldsa-wasm/build.sh /tmp/a
mkdir /tmp/b && chmod 777 /tmp/b
RUN_USER=12345:23456 SRC_MOUNT=/other/place/checkout bash tools/mldsa-wasm/build.sh /tmp/b
cmp /tmp/a/mldsa_wasm.wasm /tmp/b/mldsa_wasm.wasm && cmp /tmp/a/mldsa_wasm.js /tmp/b/mldsa_wasm.js && echo identical
```

The hashes found, and what they were compared on, are in the addendum of the
evaluation document. The hashes belong to this commit of the recipe and these
pins: a change to any of them, or to `src/main.rs`, gives other bytes.
