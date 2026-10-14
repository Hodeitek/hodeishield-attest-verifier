# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Hodeitek S.L.
#
# Build environment for the ML-DSA-65 WebAssembly module (see build.sh and
# README.md). Everything is pinned: the base image by digest, rustup by
# version and SHA-256, the Rust toolchain by version. build.sh builds this image;
# the module's build needs nothing else besides the sources and the crates
# listed in Cargo.lock.

# emscripten/emsdk 6.0.12 (Emscripten 6.0.12, Ubuntu 24.04), image index digest.
FROM emscripten/emsdk:6.0.12@sha256:77638e6c215a65f25a704c0c831d5c2463a8c0468a58c6cb82489dbe621dfa05

ARG RUSTUP_VERSION=1.28.2
ARG RUSTUP_SHA256=20a06e644b0d9bd2fbdbfd52d42540bdde820ea7df86e92e533c073da0cdd43c
ARG RUST_VERSION=1.97.1

ENV RUSTUP_HOME=/opt/rustup \
    CARGO_HOME=/opt/cargo \
    RUSTUP_TOOLCHAIN=${RUST_VERSION}
RUN curl --proto '=https' --tlsv1.2 -fsSL \
      "https://static.rust-lang.org/rustup/archive/${RUSTUP_VERSION}/x86_64-unknown-linux-gnu/rustup-init" \
      -o /tmp/rustup-init \
 && echo "${RUSTUP_SHA256}  /tmp/rustup-init" | sha256sum -c - \
 && chmod +x /tmp/rustup-init \
 && /tmp/rustup-init -y --no-modify-path --profile minimal \
      --default-toolchain "${RUST_VERSION}" --target wasm32-unknown-emscripten \
 && rm /tmp/rustup-init \
 && chmod -R a+rX /opt/rustup /opt/cargo

ENV PATH=/opt/cargo/bin:${PATH}
