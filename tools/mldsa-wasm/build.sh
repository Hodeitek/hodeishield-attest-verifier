#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Hodeitek S.L.
# =============================================================================
# tools/mldsa-wasm/build.sh - build the ML-DSA-65 WebAssembly module in a
# pinned container, reproducibly.
#
#   bash tools/mldsa-wasm/build.sh OUT_DIR
#
# Writes OUT_DIR/mldsa_wasm.wasm, OUT_DIR/mldsa_wasm.js and OUT_DIR/SHA256SUMS.
# Needs docker (or set DOCKER=podman) and network access to crates.io and
# static.rust-lang.org. Each run starts in a fresh container: empty cargo
# home, empty target directory, empty Emscripten cache. Nothing from the host
# but the sources of this directory (read-only) goes in.
#
# Environment (all optional; none may change the output, which is what
# README.md checks):
#   DOCKER       container CLI (default: docker)
#   IMAGE        tag of the build image (default: mldsa-wasm-build:local)
#   SRC_MOUNT    path the sources have inside the container (default
#                /src/mldsa-wasm); the output must not depend on it
#   RUN_USER     user:group to run the build as (default: the caller's)
# =============================================================================
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="${1:?usage: build.sh OUT_DIR}"
DOCKER="${DOCKER:-docker}"
IMAGE="${IMAGE:-mldsa-wasm-build:local}"
SRC_MOUNT="${SRC_MOUNT:-/src/mldsa-wasm}"
RUN_USER="${RUN_USER:-$(id -u):$(id -g)}"

mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"

"$DOCKER" build --quiet -t "$IMAGE" -f "$HERE/Dockerfile" "$HERE" >/dev/null

# A fixed value: the build must not depend on the time. Any constant would do.
SDE=1792000000

# The program that runs inside the container (single quotes: expanded there).
read -r -d '' INNER <<'INNER_EOF' || true
set -euo pipefail
export HOME=/tmp/home CARGO_HOME=/tmp/cargo-home CARGO_TARGET_DIR=/tmp/target \
       EM_CACHE=/tmp/em-cache TMPDIR=/tmp SOURCE_DATE_EPOCH="$SDE" \
       TZ=UTC LC_ALL=C CARGO_INCREMENTAL=0
mkdir -p "$HOME" "$CARGO_HOME" "$CARGO_TARGET_DIR" "$EM_CACHE"
cd "$SRC_MOUNT"
# No build path in the output: sources, cargo registry, the toolchain and the
# target directory are mapped to fixed names, for rustc and for the C compiler.
MAP="-ffile-prefix-map=$SRC_MOUNT=/build/src -ffile-prefix-map=$CARGO_HOME=/build/cargo -ffile-prefix-map=$CARGO_TARGET_DIR=/build/target -ffile-prefix-map=/opt/rustup=/build/rustup"
export CFLAGS_wasm32_unknown_emscripten="$MAP"
export CXXFLAGS_wasm32_unknown_emscripten="$MAP"
export RUSTFLAGS="--remap-path-prefix=$SRC_MOUNT=/build/src --remap-path-prefix=$CARGO_HOME=/build/cargo --remap-path-prefix=$CARGO_TARGET_DIR=/build/target --remap-path-prefix=/opt/rustup=/build/rustup -C codegen-units=1 -C link-arg=-sEXPORTED_FUNCTIONS=_mldsa_verify,_malloc,_free -C link-arg=-sEXPORTED_RUNTIME_METHODS=HEAPU8 -C link-arg=-sMODULARIZE=1 -C link-arg=-sENVIRONMENT=web,worker,node -C link-arg=-sALLOW_MEMORY_GROWTH=1"
cargo build --release --locked --target wasm32-unknown-emscripten
cp "$CARGO_TARGET_DIR"/wasm32-unknown-emscripten/release/mldsa_wasm.wasm \
   "$CARGO_TARGET_DIR"/wasm32-unknown-emscripten/release/mldsa_wasm.js /out/
INNER_EOF

rm -f "$OUT/mldsa_wasm.wasm" "$OUT/mldsa_wasm.js" "$OUT/SHA256SUMS"
"$DOCKER" run --rm --user "$RUN_USER" \
  --mount "type=bind,src=$HERE,dst=$SRC_MOUNT,readonly" \
  --mount "type=bind,src=$OUT,dst=/out" \
  -e "SDE=$SDE" -e "SRC_MOUNT=$SRC_MOUNT" \
  "$IMAGE" bash -c "$INNER"

( cd "$OUT" && sha256sum mldsa_wasm.wasm mldsa_wasm.js | tee SHA256SUMS )
