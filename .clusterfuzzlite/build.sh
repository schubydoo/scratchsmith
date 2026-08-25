#!/bin/bash -eu
# Build the cargo-fuzz targets and stage their binaries where ClusterFuzzLite expects them.
# --debug-assertions turns on assertions during fuzzing (fault detection before deployment).
cd "$SRC/scratchsmith"
# The OSS-Fuzz base image ships a nightly (1.91) older than our MSRV (Cargo.toml rust-version =
# 1.96) and pins it via RUSTUP_TOOLCHAIN. `rustup update` (not `install`, which no-ops when
# nightly already exists) refreshes the channel to the current release; the export forces its use.
rustup update nightly
export RUSTUP_TOOLCHAIN=nightly
cargo fuzz build -O --debug-assertions
FUZZ_TARGET_OUTPUT_DIR="$SRC/scratchsmith/fuzz/target/x86_64-unknown-linux-gnu/release"
for f in fuzz/fuzz_targets/*.rs; do
  target="$(basename "${f%.*}")"
  cp "$FUZZ_TARGET_OUTPUT_DIR/$target" "$OUT/"
done
