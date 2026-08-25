#!/bin/bash -eu
# Build the cargo-fuzz targets and stage their binaries where ClusterFuzzLite expects them.
# --debug-assertions turns on assertions during fuzzing (fault detection before deployment).
cd "$SRC/scratchsmith"
# The OSS-Fuzz base image can ship a nightly older than our MSRV (Cargo.toml rust-version =
# 1.96); update to the current nightly so cargo will build the crate.
rustup toolchain install nightly --profile minimal --component rust-src --no-self-update
rustup default nightly
cargo fuzz build -O --debug-assertions
FUZZ_TARGET_OUTPUT_DIR="$SRC/scratchsmith/fuzz/target/x86_64-unknown-linux-gnu/release"
for f in fuzz/fuzz_targets/*.rs; do
  target="$(basename "${f%.*}")"
  cp "$FUZZ_TARGET_OUTPUT_DIR/$target" "$OUT/"
done
