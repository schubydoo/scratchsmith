#!/bin/bash -eu
# Build the cargo-fuzz targets and stage their binaries where ClusterFuzzLite expects them.
# --debug-assertions turns on assertions during fuzzing (fault detection before deployment).
cd "$SRC/scratchsmith"
# Toolchain selection is coverage-sensitive.
#
# The base image ships nightly 1.91 (LLVM 21), older than our MSRV (Cargo.toml rust-version =
# 1.96), so fuzz builds must move off it. For the address/plain builds we roll to the current
# nightly (`rustup update`, not `install`, which no-ops when nightly exists); those never feed
# llvm-profdata, so a newer LLVM is harmless.
#
# The weekly coverage run is different: ClusterFuzzLite's runner reads the .profraw with its own
# pinned llvm-profdata (LLVM 22 -> raw profile format v10) and can only *upgrade* older formats,
# never downgrade. The current nightly is LLVM 23 (profraw v11), one ahead, so the merge dies
# ("raw profile version mismatch") and the report lands empty. Pin the coverage build to a
# nightly that clears MSRV yet is still LLVM 22 (v10), matching the runner. The pin is frozen in
# time: it always emits v10, and the runner's reader only moves up, so v10 stays upgradable.
if [ "${SANITIZER:-}" = "coverage" ]; then
  coverage_nightly="nightly-2026-08-01" # rustc 1.99, LLVM 22.1.8 — an LLVM-22 nightly >= MSRV 1.96
  rustup toolchain install "$coverage_nightly" --profile minimal >/dev/null
  export RUSTUP_TOOLCHAIN="$coverage_nightly"
else
  rustup update nightly
  export RUSTUP_TOOLCHAIN=nightly
fi
cargo fuzz build -O --debug-assertions
FUZZ_TARGET_OUTPUT_DIR="$SRC/scratchsmith/fuzz/target/x86_64-unknown-linux-gnu/release"
for f in fuzz/fuzz_targets/*.rs; do
  target="$(basename "${f%.*}")"
  cp "$FUZZ_TARGET_OUTPUT_DIR/$target" "$OUT/"
done
