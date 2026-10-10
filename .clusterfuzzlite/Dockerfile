# ClusterFuzzLite build environment for scratchsmith's cargo-fuzz targets.
# The base image ships a nightly Rust toolchain + cargo-fuzz. Pinned by digest (Scorecard
# Pinned-Dependencies); bump the digest when refreshing the OSS-Fuzz base (Renovate may auto-bump).
FROM gcr.io/oss-fuzz-base/base-builder-rust:latest@sha256:9178c8abf83e7a82d02c1a9bf7b2f564320f669f7a1cec512ae9a8c4ea078427
COPY . $SRC/scratchsmith
WORKDIR $SRC/scratchsmith
COPY .clusterfuzzlite/build.sh $SRC/build.sh
