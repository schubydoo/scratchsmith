# ClusterFuzzLite build environment for scratchsmith's cargo-fuzz targets.
# The base image ships a nightly Rust toolchain + cargo-fuzz. Pinned by digest (Scorecard
# Pinned-Dependencies); bump the digest when refreshing the OSS-Fuzz base (Renovate may auto-bump).
FROM gcr.io/oss-fuzz-base/base-builder-rust:latest@sha256:47bbe5147371187603326af515511e6bad2dcd6e6912fa42c66fb161b5bd770b
COPY . $SRC/scratchsmith
WORKDIR $SRC/scratchsmith
COPY .clusterfuzzlite/build.sh $SRC/build.sh
