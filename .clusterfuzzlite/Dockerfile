# ClusterFuzzLite build environment for scratchsmith's cargo-fuzz targets.
# The base image ships a nightly Rust toolchain + cargo-fuzz. Pinned by digest (Scorecard
# Pinned-Dependencies); bump the digest when refreshing the OSS-Fuzz base (Renovate may auto-bump).
FROM gcr.io/oss-fuzz-base/base-builder-rust:latest@sha256:5fd6a6afd7369a3277b9697b39cb44bf8ed3f389bb440e7294a3f3869891ef97
COPY . $SRC/scratchsmith
WORKDIR $SRC/scratchsmith
COPY .clusterfuzzlite/build.sh $SRC/build.sh
