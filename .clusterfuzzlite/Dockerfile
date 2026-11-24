# ClusterFuzzLite build environment for scratchsmith's cargo-fuzz targets.
# The base image ships a nightly Rust toolchain + cargo-fuzz. Pinned by digest (Scorecard
# Pinned-Dependencies); bump the digest when refreshing the OSS-Fuzz base (Renovate may auto-bump).
FROM gcr.io/oss-fuzz-base/base-builder-rust:latest@sha256:d345218878c78feed410f0ad57268617a368912b224f844bbdb71c54c0b9955a
COPY . $SRC/scratchsmith
WORKDIR $SRC/scratchsmith
COPY .clusterfuzzlite/build.sh $SRC/build.sh
