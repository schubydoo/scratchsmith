# ClusterFuzzLite build environment for scratchsmith's cargo-fuzz targets.
# The base image ships a nightly Rust toolchain + cargo-fuzz. Pinned by digest (Scorecard
# Pinned-Dependencies); bump the digest when refreshing the OSS-Fuzz base (Renovate may auto-bump).
FROM gcr.io/oss-fuzz-base/base-builder-rust:latest@sha256:433319ea1a6bbea6c1db1915a5d385021908cc62026d9f0efda2270ef6060de3
COPY . $SRC/scratchsmith
WORKDIR $SRC/scratchsmith
COPY .clusterfuzzlite/build.sh $SRC/build.sh
