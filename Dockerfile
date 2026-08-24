# syntax=docker/dockerfile:1
#
# The release container image: the static scratchsmith binary in a FROM scratch
# image — the minimal-image philosophy scratchsmith itself embodies.
#
# Built with buildx, NOT by scratchsmith: its own daemonless multi-arch registry
# push is a future milestone. Note that `scratchsmith pack` needs docker,
# ldconfig, syft, and strip at runtime, none of which exist inside a scratch
# image — so `pack` will not work here, but `--version`, `lint`, `doctor`, and
# `--completions` do. A fuller, runnable image is tracked at
# https://github.com/schubydoo/scratchsmith/issues/12
#
# The release workflow lays out dist/<arch>/scratchsmith before building. To
# build locally:
#   cargo zigbuild --release --target x86_64-unknown-linux-musl --bin scratchsmith
#   install -Dm755 target/x86_64-unknown-linux-musl/release/scratchsmith dist/amd64/scratchsmith
#   docker build --platform linux/amd64 -t scratchsmith:dev .
FROM scratch
ARG TARGETARCH
COPY dist/${TARGETARCH}/scratchsmith /scratchsmith
# Non-root by default (uid 65532) — the same invariant `scratchsmith pack` gives
# every image it builds, and warns about dropping. scratch has no /etc/passwd, so
# a numeric UID is required (a named user would not resolve).
USER 65532:65532
ENTRYPOINT ["/scratchsmith"]
