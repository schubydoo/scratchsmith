# syntax=docker/dockerfile:1@sha256:ecfaec9ed6d810b56388c508f4121597bfbba70d41a6dfeee4d8cad5f295fc32
#
# The release container image: the static scratchsmith binary in a FROM scratch
# image — the minimal-image philosophy scratchsmith itself embodies.
#
# Built with buildx, NOT by scratchsmith: its own daemonless multi-arch registry
# push is a future milestone. Note that `scratchsmith pack` needs docker,
# ldconfig, syft, and strip at runtime, none of which exist inside a scratch
# image — so `pack` will not work here, but `--version`, `lint`, `doctor`, and
# `--completions` do. To run `pack` in a container, use the `:toolbox` image
# instead (Dockerfile.toolbox, a Wolfi base with the toolchain) — see docs/usage.md.
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
