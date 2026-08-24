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
FROM scratch
ARG TARGETARCH
COPY dist/${TARGETARCH}/scratchsmith /scratchsmith
ENTRYPOINT ["/scratchsmith"]
