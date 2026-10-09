# syntax=docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e
#
# The release container image: the static scratchsmith binary in a FROM scratch
# image — the minimal-image philosophy scratchsmith itself embodies.
#
# Built with buildx, NOT by scratchsmith: bootstrapping its own release image with
# itself is a milestone it has not taken, though `scratchsmith index` does assemble a
# multi-arch index daemonlessly. The rule for what runs here: every subcommand that
# needs no external tool. `pack` needs docker, ldconfig, syft, and strip, so it does
# not work here. `index` does: with no certificate store in the image, it falls back
# to the Mozilla roots compiled into the binary.
# Everything else does too, `doctor` included — it probes for each tool and reports
# them all missing, which is the right answer. To run `pack` in a container, use the
# `:toolbox` image instead (Dockerfile.toolbox, a Wolfi base with the
# toolchain) — see docs/usage.md, which lists the subcommands.
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
