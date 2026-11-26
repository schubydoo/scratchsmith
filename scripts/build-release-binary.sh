#!/usr/bin/env bash
# Build one static-musl release binary, the same way for the release and for anyone who
# reproduces it (REPRODUCE.md). Usage: scripts/build-release-binary.sh <rust-target>
#
# Run it from a clean checkout of the release tag, with the Rust, zig and cargo-zigbuild
# versions that .github/actions/release-build/action.yml pins at that tag.
set -euo pipefail

target="${1:?usage: $0 <rust-target>, e.g. x86_64-unknown-linux-musl}"

# Panic locations in dependency crates embed their absolute source path under CARGO_HOME,
# so two machines with different homes would build different bytes. Remap it to a fixed
# prefix. The workspace's own paths are already relative, and aws-lc trims its C paths.
cargo_home="$(realpath -m "${CARGO_HOME:-$HOME/.cargo}")"

# RUSTFLAGS wins over every config-file rustflags, so a local ~/.cargo/config.toml can't
# change the output. CARGO_ENCODED_RUSTFLAGS would win over RUSTFLAGS, so clear it.
unset CARGO_ENCODED_RUSTFLAGS CARGO_BUILD_RUSTFLAGS
export RUSTFLAGS="--remap-path-prefix=${cargo_home}=/cargo"

# Record the toolchain in the log, so a mismatch is easy to spot.
rustc -V
cargo -V
zig version
cargo-zigbuild --version

cargo zigbuild --locked --release --target "$target" --bin scratchsmith

bin="target/${target}/release/scratchsmith"
# Fail loud if the remap did not take: an embedded CARGO_HOME path means the bytes depend
# on the build machine.
if grep -qaF "$cargo_home" "$bin"; then
  echo "::error::${bin} still embeds ${cargo_home}; the path remap did not apply" >&2
  exit 1
fi
sha256sum "$bin"
