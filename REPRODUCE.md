# Reproducing a release binary

Each release binary can be rebuilt from its tag, byte for byte. The
[`reproduce`](.github/workflows/reproduce.yml) workflow does this for every release: it rebuilds
both binaries from the tag and compares them with the ones in the published tarballs. This page
shows how to run the same check yourself.

It covers releases built with `.github/actions/release-build`. Tags from before that recipe
existed can't be rebuilt this way.

## What matches, and what doesn't

The **binary** inside each tarball (`scratchsmith-v<ver>-linux-<arch>/scratchsmith`) is
reproducible. The tarball itself is not, because `tar` records file times. So compare the binary,
and check the tarball you downloaded with `checksums.txt` (see [Verifying releases](docs/verifying.md)).

CI rebuilds on an x86_64 Linux host, for both targets (arm64 is cross-compiled with zig). That is
the setup this page describes.

## What you need

The exact versions are part of the recipe. Read them from
`.github/actions/release-build/action.yml` **at the release tag**:

```sh
git clone https://github.com/schubydoo/scratchsmith
cd scratchsmith
git checkout v<ver>
grep -A2 -E 'renovate: .*depName=(rust-lang/rust|ziglang/zig)' .github/actions/release-build/action.yml
grep 'cargo-zigbuild@' .github/actions/release-build/action.yml
```

Install those three:

- **Rust**, with both musl targets:
  `rustup toolchain install <rust> --profile minimal --target x86_64-unknown-linux-musl --target aarch64-unknown-linux-musl`
- **zig**, from [ziglang.org/download](https://ziglang.org/download/), on your `PATH`.
- **cargo-zigbuild**: `cargo install --locked cargo-zigbuild --version <cargo-zigbuild>`

## Build

From the clean checkout of the tag:

```sh
RUSTUP_TOOLCHAIN=<rust> scripts/build-release-binary.sh x86_64-unknown-linux-musl
RUSTUP_TOOLCHAIN=<rust> scripts/build-release-binary.sh aarch64-unknown-linux-musl
```

The script is the one the release uses. It builds with `--locked`, prints the tool versions and
the binary's SHA-256, and remaps your `CARGO_HOME` out of the binary, so where you build doesn't
change the bytes. It also overrides any `rustflags` in your Cargo config.

## Compare

Download the tarball and `checksums.txt` from the release, then:

```sh
sha256sum -c --ignore-missing checksums.txt
tar -xzf scratchsmith-v<ver>-linux-amd64.tar.gz
cmp scratchsmith-v<ver>-linux-amd64/scratchsmith target/x86_64-unknown-linux-musl/release/scratchsmith \
  && echo "identical"
```

Do the same for `linux-arm64` with `target/aarch64-unknown-linux-musl/release/scratchsmith`.

If the bytes differ, check the versions first: `rustc -V`, `zig version` and
`cargo-zigbuild --version` from the script's output must match the ones pinned at the tag. If they
match and the bytes still differ, please [open an issue](https://github.com/schubydoo/scratchsmith/issues).
