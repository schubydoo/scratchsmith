# Installation

Scratchsmith is **Linux only** (amd64/arm64). It stages a Linux rootfs, so it does not run
on macOS or native Windows. Use a Linux container or WSL2 there.

## One-line install

Downloads the signed release binary, verifies it against the cosign-signed `checksums.txt`, and
installs it to `~/.local/bin` (or `/usr/local/bin` as root):

```sh
curl -fsSL https://raw.githubusercontent.com/schubydoo/scratchsmith/main/install.sh | bash
```

Piping to `bash` runs [`install.sh`](https://github.com/schubydoo/scratchsmith/blob/main/install.sh).
You can read it first. The `VERSION` and `BIN_DIR` env vars override the tag and install
directory. `VERSION` takes the tag with or without its leading `v`, for example
`curl -fsSL …/install.sh | VERSION=v2.2.0 bash`. Without cosign, the script warns and verifies only the SHA-256. With cosign
installed, a missing signature bundle stops the install. The `INSECURE_ALLOW_MISSING_SIGNATURE=1`
env var installs anyway and verifies only the SHA-256. A signature that fails to verify still
stops the install.
If a download stalls for 30 seconds, the script stops with an error. It does not
retry. That limit needs curl, or a wget that takes `-T`. A BusyBox wget that was built with no
timeout feature can still hang. Uninstall with `--uninstall`:

```sh
curl -fsSL https://raw.githubusercontent.com/schubydoo/scratchsmith/main/install.sh | bash -s -- --uninstall
```

## Homebrew

```sh
brew install schubydoo/scratchsmith/scratchsmith
```

## Cargo

Build and install from source with Cargo (Rust **1.96+**):

```sh
cargo install --locked scratchsmith
```

`--locked` builds with the dependency versions the release was tested with. Without it, Cargo
resolves the dependencies fresh and can pick crates that need a newer Rust than 1.96.

## Release binary

Download a release binary, Linux **amd64** or **arm64**, from the
[latest release](https://github.com/schubydoo/scratchsmith/releases/latest). Verify the signature
and provenance first (see [Verifying releases](verifying.md)):

```sh
tar -xzf scratchsmith-*-linux-amd64.tar.gz   # or -linux-arm64
./scratchsmith-*/scratchsmith --version
```

## Container image

Pull the signed image:

```sh
docker pull ghcr.io/schubydoo/scratchsmith:latest
```

`:latest` is a minimal `FROM scratch` image. It runs every subcommand that needs no external
tool, `index` included. It does **not** run `pack`, because a scratch image carries none of the
tools `pack` needs. To run `pack` inside a container, pull
the **`:toolbox`** image instead (Wolfi base + the full toolchain). The
[toolbox section in Usage](usage.md) lists which subcommands run where.

To pin a release, use `:X.Y.Z` or `:X.Y` (for example `:2.2.0` or `:2.2`). The toolbox
equivalents are `:X.Y.Z-toolbox` and `:X.Y-toolbox`. There is no major-only tag. Both images are
multi-arch (amd64 and arm64) and signed. Verify them with the `cosign verify` command in
[Verifying releases](verifying.md).

## Build from source

Rust **1.96+**:

```sh
git clone https://github.com/schubydoo/scratchsmith
cd scratchsmith
cargo build --release
# binary at target/release/scratchsmith
```

Run `scratchsmith doctor` to see which optional external tools (syft, strip, tini, …) are present.

## Shell completions

Generate a script for your shell and drop it where the shell looks:

```sh
scratchsmith --completions bash | sudo tee /etc/bash_completion.d/scratchsmith
scratchsmith --completions zsh  > ~/.zfunc/_scratchsmith    # ensure ~/.zfunc is on $fpath
scratchsmith --completions fish > ~/.config/fish/completions/scratchsmith.fish
```
