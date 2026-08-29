# Installation

Scratchsmith is **Linux only** (amd64/arm64) — it stages a Linux glibc rootfs, so it does not run on
macOS or native Windows; use a Linux container or WSL2 there.

## One-line install

Downloads the signed release binary, verifies it against the cosign-signed `checksums.txt`, and
installs it to `~/.local/bin` (or `/usr/local/bin` as root):

```sh
curl -fsSL https://raw.githubusercontent.com/schubydoo/scratchsmith/main/install.sh | bash
```

Piping to `bash` runs [`install.sh`](https://github.com/schubydoo/scratchsmith/blob/main/install.sh) —
read it first if you prefer. `VERSION` and `BIN_DIR` env vars override the tag and install directory.
Uninstall with `--uninstall`:

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
cargo install scratchsmith
```

## Release binary

Download a release binary — Linux **amd64** or **arm64** — from the
[latest release](https://github.com/schubydoo/scratchsmith/releases/latest). Check the signature
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

`:latest` is a minimal `FROM scratch` image — it runs `--version`, `lint`, `doctor`, and
`--completions`, but **not `pack`** (a scratch image has none of the toolchain `pack` needs). To run
`pack` inside a container, pull the **`:toolbox`** image instead (Wolfi base + the full toolchain);
see the [toolbox section in Usage](usage.md).

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
