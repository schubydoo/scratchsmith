<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/logo-full-white.svg">
    <img alt="Scratchsmith" src="docs/assets/logo-full-black.svg" width="440">
  </picture>
</p>

[![CI](https://github.com/schubydoo/scratchsmith/actions/workflows/ci.yml/badge.svg)](https://github.com/schubydoo/scratchsmith/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/schubydoo/scratchsmith/branch/main/graph/badge.svg)](https://codecov.io/gh/schubydoo/scratchsmith)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
![MSRV](https://img.shields.io/badge/MSRV-1.96-blue)

**The daemonless supply-chain packager for prebuilt dynamic Linux binaries.**

Point Scratchsmith at a dynamically linked glibc ELF binary and get a minimal `FROM scratch`
OCI image — no Dockerfile, no static-linking prerequisite. It resolves the binary's shared
libraries the way `ld.so` does (RPATH/RUNPATH/`$ORIGIN`, the interpreter, versioned soname
symlinks), stages the glibc pieces nothing else remembers (NSS modules, a working
`nsswitch.conf`, minimal `passwd`/`group`), and assembles a **non-root** image with
reproducible layers.

<p align="center">
  <img src="docs/demo/scratchsmith.svg" alt="Scratchsmith packing a dynamic glibc binary into a 2.5 MB FROM scratch image with an SBOM and a smoke-run, then running it" width="720">
</p>

> **Status — v0.1.** The core works end to end (see [What works today](#what-works-today)), and
> releases are [signed and published](#install). One note on the tagline:
> - **Daemonless is here.** `--push` uploads the image straight to a registry and `--oci-archive`
>   writes an OCI archive — both with **no Docker daemon**. The *default* sink still hands the image
>   to your local Docker daemon via `docker load` (or `--no-build` for a daemon-free rootfs) because
>   it's the handiest thing for local dev; reach for `--push` / `--oci-archive` when you want the
>   daemon fully out of the loop.

## Why not just static-link + `FROM scratch`?

If you can rebuild your service as a static binary (`CGO_ENABLED=0`, musl), **do that** — you
need no packer. Scratchsmith is built for the binaries static linking *can't* help:

- **Closed-source / vendor binaries** you can't recompile.
- **glibc binaries** that rely on **NSS**, **`dlopen`**, or **locale** behaviour — static glibc
  quietly breaks these, often only in production.
- Anything where "just rebuild it static" isn't on the table.

That's the wedge. But it's not a fence: Scratchsmith **already packs a static binary too** (the
resolver detects it and stages the single file), so it's equally handy when you just want an
SBOM, a hardening report, a non-root image, and no Dockerfile — without hand-writing a
multi-stage build. Purpose-built for the hard case; useful for the easy one.

## What works today

| Capability | State |
|---|---|
| Pack a dynamic glibc ELF → runnable `FROM scratch` image | ✅ (loaded via `docker load`) |
| `ld.so`-faithful dependency resolution (RPATH/RUNPATH/`$ORIGIN`, interpreter, sonames) | ✅ |
| glibc **NSS** support staged — name-service lookups like `getent hosts` work | ✅ |
| **Non-root** by default (UID 65532), reproducible layers | ✅ |
| **SBOM** generation — `--sbom` (CycloneDX or SPDX, via syft) | ✅ |
| **ELF hardening lint** — `lint` (PIE/RELRO/NX/canary/FORTIFY), gate with `--fail-on` | ✅ |
| `dlopen` gap **detection** + `--include` escape hatch | ✅ |
| Symbol strip (`--strip`), size report, smoke-run (`--smoke`) | ✅ |
| Runtime extras: CA certs (`--ca-certs`), timezone (`--tz`), init/tini (`--init`) | ✅ |
| Config file (`scratchsmith.toml`), JSON output (`--format json`) | ✅ |
| Shell completions — `--completions <bash\|zsh\|fish>` | ✅ |
| **Signed releases** — amd64 + arm64 binaries, cosign-signed checksums + SLSA provenance, signed multi-arch GHCR image | ✅ ([verify](#verifying-releases)) |
| Dynamic musl/Alpine binaries | ❌ rejected loudly (glibc first; a musl backend is a future goal) |
| **Daemonless OCI archive** — `--oci-archive <file>` (no daemon; skopeo/buildah/registry-ready) | ✅ |
| **Daemonless registry push** — `--push <ref>` (no daemon; uses your docker credentials) | ✅ |
| Signing the image `pack` **produces** | ⏳ planned (see [Roadmap](#roadmap)) |

## Install

**Homebrew** (Linux — scratchsmith packs Linux ELF binaries):

```sh
brew install schubydoo/scratchsmith/scratchsmith
```

Or **download a release binary** — Linux **amd64** or **arm64** — from the
[latest release](https://github.com/schubydoo/scratchsmith/releases/latest). Check the signature
and provenance first (see [Verifying releases](#verifying-releases)):

```sh
tar -xzf scratchsmith-*-linux-amd64.tar.gz   # or -linux-arm64
./scratchsmith-*/scratchsmith --version
```

Or pull the signed **container image**:

```sh
docker pull ghcr.io/schubydoo/scratchsmith:latest
```

Or **build from source** (Rust **1.96+**):

```sh
git clone https://github.com/schubydoo/scratchsmith
cd scratchsmith
cargo build --release
# binary at target/release/scratchsmith
```

Run `scratchsmith doctor` to see which optional external tools (syft, strip, tini, …) are
present.

**Shell completions.** Generate a script for your shell and drop it where the shell looks:

```sh
scratchsmith --completions bash | sudo tee /etc/bash_completion.d/scratchsmith
scratchsmith --completions zsh  > ~/.zfunc/_scratchsmith    # ensure ~/.zfunc is on $fpath
scratchsmith --completions fish > ~/.config/fish/completions/scratchsmith.fish
```

## Quick start

Pack a dynamic binary into a scratch image and run it:

```sh
scratchsmith pack ./app
docker run --rm scratchsmith/app:packed --version   # image is named scratchsmith/<name>:packed
```

Inspect the rootfs without building an image — **no Docker daemon needed**:

```sh
scratchsmith pack --no-build --output ./rootfs ./app
```

Or write a **daemonless OCI archive** (loadable by skopeo/buildah, pushable to a registry — no
Docker daemon):

```sh
scratchsmith pack --oci-archive ./app.oci.tar ./app
```

Or **push straight to a registry** — no Docker daemon. Credentials come from your docker config,
so `docker login` once (for GitHub's `ghcr.io`, a token with `write:packages`):

```sh
echo "$GHCR_TOKEN" | docker login ghcr.io -u YOUR_GH_USERNAME --password-stdin
scratchsmith pack --push ghcr.io/you/app:latest ./app
```

Add supply-chain output, verify it starts, and shrink it:

```sh
scratchsmith pack --sbom --strip --smoke ./app        # SBOM + stripped + auto smoke-run
scratchsmith lint --fail-on no-pie --fail-on no-relro ./app   # hardening gate for CI
```

## GitHub Action

Pack in CI with no shell glue. The composite action downloads the signed release binary for the
runner, verifies it against the release checksums, and runs `pack`:

```yaml
- uses: schubydoo/scratchsmith@v0.1.2
  with:
    binary: ./dist/app         # your prebuilt dynamic glibc binary
    sbom: true                 # needs syft on the runner
    strip: true
    smoke: true                # fail the job if the packed image can't start
```

Outputs `image` (the loaded tag), `rootfs` (with `output:`), and the full JSON `report`. To publish
the built image, log in first and set `push`:

```yaml
- uses: docker/login-action@v3
  with: { registry: ghcr.io, username: ${{ github.actor }}, password: ${{ secrets.GITHUB_TOKEN }} }
- uses: schubydoo/scratchsmith@v0.1.2
  with:
    binary: ./dist/app
    push: ghcr.io/${{ github.repository }}:latest
```

Pin to a release tag (`@v0.1.2`) or a commit SHA — the same supply-chain hygiene the tool itself
practices. `version:` overrides which scratchsmith release the action runs (defaults to the pinned
tag, else `latest`).

## Verifying releases

Release artifacts are keyless-signed (cosign) and carry a SLSA build-provenance attestation.
Replace `<ver>` with the bare version you downloaded — e.g. `0.1.0`, no `v` (the tarball adds the
`v` prefix; the image tag doesn't).

```sh
# SLSA provenance — the simplest, ref-agnostic check
gh attestation verify scratchsmith-v<ver>-linux-amd64.tar.gz --repo schubydoo/scratchsmith

# Checksums signature (one cosign signature covers every tarball through its hash)
cosign verify-blob checksums.txt \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp '^https://github\.com/schubydoo/scratchsmith/\.github/workflows/knope-release\.yml@' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
sha256sum -c checksums.txt        # then check the tarball hashes

# The signed GHCR image
cosign verify ghcr.io/schubydoo/scratchsmith:<ver> \
  --certificate-identity-regexp '^https://github\.com/schubydoo/scratchsmith/\.github/workflows/release\.yml@refs/tags/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

## Comparison

Every tool here builds smaller/safer images; they differ mainly in **what you feed them**.

| | Input | No Dockerfile | Prebuilt **dynamic glibc** binaries | Built-in SBOM + hardening | Daemonless build |
|---|---|---|---|---|---|
| **Scratchsmith** | a prebuilt dynamic ELF binary | ✅ | ✅ *(the whole point)* | ✅ SBOM + ELF hardening lint | ✅ `--push` / `--oci-archive` (the *default* sink uses `docker load`) |
| Static + `FROM scratch` | source you can static-link | ✅ (`COPY`) | ❌ must be static | ❌ | ✅ |
| Docker multi-stage | a Dockerfile + source | ❌ | ✅ (you hand-craft it) | ❌ | ❌ needs daemon / BuildKit |
| [apko](https://github.com/chainguard-dev/apko) | apk packages | ✅ | ❌ needs apk packaging | ✅ | ✅ |
| [ko](https://github.com/ko-build/ko) | Go source | ✅ | ❌ Go only | partial | ✅ |
| [slim](https://github.com/slimtoolkit/slim) | an already-built image | ✅ | ✅ (minifies) | security profiles | ❌ needs a built image first |

Scratchsmith owns the one input the others don't serve: **an arbitrary prebuilt dynamic binary**.

## Limitations

- **glibc / host-arch only (for now).** Dynamic musl/Alpine binaries are detected by their
  interpreter and **rejected with a clear error** before anything is staged — never a silently
  broken image. This is a v1 scope choice, not a permanent boundary: musl uses a different loader
  model and has no NSS, so it needs its own resolver backend (a possible future addition).
  (A *static* musl binary is a single self-contained file and packs fine today.) No cross-arch
  resolution yet.
- **`dlopen` is best-effort.** Libraries loaded at runtime via `dlopen` are invisible to static
  analysis; Scratchsmith *warns* when it sees `dlopen` and lets you force-stage them with
  `--include <lib>`. It is not a blanket "any binary just works" guarantee.
- **`docker load` is the *default* sink.** The default hands the image to a local Docker daemon
  for convenience; go daemon-free with `--push <ref>` (straight to a registry), `--oci-archive
  <file>` (an OCI archive), or `--no-build --output` (a rootfs).
- **`pack` doesn't sign the image it *produces* — yet.** Release *artifacts* are cosign-signed
  and carry SLSA provenance ([Verifying releases](#verifying-releases)), but signing the scratch
  image `pack` builds needs a registry push (the daemonless sink) and isn't wired to a flag yet.

## How it works

1. **Resolve** — emulate the `ld.so` search order from the ELF itself (RPATH is transitive,
   RUNPATH is not, `$ORIGIN` is per-object). It never scrapes the host's `ldd`, `ld.so.cache`,
   or `LD_LIBRARY_PATH`, so the result is deterministic.
2. **Stage** — copy the interpreter to its verbatim path, mirror the libraries, recreate
   versioned-soname symlinks, regenerate `ld.so.cache`, and add the glibc NSS pieces.
3. **Assemble** — build a non-root image with reproducible layers (sorted entries, zeroed
   mtime/uid/gid; the uncompressed `diff_id` and the gzip layer digest are computed separately,
   avoiding the classic unpullable-image bug).

## Roadmap

Shipped in v0.1: signed release binaries (amd64 + arm64), cosign keyless signing + SLSA build
provenance, a signed multi-arch GHCR image, a [GitHub Action](#github-action), a Homebrew tap, a
versioned docs site, and **daemonless output** — `--oci-archive` and `--push` (pure-Rust OCI
archive + direct registry push, no Docker daemon). Next:

- **Sign the image `pack` produces** — now that `--push` gives a registry digest to sign.
- **Broader inputs (later)** — a dynamic musl/Alpine backend and cross-arch resolution are
  on the long-term wishlist. No committed date. (`crates.io` publish is also deferred.)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the dev setup, invariants, and PR flow, and the
[Code of Conduct](CODE_OF_CONDUCT.md). Security issues: [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE).
