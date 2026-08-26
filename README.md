<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/schubydoo/scratchsmith/main/docs/assets/logo-full-white.svg">
    <img alt="Scratchsmith" src="https://raw.githubusercontent.com/schubydoo/scratchsmith/main/docs/assets/logo-full-black.svg" width="440">
  </picture>
</p>

<p align="center">
  <a href="https://github.com/schubydoo/scratchsmith/actions/workflows/ci.yml"><img src="https://github.com/schubydoo/scratchsmith/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://codecov.io/gh/schubydoo/scratchsmith"><img src="https://codecov.io/gh/schubydoo/scratchsmith/branch/main/graph/badge.svg" alt="codecov"></a>
  <a href="https://www.bestpractices.dev/projects/14238"><img src="https://www.bestpractices.dev/projects/14238/badge" alt="OpenSSF Best Practices"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT"></a>
  <a href="https://blog.rust-lang.org/2026/05/28/Rust-1.96.0/"><img src="https://img.shields.io/badge/MSRV-1.96-blue" alt="MSRV 1.96"></a>
</p>

**The daemonless supply-chain packager for prebuilt dynamic Linux binaries.**

Point Scratchsmith at a dynamically linked glibc ELF binary and get a minimal `FROM scratch`
OCI image — no Dockerfile, no static-linking prerequisite. It resolves the binary's shared
libraries the way `ld.so` does (RPATH/RUNPATH/`$ORIGIN`, the interpreter, versioned soname
symlinks), stages the glibc pieces nothing else remembers (NSS modules, a working
`nsswitch.conf`, minimal `passwd`/`group`), and assembles a **non-root** image with
reproducible layers.

<p align="center">
  <img src="docs/demo/scratchsmith.svg" alt="Scratchsmith packing a dynamic glibc binary into a minimal FROM scratch image with an SBOM and a smoke-run, then running it" width="720">
</p>

> **Status — v0.2.** The core works end to end (see [What works today](#what-works-today)), and
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
| Symbol strip (`--strip`), UPX compression (`--upx`), size report, smoke-run (`--smoke`) | ✅ |
| Runtime extras: CA certs (`--ca-certs`), timezone (`--tz`), init/tini (`--init`) | ✅ |
| Config file (`scratchsmith.toml`) + named profiles (`--profile`), JSON output (`--format json`) | ✅ |
| Shell completions — `--completions <bash\|zsh\|fish>` | ✅ |
| **Signed releases** — amd64 + arm64 binaries, cosign-signed checksums + SLSA provenance, signed multi-arch GHCR image | ✅ ([verify](#verifying-releases)) |
| Dynamic musl/Alpine binaries | ❌ rejected loudly (glibc first; a musl backend is a future goal) |
| **Daemonless OCI archive** — `--oci-archive <file>` (no daemon; skopeo/buildah/registry-ready) | ✅ |
| **Daemonless registry push** — `--push <ref>` (no daemon; uses your docker credentials) | ✅ |
| **Signing the image `pack` produces** — `--push --sign` (cosign keyless, by digest) | ✅ |

## Install

**Homebrew** (Linux — scratchsmith packs Linux ELF binaries):

```sh
brew install schubydoo/scratchsmith/scratchsmith
```

Or with **Cargo** (build from source):

```sh
cargo install scratchsmith
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

Add `--sign` to cosign-sign the pushed image by digest (keyless), and `--sbom --sign` to attach
the SBOM as a signed attestation:

```sh
scratchsmith pack --push ghcr.io/you/app:latest --sbom --sign ./app
```

Add supply-chain output, verify it starts, and shrink it:

```sh
scratchsmith pack --sbom --strip --smoke ./app        # SBOM + stripped + auto smoke-run
scratchsmith pack --sbom --sbom-format spdx-json --sbom-file bom.spdx.json ./app   # SPDX SBOM, custom path
scratchsmith lint --fail-on no-pie --fail-on no-relro ./app   # hardening gate for CI
```

Set what the image runs — entrypoint, arguments, environment, working directory, and user:

```sh
scratchsmith pack ./app \
  --entrypoint /app --cmd serve --env LANG=C.UTF-8 --workdir /data --user 65532:65532
```

## Configuration

Instead of a long command line, put the defaults for `pack` in a `scratchsmith.toml` and load it
with `--config`. Every key below maps to a `pack` flag, and **a command-line flag overrides the
file**.

| `scratchsmith.toml` key | CLI flag | What it does |
|---|---|---|
| `binary` | *(positional arg)* | The ELF binary to pack. |
| `entrypoint` | `--entrypoint` | Image `ENTRYPOINT` (defaults to the packed binary's path). |
| `cmd` | `--cmd` | Default arguments appended to the entrypoint (list; `--cmd` is repeatable). |
| `env` | `--env` | Image environment entries, each `KEY=VALUE` (list). |
| `workdir` | `--workdir` | Image `WORKDIR`. |
| `user` | `--user` | Image user `UID[:GID]`. Defaults to a non-root UID; `0`/root prints a warning. |
| `strip` | `--strip` | Strip symbols from the binary and libraries. |
| `upx` | `--upx` | Compress the packed binary with UPX (it self-decompresses at runtime). |
| `smoke` | `--smoke` | Run the built image once and fail if the binary can't start. |
| `sbom` | `--sbom` | Write an SBOM of the packed rootfs (requires `syft`). |
| `sbom-file` | `--sbom-file` | SBOM output path (default: `sbom.json`). |
| `sbom-format` | `--sbom-format` | SBOM format: `cyclonedx-json` (default) or `spdx-json`. |
| `ca-certs` | `--ca-certs` | Add the TLS CA bundle (`/etc/ssl/certs/ca-certificates.crt`). |
| `tz` | `--tz` | Add the resolved local timezone (`/etc/localtime`). |
| `init` | `--init` | Add a minimal init (`tini`) as pid 1 wrapping the entrypoint. |
| `include` | `--include` | Force-stage extra libraries by soname or path — e.g. `dlopen`'d plugins (list). |
| `sign` | `--sign` | cosign-sign the pushed image (keyless, by digest). Requires a push target. |
| `push` | `--push` | Push the image straight to this registry reference, daemonless. |

A full config file, and how to run it:

```toml
# scratchsmith.toml — loaded with `scratchsmith pack --config scratchsmith.toml`.
binary = "./dist/app"
entrypoint = "/app"
cmd = ["--serve"]
env = ["LANG=C.UTF-8"]
workdir = "/data"
user = "65532:65532"
strip = true
upx = true
smoke = true
sbom = true
sbom-file = "sbom.json"
sbom-format = "cyclonedx-json"
ca-certs = true
tz = true
init = true
include = ["libnss_myhostname.so.2"]
sign = true
push = "ghcr.io/you/app:latest"
```

```sh
scratchsmith pack --config scratchsmith.toml                 # binary + all keys come from the file
scratchsmith pack --config scratchsmith.toml --push ghcr.io/you/app:dev ./other   # CLI overrides binary + push
```

The delivery sinks `--oci-archive <file>` and `--no-build` / `--output <dir>`, and the display-only
`--format`, stay command-line-only — they are not config keys.

### Profiles

Group settings under `[profile.<name>]` and pick one with `--profile <name>` (which requires
`--config`). A profile **layers over the base config**, so shared keys live at the top level and
per-environment overrides go in the profile:

```toml
binary = "./dist/app"
strip = true

[profile.ci]                    # scratchsmith pack --config scratchsmith.toml --profile ci
sbom = true
sign = true
push = "ghcr.io/you/app:latest"
```

Values layer in this order, **last wins**: base config → the selected `[profile.<name>]` → any
command-line flag. Booleans OR together (a profile can switch something **on** but not off), a
scalar is replaced by the more specific layer, and a non-empty list replaces the one beneath it.

## GitHub Action

Pack in CI with no shell glue. The composite action downloads the signed release binary for the
runner, verifies it against the release checksums, and runs `pack`:

```yaml
- uses: schubydoo/scratchsmith@v<ver>   # pin to a release tag
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
- uses: schubydoo/scratchsmith@v<ver>   # pin to a release tag
  with:
    binary: ./dist/app
    push: ghcr.io/${{ github.repository }}:latest
```

Pin `@v<ver>` to a specific release tag (or a commit SHA) — the same supply-chain hygiene the tool itself
practices. `version:` overrides which scratchsmith release the action runs (defaults to the pinned
tag, else `latest`).

## Verifying releases

Release artifacts are keyless-signed (cosign) and carry a SLSA build-provenance attestation.
Each release also ships a CycloneDX SBOM of Scratchsmith's own dependency graph
(`scratchsmith-v<ver>.cdx.json`), listed in `checksums.txt` so the signature and provenance
cover it too. Replace `<ver>` with the bare version you downloaded, no leading `v` (the tarball
adds the `v` prefix; the image tag doesn't).

```sh
# SLSA provenance — the simplest, ref-agnostic check
gh attestation verify scratchsmith-v<ver>-linux-amd64.tar.gz --repo schubydoo/scratchsmith

# Checksums signature (one cosign signature covers every tarball through its hash)
cosign verify-blob checksums.txt \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp '^https://github\.com/schubydoo/scratchsmith/\.github/workflows/knope-release\.yml@' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
sha256sum -c checksums.txt        # then check the tarball + SBOM hashes

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

<sub>*Snapshot as of 2026-08 — the other tools evolve; check their own docs for current behavior. Only Scratchsmith's row is kept current here.*</sub>

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
- **Signing the image `pack` produces needs `--push`.** `pack --push --sign` cosign-signs the
  pushed image by digest (keyless), and `--sbom --sign` attaches the SBOM as a signed
  attestation; both only apply to the registry-push sink, since cosign signs a registry image.
  Release *artifacts* are separately cosign-signed with SLSA provenance ([Verifying releases](#verifying-releases)).

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

Shipped so far: signed release binaries (amd64 + arm64), cosign keyless signing + SLSA build
provenance, a signed multi-arch GHCR image, a [GitHub Action](#github-action), a Homebrew tap, a
versioned docs site, **daemonless output** — `--oci-archive` and `--push` (pure-Rust OCI
archive + direct registry push, no Docker daemon) — and **image signing** (`--push --sign`,
cosign keyless, plus SBOM attestation). Next:

- **Broader inputs (later)** — a dynamic musl/Alpine backend and cross-arch resolution are
  on the long-term wishlist. No committed date. (`crates.io` publish is also deferred.)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the dev setup, invariants, and PR flow, and the
[Code of Conduct](CODE_OF_CONDUCT.md). Security issues: [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE).
