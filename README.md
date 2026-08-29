<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/schubydoo/scratchsmith/main/docs/assets/logo-full-white.svg">
    <img alt="Scratchsmith" src="https://raw.githubusercontent.com/schubydoo/scratchsmith/main/docs/assets/logo-full-black.svg" width="440">
  </picture>
</p>

<p align="center">
  <a href="https://github.com/schubydoo/scratchsmith/actions/workflows/ci.yml"><img src="https://github.com/schubydoo/scratchsmith/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://codecov.io/gh/schubydoo/scratchsmith"><img src="https://codecov.io/gh/schubydoo/scratchsmith/branch/main/graph/badge.svg" alt="codecov"></a>
  <a href="https://schubydoo.github.io/scratchsmith/"><img src="https://img.shields.io/badge/docs-schubydoo.github.io-4051b5?logo=materialformkdocs&logoColor=white" alt="Documentation"></a>
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
| Pack a dynamic glibc ELF → runnable `FROM scratch` image | ✅ (loaded via `docker`/`podman`/`nerdctl`) |
| `ld.so`-faithful dependency resolution (RPATH/RUNPATH/`$ORIGIN`, interpreter, sonames) | ✅ |
| glibc **NSS** support staged — name-service lookups like `getent hosts` work | ✅ |
| **Non-root** by default (UID 65532), reproducible layers | ✅ |
| **SBOM** generation — `--sbom` (CycloneDX or SPDX, via syft) | ✅ |
| **Vulnerability scan** — `--scan` (grype), gate with `--scan-fail-on <severity>` | ✅ |
| **ELF hardening lint** — `lint` (PIE/RELRO/NX/canary/FORTIFY), gate with `--fail-on` | ✅ |
| `dlopen` gap **detection** + `--include` escape hatch | ✅ |
| Symbol strip (`--strip`), UPX compression (`--upx`), size report, smoke-run (`--smoke`) | ✅ |
| Image **size budget** — `--max-size <SIZE>` (fail the build when the staged image exceeds it) | ✅ |
| Runtime extras: CA certs (`--ca-certs`), timezone (`--tz`), init/tini (`--init`) | ✅ |
| Image metadata — labels (`--label`), `HEALTHCHECK` (`--healthcheck`) | ✅ |
| Config file (`scratchsmith.toml`) + named profiles (`--profile`), JSON output (`--format json`) | ✅ |
| **Pluggable runtime** — `--runtime` (docker / podman / nerdctl) for the default load sink | ✅ |
| Shell completions — `--completions <bash\|zsh\|fish>` | ✅ |
| **Signed releases** — amd64 + arm64 binaries, cosign-signed checksums + SLSA provenance, signed multi-arch GHCR image | ✅ ([verify](docs/verifying.md)) |
| Dynamic musl/Alpine binaries | ❌ rejected loudly (glibc first; a musl backend is a future goal) |
| **Daemonless OCI archive** — `--oci-archive <file>` (no daemon; skopeo/buildah/registry-ready) | ✅ |
| **Daemonless registry push** — `--push <ref>` (no daemon; uses your docker credentials) | ✅ |
| **Signing the image `pack` produces** — `--push --sign` (cosign keyless, by digest) | ✅ |
| **Multi-arch image index** — `index` (combine per-arch pushes into one tag, daemonless) | ✅ |

## Install

Scratchsmith is **Linux only** (amd64/arm64) — it stages a Linux glibc rootfs, so it does not run on
macOS or native Windows; use a Linux container or WSL2 there.

```sh
# One-line install — downloads the signed binary and verifies its cosign-signed checksums.
curl -fsSL https://raw.githubusercontent.com/schubydoo/scratchsmith/main/install.sh | bash

# ...or a package manager:
brew install schubydoo/scratchsmith/scratchsmith
cargo install scratchsmith
```

Release binaries, the signed container image, source builds, uninstall, and shell completions:
**[Installation](docs/installation.md)**. Then run `scratchsmith doctor` to see which optional
external tools (syft, strip, tini, …) are present.

## Quick start

Pack a dynamic binary into a scratch image and run it:

```sh
scratchsmith pack ./app
docker run --rm scratchsmith/app:packed --version   # image is named scratchsmith/<name>:packed
```

Skip the daemon entirely — stage a rootfs, write an OCI archive, or push straight to a registry:

```sh
scratchsmith pack --no-build --output ./rootfs ./app      # a plain rootfs, no daemon
scratchsmith pack --oci-archive ./app.oci.tar ./app       # an OCI archive (skopeo/buildah-ready)
scratchsmith pack --push ghcr.io/you/app:latest ./app     # straight to a registry
```

More recipes — SBOM/scan/size gates, image metadata, and signing: **[Usage](docs/usage.md)**. Packing
in CI: **[GitHub Action](docs/github-action.md)**.

## Configuration

Put the defaults for `pack` in a `scratchsmith.toml` and load it with `--config`; a command-line
flag overrides the file, and `[profile.<name>]` blocks layer environment-specific overrides on top.
The full key reference and layering rules: **[Configuration](docs/configuration.md)**.

## Verifying releases

Every release is keyless-signed with cosign, carries a SLSA build-provenance attestation, and ships
a CycloneDX SBOM of its own dependency graph. The exact `gh attestation` / `cosign verify` commands:
**[Verifying releases](docs/verifying.md)**.

## Documentation

📖 **Full docs: <https://schubydoo.github.io/scratchsmith/>** (searchable, versioned). The sources also render on GitHub:

- **[Installation](docs/installation.md)** — every install method, uninstall, and shell completions.
- **[Usage](docs/usage.md)** — pack recipes, daemonless output, and image metadata.
- **[GitHub Action](docs/github-action.md)** — pack in a CI workflow with the composite action.
- **[Configuration](docs/configuration.md)** — the `scratchsmith.toml` reference and profiles.
- **[Verifying releases](docs/verifying.md)** — cosign signatures, SLSA provenance, and the SBOM.
- **[Comparison & limitations](docs/comparison.md)** — how Scratchsmith compares, and what it does not do.
- **[Architecture](docs/architecture.md)** — how resolve → stage → assemble works, and the 1.0 stability contract.
- **[Contributing](CONTRIBUTING.md)** · **[Compatibility](COMPATIBILITY.md)** · **[Security](SECURITY.md)** · **[Code of Conduct](CODE_OF_CONDUCT.md)**

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the dev setup, invariants, and PR flow, and the
[Code of Conduct](CODE_OF_CONDUCT.md). Security issues: [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE).
