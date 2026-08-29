<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/logo-mark-white.svg">
    <img alt="" src="assets/logo-mark-black.svg" width="96">
  </picture>
</p>

# Scratchsmith

**The daemonless supply-chain packager for prebuilt dynamic Linux binaries.**

Point Scratchsmith at a dynamically linked glibc ELF binary and get a minimal `FROM scratch`
OCI image — no Dockerfile, no static-linking prerequisite. It resolves the binary's shared
libraries the way `ld.so` does (RPATH/RUNPATH/`$ORIGIN`, the interpreter, versioned soname
symlinks), stages the glibc pieces nothing else remembers (NSS modules, a working
`nsswitch.conf`, minimal `passwd`/`group`), and assembles a **non-root** image with reproducible
layers.

![Scratchsmith packing a dynamic glibc binary into a minimal FROM scratch image with an SBOM and a smoke-run, then running it](demo/scratchsmith.svg)

## Why not just static-link + `FROM scratch`?

If you can rebuild your service as a static binary (`CGO_ENABLED=0`, musl), **do that** — you need
no packer. Scratchsmith is built for the binaries static linking *can't* help:

- **Closed-source / vendor binaries** you can't recompile.
- **glibc binaries** that rely on **NSS**, **`dlopen`**, or **locale** behaviour — static glibc
  quietly breaks these, often only in production.
- Anything where "just rebuild it static" isn't on the table.

That's the wedge. But it's not a fence: Scratchsmith **already packs a static binary too** (the
resolver detects it and stages the single file), so it's equally handy when you just want an SBOM,
a hardening report, a non-root image, and no Dockerfile. More: [Comparison & limitations](comparison.md).

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
| **Signed releases** — amd64 + arm64 binaries, cosign-signed checksums + SLSA provenance, signed multi-arch GHCR image | ✅ ([verify](verifying.md)) |
| **`:toolbox` image** — a runnable image (Wolfi + the full toolchain) that runs `pack` *inside* a container | ✅ ([usage](usage.md)) |
| Dynamic musl/Alpine binaries | ❌ rejected loudly (glibc first; a musl backend is a future goal) |
| **Daemonless OCI archive** — `--oci-archive <file>` (no daemon; skopeo/buildah/registry-ready) | ✅ |
| **Daemonless registry push** — `--push <ref>` (no daemon; uses your docker credentials) | ✅ |
| **Signing the image `pack` produces** — `--push --sign` (cosign keyless, by digest) | ✅ |
| **Multi-arch image index** — `index` (combine per-arch pushes into one tag, daemonless) | ✅ |

## Next

- [Installation](installation.md) — one-line install, packages, release binaries, and completions.
- [Usage](usage.md) — pack recipes and daemonless output.
- [GitHub Action](github-action.md) — pack in a CI workflow with the composite action.
- [Configuration](configuration.md) — the `scratchsmith.toml` key reference and profiles.
- [Verifying releases](verifying.md) — cosign signatures, SLSA provenance, and the SBOM.
- [Comparison & limitations](comparison.md) — how it compares, and what it does not do.
- [Architecture](architecture.md) — how resolve → stage → assemble works, and the 1.0 stability contract.
