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

> **Status — v0.1, pre-release.** The core works end to end (see [What works
> today](#what-works-today)). Two honest caveats up front:
> - **Not yet published.** No `cargo install` / Homebrew / release binaries yet — [build from
>   source](#install).
> - **Not daemonless *yet*.** Today the finished image is handed to your local Docker daemon via
>   `docker load` (or staged to a directory with `--no-build`, which needs no daemon at all). The
>   pure-Rust daemonless sink — OCI archive + direct registry push — is the next milestone. Until
>   it lands, the "daemonless" in the tagline is the design goal, not a shipped fact.

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
| Dynamic musl/Alpine binaries | ❌ rejected loudly (glibc first; a musl backend is a future goal) |
| Daemonless OCI archive + registry push, image **signing**, SLSA provenance | ⏳ planned (see [Roadmap](#roadmap)) |

## Install

Not yet published. Build from source (Rust **1.96+**):

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

Add supply-chain output, verify it starts, and shrink it:

```sh
scratchsmith pack --sbom --strip --smoke ./app        # SBOM + stripped + auto smoke-run
scratchsmith lint --fail-on no-pie --fail-on no-relro ./app   # hardening gate for CI
```

## Comparison

Every tool here builds smaller/safer images; they differ mainly in **what you feed them**.

| | Input | No Dockerfile | Prebuilt **dynamic glibc** binaries | Built-in SBOM + hardening | Daemonless build |
|---|---|---|---|---|---|
| **Scratchsmith** | a prebuilt dynamic ELF binary | ✅ | ✅ *(the whole point)* | ✅ SBOM + ELF hardening lint | ⚠️ staging yes (`--no-build`); image load uses `docker load` today |
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
- **`docker load` sink (for now).** Building the *image* currently needs a Docker daemon; use
  `--no-build --output` for a daemon-free rootfs. Daemonless OCI archive + push is next.
- **Signing is not wired yet.** `--sbom` and `lint` are real today; cosign signing / SLSA
  provenance are on the roadmap, not in this release. This README won't claim them until they
  ship.

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

Distribution and supply-chain identity are v0.1/v0.2 goals, not afterthoughts:

- **Daemonless output** — pure-Rust OCI archive + direct registry push (drops the Docker
  dependency).
- **Signing & provenance** — cosign keyless signing and SLSA build provenance on release.
- **Distribution** — signed release binaries, a GitHub Action, and a Homebrew tap.
- **Docs** — a versioned documentation site.
- **Broader inputs (later)** — a dynamic musl/Alpine backend and cross-arch resolution are
  on the long-term wishlist. No committed date.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the dev setup, invariants, and PR flow, and the
[Code of Conduct](CODE_OF_CONDUCT.md). Security issues: [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE).
