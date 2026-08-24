# Changelog

All notable changes to Scratchsmith are documented here. This file is generated from
`.changeset/*.md` fragments by [knope](https://knope.tech) — do not hand-edit it.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) (pre-1.0:
breaking changes bump the minor).
## 0.1.3 (2026-08-24)

### Features

#### Homebrew tap — `brew install schubydoo/scratchsmith/scratchsmith` ([#30](https://github.com/schubydoo/scratchsmith/pull/30))

Scratchsmith is now installable via a Homebrew tap (Linux amd64/arm64, from the signed
release tarballs). The formula (`Formula/scratchsmith.rb`) is regenerated from each
release's cosign-verified `checksums.txt` by `packaging-bump.yml`, which opens an
auto-merging PR; that merge dispatches the [tap](https://github.com/schubydoo/homebrew-scratchsmith)
to mirror it — so `brew upgrade` tracks releases hands-free.

## 0.1.2 (2026-08-24)

### Features

#### GitHub Action — `pack` in CI with no shell glue ([#27](https://github.com/schubydoo/scratchsmith/pull/27))

A composite `schubydoo/scratchsmith` action downloads the signed release binary for the runner,
verifies it against the release checksums, and runs `pack`. Inputs map to the real pack flags —
`sbom`, `strip`, `user` (non-root by default), `output`, `smoke`, `ca-certs`/`tz`/`init`, `include`,
plus an `args` escape hatch — and it exposes `image`, `rootfs`, and the full JSON `report` as
outputs. An optional `push` input tags and pushes the built image (after your own registry login).

```yaml
- uses: schubydoo/scratchsmith@v0.1.2
  with:
    binary: ./dist/app
    strip: true
    smoke: true
```

## 0.1.1 (2026-08-24)

### Fixes

#### Docs — install from signed releases, verification steps, and post-launch status ([#25](https://github.com/schubydoo/scratchsmith/pull/25))

The README and docs site now cover installing from the signed release binaries (amd64/arm64) and
the GHCR image, add a **Verifying releases** section (`cosign` + `gh attestation verify`), and
correct the pre-release "not published / signing planned" wording now that v0.1 ships signed,
published releases. The remaining "signing" gap — signing the image `pack` itself produces — is
called out precisely (it needs the daemonless registry push).

## 0.1.0 (2026-08-24)

### Features

#### Initial release — pack prebuilt dynamic glibc binaries into `FROM scratch` images ([#22](https://github.com/schubydoo/scratchsmith/pull/22))

Scratchsmith takes a dynamically linked glibc ELF and produces a minimal, non-root
`FROM scratch` OCI image — no Dockerfile, no static-linking prerequisite. v0.1.0 ships:

- **`ld.so`-faithful dependency resolution** — RPATH/RUNPATH/`$ORIGIN`, the interpreter, and
  versioned soname symlinks, resolved the way the dynamic linker does.
- **glibc pieces nothing else stages** — NSS modules, a working `nsswitch.conf`, and minimal
  `passwd`/`group`, so name-service lookups (`getent hosts`) work inside scratch.
- **Non-root by default** (UID 65532) with reproducible layers.
- **`pack`** — assemble the image (loaded via `docker load`), or stage the rootfs with
  `--no-build --output` (no daemon needed), plus symbol strip (`--strip`), a size report, and a
  smoke-run (`--smoke`).
- **`lint`** — ELF hardening report (PIE/RELRO/NX/canary/FORTIFY), gate a build with `--fail-on`.
- **`doctor`** — probe for optional external tools (syft, strip, tini, …).
- **SBOM generation** — `--sbom` in CycloneDX or SPDX (via syft).
- **`dlopen` gap detection** with an `--include` escape hatch to force-stage extra libraries.
- **Runtime extras** — CA certs (`--ca-certs`), timezone (`--tz`), init/tini (`--init`).
- **Config file** (`scratchsmith.toml`) and JSON output (`--format json`).
- **Shell completions** — `--completions bash|zsh|fish`.
- **amd64 and arm64** binaries.

Dynamic musl/Alpine binaries are rejected loudly (glibc first; a musl backend is a future goal).
The daemonless OCI-archive + registry-push sink is the next milestone — today the image is handed
to your local Docker daemon via `docker load`.
