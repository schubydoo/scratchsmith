---
default: minor
---

#### Initial release — pack prebuilt dynamic glibc binaries into `FROM scratch` images

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
