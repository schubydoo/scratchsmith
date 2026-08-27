# Comparison & limitations

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

## How Scratchsmith compares

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
  Release *artifacts* are separately cosign-signed with SLSA provenance ([Verifying releases](verifying.md)).
