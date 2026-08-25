# Scratchsmith

**The daemonless supply-chain packager for prebuilt dynamic Linux binaries.**

Point Scratchsmith at a dynamically linked glibc ELF binary and get a minimal `FROM scratch`
OCI image — no Dockerfile, no static-linking prerequisite. It resolves the binary's shared
libraries the way `ld.so` does (RPATH/RUNPATH/`$ORIGIN`, the interpreter, versioned soname
symlinks), stages the glibc pieces nothing else remembers (NSS modules, a working
`nsswitch.conf`, minimal `passwd`/`group`), and assembles a **non-root** image with reproducible
layers.

!!! info "Status — v0.1"
    The core works end to end, and releases are signed and published (see [Install](#install)).
    One honest caveat up front:

    - **Not daemonless *by default* yet.** The default sink hands the image to your local Docker
      daemon via `docker load` (or stages a rootfs with `--no-build`, no daemon), while
      `--oci-archive` writes a daemonless OCI image today. **Direct registry push** — the fully
      daemonless default — is the next milestone; until it lands the default still uses `docker load`.

## Why not just static-link + `FROM scratch`?

If you can rebuild your service as a static binary (`CGO_ENABLED=0`, musl), **do that** — you need
no packer. Scratchsmith is built for the binaries static linking *can't* help:

- **Closed-source / vendor binaries** you can't recompile.
- **glibc binaries** that rely on **NSS**, **`dlopen`**, or **locale** behaviour — static glibc
  quietly breaks these, often only in production.
- Anything where "just rebuild it static" isn't on the table.

That's the wedge. But it's not a fence: Scratchsmith **already packs a static binary too** (the
resolver detects it and stages the single file), so it's equally handy when you just want an SBOM,
a hardening report, a non-root image, and no Dockerfile.

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
| Direct registry push, and signing the image `pack` **produces** | ⏳ planned |

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

Run `scratchsmith doctor` to see which optional external tools (syft, strip, tini, …) are present.

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

Or write a **daemonless OCI archive** (skopeo/buildah/registry-ready — no Docker daemon):

```sh
scratchsmith pack --oci-archive ./app.oci.tar ./app
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

Pin to a release tag (`@v0.1.2`) or a commit SHA. `version:` overrides which scratchsmith release
the action runs (defaults to the pinned tag, else `latest`).

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

## How it works

1. **Resolve** — emulate the `ld.so` search order from the ELF itself (RPATH is transitive, RUNPATH
   is not, `$ORIGIN` is per-object). It never scrapes the host's `ldd`, `ld.so.cache`, or
   `LD_LIBRARY_PATH`, so the result is deterministic.
2. **Stage** — copy the interpreter to its verbatim path, mirror the libraries, recreate
   versioned-soname symlinks, regenerate `ld.so.cache`, and add the glibc NSS pieces.
3. **Assemble** — build a non-root image with reproducible layers (sorted entries, zeroed
   mtime/uid/gid; the uncompressed `diff_id` and the gzip layer digest are computed separately,
   avoiding the classic unpullable-image bug).

For contribution and security-reporting guidance, see the Contributing and Security links in the
navigation — they stay canonical on GitHub.
