# Scratchsmith

**The daemonless supply-chain packager for prebuilt dynamic Linux binaries.**

Point Scratchsmith at a dynamically linked glibc ELF binary and get a minimal `FROM scratch`
OCI image — no Dockerfile, no static-linking prerequisite. It resolves the binary's shared
libraries the way `ld.so` does (RPATH/RUNPATH/`$ORIGIN`, the interpreter, versioned soname
symlinks), stages the glibc pieces nothing else remembers (NSS modules, a working
`nsswitch.conf`, minimal `passwd`/`group`), and assembles a **non-root** image with reproducible
layers.

!!! info "Status — v0.2"
    The core works end to end, and releases are signed and published (see [Install](#install)).
    One honest caveat up front:

    - **Daemonless is here.** `--push` uploads the image straight to a registry and `--oci-archive`
      writes an OCI archive — both with no Docker daemon. The default sink still uses `docker load`
      (or `--no-build` for a rootfs) for local convenience; reach for `--push` / `--oci-archive` to
      take the daemon fully out of the loop.

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
| **Vulnerability scan** — `--scan` (grype), gate with `--scan-fail-on <severity>` | ✅ |
| **ELF hardening lint** — `lint` (PIE/RELRO/NX/canary/FORTIFY), gate with `--fail-on` | ✅ |
| `dlopen` gap **detection** + `--include` escape hatch | ✅ |
| Symbol strip (`--strip`), UPX compression (`--upx`), size report, smoke-run (`--smoke`) | ✅ |
| Image **size budget** — `--max-size <SIZE>` (fail the build when the staged image exceeds it) | ✅ |
| Runtime extras: CA certs (`--ca-certs`), timezone (`--tz`), init/tini (`--init`) | ✅ |
| Image metadata — labels (`--label`), `HEALTHCHECK` (`--healthcheck`) | ✅ |
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

Or **push straight to a registry** — no Docker daemon. Credentials come from your docker config,
so `docker login` once (for GitHub's `ghcr.io`, a token with `write:packages`):

```sh
echo "$GHCR_TOKEN" | docker login ghcr.io -u YOUR_GH_USERNAME --password-stdin
scratchsmith pack --push ghcr.io/you/app:latest ./app
```

Add supply-chain output, verify it starts, and shrink it:

```sh
scratchsmith pack --sbom --strip --smoke ./app        # SBOM + stripped + auto smoke-run
scratchsmith pack --sbom --sbom-format spdx-json --sbom-file bom.spdx.json ./app   # SPDX SBOM, custom path
scratchsmith pack --scan --scan-fail-on high ./app    # grype vuln scan; fail the build on a high+ CVE
scratchsmith pack --strip --max-size 8MB ./app        # fail the build if the staged image exceeds 8 MB
scratchsmith lint --fail-on no-pie --fail-on no-relro ./app   # hardening gate for CI
```

Set what the image runs — entrypoint, arguments, environment, working directory, and user:

```sh
scratchsmith pack ./app \
  --entrypoint /app --cmd serve --env LANG=C.UTF-8 --workdir /data --user 65532:65532 \
  --label role=api --healthcheck /app --healthcheck --health
```

`--healthcheck` (like `--cmd`) is repeatable, and each token is one argument of a single exec
command — so `--healthcheck /app --healthcheck --health` is the one command `["/app", "--health"]`
(the same as `healthcheck = ["/app", "--health"]` in the config below), not two healthchecks.

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
| `label` | `--label` | OCI image label `KEY=VALUE` (list; `--label` is repeatable). |
| `healthcheck` | `--healthcheck` | Container `HEALTHCHECK` in exec form (list; repeatable). It runs inside the scratch image, so it must name an executable present there — typically the packed binary. |
| `strip` | `--strip` | Strip symbols from the binary and libraries. |
| `upx` | `--upx` | Compress the packed binary with UPX (it self-decompresses at runtime). |
| `smoke` | `--smoke` | Run the built image once and fail if the binary can't start. |
| `sbom` | `--sbom` | Write an SBOM of the packed rootfs (requires `syft`). |
| `sbom-file` | `--sbom-file` | SBOM output path (default: `sbom.json`). |
| `sbom-format` | `--sbom-format` | SBOM format: `cyclonedx-json` (default) or `spdx-json`. |
| `scan` | `--scan` | Vulnerability-scan the packed rootfs with grype (reuses the SBOM if `--sbom` is set, else scans the rootfs). |
| `scan-fail-on` | `--scan-fail-on` | Fail the pack on a grype finding at or above this severity: `negligible`/`low`/`medium`/`high`/`critical` (implies `--scan`). `negligible` blocks everything, including findings grype couldn't rank; stricter levels ignore unrankable findings. |
| `ca-certs` | `--ca-certs` | Add the TLS CA bundle (`/etc/ssl/certs/ca-certificates.crt`). |
| `tz` | `--tz` | Add the resolved local timezone (`/etc/localtime`). |
| `init` | `--init` | Add a minimal init (`tini`) as pid 1 wrapping the entrypoint. |
| `include` | `--include` | Force-stage extra libraries by soname or path — e.g. `dlopen`'d plugins (list). |
| `sign` | `--sign` | cosign-sign the pushed image (keyless, by digest). Requires a push target. |
| `push` | `--push` | Push the image straight to this registry reference, daemonless. |
| `max-size` | `--max-size` | Fail the pack if the packed image (the fully-staged rootfs — payload + NSS includes + runtime extras) exceeds this size — e.g. `12MB`, `512KiB`, or a bare byte count (K/M/G are ×1000, Ki/Mi/Gi are ×1024). |

A full config file, and how to run it:

```toml
# scratchsmith.toml — loaded with `scratchsmith pack --config scratchsmith.toml`.
binary = "./dist/app"
entrypoint = "/app"
cmd = ["--serve"]
env = ["LANG=C.UTF-8"]
workdir = "/data"
user = "65532:65532"
label = ["role=api"]
healthcheck = ["/app", "--health"]
strip = true
upx = true
smoke = true
sbom = true
sbom-file = "sbom.json"
sbom-format = "cyclonedx-json"
scan = true
scan-fail-on = "high"
ca-certs = true
tz = true
init = true
include = ["libnss_myhostname.so.2"]
sign = true
push = "ghcr.io/you/app:latest"
max-size = "50MB"
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

Pin `@v<ver>` to a specific release tag (or a commit SHA). `version:` overrides which scratchsmith release
the action runs (defaults to the pinned tag, else `latest`).

## Verifying releases

Release artifacts are keyless-signed (cosign) and carry a SLSA build-provenance attestation.
Each release also ships a CycloneDX SBOM of Scratchsmith's own dependency graph
(`scratchsmith-v<ver>.cdx.json`), listed in `checksums.txt` so the signature and provenance
cover it too. It reflects the full `Cargo.lock` graph, so it includes build- and
dev-dependencies, not only the crates that link into the shipped binary.

Replace `<ver>` with the bare version you downloaded, no leading `v` (the tarball adds the
`v` prefix; the image tag doesn't).

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
