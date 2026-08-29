# Usage

## Quick start

Pack a dynamic binary into a scratch image and run it:

```sh
scratchsmith pack ./app
docker run --rm scratchsmith/app:packed --version   # image is named scratchsmith/<name>:packed
```

The default sink loads into Docker. To load with **podman** or **nerdctl** instead (and run the
`--smoke` check with it), pass `--runtime`:

```sh
scratchsmith pack --runtime podman ./app
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

## Supply-chain output, smoke-run, and size gates

```sh
scratchsmith pack --sbom --strip --smoke ./app        # SBOM + stripped + auto smoke-run
scratchsmith pack --sbom --sbom-format spdx-json --sbom-file bom.spdx.json ./app   # SPDX SBOM, custom path
scratchsmith pack --scan --scan-fail-on high ./app    # grype vuln scan; fail the build on a high+ CVE
scratchsmith pack --strip --max-size 8MB ./app        # fail the build if the staged image exceeds 8 MB
scratchsmith lint --fail-on no-pie --fail-on no-relro ./app   # hardening gate for CI
```

## Multi-arch images

Scratchsmith resolves against the host's libraries, so it packs for the architecture it runs on.
To publish a multi-arch image, run `pack --push` on each architecture (a CI matrix), then combine
the per-arch images into one **multi-arch OCI image index** with `index` — the daemonless
equivalent of `docker manifest create`, with no Docker or buildx:

```sh
# on the amd64 runner
scratchsmith pack --push ghcr.io/you/app:1.0-amd64 ./app
# on the arm64 runner
scratchsmith pack --push ghcr.io/you/app:1.0-arm64 ./app

# then, once both are pushed, assemble the index that consumers pull by one tag
scratchsmith index ghcr.io/you/app:1.0 \
  ghcr.io/you/app:1.0-amd64 \
  ghcr.io/you/app:1.0-arm64
```

Each source's platform is read from its own image config — nothing is rebuilt and no cross-arch
resolution happens. The sources must already be pushed and must live in the **target's repository**
(an index references its children by digest within one repository) — typically the same repo with a
different tag, as above. Add `--sign` to cosign-sign the index by digest.

## Image metadata and entrypoint

Set what the image runs — entrypoint, arguments, environment, working directory, and user:

```sh
scratchsmith pack ./app \
  --entrypoint /app --cmd serve --env LANG=C.UTF-8 --workdir /data --user 65532:65532 \
  --label role=api --healthcheck /app --healthcheck --health
```

`--healthcheck` (like `--cmd`) is repeatable, and each token is one argument of a single exec
command — so `--healthcheck /app --healthcheck --health` is the one command `["/app", "--health"]`
(the same as `healthcheck = ["/app", "--health"]` in the [config](configuration.md)), not two
healthchecks.

## In CI

To pack in a GitHub Actions workflow with the composite action instead of shelling out to the CLI,
see **[GitHub Action](github-action.md)**.

## Run `pack` in a container — the `:toolbox` image

The `FROM scratch` release image can only run `--version` / `lint` / `doctor`. The **`:toolbox`**
image bundles the full `pack` toolchain (ldconfig, strip, syft, grype, cosign, upx, tini, the
docker CLI) on a Wolfi base, so `pack` itself runs inside a container:

```sh
# Daemonless — no socket needed; write an OCI archive or push straight to a registry.
docker run --rm -v "$PWD:/w" -w /w ghcr.io/schubydoo/scratchsmith:toolbox \
  pack --oci-archive app.oci.tar ./app
docker run --rm -v "$PWD:/w" -w /w ghcr.io/schubydoo/scratchsmith:toolbox \
  pack --push ghcr.io/you/app:1.0 ./app
```

Prefer the daemonless sinks (`--push` / `--oci-archive`) in CI. The **default `docker load` sink**
needs a host engine, so mount its socket — **which is root-equivalent on the host**, so use it only
where you trust the workflow:

```sh
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock ghcr.io/schubydoo/scratchsmith:toolbox \
  pack ./app
```

Tags: `:toolbox` (latest), `:X.Y.Z-toolbox`, `:X.Y-toolbox`. Verify its signature exactly like the
scratch image — see [Verifying releases](verifying.md).
