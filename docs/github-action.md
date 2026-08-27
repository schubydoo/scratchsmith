# GitHub Action

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

To publish the built image, log in first and set `push`:

```yaml
- uses: docker/login-action@v3
  with: { registry: ghcr.io, username: ${{ github.actor }}, password: ${{ secrets.GITHUB_TOKEN }} }
- uses: schubydoo/scratchsmith@v<ver>   # pin to a release tag
  with:
    binary: ./dist/app
    push: ghcr.io/${{ github.repository }}:latest
```

Set image metadata, gate on vulnerabilities, or cap the size. The list-valued inputs (`cmd`, `env`,
`label`, `healthcheck`, `include`) take **one value per line**:

```yaml
- uses: schubydoo/scratchsmith@v<ver>
  with:
    binary: ./dist/app
    entrypoint: /app
    env: |
      LANG=C.UTF-8
    workdir: /data
    label: |
      org.opencontainers.image.source=https://github.com/you/app
      role=api
    healthcheck: |
      /app
      --health
    scan: true
    scan-fail-on: high        # needs grype on the runner
    max-size: 25MB
```

Pin `@v<ver>` to a specific release tag (or a commit SHA) — the same supply-chain hygiene the tool
itself practices. `version:` overrides which scratchsmith release the action runs (defaults to the
pinned tag, else `latest`).

## Inputs

Most inputs map to the `pack` flag of the same name — see [Configuration](configuration.md) for what
each does and [Usage](usage.md) for the equivalent command-line recipes. A few are action-specific:
`version` picks which release to download, `output` maps to `--no-build --output`, and `args` is a
verbatim escape hatch for any flag without a dedicated input (e.g. `--sign`, `--oci-archive`). Note
`push` publishes with `docker tag`/`docker push`, **not** pack's daemonless, cosign-signable `--push`.

| Input | Default | Description |
|---|---|---|
| `binary` | *(required)* | Path to the dynamically linked glibc ELF binary to pack. |
| `version` | *(the pinned tag, else `latest`)* | Which scratchsmith release to download — a tag like `v1.0.0`, or `latest`. |
| `output` | | Stage the rootfs into this directory instead of building an image (`--no-build`). |
| `entrypoint` | *(the binary's path)* | Image `ENTRYPOINT`. |
| `cmd` | | Default arguments appended to the entrypoint, one per line. |
| `env` | | Image environment entries, one `KEY=VALUE` per line. |
| `workdir` | | Image `WORKDIR`. |
| `user` | `65532` | Image user `UID[:GID]`; `0` warns. |
| `label` | | OCI image labels, one `KEY=VALUE` per line. |
| `healthcheck` | | `HEALTHCHECK` in exec form, one token per line; must name an executable in the image. |
| `strip` | `false` | Strip symbols from the binary and libraries. |
| `upx` | `false` | Compress the binary with UPX (needs `upx` on the runner). |
| `smoke` | `false` | After building, run the image once and fail if the binary can't start. |
| `sbom` | `false` | Generate an SBOM of the packed rootfs (needs `syft` on the runner). |
| `sbom-file` | `sbom.json` | SBOM output path. Requires `sbom` — ignored on its own. |
| `sbom-format` | `cyclonedx-json` | SBOM format: `cyclonedx-json` or `spdx-json`. |
| `scan` | `false` | Vulnerability-scan the rootfs with grype (needs `grype`; reuses the SBOM if `sbom` is set). |
| `scan-fail-on` | | Fail on a grype finding at or above this severity (`negligible`…`critical`). Implies `scan`. |
| `ca-certs` | `false` | Add the TLS CA bundle to the image. |
| `tz` | `false` | Add the resolved local timezone to the image. |
| `init` | `false` | Add a minimal init (tini) as pid 1 wrapping the entrypoint. |
| `include` | | Extra libraries to force-stage (e.g. `dlopen`'d plugins), one soname/path per line. |
| `max-size` | | Fail if the fully-staged image exceeds this size — e.g. `25MB`, `512KiB`, or a byte count. |
| `push` | | Tag the built image as this registry ref and `docker push` it (needs a prior registry login; not compatible with `output`). |
| `args` | | Extra raw `pack` flags appended verbatim — the escape hatch for anything above. |

## Outputs

| Output | Description |
|---|---|
| `image` | The loaded image tag (empty when `output` staged a rootfs instead). |
| `rootfs` | The staged rootfs directory (empty when an image was built). |
| `report` | The full pack report as JSON. |
