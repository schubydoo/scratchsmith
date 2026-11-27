# GitHub Action

Pack in CI with no shell glue. The composite action downloads the signed release binary for the
runner, verifies it against the release checksums, and runs `pack`:

```yaml
- uses: schubydoo/scratchsmith@v<ver>   # pin to a release tag
  with:
    binary: ./dist/app         # your prebuilt dynamic glibc or musl binary
    sbom: true                 # needs syft on the runner
    strip: true
    smoke: true                # fail the job if the packed image can't start
```

A musl binary (x86_64 only) packs the same way, but `pack` reads its libraries from the runner,
so the runner needs musl's loader at `/lib/ld-musl-x86_64.so.1`. On an Ubuntu runner, install
the `musl` package in an earlier step. See [Pack a musl binary](usage.md#pack-a-musl-binary).
musl needs scratchsmith v2.3.0 or later.

To publish the built image, log in first and set `push`:

```yaml
- uses: docker/login-action@v4
  with:
    registry: ghcr.io
    username: ${{ github.actor }}
    password: ${{ secrets.GITHUB_TOKEN }}   # the job needs `permissions: packages: write`
- uses: schubydoo/scratchsmith@v<ver>   # pin to a release tag
  with:
    binary: ./dist/app
    push: ghcr.io/${{ github.repository }}:latest   # must be lowercase: spell it out if the name has capitals
```

Ten inputs take **one value per line**: `cmd`, `env`, `label`, `healthcheck`, `add-file`,
`add-binary`, `locale`, `include`, `deny`, and `require`. Set image metadata, gate on vulnerabilities, or cap
the size:

```yaml
- uses: schubydoo/scratchsmith@v<ver>
  with:
    binary: ./dist/app
    env: |
      LANG=C.UTF-8
    workdir: /data
    label: |
      org.opencontainers.image.source=https://github.com/you/app
      role=api
    healthcheck: |
      ${{ github.workspace }}/dist/app
      --health
    scan: true
    scan-fail-on: high        # needs grype on the runner
    max-size: 25MB
```

The binary is staged at its real absolute path on the runner, and that path is also the default
entrypoint. So a healthcheck or `entrypoint` has to name that path, not a short one like `/app`.

Pin `@v<ver>` to a specific release tag (or a commit SHA). That is the same supply-chain hygiene the
tool itself practices. `version:` overrides which scratchsmith release the action runs (defaults to
the pinned tag, else `latest`). The action only reads a version from a `vX.Y.Z` tag ref, so if you
pin a commit SHA, also set `version:` to the matching release (for example `version: v2.2.0`).
Otherwise a SHA pin downloads the latest release.

## Inputs

Most inputs map to the `pack` flag of the same name. See [Configuration](configuration.md) for what
each does, and [Usage](usage.md) for the equivalent command-line recipes. A few inputs are
action-specific. `version` picks which release to download. `output` maps to `--no-build --output`.
`args` is split on whitespace and appended to the command. Quotes are not honoured, so a value
cannot hold a space, and an unquoted `*` or `?` expands against the workspace. It is the escape
hatch for any flag without a dedicated input, for example
`--oci-archive out.tar`, or `--push <ref> --sign` for a daemonless, cosign-signed push (that job
needs `permissions: id-token: write`). With `--push` or `--oci-archive` in `args`, the `image`
output is empty, because only the default docker-load sink sets it. Note that `push` publishes with
`docker tag`/`docker push`, **not** pack's daemonless, cosign-signable `--push`.

The action reads the JSON report, so every pack through it runs the `--packages` lookup by default. The
`report` output holds a `packages` list and a `timings` object. To turn the lookup off, set
the `packages` input to `none`.

| Input | Default | Description |
|---|---|---|
| `binary` | *(required)* | Path to the dynamically linked ELF binary to pack (glibc, or musl on x86_64). |
| `version` | *(the pinned tag, else `latest`)* | Which scratchsmith release to download: a tag like `v1.0.0`, or `latest`. |
| `output` | | Stage the rootfs into this directory instead of building an image (`--no-build`). The directory must be new or empty. |
| `entrypoint` | *(the binary's path)* | Image `ENTRYPOINT`. |
| `cmd` | | Default arguments appended to the entrypoint, one per line. |
| `env` | | Image environment entries, one `KEY=VALUE` per line. A line with no `=` fails the pack. Write `KEY=` for an empty value. |
| `workdir` | | Image `WORKDIR`. |
| `user` | `65532` | Image user `UID[:GID]`. `0` warns. |
| `label` | | OCI image labels, one `KEY=VALUE` per line. A line with no `=` fails the pack. Write `KEY=` for an empty value. |
| `healthcheck` | | `HEALTHCHECK` in exec form, one token per line. It must name an executable in the image. |
| `strip` | `false` | Strip symbols from the binary and libraries. |
| `upx` | `false` | Compress the binary with UPX (needs `upx` on the runner). |
| `smoke` | `false` | After the build, run the image once. If the binary cannot start, the job fails. It cannot be combined with `output`, because `output` builds no image. |
| `sbom` | `false` | Generate an SBOM of the packed rootfs (needs `syft` on the runner). |
| `sbom-file` | `sbom.json` | SBOM output path. Requires `sbom`, and is ignored on its own. |
| `sbom-format` | `cyclonedx-json` | SBOM format: `cyclonedx-json` or `spdx-json`. |
| `scan` | `false` | Vulnerability-scan the rootfs with grype (needs `grype` on the runner). When `sbom` is set, it reuses that SBOM. |
| `scan-fail-on` | | Fail on a grype finding at or above this severity (`negligible`…`critical`). Implies `scan`. |
| `ca-certs` | `false` | Add the TLS CA bundle to the image. |
| `tz` | `false` | Add the resolved local timezone to the image. |
| `init` | `false` | Add a minimal init (tini) as pid 1 wrapping the entrypoint. |
| `tmp` | `false` | Add an empty, writable `/tmp` (mode `1777`, owned by uid 0), so the non-root user can write there with no `--tmpfs` mount. See [Usage](usage.md#add-a-writable-tmp). Needs scratchsmith v2.1.0 or later. |
| `add-file` | | Copy host files into the image, one `SRC:DST` per line. A bare absolute `SRC` keeps its own path. Regular files only, and a missing source, a directory, or a `DST` already in the image fails the pack. A `symlinks` mode that stages a link changes two of those rules for a symlink source. A preserved link is staged as a link, so a link to a directory no longer fails. Under `skip-unsafe`, an entry the pack cannot honor stages nothing and warns. A taken `DST` still fails under every mode. The file lands owned by uid 0 at mode `0644`, or `0755` for an executable source, so do not add a secret this way. |
| `add-binary` | | Copy host ELF programs into the image with the shared libraries they need, one `SRC:DST` per line. A bare absolute `SRC` keeps its own path. Each program's libraries resolve by the same loader rules as the packed binary, and a library both need is staged once. An ELF for another architecture, a program for another loader, or a program or library that uses the other libc fails the pack, and so does one that uses `$ORIGIN` with a `DST` outside its real directory. A path may hold spaces, which `args` cannot pass. See [Usage](usage.md#add-a-program-with-its-libraries). Needs scratchsmith v2.1.0 or later. |
| `locale` | | Compiled glibc locales to stage at `/usr/lib/locale`, one name per line, for example `en_US.UTF-8`. A name, never a path. Needs a prebuilt directory on the runner, or `localedef` plus the glibc sources at `/usr/share/i18n`. Staging a locale does not select it, so also set `LANG` through `env`. The host `locale-archive` is never copied. glibc only: set for a musl binary, it fails the pack. |
| `symlinks` | `copy-all` | What a symlink you name becomes in the image: `copy-all`, `preserve`, `copy-unsafe`, or `skip-unsafe`. Covers the packed binary's own path and each `add-file` source, never the resolved libraries. |
| `include` | | Extra libraries to force-stage, for example `dlopen`'d plugins, one soname/path per line. |
| `nss` | `files,dns` | NSS modules to stage for glibc lookups, comma-separated (`files,dns`, or `none`). Fewer modules trim CVE surface. glibc only: set for a musl binary, it fails the pack. |
| `packages` | `report,sbom` | Where to record the distribution packages that own the bundled files, comma-separated: `report`, `sbom`, `image`, or `none`. `sbom` shows them to `sbom` and `scan`. `image` keeps the package records in the image. A `sbom` you set does nothing, and warns, unless the `sbom` or the `scan` input is on. The default `sbom` stays quiet. With a 1.x `version`, the default is `report`. Set `report` to keep the 1.x result. See [Usage](usage.md#name-the-packages-behind-the-bundled-files). |
| `max-size` | | If the fully-staged image exceeds this size, the job fails. Write the size as `25MB`, `512KiB`, or a byte count. |
| `deny` | | If a listed library ships, fail the pack (soname or staged file name), one per line. |
| `require` | | If a listed library does not ship, fail the pack (same scope as `deny`), one per line. |
| `push` | | Tag the built image as this registry ref and `docker push` it. Needs a prior registry login. Not compatible with `output`. |
| `args` | | Extra raw `pack` flags, split on whitespace (no quoting) and appended: the escape hatch for anything above. |

## Outputs

| Output | Description |
|---|---|
| `image` | The loaded image tag. It is empty when `output` staged a rootfs, or when `--push` or `--oci-archive` in `args` replaced the docker load. |
| `rootfs` | The staged rootfs directory. When an image was built instead, this is empty. |
| `report` | The full pack report as JSON. |
