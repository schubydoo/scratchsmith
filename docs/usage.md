# Usage

## Quick start

Pack a dynamic binary into a scratch image and run it:

```sh
scratchsmith pack ./app
docker run --rm scratchsmith/app:packed --version   # image is named scratchsmith/<name>:packed
```

The default sink loads into Docker. To load with **podman** or **nerdctl** instead (and run
`--smoke` with it), pass `--runtime`:

```sh
scratchsmith pack --runtime podman ./app
```

Inspect the rootfs without building an image (**no Docker daemon needed**):

```sh
scratchsmith pack --no-build --output ./rootfs ./app
```

Or write a **daemonless OCI archive** (loadable by skopeo/buildah, and pushable to a registry with
no Docker daemon):

```sh
scratchsmith pack --oci-archive ./app.oci.tar ./app
```

Or **push straight to a registry**, with no Docker daemon. Credentials come from your Docker
configuration, so `docker login` once (for GitHub's `ghcr.io`, a token with `write:packages`):

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

## Trim the NSS modules

glibc loads name-service (NSS) modules at runtime to resolve names: hostnames to IP addresses,
and user or group IDs to names. Scratchsmith stages a default set (local files plus DNS). If your
program does fewer lookups, drop the modules it does not need with `--nss`. Fewer modules mean a
smaller image and less code that can carry a CVE.

```sh
scratchsmith pack ./app                 # default: local files + DNS
scratchsmith pack --nss files ./app     # local-file lookups only, no DNS
scratchsmith pack --nss none ./app      # no NSS modules, for a program that resolves no names
```

`dns` covers hostname resolution only, not the network itself. A program that connects to a raw IP
address needs no NSS module. A program that reaches a host by name over TLS also needs CA
certificates, which you add separately with `--ca-certs`. `--nss none` also skips the generated
`/etc/nsswitch.conf`, and `--nss files` writes one that lists local files alone. A mode without
`files` also drops `/etc/passwd` and `/etc/group`. Because glibc reads them through the `files`
module, user and group lookups do not work there.

## Add a host file

`--ca-certs` and `--tz` each add one fixed file. To add any other host file, use `--add-file`.
A scratch image starts empty. A program that reads a configuration file, a template, or a
data file at runtime needs that file copied in.

```sh
scratchsmith pack --add-file ./app.conf:/etc/app/app.conf ./app   # copy to a chosen path
scratchsmith pack --add-file /etc/motd ./app                      # keep the host path
```

Write each entry as `SRC:DST`, where `SRC` is the host file and `DST` is the absolute path
inside the image. Scratchsmith creates the parent directories of `DST`. A bare `SRC` is its own
destination, so it must be an absolute path. The flag repeats, and the `add-file` key in
`scratchsmith.toml` takes the same list.

An added file does not keep its host permission bits. In an image it lands owned by uid 0, with
mode `0644`. The mode is `0755` for an executable source. The layer writer canonicalizes modes so
that the layer stays reproducible. A source at mode `0600` is therefore world-readable inside
the image. Do not add a secret this way. Only a `--no-build --output` rootfs keeps the source
bits.

The flag takes regular files only. If the source is missing or is a directory, the pack fails
and names the path. If `DST` is already in the image, the pack fails as well, so a second entry
for one path cannot quietly replace the first. Scratchsmith never skips a file you asked for.
A skipped file means an image that ships without it. The added files count toward `--max-size`.

## Stage a locale

A scratch image carries no locale data, so a glibc program runs in the C locale and `setlocale`
fails for any other. `--locale` stages one compiled locale at `/usr/lib/locale/<name>`. With no
`LOCPATH` set, glibc reads exactly that path.

```sh
scratchsmith pack --locale en_US.UTF-8 --env LANG=en_US.UTF-8 ./app
```

Name the locale the way glibc names it, such as `en_US.UTF-8` or `de_DE.UTF-8@euro`.
Scratchsmith takes the data from a matching directory under `/usr/lib/locale` on the host. If
there is no such directory, it compiles the locale with `localedef`, which reads the glibc
locale sources at `/usr/share/i18n`. If neither source is available, the pack fails and names
what is missing.

The host `locale-archive` file is never copied. One archive holds every locale the host has.
That is hundreds of megabytes on a full distribution, far more than one program needs. A single
locale costs about 3 MB, and most of that is the collation table `LC_COLLATE`.

Staging the data does not select it. Set `LANG`, `LC_ALL`, or a per-category entry such as
`LC_TIME` with `--env`, because the environment is what glibc reads at startup. If you stage a
locale and set none of them, the pack warns and the program runs in the C locale. If a selector
names a locale the pack did not stage, the pack warns as well. glibc falls back to the C locale
for that category. The flag repeats, and the `locale` key in `scratchsmith.toml` takes the same
list. Locale data counts toward `--max-size`.

## Inspect the dependency graph

To see what `pack` stages without building an image, run `graph`:

```sh
scratchsmith graph ./app                            # ASCII tree of the resolved deps
scratchsmith graph --format json ./app              # machine-readable adjacency list
scratchsmith graph --include libplugin.so.1 ./app   # add a dlopen'd library, like pack
```

The tree shows each library in full the first time. A later repeat is marked `(*)`, so
a shared dependency or a cycle does not print twice. A dependency that does not resolve is
shown as `(missing)`. The last line names the loader (`PT_INTERP`).

## Gate on libraries

To enforce a library policy in CI, fail the pack on a forbidden library or a missing required
one:

```sh
scratchsmith pack --deny libssl.so.3 ./app        # fail if OpenSSL is staged
scratchsmith pack --require libseccomp.so.2 ./app  # fail if seccomp is missing
```

Both flags repeat and match exactly, by soname or staged file name. The resolved libraries,
the loader, and the NSS modules are all in scope. Read the names from `scratchsmith graph`.
The same keys work in `scratchsmith.toml` as `deny` and `require`.

## Diff two builds

To catch image drift, stage two builds and compare their rootfs directories:

```sh
scratchsmith pack --no-build --output old ./app-v1
scratchsmith pack --no-build --output new ./app-v2
scratchsmith diff old new              # files added, removed, changed, and the size delta
scratchsmith diff --exit-code old new  # exit non-zero on any difference (a CI gate)
```

`diff` marks an added file with `+`, a removed file with `-`, and a changed file with `~`.
It then prints the total size delta. `--format json` emits the same data for a machine.

## Unpack an image

To audit an image you did not build, extract its OCI archive to a directory:

```sh
scratchsmith unpack app.oci.tar ./rootfs   # apply the layers into ./rootfs
```

`unpack` reads an OCI-layout archive (what `pack --oci-archive` writes, or a skopeo/buildah
export), applies each layer in order, and honors whiteouts. Combine it with `diff` to
compare two images: unpack both, then run `scratchsmith diff old new`.

## Multi-arch images

Scratchsmith resolves against the host's libraries, so it packs for the architecture it runs on.
To publish a multi-arch image, run `pack --push` on each architecture (a CI matrix). Then combine
the per-arch images into one **multi-arch OCI image index** with `index`. That is the daemonless
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

Each source's platform is read from its own image configuration. Nothing is rebuilt, and no
cross-arch resolution happens. The sources must already be pushed, and must live in the
**target's repository**. An index references its children by digest within one repository, so
this is typically the same repo with a different tag, as above. Add `--sign` to cosign-sign the
index by digest.

## Image metadata and entrypoint

Set what the image runs: entrypoint, arguments, environment, working directory, and user:

```sh
scratchsmith pack ./app \
  --entrypoint /app --cmd serve --env LANG=C.UTF-8 --workdir /data --user 65532:65532 \
  --label role=api --healthcheck /app --healthcheck --health
```

`--healthcheck` (like `--cmd`) is repeatable, and each token is one argument of a single exec
command. So `--healthcheck /app --healthcheck --health` is the one command `["/app", "--health"]`,
not two healthchecks. It is the same as `healthcheck = ["/app", "--health"]` in the
[configuration file](configuration.md).

## In CI

To pack in a GitHub Actions workflow with the composite action instead of shelling out to the CLI,
see **[GitHub Action](github-action.md)**.

## Run `pack` in a container — the `:toolbox` image

The `FROM scratch` release image can only run `--version` / `lint` / `doctor` / `--completions`. The **`:toolbox`**
image bundles the full `pack` toolchain (ldconfig, strip, syft, grype, cosign, upx, tini, the
docker CLI) on a Wolfi base. With it, `pack` itself runs inside a container:

```sh
# Daemonless — no socket needed; write an OCI archive or push straight to a registry.
docker run --rm -v "$PWD:/w" -w /w ghcr.io/schubydoo/scratchsmith:toolbox \
  pack --oci-archive app.oci.tar ./app
docker run --rm -v "$PWD:/w" -w /w ghcr.io/schubydoo/scratchsmith:toolbox \
  pack --push ghcr.io/you/app:1.0 ./app
```

Prefer the daemonless sinks (`--push` / `--oci-archive`) in CI. The **default `docker load` sink**
needs a host engine, so mount its socket. That socket is **root-equivalent on the host**, so use
it only where you trust the workflow:

```sh
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock ghcr.io/schubydoo/scratchsmith:toolbox \
  pack ./app
```

Tags: `:toolbox` (latest), `:X.Y.Z-toolbox`, `:X.Y-toolbox`. Verify its signature exactly like the
scratch image. See [Verifying releases](verifying.md).
