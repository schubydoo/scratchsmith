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

The report names the loader the image carries, because the binary's `PT_INTERP` chooses that
path and not scratchsmith. `--format json` carries it as `interpreter`, so a job can assert it
without unpacking the image. An ELF that carries no `PT_INTERP` reports null, which is the
case for a static binary.

```sh
scratchsmith pack --format json ./app | jq -e '.interpreter == "/lib64/ld-linux-x86-64.so.2"'
```

`--format json` also carries `timings`: the time that each phase of the pack took, in
milliseconds. Use it to find the slow part of a pack in CI, or to turn the phases into the spans
of a build trace.

```sh
scratchsmith pack --format json --sbom --oci-archive app.tar ./app | jq .timings
```

```json
{
  "resolve_ms": 19,
  "stage_ms": 9,
  "sbom_ms": 1569,
  "scan_ms": null,
  "deliver_ms": 734,
  "smoke_ms": null,
  "sign_ms": null,
  "total_ms": 2332
}
```

| Field | Phase |
|---|---|
| `resolve_ms` | Read the binary and resolve its libraries |
| `stage_ms` | Build the root filesystem: libraries, loader, NSS, extras, added files, locales, strip and UPX, and the package lookup |
| `sbom_ms` | Generate the SBOM (`--sbom`) |
| `scan_ms` | Scan for vulnerabilities (`--scan`) |
| `deliver_ms` | Build the image and load it, write the archive, or push it |
| `smoke_ms` | Smoke-run the image (`--smoke`) |
| `sign_ms` | Sign the image and attest the SBOM (`--sign`) |
| `total_ms` | The whole pack |

A phase that did not run is `null`. With `--no-build`, `deliver_ms` is `null`, because no image
is built. The phases add up to a little less than `total_ms`. The text report does not show the
timings.

## Name the packages behind the bundled files

Scratchsmith copies libraries from the build host into the image. The image has no package
database, so an SBOM of it names almost none of those libraries, and a vulnerability scan cannot
see them. The host knows which package owns each of those paths. `--packages` records that.

`--packages` takes a comma-separated list of the places the data goes:

| Value | Where the data goes |
|---|---|
| `report` | A `packages` list in the `--format json` report |
| `sbom` | The SBOM (`--sbom`) names the packages, and the scan (`--scan`) sees them |
| `image` | The package records stay in the image, for any scanner that reads the image |
| `none` | Nowhere. Scratchsmith looks nothing up. `none` must be the only value |

The default is `report`. The default changes no SBOM, no scan and no image.

```sh
scratchsmith pack --format json ./app | jq .packages       # default: the report
scratchsmith pack --packages report,sbom --sbom --scan ./app
scratchsmith pack --packages report,sbom,image --push ghcr.io/you/app:1.0 ./app
scratchsmith pack --packages none ./app                    # look nothing up
```

The `sbom` output can make a scan gate fail. With `sbom`, the scan sees packages such as glibc
and openssl that it did not see before. A pipeline that runs `--scan --scan-fail-on high` can
pass without `--packages sbom` and fail with it. The vulnerabilities were in the image before.
The scan did not see them.

### The report

Each entry names one package and the files in the image that it owns:

```json
{
  "name": "libc6",
  "version": "2.41-12+deb13u4",
  "arch": "amd64",
  "source": "glibc",
  "type": "deb",
  "files": [
    "/lib64/ld-linux-x86-64.so.2",
    "/usr/lib/x86_64-linux-gnu/libc.so.6"
  ]
}
```

- `source` is the source package, which is the name that security advisories use.
- `type` is `deb` on a dpkg host and `rpm` on an rpm host.
- `files` are paths in the image. One host file can be in the image two times, as the loader
  is in this example.
- The lookup covers the binary, the libraries that it needs, the loader, and the NSS modules.
  It also covers the files from `--tz`, `--init` and `--add-file`.
- If `--symlinks` staged an `--add-file` entry as a link, that entry is not in the list. A link
  carries none of the package's content.
- The `--ca-certs` bundle is a special case. The host generates that file, so no package owns
  its path. Scratchsmith names the `ca-certificates` package for it, because the bundle is
  built from that package. This one entry is a convention and not a lookup.
- A locale from `--locale` is not in the list.
- A file that no package owns, such as a binary that you built, is not in the list.
- Scratchsmith asks which package owns the path. It does not compare the file's contents with
  the package's. If a file on the host was replaced by hand, the report still names the package.

The `packages` field is always in the JSON report. Its value tells you what scratchsmith knows:

| Value | Meaning |
|---|---|
| A list with entries | The host named these owners |
| An empty list | The host was asked, and no package owns a bundled file |
| `null` | Not reported: the `report` output is off, the host has no dpkg or rpm database, or the lookup failed |

### The SBOM and the image

For the `sbom` and `image` outputs, scratchsmith writes records that scanners already read, and
copies the host's `/etc/os-release`. Syft, grype and other scanners read both. The scanner needs
`os-release` to know the distribution. Without it, a scanner cannot match a package to an
advisory.

The records depend on the package manager of the build host:

| Host | Records |
|---|---|
| dpkg (Debian, Ubuntu and their relatives) | One text file for each package, under `/var/lib/dpkg/status.d/` |
| rpm (Fedora, RHEL and their relatives) | One rpm database that holds only the owning packages, at the host's database path |

- With `sbom`, those files are in the staged tree only while the SBOM and the scan run. The
  image does not contain them. With `--no-build`, an `/etc/os-release` that is already in the
  output directory stays there.
- With `image`, they stay, and they count toward `--max-size`. Your image then has an
  `/etc/os-release` that names the build host's distribution. If you add your own
  `/etc/os-release` with `--add-file`, scratchsmith keeps yours. An SBOM of that image names
  the packages too, because the records are in the tree that syft reads.
- On an rpm host, the database is about half a megabyte for a small program. The dpkg records
  are a few kilobytes.
- If you add a file with `--add-file` at a path that a record needs, the pack fails.
  Scratchsmith does not replace a file that you added.

### Hosts with no package database

`--packages` works on a host with a dpkg or an rpm database. What happens on another host
depends on what you asked for:

| You set | Result on a host with neither database |
|---|---|
| Nothing (the default) | `packages` is `null`. No warning |
| `--packages report` | `packages` is `null`, with a warning |
| `--packages` with `sbom` or `image` | The pack fails. Scratchsmith does not ship an SBOM or an image without the data that you asked for |

If you asked for `sbom` or `image` and scratchsmith cannot write the records, the pack also
fails.

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

With the default `--symlinks copy-all`, the flag takes regular files only. If the source is
missing or is a directory, the pack fails and names the path. If `DST` is already in the image,
the pack fails as well, so a second entry for one path cannot quietly replace the first. A file
you asked for is never skipped without a word. The added files count toward `--max-size`.

Another `--symlinks` mode changes two of those rules, and only for a source that is itself a
symlink. A preserved link is staged as a link, so a link to a directory no longer fails. Under
`skip-unsafe` an entry the pack cannot honor stages nothing and warns. The section below has
the detail.

## Keep a symlink as a symlink

Scratchsmith copies the content of a symlink you name, so the image gets a regular file and
not the link. That loses the path itself. If you pack `/usr/bin/python3`, which is a link to
`python3.13`, the image holds the real file and nothing at `/usr/bin/python3`. A container
that runs the name rather than the target then fails to start. `--symlinks` chooses what
happens instead.

```sh
scratchsmith pack --symlinks preserve /usr/bin/python3
```

| Mode | What a named symlink becomes |
|---|---|
| `copy-all` | The target's content, at the named path. This is the default, and what every earlier release did. |
| `preserve` | A link. A target outside the image makes it dangle, and the pack warns. |
| `copy-unsafe` | A link for a target inside the image. The target's content for a target outside it. |
| `skip-unsafe` | A link for a target inside the image. Nothing at all for a target outside it, and the pack warns. |

The mode covers the packed binary's own path and each `--add-file` source. Resolved libraries
are not in scope, because the loader decides those and the stager already recreates the
soname links it needs.

Preserving a link never pulls its target into the image. You add the target yourself, with
`--add-file`, or you accept a link that dangles. The packed binary is the exception: its real
file is always staged, so a preserved link to it always resolves. Added files are staged in
the order you list them, so a link can point at an earlier `--add-file` but not at a later
one.

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

## Pack again on every change

While you develop the program that you pack, `--watch` packs it again after each build. It
packs one time, and then packs again each time the binary changes:

```sh
scratchsmith pack --watch ./target/release/app
```

Scratchsmith looks at the binary two times each second. After a change, it waits until the file
is the same on two looks in a row. That keeps most half-written binaries out. If the linker
stalls for longer, the pack of the half-written file fails, and the finished file packs next.
If the binary is gone for five seconds, scratchsmith says so one time and continues to watch.

Each pack prints its text report. To stop, press Ctrl-C. Scratchsmith does not catch the
interrupt, so the exit status is the one your shell gives a process that Ctrl-C ended.

Only the binary is watched. A change to a library or to an `--add-file` source does not start a
pack. The next pack that the binary starts picks it up. A change to the configuration file is
not picked up at all, because scratchsmith reads that file one time. Stop the watch and start it
again.

If the first pack fails, the command exits with an error, the same as a pack with no `--watch`.
If a later pack fails, scratchsmith prints the error and continues to watch. A build that fails
halfway does not end the watch.

`--watch` works with the default load and with `--oci-archive`. It refuses three things:

- `--push`, and a `push` key from the configuration file. A registry is not the place for an
  image from every save.
- `--no-build`. That sink stages into one directory, and a second pack into the same directory
  collides with the files from the first.
- `--format json`. Each pack prints a text report.

`--watch` is a command-line flag only. It has no key in the configuration file and no input on
the GitHub Action.

## In CI

To pack in a GitHub Actions workflow with the composite action instead of shelling out to the CLI,
see **[GitHub Action](github-action.md)**.

## Run `pack` in a container — the `:toolbox` image

The `FROM scratch` release image carries the binary and nothing else: no shell, no tools, and no
certificate store. It runs every subcommand that needs no external tool. That is `lint`,
`doctor`, `graph`, `diff`, `unpack`, and `index`, plus the `--version` and `--completions` flags.
`doctor` is the one that looks like an exception: it probes for each external tool and reports
every one as missing, which is the right answer on an image that carries none.

`index` reaches a registry over HTTPS, which needs a list of trusted certificate authorities.
On a host with a certificate store, scratchsmith uses that store. This image has none, so
scratchsmith uses the Mozilla root certificates that are compiled into the binary. It prints one
warning to standard error to say so. To use your own certificates, mount a PEM file and set
`SSL_CERT_FILE` to its path. A registry behind a proxy that inspects TLS needs that.

The compiled-in certificates are as new as the scratchsmith release that carries them. A
certificate store on the host gets updates from the operating system. The compiled-in set
changes only with a newer scratchsmith release.

If `SSL_CERT_FILE` or `SSL_CERT_DIR` is set, scratchsmith never uses the compiled-in
certificates. If the path that you set gives no certificates, the command fails and names the
variable.

One subcommand does not run there. `pack` needs ldconfig, strip, and the SBOM tools.

The **`:toolbox`** image bundles the full `pack` toolchain (ldconfig, strip, syft, grype, cosign,
upx, tini, the docker CLI) on a Wolfi base. With it, `pack` itself runs inside a container:

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
