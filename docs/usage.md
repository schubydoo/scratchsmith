# Usage

## Quick start

Pack a dynamic binary into a scratch image and run it:

```sh
scratchsmith pack ./app
docker run --rm scratchsmith/app:packed --version   # image is scratchsmith/<name>:packed, <name> lowercased (other characters an image name cannot hold become -)
```

The image gets the build host's glibc. A binary built against a newer glibc than the host's
packs, and then fails to start with an error like ``version `GLIBC_2.38' not found``. `pack`
reads the `GLIBC_` versions that the binary and each library need. For each object that needs
a version the staged glibc does not define, it adds a warning to the report that names the
highest missing version. The text report prints it on standard output as `warning: …`, and
`--format json` lists it in `warnings`. The pack still succeeds, with the same exit code.
Pack on a host whose glibc is as new as the one the binary was built against.

The default sink loads into Docker. To load with **podman** or **nerdctl** instead (and run
`--smoke` with it), pass `--runtime`:

```sh
scratchsmith pack --runtime podman ./app
```

Inspect the rootfs without building an image (**no Docker daemon needed**):

```sh
scratchsmith pack --no-build --output ./rootfs ./app    # or -n -o ./rootfs
```

Give `--output` a new directory or an empty one. Scratchsmith does not empty the directory, so
a directory that holds anything is an error, and nothing is staged. A file is an error
too. A directory that scratchsmith cannot list is an error, because it cannot prove the directory
is empty. Remove the old directory first, or choose another. A pack that fails after it starts
to stage, for example on `--deny`, leaves the partial tree in the directory. Remove the directory
before you run the pack again.

Or write a **daemonless OCI archive** (loadable by skopeo/buildah, and pushable to a registry with
no Docker daemon):

```sh
scratchsmith pack --oci-archive ./app.oci.tar ./app
```

For a regular file, scratchsmith writes the archive to a temporary file beside the target, and
then renames it. A failed pack never leaves half an archive under the name that you gave. The
directory of the archive must be writable. A pack that is interrupted can leave one
`.scratchsmith-oci-*.tmp` file there, which is safe to delete.

A destination that already exists and is not a regular file is different. Examples are
`/dev/stdout`, a FIFO and a symbolic link. Scratchsmith writes straight into it, with no
temporary file and no rename.

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

`--sign` checks that cosign runs before anything is pushed. It signs the digest of the manifest
that scratchsmith sent, also when the registry's answer names no digest, and refuses one that
names another digest. If signing fails after the push, the error says that the image was pushed
but is not signed. `index --sign` works the same way.

A reference with no tag pushes to `latest`, as it always has. To push the image without
creating or moving an image tag, add `--push-untagged` and name only the repository:

```sh
scratchsmith pack --push ghcr.io/you/app --push-untagged --sign ./app
```

The manifest goes up under its own digest. The report gives the pushed
`ghcr.io/you/app@sha256:...` reference (the `pushed` field in `--format json`), and `--sign`
signs that digest. cosign still stores the signature, and the SBOM attestation if there is one,
under a `sha256-<hex>` tag in the same repository, so `--sign` adds those tags. No image tag is
created or moved. A tag or a digest in the reference is a usage error with exit code 2. Tag
the image later, for example after a review, with `crane tag` or `oras tag`.

cosign signs and attests with your terminal's standard input and standard error. Outside CI,
keyless signing prints a login URL there and can ask for a code, and you answer it as you would
when you run cosign yourself. cosign's standard output stays captured, so `--format json` stays
parseable. A failed cosign run is reported with its exit status, and its own messages are above.

To check the signature later, against the signer you expect, run `scratchsmith verify`. See
[Verifying an image you signed with `pack`](verifying.md#with-scratchsmith-verify).

## Supply-chain output, smoke-run, and size gates

```sh
scratchsmith pack --sbom --strip --smoke ./app        # SBOM + stripped + auto smoke-run
scratchsmith pack --sbom --sbom-format spdx-json --sbom-file bom.spdx.json ./app   # SPDX SBOM, custom path
scratchsmith pack --scan --scan-fail-on high ./app    # grype vuln scan; fail the build on a high+ CVE
scratchsmith pack --strip --max-size 8MB ./app        # fail the build if the staged image exceeds 8 MB
scratchsmith lint --fail-on no-pie --fail-on no-relro ./app   # hardening gate for CI
scratchsmith lint --format json --fail-on no-fortify ./app     # the same report as JSON
```

`lint --format json` prints one object: `binary` (the path as given), `hardening` (`pie`, `nx`,
`canary` and `fortify` as booleans, `relro` as `"full"`, `"partial"` or `"none"`), `fail_on`
(the gates asked for) and `violations` (the gates this binary fails). Gates use the `--fail-on`
spelling, each listed once in the order given, so a CI script can feed a violation back to the
flag. The report prints in full before a failing gate exits `1`. The six gates are:

| Gate | Fails when |
|---|---|
| `no-pie` | the binary is not PIE |
| `no-relro` | it has no RELRO |
| `partial-relro` | its RELRO is not full (so it also fails with no RELRO) |
| `no-nx` | its stack is executable |
| `no-canary` | it imports no stack-protector guard |
| `no-fortify` | it imports no `*_chk` wrapper |

`canary` and `fortify` mean the binary imports the guard or a `*_chk` wrapper, so a static binary
reads `false`.

The report also carries `libc` (`"glibc"`, `"musl"`, or null for a binary with no loader) and
`fortify_detectable`. musl's `fortify-headers` check in inline code and leave no `*_chk` symbol,
so for a musl binary the text report shows `Fortify: unknown (musl's fortify-headers leave no
symbol)`, `fortify` is `false` and `fortify_detectable` is `false`. `--fail-on no-fortify` cannot
be checked there, so it exits `2` for a musl binary. The other gates work for musl as for glibc.

`--smoke` runs the image once and fails the pack only when the binary could not start: a
missing library or loader, or an entrypoint the runtime could not exec. An app that starts and
exits with an error passes, unless the code is 126 or 127, which shells use for a command
that could not run. A binary still running after 15 seconds counts as started, and its
container is removed. `--smoke` needs the default load sink: with `--no-build`, `--oci-archive`
or `--push` (or a `push` key in the configuration file) it is a usage error, exit code 2.

syft, grype and cosign each have a time limit: syft 15 minutes, grype 30 minutes, and cosign
10 minutes. A run past its limit is stopped, and the pack fails with an error that names the tool
and the limit. grype's limit leaves room for its first run, which downloads its vulnerability
database.

`--push` and `index` give up on a registry or token host that does not accept the connection
within 30 seconds, and the error names the endpoint. The identity-token exchange also fails
after 60 seconds of silence from the token host. Talking to the registry itself has no read
limit, so a slow upload of a large layer is not cut off, and a registry that accepts the
connection and then sends nothing still keeps the command waiting.

A login stored as an identity token (`identitytoken` in the Docker config) is exchanged for an
access token at the realm the registry names. scratchsmith sends it only to an `https` realm,
or to a loopback `http` realm for a local registry, and follows no redirect from that realm. A
failed exchange shows at most the first 1 KiB of the token host's answer, escaped.

The report names the loader the image carries, because the binary's `PT_INTERP` chooses that
path and not scratchsmith. `--format json` carries it as `interpreter`, so a job can assert it
without unpacking the image. An ELF that carries no `PT_INTERP` reports null, which is the
case for a static binary.

```sh
scratchsmith pack --format json ./app | jq -e '.interpreter == "/lib64/ld-linux-x86-64.so.2"'
```

`libc` names the C library behind that loader: `"glibc"`, `"musl"`, or null with no loader.

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

The other fields of the pack report:

- `tag`, `archive`, `pushed`, `staged_dir`: where the image went. The one for the sink you used
  is set and the others are null: the loaded image tag, the `--oci-archive` path, the `--push`
  reference, or the `--no-build` directory.
- `entrypoint`: the packed binary's path in the image. It does not change with `--entrypoint`
  or `--init`.
- `size`: `entries` (each with `path`, `before` and `after` in bytes), `total_before`,
  `total_after`, and the booleans `stripped` and `upx`. It covers the ELF payload: the binary,
  the loader, the libraries and the NSS modules. An `--add-binary` program's libraries are
  included, and the added program itself is not.
- `warnings`: a list of warning lines, empty when there are none.
- `smoke_ok`: `true` after a passing `--smoke`, otherwise null.
- `sbom`: the SBOM path with `--sbom`, otherwise null.
- `scan`: with `--scan`, the finding counts `critical`, `high`, `medium`, `low`, `negligible`,
  `unknown` and `total`. Otherwise null.
- `signed`: the by-digest reference that `--sign` signed, otherwise null.
- `packages`: see the next section.

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

The default is `report,sbom`. The default changes no image. Before 2.0 the default was
`report`. To keep that result, set `--packages report`.

`sbom` needs a reader. If neither `--sbom` nor `--scan` is on, nothing reads the records.
Scratchsmith then turns that output off and skips its lookup. If you set `sbom` yourself, the
pack prints a warning. The default `sbom` goes quietly. The pack does not fail.

The text report does not show the list. So a pack with the text report, and with no `--packages`
value and no `packages` key, drops the `report` output. It then runs the lookup only for `--sbom`
or `--scan`. To fill the list with the text report, name the outputs on the command line or in
the configuration file.

```sh
scratchsmith pack --format json ./app | jq .packages       # default: the report
scratchsmith pack --sbom --scan ./app                      # default: the SBOM and scan see them
scratchsmith pack --packages report,sbom,image --push ghcr.io/you/app:1.0 ./app
scratchsmith pack --packages none ./app                    # look nothing up
```

The `sbom` output can make a scan gate fail. With `sbom`, the scan sees packages such as glibc
and openssl that it did not see before. A pipeline that runs `--scan --scan-fail-on high` can
pass with `--packages report` and fail with the default. The vulnerabilities were in the image
before. The scan did not see them.

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
    "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
    "/usr/lib/x86_64-linux-gnu/libc.so.6"
  ]
}
```

- `source` is the source package, which is the name that security advisories use.
- `type` is `deb` on a dpkg host and `rpm` on an rpm host.
- On an rpm host, `version` is the version and the release with a hyphen between them, such as
  `2.34-83.el9.7`. If the package has an epoch, the epoch and a colon come first.
- `files` are paths in the image. The loader is listed at two paths in this example. The
  interpreter path holds the one copy, and the other path is a relative symlink to it.
- The lookup covers the binary, the libraries that it needs, the loader, and the NSS modules.
  It also covers the files from `--tz`, `--init`, `--add-file` and `--add-binary`.
- If `--symlinks` staged an `--add-file` entry as a link, that entry is not in the list. A link
  carries none of the package's content.
- The `--ca-certs` bundle is a special case. The host generates that file, so no package owns
  its path. Scratchsmith names the `ca-certificates` package for it, because the bundle is
  built from that package. This one entry is a convention and not a lookup.
- A locale from `--locale` is not in the list.
- A file that no package owns, such as a binary that you built, is not in the list.
- On a dpkg host, a file whose host path contains `*`, `?`, `[` or `\` is not in the list.
  `dpkg-query` reads those characters as a pattern, so scratchsmith does not ask about that
  path, and it prints a warning that names the file.
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
  image does not contain them.
- With `image`, they stay, and they count toward `--max-size`. Your image then has an
  `/etc/os-release` that names the build host's distribution. If you add your own
  `/etc/os-release` with `--add-file`, scratchsmith keeps yours. An SBOM of that image names
  the packages too, because the records are in the tree that syft reads.
- On an rpm host, the database is about half a megabyte for a small program. The dpkg records
  are a few kilobytes.
- On an rpm host that keeps its database in the Berkeley DB format, an image with the records
  is not reproducible. Rocky Linux 8 and the rest of the RHEL 8 family are such hosts. rpm
  writes different bytes each time it builds that database, so two packs of the same program
  give two digests. The pack prints a warning. The `report` and `sbom` outputs are not
  affected.
- The records need an rpm that has `rpmdb --exportdb`. rpm 4.11, on CentOS 7 and Amazon
  Linux 2, does not have it. On those hosts `report` works and the `image` output fails. If
  `--sbom` or `--scan` is on, a `sbom` that you set fails too. The default `sbom` turns off
  quietly there. The report still names the packages, and the SBOM and the scan see none.
- If the pack stages a file, a link or a directory at a path that a record needs, scratchsmith
  keeps it and does not replace or remove it. It can be a file that you add with `--add-file`.
  When the host keeps the program or a library at that path, it can be that file too. A
  `sbom` or `image` that you set then fails the pack, and the error says which output to
  remove. The default `sbom` leaves the records out and prints a warning, and the pack goes
  on. The SBOM and the scan then see no package records.

### Hosts with no package database

`--packages` works on a host with a dpkg or an rpm database. What happens on another host
depends on what you asked for:

| You set | Result on a host with neither database |
|---|---|
| Nothing (the default) | `packages` is `null`, and the SBOM and the scan see no packages. No warning |
| `--packages report` | `packages` is `null`, with a warning |
| `--packages` with `image` | The pack fails. Scratchsmith does not ship an image without the data that you asked for |
| `--packages` with `sbom`, and `--sbom` or `--scan` | The pack fails. Scratchsmith does not ship an SBOM without the data that you asked for |
| `--packages` with `sbom`, and neither `--sbom` nor `--scan` | The pack works and warns. Nothing reads the records, so scratchsmith does not ask for them |

If scratchsmith needs the records for one of those outputs and cannot write them, the pack
also fails.

`scratchsmith doctor` tells you before you pack. On an rpm host that cannot write the records,
the `rpm` row starts with `warn` and names the outputs that fail.

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
module, user and group lookups do not work there. musl has no NSS, so `--nss` is refused for a
musl binary (see [Pack a musl binary](#pack-a-musl-binary)).

## Add a writable /tmp

A scratch image has no `/tmp`, and many programs exit at startup without one. `--tmp` adds an
empty `/tmp`, mode `1777` and owned by uid 0, the same as on a Linux host. If a library staged
from an RPATH under `/tmp` already made it, `/tmp` keeps that library and only its mode is
set. The image's non-root user can then write there with no `--tmpfs` at run time.

```sh
scratchsmith pack --tmp ./app
```

The layer stays reproducible: the directory gets the same mode, owner and mtime on every
pack. A `--no-build` rootfs has the same mode, owned by the user who ran the pack. Files
written to `/tmp` live in the container's writable layer, so mount a `--tmpfs` instead when
the container runs with `--read-only`.

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
missing or is a directory, the pack fails and names the path. One `DST` given in two entries is
a usage error with exit code 2, so a second entry cannot quietly replace the first. If `DST` is
already in the image for another reason, the pack fails as well. A file
you asked for is never skipped without a word. The added files count toward `--max-size`.

Another `--symlinks` mode changes two of those rules, and only for a source that is itself a
symlink. A preserved link is staged as a link, so a link to a directory no longer fails. Under
`skip-unsafe` an entry the pack cannot honor stages nothing and warns. The section below has
the detail.

## Add a program with its libraries

`--add-file` copies a file as it is. An ELF program added that way arrives without the shared
libraries it needs, so it fails in the image with `error while loading shared libraries`.
`--add-binary` takes the same `SRC[:DST]` form and also resolves the program's libraries,
with the same `ld.so` rules as the packed binary. `$ORIGIN` in its RPATH or RUNPATH names the
real directory of the added file on the host, and ld.so reads it from the program's directory
in the image. So the pack fails when a program that uses `$ORIGIN` is given a `DST` in another
directory, and the message names the `DST` to use.

```sh
scratchsmith pack --add-binary /usr/bin/bash:/bin/bash ./app
```

A library that the packed binary needs too is staged once. The image's `ld.so.cache`,
`--deny` and `--require`, `--strip`, the SBOM and `--packages` all cover the added libraries.
The added program itself is copied like an `--add-file` entry, so the same destination rules
apply to it. It is always copied as a file, whatever `--symlinks` says, so a symlinked `SRC`
brings its target's content. One image has one loader, so the pack fails when the added ELF is
built for another architecture or names another program interpreter than the packed binary.
A static ELF, or a shared library, names none and is accepted. A file that is not an ELF
fails too: add it with `--add-file`.

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
| `copy-all` | The target's content. An `--add-file` source gets it at the named path. The packed binary gets it at its real path, with nothing at the named path. This is the default, and the only behavior before 1.4.0. |
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
list. Locale data counts toward `--max-size`. musl does not read these locales, so `--locale` is
refused for a musl binary.

## Pack a musl binary

A dynamic musl program, such as one built on Alpine or with `musl-gcc`, packs the same way as a
glibc one. Scratchsmith sees musl in the binary's loader (`/lib/ld-musl-x86_64.so.1`) and
resolves the libraries by musl's rules, which
[Architecture](architecture.md#the-musl-backend) lists. Only x86_64 is supported for now.

```sh
scratchsmith pack ./app                      # on Alpine, or with musl's libraries in the host root
scratchsmith pack --format json ./app | jq -e '.libc == "musl"'
```

What changes for a musl binary:

- **No loader cache.** musl reads no `ld.so.cache`, so `pack` writes none and does not need
  `ldconfig`. An Alpine host has no glibc `ldconfig`, and that is fine. When a library comes from
  a directory outside musl's defaults (`/lib`, `/usr/local/lib`, `/usr/lib`), the image gets an
  `/etc/ld-musl-x86_64.path` that lists it.
- **No NSS.** musl reads `/etc/passwd` and `/etc/group` itself, so the image always gets the
  minimal pair and no NSS module. `--nss`, or an `nss` key in `scratchsmith.toml`, exits `2`.
- **No glibc locales.** musl has a built-in C.UTF-8 and does not read compiled glibc locales, so
  `--locale`, or a `locale` key, exits `2`.
- **One libc per image.** An `--add-binary` program of the other libc fails the pack.
- **`--ca-certs`.** Alpine's OpenSSL and curl read the CA bundle at `/etc/ssl/cert.pem`, not at
  `/etc/ssl/certs/ca-certificates.crt`. `--ca-certs` stages the bundle at the second path and
  links the first to it, as Alpine does, so TLS works with no `--cacert` flag. A file that
  `--add-file` puts at `/etc/ssl/cert.pem` is kept, and no link is made.
- **`--packages`.** An Alpine host keeps an apk database, which `--packages` does not read yet.
  The report says null there, as on any host with no dpkg or rpm database.

## Inspect the dependency graph

To see the libraries `pack` resolves for the binary, without building an image, run `graph`:

```sh
scratchsmith graph ./app                            # ASCII tree of the resolved deps
scratchsmith graph --format json ./app              # machine-readable adjacency list
scratchsmith graph --include libplugin.so.1 ./app   # add a dlopen'd library, like pack
```

The tree shows each library in full the first time. A later repeat is marked `(*)`, so
a shared dependency or a cycle does not print twice. A dependency that does not resolve is
shown as `(missing)`, and `graph` then exits with code 1 after it prints the tree. If the binary
has a loader (`PT_INTERP`), the last line names it.

`graph` shows the binary's own dependency tree and `--include`. It does not show the NSS modules
(`libnss_files.so.2`, `libnss_dns.so.2` and `libresolv.so.2` by default) or an `--add-binary`
program and its libraries, which `pack` also stages. The pack report lists the NSS modules
under its payload sizes (`size.entries` in `--format json`).

`graph --format json` prints one object: `root` (the binary's real path), `interpreter` (the
loader, or null), `libc` (`"glibc"`, `"musl"`, or null with no loader), `nodes` and `missing` (every soname that did not resolve). Each node has `id`
(its real path), `name` (the soname the loader searched for, or the binary's file name), `needs`
(the ids of the nodes it needs) and `missing` (its own sonames that did not resolve).

## See each decision with `--verbose`

To see why a library was picked, or where a file was staged, add `--verbose`. It works before
or after the subcommand:

```sh
scratchsmith --verbose pack --no-build -o rootfs ./app
scratchsmith graph --verbose ./app
```

`pack` and `graph` then print one line on standard error for each decision, each starting
`verbose: `. The lines say which directories each object searches, the file each `DT_NEEDED`
name resolves to (or that it is not found, or already loaded), and, for `pack`, the binary,
interpreter, libraries and name-service files it stages, each link it makes, and the
directories in the image's `/etc/ld.so.cache`. Standard output and every other line stay as
they are without the flag, so `--format json` still prints only JSON. The wording of the
`verbose: ` lines is for reading, not parsing, and can change in any release.

## Gate on libraries

To enforce a library policy in CI, fail the pack on a forbidden library or a missing required
one:

```sh
scratchsmith pack --deny libssl.so.3 ./app        # fail if OpenSSL is staged
scratchsmith pack --require libseccomp.so.2 ./app  # fail if seccomp is missing
```

Both flags repeat and match exactly, by soname or staged file name. The resolved libraries,
the loader, and the NSS modules are all in scope. Read the library names from
`scratchsmith graph`. The NSS modules are not in `graph`, so read those from the pack report.
The same keys work in `scratchsmith.toml` as `deny` and `require`.

## Diff two builds

To catch image drift, stage two builds and compare their rootfs directories:

```sh
scratchsmith pack --no-build --output old ./app-v1
scratchsmith pack --no-build --output new ./app-v2
scratchsmith diff old new              # files added, removed, changed, mode changes, size delta
scratchsmith diff --exit-code old new  # exit non-zero on any difference (a CI gate)
```

`diff` marks an added file with `+`, a removed file with `-`, and a changed file with `~`.
It also compares permission bits: a regular file or directory in both trees whose mode differs
prints as `~ path (mode 0755 -> 0644)`, so a lost exec bit or a world-writable directory fails
`--exit-code`. A symlink has no mode of its own, so only its target is compared. An empty
directory in only one tree prints as `+ path/ (empty directory)` or `- path/ (empty directory)`.
A directory that holds anything shows through the files in it. `diff` then prints the total
size delta. `--format json` emits the same data for a machine: `added` and `removed` (each
entry has `path` and `size`), `changed` (a list of paths), `mode_changed` (each with `path`,
`before` and `after` as four octal digits), the empty directories in `dirs_added` and
`dirs_removed`, and the total file bytes of each tree in `size_before` and `size_after`.

A staged rootfs keeps the modes from the host: a directory gets its mode from the umask, and a
file keeps the mode of its source. The image layer rewrites them, to `0755` for a directory and
`0755` or `0644` for a file by its exec bit. So two staged trees from builders with different
umasks, or with a binary at `0775` on one and `0755` on the other, differ in mode although their
images are the same. A sticky directory such as the `--tmp` `/tmp` keeps `1777` in the layer.
Stage both builds on one builder, or compare the modes that ship: `unpack` both images and diff
those trees, which carry the layer's modes.

A file name that is not valid UTF-8 is escaped whole, in both the text and the JSON output:
its invalid bytes become `\xNN`, and a backslash, a quote or a control character in it is
escaped too.

Both arguments must be directories. A file argument, such as an OCI archive, is read as an
empty tree and prints a deprecation warning. 3.0 refuses it. To compare two archives, `unpack`
each one first.

## Unpack an image

To audit an image you did not build, extract its OCI archive to a directory:

```sh
scratchsmith unpack app.oci.tar ./rootfs   # apply the layers into ./rootfs
```

`unpack` reads an OCI-layout archive (what `pack --oci-archive` writes, or a skopeo/buildah
export), applies each layer in order, and honors whiteouts. Combine it with `diff` to
compare two images: unpack both, then run `scratchsmith diff old new`. When a later layer holds
an entry for a path that exists, `unpack` replaces that path, as a container runtime does. A
directory over a directory keeps its contents. A symlink inside the image resolves against the
target directory as the image's `/`, so a file under Debian's `var/run -> /run` lands in
`run/`. `unpack` refuses, and exits `1`, an entry or hard link that would leave the target.
When the archive's index lists more than one manifest, `unpack` applies only the first, and
prints a warning on standard error that names its digest, and its platform when the index gives
one.

`unpack` reads every gzip member of a layer, as Docker does. It refuses a layer that is cut
short, has data after its end, or holds a sparse entry, an entry with a `..` part, a hard link
above the image root or a malformed PAX record, and exits `1` before that layer writes or deletes
any file. A layer may hold at most 2 GiB once decompressed, and
all layers together at most 16 GiB. A layer that the manifest lists twice counts twice.

`unpack` writes each entry relative to the directory that holds it, so an entry deeper than
the host's path limit (4096 bytes) unpacks. It reaches that directory through `/proc`, which a
container runtime mounts by default. Without `/proc`, `unpack` fails and names the entry.

`unpack` clears the setuid and setgid bits on every file and directory it writes. An untrusted
image cannot then plant a setuid program owned by the user who unpacks it. `unpack` prints one
warning line on standard error for each path in the final image that had one of those bits.
The `stripped_setid` field of `--format json` lists the same paths. The other fields are
`source` (the archive), `dir` (where it was extracted), `layers` (how many were applied) and
`files` (how many files and symlinks were written).

`unpack` applies the mode of each directory after the last layer, so a directory without owner
write permission, such as `/root` in a Fedora image, unpacks for a user who is not root. Until
then such a directory stays open to its owner, so a failed unpack leaves a tree that its owner
can remove. A finished tree keeps the image's modes, so it may need `chmod -R u+w` before
`rm -rf`.

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

`index --format json` prints one object with four fields:

- `pushed`: the target reference, as you gave it.
- `manifests`: one entry per source, in the order you gave them. Each entry has `source` (the
  reference as you gave it), `platform` (such as `linux/amd64`, read from the source's image
  configuration) and `digest` (the child manifest's `sha256:` digest).
- `signed`: the by-digest reference that `--sign` signed, or `null` without `--sign`.
- `warnings`: a list of warnings about the push, such as a registry that answered with another
  digest. It is empty when there are none. With `--sign`, a digest mismatch fails the command
  instead, so `warnings` stays empty.

## Image metadata and entrypoint

Set what the image runs: entrypoint, arguments, environment, working directory, and user:

```sh
scratchsmith pack /opt/app/bin/app \
  --cmd serve --env LANG=C.UTF-8 --workdir /data --user 65532:65532 \
  --label role=api --healthcheck /opt/app/bin/app --healthcheck --health
```

The packed binary keeps its host path in the image (its real path, after symlinks), and that path
is the default entrypoint. So an `--entrypoint` or `--healthcheck` that runs the binary must name
that path. Scratchsmith does not check either one.

`--healthcheck` (like `--cmd`) is repeatable, and each token is one argument of a single exec
command. So `--healthcheck /opt/app/bin/app --healthcheck --health` is the one command
`["/opt/app/bin/app", "--health"]`, not two healthchecks. It is the same as
`healthcheck = ["/opt/app/bin/app", "--health"]` in the [configuration file](configuration.md).

Each `--env` and `--label` entry needs an `=`. An entry with no `=` is an error with exit code 2.
To set an empty value, end the entry with `=`, as in `--label build=`.

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

- `--push`, and a `push` key from the configuration file unless `--oci-archive` replaces it. A
  registry is not the place for an image from every save.
- `--no-build`. That sink stages into one directory, and a second pack into the same directory
  is an error, because the directory is no longer empty.
- `--format json`. Each pack prints a text report.

`--watch` is a command-line flag only. It has no key in the configuration file and no input on
the GitHub Action.

## In CI

To pack in a GitHub Actions workflow with the composite action instead of shelling out to the CLI,
see **[GitHub Action](github-action.md)**.

## Run `pack` in a container — the `:toolbox` image

The `FROM scratch` release image carries the binary and nothing else: no shell, no tools, and no
certificate store. It runs every subcommand that needs no external tool. That is `lint`,
`doctor`, `graph`, `diff`, `unpack`, and `index` without `--sign`, plus the `--version` and
`--completions` flags.
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

Scratchsmith reads the compiled-in certificates through `/proc`. A container runtime mounts
`/proc` by default. Without it, the command fails and says so.

If `SSL_CERT_FILE` or `SSL_CERT_DIR` is set, scratchsmith never uses the compiled-in
certificates. If the path that you set gives no certificates, the command fails and names the
variable.

One subcommand does not run there. `pack` needs ldconfig, plus a container engine for the
default sink and strip, syft or grype for the options that use them.

The **`:toolbox`** image bundles the `pack` toolchain (ldconfig, strip, syft, grype, cosign,
upx, tini, the docker CLI) on a Wolfi base. With it, `pack` itself runs inside a container.
That image has no dpkg and no rpm database, so `--packages` has no data there. The `packages`
field is `null`. An `image` output that you set fails. If `--sbom` or `--scan` is on, a `sbom`
output that you set fails too. The default stays quiet.

```sh
# Daemonless — no socket needed; write an OCI archive or push straight to a registry.
docker run --rm -v "$PWD:/w" -w /w ghcr.io/schubydoo/scratchsmith:toolbox \
  pack --oci-archive app.oci.tar ./app
docker run --rm -v "$PWD:/w" -w /w \
  -v "$HOME/.docker:/docker:ro" -e DOCKER_CONFIG=/docker \
  ghcr.io/schubydoo/scratchsmith:toolbox pack --push ghcr.io/you/app:1.0 ./app
```

`--push` reads the registry login from the Docker config, so mount one that holds the
credentials themselves. A credential helper on the host is not available inside the container.

Prefer the daemonless sinks (`--push` / `--oci-archive`) in CI. The **default `docker load` sink**
needs a host engine, so mount its socket. That socket is **root-equivalent on the host**, so use
it only where you trust the workflow:

```sh
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v "$PWD:/w" -w /w \
  ghcr.io/schubydoo/scratchsmith:toolbox pack ./app
```

Tags: `:toolbox` (latest), `:X.Y.Z-toolbox`, `:X.Y-toolbox`. Verify its signature exactly like the
scratch image. See [Verifying releases](verifying.md).
