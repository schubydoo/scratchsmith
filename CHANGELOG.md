# Changelog

All notable changes to Scratchsmith are documented here. This file is generated from
`.changeset/*.md` fragments by [knope](https://knope.tech) — do not hand-edit it.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
## 1.5.0 (2026-09-21)

### Features

#### `locale` and `symlinks` GitHub Action inputs ([#196](https://github.com/schubydoo/scratchsmith/pull/196))

The action now takes `locale` and `symlinks` directly, instead of through the `args` escape
hatch. `locale` takes one locale name per line. `symlinks` takes one of `copy-all`, `preserve`,
`copy-unsafe`, or `skip-unsafe`. Both pass straight to the pack flag of the same name.

Under a `symlinks` mode that stages a link, an `add-file` source that is a link to a directory
no longer fails. `skip-unsafe` stages nothing for a link it cannot honor.

#### Three silently accepted input shapes now warn ([#207](https://github.com/schubydoo/scratchsmith/pull/207))

`--label NAME` and `--env NAME` without an `=`, and a nested `[profile.a.profile.b]` table, each
print one warning line to standard error. The pack still succeeds and the exit code does not
change. A well-formed pair, including a deliberate empty value like `--label build=`, stays
quiet.

### Fixes

#### A rootfs entry that cannot be read now fails the pack ([#200](https://github.com/schubydoo/scratchsmith/pull/200))

Building the image layer skipped unreadable files, and everything under an unreadable directory.
The pack reported success, and under `--push --sign` it signed the short image. It failed at run
time instead, on a library that was never there.

The build now stops at the file and names its path in the staged rootfs under `TMPDIR`.

#### `index` and `--push` now report a missing certificate store ([#216](https://github.com/schubydoo/scratchsmith/pull/216))

On a host with no CA trust store, which covers most minimal containers and every `FROM scratch`
image, both commands died with no message. They now fail with an error that names the cause and
what to install. Nothing changes where a trust store is present.

#### A broken credential helper no longer pushes anonymously ([#202](https://github.com/schubydoo/scratchsmith/pull/202))

A failed credential lookup counted as "no credential here", so the push went ahead anonymously.
You saw a bare 401, or a push that worked under an identity you did not choose.

A lookup that fails now stops the push and names the registry. No credential is still anonymous,
which is how you push to a public or local registry.

Separately, a token response body that cannot be read now reports the dropped connection instead
of a token-decoding problem.

#### A library that cannot be read now fails the pack ([#201](https://github.com/schubydoo/scratchsmith/pull/201))

The resolver skipped a library it cannot read and carried on, so nothing that library needs was
resolved or staged. `graph` then printed a tree with a branch missing. `pack` failed later, at
the copy, naming the wrong thing.

It now stops at the library and names the path.

### Deprecated

#### A label, an environment entry, or a profile table that scratchsmith cannot use ([#207](https://github.com/schubydoo/scratchsmith/pull/207))

Scratchsmith 2.0 rejects `--label NAME` and `--env NAME` without an `=`, and a nested
`[profile.a.profile.b]` table. Write `--label NAME=value` and `--env NAME=value`, and move a
nested profile to a top-level `[profile.<name>]` table. The new
[Deprecations](https://schubydoo.github.io/scratchsmith/latest/deprecations/) page carries the
migration for each.

## 1.4.0 (2026-09-20)

### Features

#### `add-file` GitHub Action input ([#188](https://github.com/schubydoo/scratchsmith/pull/188))

The action now exposes `--add-file` as a first-class input. Each line is one `SRC:DST` spec, or
one bare absolute `SRC` that keeps its own path in the image. The action passes each line to the
pack flag of the same name, so the rules do not change. Regular files only. A missing source, a
directory, or a destination already in the image fails the pack. Before this, the flag was
reachable only through the `args` escape hatch.

#### `--locale`: stage a glibc locale in the image ([#189](https://github.com/schubydoo/scratchsmith/pull/189))

`pack --locale en_US.UTF-8` stages one compiled locale at `/usr/lib/locale/en_US.UTF-8`. With no
`LOCPATH` set, glibc reads exactly that path. Until now a scratch image carried no locale data.
Every packed binary ran in the C locale, and `setlocale` failed for any other.

The data comes from a matching host directory under `/usr/lib/locale`. When there is none,
`localedef` compiles the locale from the glibc sources at `/usr/share/i18n`. When neither
source is available, the pack fails and names what is missing. `scratchsmith doctor` now
probes `localedef` too.

The host `locale-archive` is never copied, because one archive holds every locale the host has.
A single locale costs about 3 MB, and most of that is the collation table `LC_COLLATE`.

Staging the data does not select it, so set `LANG`, `LC_ALL`, or a per-category `LC_*` entry
with `--env`. If nothing selects a staged locale, the pack warns. If a selector names a locale
the pack did not stage, the pack warns as well. glibc answers that mismatch with a silent
fallback to the C locale.

The flag repeats and takes a locale name, not a path. The `locale` key in `scratchsmith.toml`
takes the same list.

#### The pack report names the loader ([#192](https://github.com/schubydoo/scratchsmith/pull/192))

`pack --format json` gains an `interpreter` field, and the text output gains a `loader` line.
Both carry the image path of the dynamic loader, which is the one staged path the binary's
`PT_INTERP` chooses rather than scratchsmith. An ELF that carries no `PT_INTERP` reports null,
and the text line is absent. A static binary is the usual case for that, but not the only
one. Read the field as "no `PT_INTERP`", not as "static".

Until now a pack recorded every other fact about the image and stayed silent about the loader.
A job that wanted to assert which loader shipped had to unpack the image and look. It can now
read one field.

The field is additive, so an existing consumer of the JSON is unaffected.

#### `--symlinks`: keep a named symlink as a symlink ([#191](https://github.com/schubydoo/scratchsmith/pull/191))

Scratchsmith copies the content of a symlink you name, so the image gets a regular file and
not the link. That loses the path itself. Packing `/usr/bin/python3`, a link to `python3.13`,
produced an image with the real file and nothing at `/usr/bin/python3`. A container that ran
the name rather than the target then failed to start.

`pack --symlinks <mode>` chooses what happens. `copy-all` copies the content to the named
path, which is the default and what every earlier release did. `preserve` recreates the link.
`copy-unsafe` recreates a link whose target is in the image and copies the content for one
whose target is not. `skip-unsafe` recreates the safe link and stages nothing for the other.
A dangling or skipped link warns and names the target.

The mode covers the packed binary's own path and each `--add-file` source. Resolved libraries
are not in scope, because the loader decides those and the stager already recreates the soname
links it needs. Preserving a link never pulls its target into the image, so an image still
gains only what you asked for. The packed binary is the exception: its real file is always
staged, so a preserved link to it always resolves. The `symlinks` key in `scratchsmith.toml`
takes the same value.

A mode other than `copy-all` relaxes two `--add-file` rules, and only for a source that is
itself a symlink. A preserved link is staged as a link, so a link to a directory no longer
fails. Under `skip-unsafe` an entry the pack cannot honor stages nothing and warns. Every link
the stager writes carries a relative value, so a staged tree resolves inside itself.

## 1.3.0 (2026-09-19)

### Features

#### `--add-file`: copy any host file into the image ([#181](https://github.com/schubydoo/scratchsmith/pull/181))

`pack --add-file SRC:DST` copies a host file into the image at `DST`. A bare absolute
`--add-file SRC` keeps the host path. Until now `--ca-certs` and `--tz` each added one fixed
file, and there was no way to add another. A program that reads a configuration file or a data
file at runtime now packs without a wrapper step. The flag repeats and takes regular files
only. The `add-file` key in `scratchsmith.toml` takes the same list. A missing source, a
directory, or a `DST` that is already in the image fails the pack and names the path. The
layer writer canonicalizes modes, so in an image the file lands owned by uid 0. Its mode is
`0644`. When the source is executable, the mode is `0755`.

## 1.2.1 (2026-09-15)

### Security

#### rustls 0.23.45 (RUSTSEC-2026-0285) ([#168](https://github.com/schubydoo/scratchsmith/pull/168))

The shipped binary now links rustls 0.23.45. Version 0.23.44 accepts TLS 1.3 handshake
messages across encryption level boundaries (RUSTSEC-2026-0285, medium, 5.3). rustls
arrives through `reqwest`, so only `Cargo.lock` changes.

## 1.2.0 (2026-09-11)

### Features

#### `nss`, `deny`, and `require` GitHub Action inputs ([#142](https://github.com/schubydoo/scratchsmith/pull/142))

The action now exposes three more pack options as first-class inputs. `nss` selects the NSS
modules to stage. If a listed library ships, `deny` fails the pack. If a listed library is
absent, `require` fails the pack. Each input maps to the pack flag of the same name.

#### `graph` — print a binary's resolved dependency tree ([#133](https://github.com/schubydoo/scratchsmith/pull/133))

`scratchsmith graph <binary>` prints the binary's dependency tree. It resolves the binary
the same way `pack` does. The default output is an ASCII tree. `--format json` prints a
machine-readable adjacency list. The command builds no image and stages nothing, so it
audits an image fast. A repeated library is shown once in full and marked `(*)` after that.
An unresolved dependency is shown as `(missing)`. `--include <lib>` adds a `dlopen`'d
library, like `pack`.

#### `diff` — compare two staged rootfs directories ([#136](https://github.com/schubydoo/scratchsmith/pull/136))

`scratchsmith diff <before> <after>` reports the files added, removed, and changed between
two staged rootfs directories, plus the total size delta. `--exit-code` makes it exit
non-zero on any difference, so CI can gate on image drift. `--format json` emits the same
data. Stage the directories with `pack --no-build --output`, or later from an unpacked image.

#### `--deny` / `--require` — gate the pack on its libraries ([#135](https://github.com/schubydoo/scratchsmith/pull/135))

`pack` can now enforce a library policy in CI. If a `--deny <soname>` library is staged,
the pack fails. If a `--require <soname>` library is absent, the pack fails. Both flags take
an exact soname, repeat, and have matching `deny` and `require` keys in `scratchsmith.toml`.
Read the sonames from `scratchsmith graph`. This gate complements `lint`.

#### `--nss` — choose which NSS modules the image carries ([#130](https://github.com/schubydoo/scratchsmith/pull/130))

`pack --nss <files,dns,none>` (and the matching `nss` key in `scratchsmith.toml`) selects which
glibc name-service (NSS) modules stage into the image. Pass a comma-separated list: `--nss files`
keeps local-file lookups but drops DNS, and `--nss none` stages no modules and no `nsswitch.conf`.
Fewer modules trim the image's CVE surface. The generated `nsswitch.conf` always matches the
selection, and a mode without `files` also drops the now-unreadable `/etc/passwd` and `/etc/group`.
The default stays `files,dns`, so existing packs are unchanged.

#### `unpack` — extract an OCI image archive to a directory ([#137](https://github.com/schubydoo/scratchsmith/pull/137))

`scratchsmith unpack <archive> <dir>` reads an OCI-layout archive (from `pack --oci-archive`,
or any skopeo/buildah export), applies each layer in order into `<dir>`, and honors whiteouts.
It refuses any path that escapes the target. `--format json` reports the source, the
directory, and the layer and file counts. Combine it with `diff` to audit an image you did
not build: unpack two images, then compare the directories.

## 1.1.0 (2026-08-30)

### Features

#### `index` — assemble a multi-arch image index, daemonless ([#94](https://github.com/schubydoo/scratchsmith/pull/94))

New `scratchsmith index <target> <source>...` subcommand assembles the per-arch images a CI
matrix already pushed into a multi-arch OCI image index and pushes it to `<target>` — the
daemonless equivalent of `docker manifest create`, with no Docker or buildx involved. Each
source's platform is read from its own image config. Add `--sign` to cosign-sign the index by
digest.

#### `--runtime` — pack with podman or nerdctl, not just docker ([#100](https://github.com/schubydoo/scratchsmith/pull/100))

`pack --runtime <docker|podman|nerdctl>` (and the matching `runtime` key in `scratchsmith.toml`)
selects the container engine for the default load sink and the `--smoke` run, so podman/nerdctl
users can pack without Docker. It defaults to `docker`; the daemonless sinks (`--oci-archive`,
`--push`) never invoke a runtime and are unaffected.

#### `:toolbox` image — run `pack` inside a container ([#101](https://github.com/schubydoo/scratchsmith/pull/101))

A new `ghcr.io/schubydoo/scratchsmith:toolbox` image bundles the full `pack` toolchain (ldconfig,
strip, syft, grype, cosign, upx, tini, and the docker CLI) on a Wolfi base, so `scratchsmith pack`
runs *inside* a container — unlike the minimal `FROM scratch` release image, which can only run
`--version`/`lint`/`doctor`. It's cosign-signed and multi-arch, published on release with
`:toolbox` / `:X.Y.Z-toolbox` tags. Prefer the daemonless `--push` / `--oci-archive` sinks in CI;
the default `docker load` sink needs a mounted (root-equivalent) docker socket.

### Fixes

#### Stamp the host architecture into the image config ([#93](https://github.com/schubydoo/scratchsmith/pull/93))

The generated image config previously always recorded `architecture: amd64`. Packing on an
arm64 host therefore produced an image mislabeled as amd64, which runtimes could refuse to run
and which broke multi-arch image indexes. Scratchsmith now records the real host architecture
(`amd64`, `arm64`, …), so a per-arch CI matrix produces correctly-labeled images.

## 1.0.0 (2026-08-27)

### Features

- The GitHub Action now exposes `entrypoint`, `cmd`, `env`, `workdir`, `label`, `healthcheck`, `upx`, `sbom-file`, `scan`, `scan-fail-on`, and `max-size` as first-class inputs, each mapping to the `pack` flag of the same name (previously reachable only through the `args` escape hatch). `scan`/`scan-fail-on` fail fast with a clear message when grype is missing from the runner, mirroring the existing syft preflight for `sbom`. ([#87](https://github.com/schubydoo/scratchsmith/pull/87))
- `pack --label KEY=VALUE` writes OCI image labels and `pack --healthcheck <cmd>` sets the image `HEALTHCHECK` (exec form — it runs inside the scratch image, so it must name an executable present there). Both are repeatable and config-settable (`label` / `healthcheck`). ([#79](https://github.com/schubydoo/scratchsmith/pull/79))
- Added a one-line installer. `curl -fsSL https://raw.githubusercontent.com/schubydoo/scratchsmith/main/install.sh | bash` downloads the signed Linux release binary (amd64/arm64), verifies its SHA-256 against the cosign-signed `checksums.txt` (and checks the cosign signature itself when cosign is installed), and installs it; `bash -s -- --uninstall` removes it. Linux only — macOS/Windows fail fast with guidance to use a container or WSL2. ([#83](https://github.com/schubydoo/scratchsmith/pull/83))
- `pack --max-size <SIZE>` fails the build when the packed payload exceeds a budget — e.g. `12MB`, `512KiB`, or a bare byte count (decimal K/M/G are ×1000, binary Ki/Mi/Gi are ×1024). Config-settable as `max-size`. ([#80](https://github.com/schubydoo/scratchsmith/pull/80))
- Every release now ships a CycloneDX SBOM of Scratchsmith's own dependency graph (`scratchsmith-v<ver>.cdx.json`, generated by syft from `Cargo.lock`). It's listed in `checksums.txt`, so the existing cosign signature and SLSA provenance cover it too. ([#75](https://github.com/schubydoo/scratchsmith/pull/75))
- Scratchsmith declares its stable API surface for 1.0. The CLI flags, `scratchsmith.toml` keys, the `--format json` report schema (now pinned by a golden test), and exit codes are covered by Semantic Versioning — a breaking change to any of them requires a new major version. See the new **Stability** section in the README. Human-readable text, log output, and exact image bytes are explicitly not frozen. ([#82](https://github.com/schubydoo/scratchsmith/pull/82))
- `pack --scan` vulnerability-scans the packed rootfs with grype (reusing the SBOM when `--sbom` is set, else scanning the rootfs), and `--scan-fail-on <severity>` fails the build on a finding at or above that severity. The report includes vulnerability counts by severity, and `doctor` reports whether `grype` is available. ([#78](https://github.com/schubydoo/scratchsmith/pull/78))

## 0.2.2 (2026-08-26)

### Features

- `scratchsmith.toml` now covers every packing flag, and supports named `[profile.<name>]` sections selectable with `pack --profile <name>` (layered over the base config, CLI flags still win) — so a `[profile.ci]` can set strip/sbom/sign/push together. ([#71](https://github.com/schubydoo/scratchsmith/pull/71))
- `pack --upx` compresses the packed binary with UPX (it self-decompresses at runtime); the size report shows the delta, and `doctor` reports whether `upx` is available. ([#69](https://github.com/schubydoo/scratchsmith/pull/69))

## 0.2.1 (2026-08-26)

### Fixes

- Automate crates.io publishing with OIDC trusted publishing, and fix the logo so it renders on the crates.io page. ([#66](https://github.com/schubydoo/scratchsmith/pull/66))

## 0.2.0 (2026-08-25)

### Features

#### The daemonless & supply-chain features, under their intended version ([#46](https://github.com/schubydoo/scratchsmith/pull/46))

The daemonless output (`--oci-archive`, `--push`), Docker identity-token authentication, and
image signing (`--push --sign`) are the substance of this release. They first shipped in 0.1.4,
which was cut in error under a patch version; 0.2.0 re-releases the identical code under the
minor version those features warrant. **No code changed between 0.1.4 and 0.2.0** — pin to
0.2.0 (or later).

## 0.1.4 (2026-08-25)

### Features

#### `--push` now authenticates with Docker identity-token credentials ([#41](https://github.com/schubydoo/scratchsmith/pull/41))

Registries that hand out an **identity token** at `docker login` (an OAuth2 refresh token)
now work with `--push`. Previously only username/password credentials were used and an
identity token fell back to an anonymous, failing push. Scratchsmith now runs the
`grant_type=refresh_token` exchange against the registry's token endpoint itself — reading the
`WWW-Authenticate` realm from `/v2/` and trading the identity token for a short-lived bearer
access token — because `oci-client` only performs that exchange for Basic credentials. The
common username/password path is unchanged.

#### `--oci-archive <file>` — daemonless OCI image output (Task 5.1) ([#34](https://github.com/schubydoo/scratchsmith/pull/34))

`scratchsmith pack --oci-archive img.tar ./app` writes a standard **OCI image-layout**
tarball (`oci-layout` + `index.json` + content-addressed `blobs/sha256/*`) with **no Docker
daemon** — the first half of the daemonless sink. The blobs are the exact same reproducible
layer + config the docker-load path uses, so the image is byte-identical; it's consumable by
`skopeo`, `buildah`, and any OCI-aware tooling (and by `docker load` where the containerd
image store is enabled). Direct registry push (Task 5.2) is next.

#### `--sign` — cosign-sign the image `pack` produces ([#43](https://github.com/schubydoo/scratchsmith/pull/43))

`scratchsmith pack --push <ref> --sign` keyless-signs the pushed image **by digest** with
cosign, and `--sbom --sign` additionally attaches the SBOM as a signed `cosign attest`
attestation (CycloneDX or SPDX, matching `--sbom-format`). Signing targets the exact digest the
push returns, so it's immune to a tag being moved afterwards. `--sign` requires `--push` (cosign
signs a registry image), and the signature is `cosign verify`-able — proven end-to-end by the
`push-auth-smoke` workflow. This closes the last gap in the supply-chain story: not just signed
release *artifacts*, but a signature on the image scratchsmith itself builds.

#### `--push <ref>` — daemonless registry push (Task 5.2) ([#36](https://github.com/schubydoo/scratchsmith/pull/36))

`scratchsmith pack --push ghcr.io/you/app:latest ./app` pushes the assembled image
**straight to a registry with no Docker daemon** — the config + layer blobs and the manifest
go up over HTTPS (via `oci-client`), blobs the registry already has are skipped, and
credentials come from your local `docker login`. Together with `--oci-archive`, this completes
the daemonless sink: you can pack **and publish** an image without ever touching a Docker
daemon. (A localhost registry is treated as plain-HTTP, matching Docker's insecure-localhost
default.)

## 0.1.3 (2026-08-24)

### Features

#### Homebrew tap — `brew install schubydoo/scratchsmith/scratchsmith` ([#30](https://github.com/schubydoo/scratchsmith/pull/30))

Scratchsmith is now installable via a Homebrew tap (Linux amd64/arm64, from the signed
release tarballs). The formula (`Formula/scratchsmith.rb`) is regenerated from each
release's cosign-verified `checksums.txt` by `packaging-bump.yml`, which opens an
auto-merging PR; that merge dispatches the [tap](https://github.com/schubydoo/homebrew-scratchsmith)
to mirror it — so `brew upgrade` tracks releases hands-free.

## 0.1.2 (2026-08-24)

### Features

#### GitHub Action — `pack` in CI with no shell glue ([#27](https://github.com/schubydoo/scratchsmith/pull/27))

A composite `schubydoo/scratchsmith` action downloads the signed release binary for the runner,
verifies it against the release checksums, and runs `pack`. Inputs map to the real pack flags —
`sbom`, `strip`, `user` (non-root by default), `output`, `smoke`, `ca-certs`/`tz`/`init`, `include`,
plus an `args` escape hatch — and it exposes `image`, `rootfs`, and the full JSON `report` as
outputs. An optional `push` input tags and pushes the built image (after your own registry login).

```yaml
- uses: schubydoo/scratchsmith@v0.1.2
  with:
    binary: ./dist/app
    strip: true
    smoke: true
```

## 0.1.1 (2026-08-24)

### Fixes

#### Docs — install from signed releases, verification steps, and post-launch status ([#25](https://github.com/schubydoo/scratchsmith/pull/25))

The README and docs site now cover installing from the signed release binaries (amd64/arm64) and
the GHCR image, add a **Verifying releases** section (`cosign` + `gh attestation verify`), and
correct the pre-release "not published / signing planned" wording now that v0.1 ships signed,
published releases. The remaining "signing" gap — signing the image `pack` itself produces — is
called out precisely (it needs the daemonless registry push).

## 0.1.0 (2026-08-24)

### Features

#### Initial release — pack prebuilt dynamic glibc binaries into `FROM scratch` images ([#22](https://github.com/schubydoo/scratchsmith/pull/22))

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
