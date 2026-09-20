# Configuration

Instead of a long command line, put the defaults for `pack` in a `scratchsmith.toml` and load it
with `--config`. Every key below maps to a `pack` flag, and **a command-line flag overrides the
file**.

| `scratchsmith.toml` key | CLI flag | What it does |
|---|---|---|
| `binary` | *(positional arg)* | The ELF binary to pack. |
| `entrypoint` | `--entrypoint` | Image `ENTRYPOINT` (defaults to the packed binary's path). |
| `cmd` | `--cmd` | Default arguments appended to the entrypoint (list, and `--cmd` is repeatable). |
| `env` | `--env` | Image environment entries, each `KEY=VALUE` (list). |
| `workdir` | `--workdir` | Image `WORKDIR`. |
| `user` | `--user` | Image user `UID[:GID]`. Defaults to a non-root UID. `0`/root prints a warning. |
| `label` | `--label` | OCI image label `KEY=VALUE` (list, and `--label` is repeatable). |
| `healthcheck` | `--healthcheck` | Container `HEALTHCHECK` in exec form (list, and repeatable). It runs inside the scratch image, so it must name an executable present there, typically the packed binary. |
| `strip` | `--strip` | Strip symbols from the binary and libraries. |
| `upx` | `--upx` | Compress the packed binary with UPX (it self-decompresses at runtime). |
| `smoke` | `--smoke` | Run the built image once. If the binary cannot start, the pack fails. |
| `sbom` | `--sbom` | Write an SBOM of the packed rootfs (requires `syft`). |
| `sbom-file` | `--sbom-file` | SBOM output path (default: `sbom.json`). |
| `sbom-format` | `--sbom-format` | SBOM format: `cyclonedx-json` (default) or `spdx-json`. |
| `scan` | `--scan` | Vulnerability-scan the packed rootfs with grype. When `--sbom` is set, it reuses that SBOM. Otherwise it scans the rootfs. |
| `scan-fail-on` | `--scan-fail-on` | Fail the pack on a grype finding at or above this severity: `negligible`/`low`/`medium`/`high`/`critical` (implies `--scan`). `negligible` blocks everything, including findings grype cannot rank. Stricter levels ignore unrankable findings. |
| `ca-certs` | `--ca-certs` | Add the TLS CA bundle (`/etc/ssl/certs/ca-certificates.crt`). |
| `tz` | `--tz` | Add the resolved local timezone (`/etc/localtime`). |
| `init` | `--init` | Add a minimal init (`tini`) as pid 1 wrapping the entrypoint. |
| `add-file` | `--add-file` | Copy a host file into the image (list). Each entry is `SRC:DST`, or a bare absolute `SRC` to keep the host path. Regular files only. A missing source, a directory, or a `DST` already in the image fails the pack. In an image the file lands owned by uid 0 at mode `0644`, or `0755` for an executable source. The layer writer canonicalizes modes, so do not add a secret this way. |
| `locale` | `--locale` | Stage a compiled glibc locale under `/usr/lib/locale` (list). Name it as glibc does, such as `en_US.UTF-8`. The data comes from a matching host directory under `/usr/lib/locale`. When there is none, `localedef` compiles the locale from `/usr/share/i18n`. The host `locale-archive` is never copied. Set `LANG`, `LC_ALL`, or a per-category `LC_*` entry with `--env` to select the locale. If nothing selects a staged locale, the pack warns. If a selector names a locale the pack did not stage, the pack warns as well. |
| `include` | `--include` | Force-stage extra libraries by soname or path, for example `dlopen`'d plugins (list). |
| `nss` | `--nss` | Name-service (NSS) modules to stage for glibc name lookups: `files`, `dns`, or `none` (list). Fewer modules trim CVE surface. A mode without `files` also drops `/etc/passwd` and `/etc/group`, which glibc reads through the `files` module. Default: `files` and `dns`. |
| `deny` | `--deny` | If this library ships, the pack fails (list). Resolved libraries, the loader, and NSS modules are all in scope, matched by soname or staged file name. This is a CI policy gate. Read sonames from `scratchsmith graph`. |
| `require` | `--require` | If this library does not ship, the pack fails (list). Same scope as `deny`. |
| `sign` | `--sign` | cosign-sign the pushed image (keyless, by digest). Requires a push target. |
| `push` | `--push` | Push the image straight to this registry reference, daemonless. |
| `max-size` | `--max-size` | If the packed image exceeds this size, the pack fails. The packed image is the fully-staged rootfs: payload + NSS includes + runtime extras. Write the size as `12MB`, `512KiB`, or a bare byte count (K/M/G are ×1000, Ki/Mi/Gi are ×1024). |
| `runtime` | `--runtime` | Container engine for the default load sink and the `--smoke` run: `docker` (default), `podman`, or `nerdctl`. The daemonless sinks (`--oci-archive`, `--push`) never invoke a runtime, so this is ignored there. |

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
add-file = ["./app.conf:/etc/app/app.conf", "/etc/motd"]
locale = ["en_US.UTF-8"]
include = ["libnss_myhostname.so.2"]
nss = ["files", "dns"]
deny = ["libssl.so.3"]
require = ["libseccomp.so.2"]
sign = true
push = "ghcr.io/you/app:latest"
max-size = "50MB"
runtime = "docker"
```

```sh
scratchsmith pack --config scratchsmith.toml                 # binary + all keys come from the file
scratchsmith pack --config scratchsmith.toml --push ghcr.io/you/app:dev ./other   # CLI overrides binary + push
```

The delivery sinks `--oci-archive <file>` and `--no-build` / `--output <dir>`, and the display-only
`--format`, stay command-line-only. They are not config keys.

## Profiles

Group keys under `[profile.<name>]` and pick one with `--profile <name>` (which requires
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
command-line flag. Booleans OR together, so a profile can switch something **on** but not off.
A scalar is replaced by the more specific layer. A non-empty list replaces the one beneath it.
