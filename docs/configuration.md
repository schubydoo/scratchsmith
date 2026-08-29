# Configuration

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
include = ["libnss_myhostname.so.2"]
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
`--format`, stay command-line-only — they are not config keys.

## Profiles

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
