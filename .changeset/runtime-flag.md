---
default: minor
---

#### `--runtime` — pack with podman or nerdctl, not just docker

`pack --runtime <docker|podman|nerdctl>` (and the matching `runtime` key in `scratchsmith.toml`)
selects the container engine for the default load sink and the `--smoke` run, so podman/nerdctl
users can pack without Docker. It defaults to `docker`; the daemonless sinks (`--oci-archive`,
`--push`) never invoke a runtime and are unaffected.
