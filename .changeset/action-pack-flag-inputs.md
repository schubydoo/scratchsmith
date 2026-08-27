---
default: minor
---

The GitHub Action now exposes `entrypoint`, `cmd`, `env`, `workdir`, `label`, `healthcheck`, `upx`, `sbom-file`, `scan`, `scan-fail-on`, and `max-size` as first-class inputs, each mapping to the `pack` flag of the same name (previously reachable only through the `args` escape hatch). `scan`/`scan-fail-on` fail fast with a clear message when grype is missing from the runner, mirroring the existing syft preflight for `sbom`.
