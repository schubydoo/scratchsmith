---
default: minor
---

#### `--push <ref>` — daemonless registry push (Task 5.2)

`scratchsmith pack --push ghcr.io/you/app:latest ./app` pushes the assembled image
**straight to a registry with no Docker daemon** — the config + layer blobs and the manifest
go up over HTTPS (via `oci-client`), blobs the registry already has are skipped, and
credentials come from your local `docker login`. Together with `--oci-archive`, this completes
the daemonless sink: you can pack **and publish** an image without ever touching a Docker
daemon. (A localhost registry is treated as plain-HTTP, matching Docker's insecure-localhost
default.)
