---
default: minor
---

#### `--oci-archive <file>` — daemonless OCI image output (Task 5.1)

`scratchsmith pack --oci-archive img.tar ./app` writes a standard **OCI image-layout**
tarball (`oci-layout` + `index.json` + content-addressed `blobs/sha256/*`) with **no Docker
daemon** — the first half of the daemonless sink. The blobs are the exact same reproducible
layer + config the docker-load path uses, so the image is byte-identical; it's consumable by
`skopeo`, `buildah`, and any OCI-aware tooling (and by `docker load` where the containerd
image store is enabled). Direct registry push (Task 5.2) is next.
