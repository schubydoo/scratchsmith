---
default: minor
---

#### `pack --push-untagged` pushes an image by digest without touching an image tag

`pack --push` with a reference that names no tag pushes to `latest`, and that is unchanged. The new `--push-untagged` flag, or `push-untagged = true` in `scratchsmith.toml`, pushes the manifest under its own digest and creates or moves no image tag. The `--push` reference then names only the repository. The report, and the `pushed` field of `--format json`, give the pushed `registry/repo@sha256:...` reference, and `--sign` signs that digest. cosign still stores the signature, and the SBOM attestation, under its own `sha256-<hex>` tags. A tag or a digest in the reference is a usage error.
