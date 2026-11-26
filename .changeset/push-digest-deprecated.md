---
default: minor
---

#### A digest in `--push` no longer crashes, and is deprecated

`pack --push` with a reference that names a digest, such as `ghcr.io/owner/app@sha256:…`, crashed when the registry answered the manifest upload with no `Location` header, as AWS ECR does. The push now completes. A digest in the `--push` reference is deprecated: it prints one warning line on standard error, the exit code is unchanged, and 3.0 will refuse it. Push to a tag instead.
