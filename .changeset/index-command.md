---
default: minor
---

#### `index` — assemble a multi-arch image index, daemonless

New `scratchsmith index <target> <source>...` subcommand assembles the per-arch images a CI
matrix already pushed into a multi-arch OCI image index and pushes it to `<target>` — the
daemonless equivalent of `docker manifest create`, with no Docker or buildx involved. Each
source's platform is read from its own image config. Add `--sign` to cosign-sign the index by
digest.
