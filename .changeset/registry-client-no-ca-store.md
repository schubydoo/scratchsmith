---
default: patch
---

#### `index` and `--push` now report a missing certificate store

On a host with no CA trust store, which covers most minimal containers and every `FROM scratch`
image, both commands died with no message. They now fail with an error that names the cause and
what to install. Nothing changes where a trust store is present.
