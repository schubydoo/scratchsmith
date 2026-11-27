---
default: patch
---

#### `install.sh` accepts `VERSION` with or without the leading `v`

`VERSION=2.2.0` used to look for a release tag named `2.2.0`, which does not exist, so the download failed. The installer now adds the `v` when it is missing, so `VERSION=2.2.0` and `VERSION=v2.2.0` install the same release, as the GitHub Action's `version` input already did.
