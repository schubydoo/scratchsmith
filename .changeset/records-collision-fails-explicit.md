---
default: major
---

#### An explicit `sbom` or `image` fails when a staged file is at a record path

The packed program or an `--include` library can sit on the host at a package record path, such as `/var/lib/dpkg/status.d/libc6`. A `sbom` or `image` that you set in `--packages` then fails with exit code 1, where 1.x exited 0 and lost the file.
