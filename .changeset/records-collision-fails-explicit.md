---
default: major
---

#### A package record no longer replaces or removes a file that the pack staged

The packed program or an `--include` library can sit on the host at a package record path, such as `/var/lib/dpkg/status.d/libc6`. In 1.x, an explicit `sbom` or `image` in `--packages` wrote the record over that file, and `sbom` then removed it, with exit code 0. Now an explicit `image`, or an explicit `sbom` with `--sbom` or `--scan`, fails the pack with exit code 1, and the file stays. With the default `--packages`, the pack leaves the records out and warns.
