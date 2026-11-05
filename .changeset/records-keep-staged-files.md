---
default: patch
---

#### Package records no longer replace or remove a file that the pack staged

The packed program or an `--include` library can sit on the host at a package record path, such as `/var/lib/dpkg/status.d/libc6`. A pack with `sbom` or `image` wrote the record over that file, and `sbom` then removed it. Now the file stays, and the default `sbom` leaves the records out with a warning. A `sbom` or `image` that you set fails the pack, as for an `--add-file` at that path.
