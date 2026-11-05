---
default: patch
---

#### Package records no longer replace or remove a file that the pack staged

A pack with `sbom` or `image` wrote a package record over a staged program or library, and `sbom` then removed it. Now the file stays, and the default `sbom` leaves the records out with a warning. A link or a directory at a record path gets that warning too, where it failed the pack before.
