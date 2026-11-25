---
default: patch
---

#### unpack applies a layer that replaces a hard link or changes a path's type

`unpack` failed with "File exists" or "Is a directory" when a later layer wrote a hard link again or turned a directory into a symlink, which package upgrades and merged-`/usr` conversions do. It now replaces the existing path, as the OCI layer rules say, and a directory over a directory keeps its contents. A second `unpack` into the same directory works too.
