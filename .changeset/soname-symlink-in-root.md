---
default: security
---

#### `pack` keeps soname symlinks inside the image root

A `DT_NEEDED` name such as `../../../tmp/libx.so` comes from the packed binary, and scratchsmith created its soname symlink at that path joined under the staging directory. The link could land outside that directory. Scratchsmith now walks the name inside the image, where `..` at the root stays at the root, and fails with exit `1` when a staged link leads out of the root.
