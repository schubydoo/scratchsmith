---
default: security
---

#### `pack` keeps soname symlinks inside the image root

A `DT_NEEDED` name such as `../../../tmp/libx.so` comes from the packed binary, and scratchsmith created its soname symlink at that path joined under the staging directory. The link could land outside that directory. Scratchsmith now walks the name inside the image, where `..` at the root stays at the root. A link already in a reused `--output` directory is read the same way, so an absolute link value names a path in the image, not on the host.
