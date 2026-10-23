---
default: security
---

#### `pack` keeps the staged loader inside the image root

The program interpreter path comes from the packed binary, and scratchsmith joined it under the staging directory as text. A path such as `/../../tmp/x` put the loader copy outside that directory. Scratchsmith now walks the path the way the kernel does inside the image, where `..` at the root stays at the root. A link already in a reused `--output` directory is read the same way, so an absolute link value names a path in the image, not on the host.
