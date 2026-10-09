---
default: patch
---

#### `--packages` on older rpm hosts

Scratchsmith now finds the rpm database on openSUSE Leap 15, where the package that provides
`rpm` has another name. Before, `packages` was empty there, with no warning. Rocky Linux 8 keeps
its database in the Berkeley DB format. There, `--packages image` now warns that the image is
not reproducible, and the image no longer contains the database lock file.
