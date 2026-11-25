---
default: patch
---

#### `unpack` warns when an archive's index lists more than one manifest

`unpack` applies only the first manifest of the archive's index. With more than one, it said nothing, so an audit of a multi-platform archive could pass for a platform it never read. It now prints a warning on stderr that names the digest and platform of the manifest it applied. The output on stdout and the exit code do not change.
