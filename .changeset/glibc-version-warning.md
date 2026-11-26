---
default: minor
---

#### `pack` warns when the binary needs a newer glibc than the host's

A binary built against a newer glibc than the build host's used to pack without a word, and then fail to start with `version 'GLIBC_2.38' not found`. `pack` now reads the `GLIBC_` symbol versions that the binary and each staged library need, and prints a warning on standard error for each object that needs a version the staged glibc does not define. The warning names the object, the version it needs and the staged glibc's version. The pack still succeeds, with the same exit code.
