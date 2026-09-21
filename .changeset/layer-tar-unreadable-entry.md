---
default: patch
---

#### A rootfs entry that cannot be read now fails the pack

Building the image layer skipped unreadable files, and everything under an unreadable directory.
The pack reported success, and under `--push --sign` it signed the short image. It failed at run
time instead, on a library that was never there.

The build now stops at the file and names its path in the staged rootfs under `TMPDIR`.
