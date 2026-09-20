---
default: patch
---

#### A rootfs entry that cannot be read now fails the pack

Building the image layer skipped any file it cannot read. When a directory itself was
unreadable, everything under it went too. The pack then reported success and signed an image
with files missing. It failed at run time instead, on a library that was never there.

The build now stops at the file and names the path.
