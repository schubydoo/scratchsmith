---
default: patch
---

#### The loader is staged once on merged-/usr hosts

On a merged-/usr host such as Debian or Ubuntu, the image held two copies of the dynamic loader: one at its `PT_INTERP` path (`/lib64/ld-linux-x86-64.so.2`) and one at its real path (`/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2`). The second path is now a relative symlink to the first, which leaves one copy of the loader (about 230 KiB unpacked) out of the image. The payload report lists the loader once.
