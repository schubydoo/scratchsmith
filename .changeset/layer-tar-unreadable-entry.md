---
default: patch
---

#### A rootfs entry that cannot be read now fails the pack

Building the image layer walked the staged rootfs and dropped every entry it cannot read. When
the unreadable entry was a directory, every entry below it left the layer too. The pack then
reported success, and it hashed the short layer into the image and signed it under
`--push --sign`. Nothing said that anything was missing. The image failed later: the container
started, and the loader looked for a library that was never there.

You do not supply this tree. Scratchsmith stages it itself under `TMPDIR`. The trigger is an
entry of that staged tree that becomes unreadable or vanishes while the layer is built. A
cleaner that reaps `TMPDIR`, a restrictive mode, or an IO error all do it.

The walk now stops at the first entry it cannot read, and the error names that path. Read the
path, fix it or re-run.

A run that was silently wrong now reports the failure it always was. `COMPATIBILITY.md` already
promises a non-zero exit on any failure, so this keeps that promise rather than changing it.
