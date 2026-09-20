---
default: minor
---

#### A rootfs entry that cannot be read now fails the pack

Building the image layer walked the staged rootfs and dropped every entry it cannot read. When
the unreadable entry was a directory, every entry below it left the layer too. The pack then
reported success, and it hashed and signed the short layer. Nothing said that anything was
missing. The image failed later: the container started, and the loader looked for a library that
was never there.

The walk now stops at the first entry it cannot read, and the error names that path.

This changes an exit code. A pack over a rootfs it cannot fully read used to exit 0 and write an
image. It now exits non-zero and writes nothing. The old exit code reported a result that was
wrong, so this is a fix rather than a new rule. A signed image that is missing files is worse
than a pack that stops.
