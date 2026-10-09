---
default: patch
---

#### `--oci-archive` replaces the archive in one step

`pack --oci-archive` emptied the destination file first and then wrote the new archive into it.
A tool that read the file at that moment got a short archive. Scratchsmith now writes a file
beside the destination and renames it into place, so a reader gets the old archive or the new
one. A destination that is not a regular file, such as `/dev/stdout`, is written directly as
before.

Two things follow from the rename. The pack now needs write permission on the directory that
holds the archive, not only on the archive. If you interrupt a pack, a file named
`.scratchsmith-oci-*.tmp` can remain beside the archive, and you can delete it. An archive that
replaces an existing one keeps that file's permissions.
