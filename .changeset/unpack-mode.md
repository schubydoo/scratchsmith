---
default: minor
---

#### `unpack` — extract an OCI image archive to a directory

`scratchsmith unpack <archive> <dir>` reads an OCI-layout archive (from `pack --oci-archive`,
or any skopeo/buildah export), applies each layer in order into `<dir>`, and honors whiteouts.
It refuses any path that escapes the target. `--format json` reports the source, the
directory, and the layer and file counts. Combine it with `diff` to audit an image you did
not build: unpack two images, then compare the directories.
