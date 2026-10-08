---
default: minor
---

#### `pack --watch` packs again each time the binary changes

`scratchsmith pack --watch ./app` packs one time and then packs again after every change to the
binary, until you press Ctrl-C. It waits until the file stops changing, and a pack that fails
does not end the watch. It works with the default load and `--oci-archive`, and it refuses
`--push`, `--no-build` and `--format json`. Only the binary is watched.
