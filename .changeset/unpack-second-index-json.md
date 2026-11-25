---
default: security
---

#### `unpack` refuses an OCI archive with two `index.json` files

An OCI archive that held two `index.json` entries (or `index.json` and `./index.json`) was unpacked from the last one, with no warning. Two tools reading the same archive could then show two different images. `unpack` now refuses the archive, names the second entry, and exits `1`.
