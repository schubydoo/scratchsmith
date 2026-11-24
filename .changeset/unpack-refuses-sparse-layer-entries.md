---
default: security
---

# `unpack` refuses a sparse entry in a layer

A sparse tar entry in a layer could claim a file of any size from a few header bytes, and `unpack` wrote it out, so a small image could fill the disk. `unpack` now refuses the layer, in GNU or PAX sparse form, before it writes any file from it, and exits `1`. No layer writer that Docker or BuildKit uses emits a sparse entry. This is a security exception in COMPATIBILITY.md, with no deprecation cycle. [Deprecations](https://schubydoo.github.io/scratchsmith/latest/deprecations/) lists the change.
