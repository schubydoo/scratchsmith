---
default: security
---

# `unpack` reads every gzip member of a layer and refuses data after a layer's end

`unpack` read only the first member of a gzip layer. Docker reads every member, so a second member could carry files that the image installs and `unpack` never showed. `unpack` now reads every member. It refuses a layer with bytes after its last gzip member, or with anything but zeros after its tar's end, and exits `1`. A layer cut short now fails before `unpack` writes or deletes any file for that layer. This is a security exception in COMPATIBILITY.md, with no deprecation cycle. [Deprecations](https://schubydoo.github.io/scratchsmith/latest/deprecations/) lists the change.
