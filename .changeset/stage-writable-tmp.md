---
default: minor
---

#### `pack --tmp` adds a writable `/tmp` to the image

A scratch image has no `/tmp`, and many programs exit at startup without one. The new `--tmp` flag, or `tmp = true` in `scratchsmith.toml`, stages an empty `/tmp` directory, mode `1777` and owned by uid 0, so the image's default non-root user can write there without a `--tmpfs` mount. It works for every sink and for `--no-build`, and the layer stays reproducible.
