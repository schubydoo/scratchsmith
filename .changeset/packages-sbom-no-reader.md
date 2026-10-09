---
default: patch
---

#### `--packages sbom` with nothing to read it now warns

`--packages sbom` shows the packages to `--sbom` and `--scan`. With neither of them on, the pack
looked the packages up, wrote them nowhere, and said nothing. It now prints a warning and
skips that lookup. The pack still succeeds.
