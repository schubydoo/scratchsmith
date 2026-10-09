---
default: patch
---

#### `doctor` and `--help` name things as they are

`doctor` described syft and cosign with a "v0.2" label from an early plan. It now names the flags
that use them, `--sbom` and `--sign`. The `--max-size` help text said "packed payload", and it now
says what the check measures: the whole staged image. The README and the docs home page link to
the Deprecations page.
