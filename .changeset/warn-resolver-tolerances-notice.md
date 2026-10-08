---
default: deprecated
---

#### A damaged library, or a `$PLATFORM` search path with no value

Scratchsmith 2.0 rejects a resolved library that is truncated or corrupt. It also rejects a
`$PLATFORM` token in an `RPATH` or `RUNPATH` on an architecture other than `x86_64` and `aarch64`.
Today both pack, and the image can ship without the correct libraries. The
[Deprecations](https://schubydoo.github.io/scratchsmith/latest/deprecations/) page carries the
fix for each.
