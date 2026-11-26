---
default: deprecated
---

#### A `diff` argument that is not a directory

3.0 refuses a `diff` argument that is not a directory, such as `diff a.tar b.tar`. Pass two rootfs directories, or `unpack` each archive first. The [Deprecations](https://schubydoo.github.io/scratchsmith/latest/deprecations/) page has the detail.
