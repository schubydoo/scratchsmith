---
default: patch
---

#### A library that cannot be read now fails the pack

Resolving a dependency read each library to find what it needs in turn. When that read failed,
the resolver kept the library as a leaf and carried on. The library still shipped, but nothing
it needs was ever looked for, so those libraries never shipped and never appeared in the report
as missing. The pack succeeded over an image with holes in it, and `--require` was blind to
them, because nothing ever asked for the absent libraries.

When the resolver cannot read a library, it now stops, and the error names that path.

A file that reads correctly and is not an ELF file is unchanged. It has no dependencies of its
own, so it stays a leaf, which is what the old code meant to do. The two cases now have
different types, so one cannot be mistaken for the other again.

This is the same defect as the layer tar one in the release before it, reached by a different
route. `COMPATIBILITY.md` promises a non-zero exit on any failure, so reporting this failure
keeps that promise.
