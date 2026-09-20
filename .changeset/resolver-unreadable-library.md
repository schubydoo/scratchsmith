---
default: patch
---

#### A library that cannot be read now fails the pack

Resolving a dependency read each library to find what it needs in turn. When that read failed,
the resolver kept the library as a leaf and carried on, so nothing that library needs was ever
looked for. Those libraries never reached the report as missing either, because nothing ever
asked for them.

What you saw depended on the command. `graph` exited 0 and printed a dependency tree with a
whole branch absent, and nothing said so. `pack` did fail, but late and for the wrong reason. It
got as far as copying the library into the image, then reported a copy error. That is long after
the point where it knew the real problem.

When the resolver cannot read a library, it now stops there, and the error names that path.

A file that reads correctly and does not claim to be an ELF file is unchanged. It has no
dependencies of its own, so it stays a leaf, which is what the old code meant to do.

A file that claims to be an ELF file and then fails to parse now stops the resolver as well. Its
dependencies are unknown for the same reason.

`COMPATIBILITY.md` promises a non-zero exit on any failure, so reporting these failures keeps
that promise.
