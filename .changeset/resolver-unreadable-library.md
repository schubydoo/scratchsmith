---
default: patch
---

#### A library that cannot be read now fails the pack

The resolver skipped a library it cannot read and carried on, so nothing that library needs was
resolved or staged. `graph` then printed a tree with a branch missing. `pack` failed later, at
the copy, naming the wrong thing.

It now stops at the library and names the path.
