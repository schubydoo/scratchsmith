---
default: minor
---

#### The resolver follows the loader's `RUNPATH` rule

A library that has its own `RUNPATH` does not search an `RPATH` inherited from the program.
Scratchsmith searched it anyway. When a second copy of a library was in a system directory, the
image got a different copy than the program uses on the host. Scratchsmith now stages the copy
that the loader uses.

If a library is found only through an inherited `RPATH`, the pack still works and prints a
warning.
