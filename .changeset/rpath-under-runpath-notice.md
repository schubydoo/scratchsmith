---
default: deprecated
---

#### A library found only through an inherited `RPATH`

A library with its own `RUNPATH` does not search the program's `RPATH`. If a file that it needs
is only in that `RPATH` directory, the loader cannot find it. Scratchsmith 2.0 reports that file
as missing. Today the pack works and prints a warning. Put the directory in the `RUNPATH` of the
library that needs the file.
The [Deprecations](https://schubydoo.github.io/scratchsmith/latest/deprecations/) page has the
detail.
