---
default: major
---

#### A library found only through an inherited RPATH under RUNPATH is now missing

A library with `RUNPATH` can need a file that sits only in a parent's `RPATH` directory. Since
1.6.0, scratchsmith staged that file with a warning. The loader never searches there, so 2.0 reports
that library as missing, and `pack` and `graph` fail. Give the library that needs the file a
`RUNPATH` that holds the directory, and pack again.
