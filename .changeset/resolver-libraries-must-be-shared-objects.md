---
default: security
---

#### `pack` and `graph` refuse a library or a loader that cannot load

A `DT_NEEDED` entry or a program interpreter (`PT_INTERP`) can name any host file that is an ELF, such as a core dump, and scratchsmith copied that file into the image. Scratchsmith now refuses a library that is not a shared object (`ET_DYN`), and an interpreter that is not `ET_DYN` or `ET_EXEC`, and exits `1`. A PIE executable is `ET_DYN`, so this check does not refuse one.
