---
default: security
---

#### `pack` and `graph` refuse a library that is not a shared object

A `DT_NEEDED` entry or a program interpreter (`PT_INTERP`) can name any host file that is an ELF, such as a core dump, and scratchsmith copied that file into the image. Scratchsmith now refuses a library or an interpreter that is not a shared object (`ET_DYN`), and exits `1`. A file that you name with `--include` stages as before.
