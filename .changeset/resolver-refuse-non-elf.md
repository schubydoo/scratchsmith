---
default: security
---

#### `pack` and `graph` refuse a non-ELF file named by the binary

A `DT_NEEDED` entry or a program interpreter (`PT_INTERP`) can name any host file, such as `~/.docker/config.json`, and scratchsmith copied that file into the image. Scratchsmith now refuses a library that is not an ELF, and an interpreter that is not a regular ELF file, and exits `1`. A data file that you name with `--include` stages as before.
