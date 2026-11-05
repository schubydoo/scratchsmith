---
default: major
---

#### A program interpreter that starts like an ELF and cannot be parsed now fails the run

Since 1.8.0, `pack` and `graph` warned about a truncated or corrupt program interpreter
(`PT_INTERP`) and went on, and the image did not start. Now both commands fail with exit `1`
and name the file. Replace the damaged loader with an intact copy, for example by reinstalling
glibc.
