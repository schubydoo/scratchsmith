---
default: major
---

#### `$PLATFORM` in a search path on an unnamed architecture now fails the run

On RISC-V, for example, `$PLATFORM` has no value. Since 1.6.0, `pack` and `graph` warned about it in an `RPATH` or `RUNPATH`. They searched the path with the token removed, and so shipped a library from the parent directory. Now both commands fail with exit code 1. The error names the file to link again, with the directory name in place of the token.
