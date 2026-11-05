---
default: major
---

#### `$PLATFORM` in a search path on an unnamed architecture now fails the run

On an architecture other than `x86_64` or `aarch64`, `$PLATFORM` has no value. Since 1.6.0, an
`RPATH` or `RUNPATH` entry with that token made `pack` and `graph` warn. They searched the path
with the token removed, so a library from the parent directory shipped. Now both commands fail
with exit `1` in each case that warned, and name the file that holds the search path. Write the
directory name in the path in place of the token, and link that file again.
