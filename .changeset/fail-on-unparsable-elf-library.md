---
default: major
---

#### A library that starts like an ELF and cannot be parsed now fails the run

Since 1.6.0, `pack` and `graph` warned about a truncated or corrupt library and kept it. The
libraries that it needs did not reach the image. Now both commands fail with exit `1`
and name the file. Replace the damaged file with an intact copy. A file that you name with
`--include` and that is not an ELF at all still stages as before.
1.x did not warn for an `--include` file that is not a regular file, such as a FIFO. If its
bytes start with the ELF magic, `graph` now fails on it too.
