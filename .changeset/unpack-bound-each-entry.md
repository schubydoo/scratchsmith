---
default: security
---

#### `unpack` limits each archive entry and a piped archive

A large or sparse archive file on disk, or an archive read from a pipe, let one entry fill memory, and a pipe had no total limit. `unpack` now refuses an entry larger than 2 GiB plus 2 MiB, and a pipe that yields more than 16 GiB in all, and exits `1`. An uncompressed layer over 2 GiB is now refused, as a gzip layer that decompresses past 2 GiB already was.
