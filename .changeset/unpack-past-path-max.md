---
default: patch
---

#### `unpack` extracts an entry whose path is longer than 4096 bytes

`unpack` wrote each entry by its full path on the host, so an entry whose path under the target directory was longer than the host's limit (`PATH_MAX`, 4096 bytes on Linux) failed with `File name too long`. It now writes each entry relative to the directory that holds it, which it reaches through `/proc`, so a deep tree unpacks.
