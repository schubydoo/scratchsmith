---
default: security
---

#### `pack` and `graph` stop reading a device after 256 MiB

A `DT_NEEDED` entry can name a device such as `/dev/zero`, and the resolver read it until the host ran out of memory. Scratchsmith now stops after 256 MiB of a character or block device and exits `1` with an error that names the file.
