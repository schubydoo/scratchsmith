---
default: minor
---

#### `--verbose` prints each resolution and staging decision

A new global `--verbose` flag makes `pack` and `graph` print one `verbose: ` line on standard error for each decision: the directories each object searches, the file each `DT_NEEDED` name resolves to, and, for `pack`, each file and link it stages and the directories in the image's `/etc/ld.so.cache`. Without the flag, the output is unchanged.
