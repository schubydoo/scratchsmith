---
default: security
---

#### `pack` and `graph` no longer hang on a FIFO

A `DT_NEEDED` entry can name a FIFO, and the read of it waited forever for a writer, or read a writer's endless stream. Scratchsmith now refuses a library that is not a regular file before it opens it, and exits `1`. A FIFO that you name with `--include` no longer hangs `graph` after its read, and `pack` refuses it at once, because it cannot be staged.
