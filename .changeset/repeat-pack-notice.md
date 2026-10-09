---
default: deprecated
---

#### `--no-build` into a directory that is not empty

A second pack into the same `--output` directory merges with the first, and a file that the new
pack does not stage stays there. Scratchsmith 2.0 refuses a directory that is not empty. Today
the pack works and prints a warning. Use a new directory, or empty it first.
The [Deprecations](https://schubydoo.github.io/scratchsmith/latest/deprecations/) page has the
detail.
