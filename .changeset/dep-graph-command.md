---
default: minor
---

#### `graph` — print a binary's resolved dependency tree

`scratchsmith graph <binary>` prints the binary's dependency tree. It resolves the binary
the same way `pack` does. The default output is an ASCII tree. `--format json` prints a
machine-readable adjacency list. The command builds no image and stages nothing, so it
audits an image fast. A repeated library is shown once in full and marked `(*)` after that.
An unresolved dependency is shown as `(missing)`. `--include <lib>` adds a `dlopen`'d
library, like `pack`.
