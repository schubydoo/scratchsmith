---
default: security
---

#### `graph`, `pack`, `index` and `diff` escape the rest of their untrusted text

Some output still printed text from a binary, an image or a registry without escaping it: the names, paths and interpreter in `graph` text output, the loader line and the size table in the `pack` text report, the duplicate-platform and multi-arch errors from `index`, and file-walk errors from `diff`. A line break or a terminal escape sequence in that text could forge output lines. Scratchsmith now escapes it. JSON output and exit codes do not change.
