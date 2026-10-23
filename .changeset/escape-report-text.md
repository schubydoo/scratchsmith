---
default: security
---

#### `diff`, `index` and the musl check escape control characters

A file name in an image, a platform string from a registry, or a string in a musl binary can hold a newline or a terminal escape sequence. `diff` and `index` text output and the musl error printed that text raw, so it could forge report lines or drive the terminal. Scratchsmith now escapes those characters. JSON output and exit codes do not change.
