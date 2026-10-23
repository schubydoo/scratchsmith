---
default: security
---

#### `pack --no-build` keeps every write inside a reused output directory

A reused `--output` directory can hold a link with an absolute target, such as `lib -> /usr/lib`. Scratchsmith joined each staged path under the directory and let the host follow that link, so a library copy, a `--strip`, or a generated file such as `/etc/passwd` could land on the host's own files. Scratchsmith now reads every link in the directory the way the image will, so each write stays inside the directory.
