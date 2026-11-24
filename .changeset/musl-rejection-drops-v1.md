---
default: patch
---

# The musl rejection no longer names v1

`pack` refused a musl binary with "v1 targets glibc", which reads as stale after 2.0. It now
says "Scratchsmith packs glibc binaries only". The exit code does not change.
