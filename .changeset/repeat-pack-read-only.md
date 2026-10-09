---
default: patch
---

#### A second pack into the same directory no longer fails on a read-only file

If the output directory held a read-only file from an earlier pack, and the user was not root,
`pack --no-build --output <dir>` failed with `Permission denied`. A binary with mode `0555` and a
`--ca-certs` bundle with mode `0444` both caused it. Scratchsmith now replaces the staged file.
