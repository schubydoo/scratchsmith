---
default: minor
---

#### A pack into an output directory that is not empty now warns

If the output directory already holds files, `pack --no-build --output <dir>` prints one
warning line to standard error. The pack merges into that directory, so a file from an earlier pack can
stay in it. The run still succeeds and the exit code does not change.
