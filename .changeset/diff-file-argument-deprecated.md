---
default: minor
---

#### `diff` warns when an argument is not a directory

`diff` read a file argument, such as an OCI archive, as an empty tree, so two different files compared as no change and `--exit-code` passed. It now prints a deprecation warning on standard error for each such argument, and the exit code is unchanged. 3.0 refuses it. To compare two archives, `unpack` each one into a directory and compare those.
