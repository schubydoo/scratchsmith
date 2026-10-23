---
default: minor
---

#### `unpack` reports the setuid and setgid bits it clears

For each path in the final image that had a setuid or setgid bit, `unpack` prints a warning line on standard error. The new `stripped_setid` field of `--format json` lists the same paths.
