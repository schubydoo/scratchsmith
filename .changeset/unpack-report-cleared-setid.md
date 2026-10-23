---
default: minor
---

#### `unpack` reports the setuid and setgid bits it clears

`unpack` clears the setuid and setgid bits on every file it writes, and it now says where. Each path in the final image that had one of those bits prints a warning line on standard error, and the new `stripped_setid` field of `--format json` lists the same paths.
