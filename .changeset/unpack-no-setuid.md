---
default: security
---

#### `unpack` clears setuid and setgid bits

`unpack` kept the setuid and setgid bits of each file in an image layer. A hostile image could then plant a setuid program owned by the user who unpacked it, or by root when `unpack` ran as root. Scratchsmith now clears both bits on every file it writes. Owners and contents do not change.
