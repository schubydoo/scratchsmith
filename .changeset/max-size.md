---
default: minor
---

`pack --max-size <SIZE>` fails the build when the packed payload exceeds a budget — e.g. `12MB`, `512KiB`, or a bare byte count (decimal K/M/G are ×1000, binary Ki/Mi/Gi are ×1024). Config-settable as `max-size`.
