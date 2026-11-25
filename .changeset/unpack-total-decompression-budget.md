---
default: security
---

#### `unpack` stops at 16 GiB of decompressed layers in all

Each layer was capped at 2 GiB, but one small gzip layer that the manifest lists many times decompressed again for each listing, so `unpack` could write many times 2 GiB to the target. `unpack` now refuses an image whose layers hold more than 16 GiB in all once decompressed, and exits `1` with an error that names the limit. A layer listed twice counts twice.
