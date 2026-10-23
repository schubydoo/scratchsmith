---
default: security
---

#### `unpack` and `diff` bound the memory they use on a hostile archive

`unpack` read each entry of the outer OCI archive into memory. A small GNU sparse entry could expand to gigabytes of zeros and go around the decompression limit. Scratchsmith now skips entries it does not use, refuses a sparse entry that it must read, and reads no more than the archive's own size. `diff` now hashes files as a stream instead of loading each whole file.
