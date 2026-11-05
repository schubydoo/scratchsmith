---
default: major
---

#### A needed library in a directory whose name holds `:` must be one that `ldconfig` caches

A `DT_NEEDED` library found only in a directory such as `x:y`, from `RUNPATH` `$ORIGIN/x:y`, loads only through the image's `ld.so.cache`. If `ldconfig` skips it, as it skips `foo.so`, `pack` and `graph` now fail, where 1.9 packed an image that exited 127. An `--include` file there still stages as before.
