---
default: minor
---

#### The GitHub Action gains `tmp` and `add-binary` inputs

The Action passed `--tmp` and `--add-binary` only through its `args` input, which splits on whitespace, so an `--add-binary` path with a space could not work. The new `tmp` input adds the writable `/tmp`, and the new `add-binary` input takes one `SRC[:DST]` program per line, the same shape as `add-file`. Both need scratchsmith v2.1.0 or later.
