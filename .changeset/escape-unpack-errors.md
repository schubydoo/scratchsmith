---
default: security
---

#### `unpack` escapes archive text in its error messages

`unpack` put text from the archive into its error messages raw: media types, digests, blob names, entry paths and the tar error. A hostile archive could then forge lines or send terminal escape sequences to standard error. Scratchsmith now escapes that text and caps each string at 8 KiB. Exit codes do not change.
