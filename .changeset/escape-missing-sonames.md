---
default: patch
---

#### A missing library name can no longer forge a line of output

When a library that a binary needs is not found, scratchsmith prints its name in the error and in
the `graph` tree. That name comes from the binary, and it was printed as it was. With a line
break or a terminal escape in the name, a crafted binary was able to fake a line of
scratchsmith's output. Scratchsmith now escapes those characters. The JSON output was already
safe.
