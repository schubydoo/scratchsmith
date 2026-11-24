---
default: patch
---

# A slash soname reached through a link names the real library

When a `DT_NEEDED` entry holds a slash and a link on the host resolves it into another
directory, the soname link in the image now points at the staged library. Before, its value
was the library's bare file name, so the link dangled, or pointed at itself when both names
matched. Bare soname links do not change.
