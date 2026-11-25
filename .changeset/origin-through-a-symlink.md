---
default: patch
---

#### $ORIGIN of a library found through a symlink names the symlink's directory

When a search found a library through a symlink, the resolver expanded that library's `$ORIGIN` from the symlink's target, so `pack` and `graph` could report a dependency missing that the loader finds. It now expands `$ORIGIN` to the directory that holds the symlink, as `ld.so` does. The image still ships the real file, once.
