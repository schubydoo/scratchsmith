---
default: patch
---

#### `$LIB` in a search path now matches the host glibc

An RPATH or RUNPATH entry that holds `$LIB`, such as `$ORIGIN/../$LIB`, now expands to the directory the host glibc uses for it: `lib/x86_64-linux-gnu` on Debian and Ubuntu, `lib64` on Fedora, `lib` on Arch. Before, it always expanded to `lib64` (`lib` for a 32-bit binary), so on Debian or Ubuntu `pack` and `graph` reported a library as missing that the program loads on the host, or staged a different copy from the one the loader uses. `lib64` (or `lib`) is still searched after the glibc value, so a library found there before still resolves. The one exception is a search path whose directory name holds a `:`, which is now tried whole with the glibc value only.
