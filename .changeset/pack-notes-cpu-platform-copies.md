---
default: patch
---

# `pack` and `graph` point out copies under glibc's CPU names for `$PLATFORM`

On x86_64, glibc reads `$PLATFORM` in an RPATH or RUNPATH entry as `haswell` or `xeon_phi` on
some Intel CPUs, and as `x86_64` everywhere else. Scratchsmith reads it as `x86_64`, as before.
A library refused as missing now gets a hint when a copy sits under one of those CPU names. When
a library ships but `ld.so` on such a CPU would load a CPU-specific copy instead, `pack` prints
one `note:` line on stderr saying the image leaves that copy out, and whether the image can
still load the shipped copy on such a CPU. Exit codes and the staged files do not change.
