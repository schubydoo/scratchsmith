---
default: patch
---

# `pack` notes a search-path entry that `ld.so` does not search

Three kinds of RPATH or RUNPATH entry resolve in Scratchsmith but not in `ld.so`: a wholly
empty string, a relative entry, and a name glued to a token such as `$ORIGINX` or `$ORIGIN_x`.
A library found only through one still packs, as before, and the image loads it through its
`ld.so.cache` when `ldconfig` caches it under the needed name. `pack` now prints one `note:` line
on stderr for each such entry. It names the entry and the libraries found through it, and says
which of them the cache does not list, so the image cannot load them. Exit codes, the resolution
and the staged files do not change.
