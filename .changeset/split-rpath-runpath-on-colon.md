---
default: patch
---

#### `RPATH` and `RUNPATH` lists are searched entry by entry

A search path with more than one directory, such as `-Wl,-rpath,/opt/none:$ORIGIN`, was read as one directory. So `pack` and `graph` reported a library as missing that the loader finds, and failed. Each `:` entry is now searched in order, as `ld.so` does, and `$ORIGIN` and `$PLATFORM` are checked in each entry. An empty entry is not searched, because it means the directory the program starts in.
