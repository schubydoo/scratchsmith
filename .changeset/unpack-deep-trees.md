---
default: patch
---

#### unpack handles a deep directory tree

unpack held one file descriptor per directory level while it walked or removed a tree, so a whiteout or an entry in a tree deeper than the open-file limit failed with "Too many open files". With a limit of 1024 that was at about 1020 levels. It now holds one directory open at a time, and a step back up checks that it reached the directory it left.
