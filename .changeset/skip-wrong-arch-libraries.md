---
default: patch
---

#### The resolver skips a library of another ELF class or machine

With RPATH `lib:lib64` and 32-bit copies in `lib`, the resolver staged the 32-bit library, and the image exited 127 while the pack exited 0. Like `ld.so`, it now skips a file of another class or machine than the binary and keeps searching. When every copy is of another arch, or the binary names the file by path, the file still stages as before, and a warning on stderr names it and says the image cannot load it. The exit code does not change.
