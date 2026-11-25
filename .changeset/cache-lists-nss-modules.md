---
default: patch
---

#### The image's ld.so.cache lists the NSS modules

`pack` built the image's `ld.so.cache` before it staged the NSS modules, so the cache did not list them. glibc loads those modules by name, so a glibc that the binary reaches only through its RUNPATH could not find them in the image. The cache is now built after every library and NSS module is staged.
