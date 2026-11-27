---
default: minor
---

#### `pack` and `graph` now support dynamic musl binaries

A dynamic musl program, such as one built on Alpine or with `musl-gcc`, used to be refused. It now resolves by musl's own loader rules and packs into a `FROM scratch` image that runs with no NSS and no `ld.so.cache`, on x86_64. `--nss` and `--locale` exit `2` for a musl binary, because musl has no NSS and reads no glibc locales. The `pack`, `graph` and `lint` JSON reports gain a `libc` field (`"glibc"`, `"musl"` or null), and `lint` gains `fortify_detectable`: musl's fortify-headers leave no symbol, so `lint --fail-on no-fortify` exits `2` for a musl binary.
