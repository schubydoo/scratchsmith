---
default: minor
---

#### `pack` and `graph` now support dynamic musl binaries

`pack` used to refuse a dynamic musl program, such as one built on Alpine or with `musl-gcc`. It now resolves by musl's own loader rules and packs into a `FROM scratch` image that runs with no NSS and no `ld.so.cache`, on x86_64. `--nss` and `--locale` exit `2` for a musl binary, because musl has no NSS and reads no glibc locales. The `pack`, `graph` and `lint` JSON reports gain a `libc` field (`"glibc"`, `"musl"` or null), and `lint` gains `fortify_detectable`: musl's fortify-headers leave no symbol, so `lint --fail-on no-fortify` fails every musl binary and warns that the gate cannot be checked. One image holds one libc: `--add-binary` fails the pack for a program, or a shared library, that uses the other libc. An added shared library's own dependencies are still found by glibc's search rules, in a musl image too, and `pack` prints a note when that happens. Check such an image with `--smoke`.
