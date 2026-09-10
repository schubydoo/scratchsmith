---
default: minor
---

#### `--nss` — choose which NSS modules the image carries

`pack --nss <files,dns,none>` (and the matching `nss` key in `scratchsmith.toml`) selects which
glibc name-service (NSS) modules stage into the image. Pass a comma-separated list: `--nss files`
keeps local-file lookups but drops DNS, and `--nss none` stages no modules and no `nsswitch.conf`.
Fewer modules trim the image's CVE surface. The generated `nsswitch.conf` always matches the
selection, and a mode without `files` also drops the now-unreadable `/etc/passwd` and `/etc/group`.
The default stays `files,dns`, so existing packs are unchanged.
