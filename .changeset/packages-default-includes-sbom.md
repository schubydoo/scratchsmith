---
default: major
---

# The default `--packages` selection is now `report,sbom`

With no `--packages` value, `--sbom` and `--scan` now see the distribution packages that own the bundled files, such as glibc and openssl. A `--scan-fail-on` gate can then fail a pack that passed on 1.9, and `--packages report` or `packages = ["report"]` keeps the 1.x result. With no dpkg or rpm database, rpm 4.11, or no `--sbom` or `--scan`, the 1.9 result stays and 2.0 does not warn. If an `--add-file` takes a path that a record needs, the default leaves the records out and warns.
