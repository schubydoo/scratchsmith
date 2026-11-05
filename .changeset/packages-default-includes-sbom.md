---
default: major
---

# The default `--packages` selection is now `report,sbom`

With no `--packages` value, `--sbom` and `--scan` now see the distribution packages that own the bundled files, such as glibc and openssl. A `--scan-fail-on` gate can then report findings in those packages, so a pack that passed on 1.9 can fail. To keep the 1.x result, set `--packages report` or `packages = ["report"]`. Without the 1.9 warning, the default is quiet with no dpkg or rpm database, with rpm 4.11, or with neither `--sbom` nor `--scan`.
