---
default: major
---

#### The default `--packages` selection is now `report,sbom`

With no `--packages` value, `--sbom` and `--scan` now see the distribution packages that own the bundled files, such as glibc. A `--scan-fail-on` gate can then fail a pack that passed on 1.9. To keep the 1.x result, set `--packages report` or `packages = ["report"]`. Nothing changes without `--sbom` or `--scan`, or on a host with no dpkg or rpm database.
