---
default: deprecated
---

#### The default `--packages` gains `sbom` in 2.0

Scratchsmith 2.0 changes the default `--packages` from `report` to `report,sbom`. A
`--scan-fail-on` gate can then find more in the bundled packages. To keep today's result, set
`--packages report`. The
[Deprecations](https://schubydoo.github.io/scratchsmith/latest/deprecations/) page has the detail.
