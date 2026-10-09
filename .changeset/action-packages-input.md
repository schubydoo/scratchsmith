---
default: minor
---

#### `packages` GitHub Action input

The action now exposes `--packages` as an input. Set `packages: report,sbom` to make the SBOM
and the scan see the distribution packages, or `packages: image` to keep the package records
in the image. Set `packages: none` to turn the lookup off. Empty keeps the default, `report`.
