---
default: patch
---

#### syft, grype and cosign get non-UTF-8 paths byte for byte

A path with a byte that is not UTF-8 reached syft, grype and cosign with that byte replaced, so `--sbom` wrote the SBOM to another file and `--scan` read nothing. The tools now get the exact path. The report's `sbom` field still shows the path as text.
