---
default: patch
---

#### A warning for --sbom-file or --sbom-format without --sbom

`pack --sbom-file s.json` without `--sbom` wrote no SBOM and said nothing. The report's warnings now name each SBOM flag or config key that is set while `--sbom` is off. The exit code stays 0.
