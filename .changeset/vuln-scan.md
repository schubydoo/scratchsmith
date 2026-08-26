---
default: minor
---

`pack --scan` vulnerability-scans the packed rootfs with grype (reusing the SBOM when `--sbom` is set, else scanning the rootfs), and `--scan-fail-on <severity>` fails the build on a finding at or above that severity. The report includes vulnerability counts by severity, and `doctor` reports whether `grype` is available.
