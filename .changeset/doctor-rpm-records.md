---
default: patch
---

#### `doctor` now says when an rpm is too old for the package records

CentOS 7 and Amazon Linux 2 have rpm 4.11, and `--packages sbom` and `--packages image` fail
there. `doctor` reported that rpm as present, with no note. The `rpm` row now starts with
`warn` on such a host and names the outputs that fail.
