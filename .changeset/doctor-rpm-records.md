---
default: patch
---

#### `doctor` shows the package tools, and says when an rpm is too old

`doctor` has two new rows, `dpkg-query` and `rpm`, for the tools behind `--packages`. CentOS 7
and Amazon Linux 2 have rpm 4.11, and `--packages sbom` and `--packages image` fail there. On
such a host the `rpm` row starts with `warn` and names the outputs that fail.
