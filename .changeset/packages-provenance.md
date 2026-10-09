---
default: minor
---

#### `--packages` names the distribution package behind each bundled library

A scratch image has no package database. An SBOM of it named almost none of the libraries that
scratchsmith copied in, and `--scan` did not see them. On a dpkg host, scratchsmith now asks
which package owns each bundled file, and the JSON report gains a `packages` list.

Two more outputs are opt-in. `--packages report,sbom` makes `--sbom` and `--scan` see those
packages. A scan gate can then fail on vulnerabilities that it did not see before.
`--packages image` keeps the package records and `/etc/os-release` in the image. If you ask for
`sbom` or `image` on a host with no dpkg database, the pack fails.
