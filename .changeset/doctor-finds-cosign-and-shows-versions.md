---
default: patch
---

# `doctor` finds an installed cosign and shows the real syft and grype versions

`doctor` looked for every tool with `--version`, and cosign takes only `cosign version`, so
an installed cosign showed as `MISS`. The syft and grype rows showed `Application: syft`,
the first line of their output, in place of a version. `doctor` now asks each tool its own
version command, and shows the value of a `Version:` or `GitVersion:` line when the output
has one. It still exits 0 in every case.
