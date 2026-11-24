---
default: patch
---

# `--init` prefers a static tini

When both are installed, `--init` now stages the static `tini-static` instead of the dynamic
`tini`. A static tini needs nothing from the image to start. When only a dynamic tini is
found, the pack still succeeds and the report warns that it starts only if the image holds
its loader and libraries. `doctor` now checks the same places `--init` does, names the tini
a pack would stage, and warns when that tini is dynamic.
