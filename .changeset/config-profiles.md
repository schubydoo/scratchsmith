---
default: minor
---

`scratchsmith.toml` now covers every packing flag, and supports named `[profile.<name>]` sections selectable with `pack --profile <name>` (layered over the base config, CLI flags still win) — so a `[profile.ci]` can set strip/sbom/sign/push together.
