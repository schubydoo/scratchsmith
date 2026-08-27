---
default: minor
---

Scratchsmith declares its stable API surface for 1.0. The CLI flags, `scratchsmith.toml` keys, the `--format json` report schema (now pinned by a golden test), and exit codes are covered by Semantic Versioning — a breaking change to any of them requires a new major version. See the new **Stability** section in the README. Human-readable text, log output, and exact image bytes are explicitly not frozen.
