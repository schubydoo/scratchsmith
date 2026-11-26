---
default: minor
---

#### Release binaries are reproducible

Each release binary can now be rebuilt from its tag, byte for byte. A CI job rebuilds both binaries for every release and compares them with the published ones, and `REPRODUCE.md` shows how to run the same check yourself. The release build now uses a pinned Rust toolchain and `--locked`, and it remaps the build machine's Cargo home out of the binary.
