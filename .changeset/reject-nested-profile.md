---
default: major
---

#### A nested profile table is now an error

A `[profile.a.profile.b]` table in `scratchsmith.toml` now fails the pack with exit code 1. Through 1.9, scratchsmith warned and ignored the table, because no `--profile` value reaches it. The error names every nested table by its full path, and says how to fix each one. Move it to a top-level `[profile.b]` table, or merge its keys into the profile that already has that name.
