---
default: major
---

#### A nested profile table is now an error

A `[profile.a.profile.b]` table in `scratchsmith.toml` now fails the pack with exit code 1. Through 1.9, scratchsmith printed a warning and ignored the table, because no `--profile` value could reach it. The error names the table. Move it to a top-level `[profile.b]` table and repeat the keys it relied on.
