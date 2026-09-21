---
default: deprecated
---

#### A label, an environment entry, or a profile table that scratchsmith cannot use

Scratchsmith 2.0 rejects `--label NAME` and `--env NAME` without an `=`, and a nested
`[profile.a.profile.b]` table. Write `--label NAME=value` and `--env NAME=value`, and move a
nested profile to a top-level `[profile.<name>]` table. The new
[Deprecations](https://schubydoo.github.io/scratchsmith/latest/deprecations/) page carries the
migration for each.
