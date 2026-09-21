---
default: minor
---

#### Three silently accepted input shapes now warn

`--label NAME` and `--env NAME` without an `=`, and a nested `[profile.a.profile.b]` table, each
print one warning line to standard error. The pack still succeeds and the exit code does not
change. A well-formed pair, including a deliberate empty value like `--label build=`, stays
quiet.
