---
default: patch
---

#### The nested profile error names every table by its full path

When `scratchsmith.toml` nested profiles more than one level deep, the error named only the first nested table, so the suggested fix failed again on the next level. It now lists every nested table by its full path, such as `[profile.a.profile.b.profile.c]`, and uses plural wording for several. If the inner name is already a top-level profile, the error tells you to merge the keys into it. The exit code (1) and the set of refused files are unchanged.
