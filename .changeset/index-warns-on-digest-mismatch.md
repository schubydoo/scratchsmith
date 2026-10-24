---
default: patch
---

#### `index` warns when the registry names another digest

When the registry's answer names a digest other than the index just pushed, `index --sign` refuses to sign, but `index` without `--sign` said nothing. It now reports a warning, as `pack --push` does: a `warning:` line in the text output, and a new `warnings` array in `--format json`. The push and the exit code are unchanged.
