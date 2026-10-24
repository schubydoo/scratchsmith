---
default: patch
---

#### `index` warns when the registry names another digest

When the registry's answer names a digest other than the index just pushed, `index --sign` refuses to sign, but `index` without `--sign` said nothing. It now prints a warning on stderr, as `pack --push` does. The push and the exit code are unchanged.
