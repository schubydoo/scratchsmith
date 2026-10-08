---
default: minor
---

#### Two silently tolerated resolver inputs now warn

`pack` and `graph` print one warning line to standard error for a library that starts like an ELF
and cannot be parsed. They do the same for a `$PLATFORM` token in a search path on an
architecture that has no value for it. The run still succeeds and the exit code does not change.
A file that is not an ELF at all stays quiet.
