---
default: minor
---

#### `--deny` / `--require` — gate the pack on its libraries

`pack` can now enforce a library policy in CI. If a `--deny <soname>` library is staged,
the pack fails. If a `--require <soname>` library is absent, the pack fails. Both flags take
an exact soname, repeat, and have matching `deny` and `require` keys in `scratchsmith.toml`.
Read the sonames from `scratchsmith graph`. This gate complements `lint`.
