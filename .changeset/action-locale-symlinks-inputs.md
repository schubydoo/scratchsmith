---
default: minor
---

#### `locale` and `symlinks` GitHub Action inputs

The action now takes `locale` and `symlinks` directly, instead of through the `args` escape
hatch. `locale` takes one locale name per line. `symlinks` takes one of `copy-all`, `preserve`,
`copy-unsafe`, or `skip-unsafe`. Both pass straight to the pack flag of the same name, so the
rules do not change.

The `add-file` input description changed with them, because a `symlinks` mode that stages a link
relaxes two of its rules.
