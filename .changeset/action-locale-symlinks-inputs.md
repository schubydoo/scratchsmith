---
default: minor
---

#### `locale` and `symlinks` GitHub Action inputs

The action now takes `locale` and `symlinks` directly, instead of through the `args` escape
hatch. `locale` takes one locale name per line. `symlinks` takes one of `copy-all`, `preserve`,
`copy-unsafe`, or `skip-unsafe`. Both pass straight to the pack flag of the same name.

Under a `symlinks` mode that stages a link, an `add-file` source that is a link to a directory
no longer fails. `skip-unsafe` stages nothing for a link it cannot honor.
