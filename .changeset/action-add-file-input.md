---
default: minor
---

#### `add-file` GitHub Action input

The action now exposes `--add-file` as a first-class input. Each line is one `SRC:DST` spec, or
one bare absolute `SRC` that keeps its own path in the image. The action passes each line to the
pack flag of the same name, so the rules do not change. Regular files only. A missing source, a
directory, or a destination already in the image fails the pack. Before this, the flag was
reachable only through the `args` escape hatch.
