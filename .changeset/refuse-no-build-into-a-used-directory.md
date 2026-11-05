---
default: major
---

#### `pack --no-build --output DIR` refuses a directory that is not empty

In 1.x, a `DIR` that held an earlier pack gave a warning, and the new pack merged into the old tree. Version 2.0 stops with an error before it stages any file. 1.x did not warn when it could not list `DIR`, and 2.0 refuses that case too because it cannot prove the directory is empty. An absent or empty `DIR` works as before, but a pack that fails after the check leaves a new empty `DIR` behind. Remove the old directory first, or choose another one.
