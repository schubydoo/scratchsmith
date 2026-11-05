---
default: major
---

#### `pack --no-build --output DIR` refuses a directory that is not empty

In 1.x, a `DIR` that held an earlier pack gave a warning, and the new pack merged into the old tree. Now the command stops with an error before it stages any file. If it cannot list `DIR`, it also stops, because it cannot prove that `DIR` is empty. Remove the old directory, or choose another one.
