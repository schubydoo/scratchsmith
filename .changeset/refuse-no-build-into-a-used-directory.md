---
default: major
---

#### `pack --no-build --output DIR` refuses a directory that is not empty

In 1.x, a `DIR` that held an earlier pack gave a warning, and the new pack merged into the old tree. Version 2.0 stops with an error before it stages any file. An absent or empty `DIR` works as before. Remove the old directory first, or choose another one.
