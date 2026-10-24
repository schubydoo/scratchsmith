---
default: security
---

#### `unpack` deletes a whiteout's target through the directory it opened

`unpack` checked a whiteout's directory and then deleted through its path again, so a local user who could write inside the output directory could swap in a symlink and redirect the deletion outside it. `unpack` now opens the directory one step at a time and deletes relative to it. A symlink in that path now resolves inside the image, as `/` there, so a whiteout under a usrmerge `lib -> /usr/lib` link deletes the file that the image means.
