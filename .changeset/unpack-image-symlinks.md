---
default: patch
---

#### unpack follows the image's own symlinks inside the target

`unpack` refused an image that wrote through an absolute symlink, such as a file under Debian's `var/run -> /run`, because it resolved the link against the host. It now resolves every symlink with the target directory as the image's `/`, so the file lands at `run/app.pid`. An entry, symlink or hard link that would climb out of the target is still refused.
