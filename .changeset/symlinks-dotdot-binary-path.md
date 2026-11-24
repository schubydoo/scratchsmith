---
default: patch
---

# `--symlinks` handles a binary path that contains `..`

`pack --symlinks preserve ../app`, and the same with `copy-unsafe` or `skip-unsafe`, failed
with `File exists`, because the `..` stayed in the image path and the link for the name landed
on the staged binary itself. A symlinked binary named through `..`, such as `../bin/app`, got a
link whose value counted the `..` as a directory and pointed past the binary. The parent
directory is now resolved the way the kernel walks it, so both pack, and the link points at the
staged binary. A binary path with no `..` stages exactly as before.
