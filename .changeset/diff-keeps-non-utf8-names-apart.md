---
default: patch
---

# `diff` keeps file names that are not valid UTF-8 apart

`diff` turned every file name into text before it compared the two trees, and each invalid
byte became the same replacement character. So two names that differed only in non-UTF-8
bytes, such as `x\xfe` and `x\xff`, counted as one file. A file added under such a name
gave `no changes`, and `diff --exit-code` passed. `diff` now compares the raw names, and
symlink targets too, and prints a non-UTF-8 name escaped, its invalid bytes as `\xNN`, in
both the text and the JSON output.
