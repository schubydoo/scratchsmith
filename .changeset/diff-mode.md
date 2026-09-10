---
default: minor
---

#### `diff` — compare two staged rootfs directories

`scratchsmith diff <before> <after>` reports the files added, removed, and changed between
two staged rootfs directories, plus the total size delta. `--exit-code` makes it exit
non-zero on any difference, so CI can gate on image drift. `--format json` emits the same
data. Stage the directories with `pack --no-build --output`, or later from an unpacked image.
