---
default: patch
---

# `--strip` leaves a non-ELF `--include` alone

A pack with `--strip` and an `--include` that is not an ELF, such as a plugin's data file,
failed with `strip: file format not recognized`. Strip now skips any staged file that is not
an ELF, so the pack succeeds and the data file ships byte-identical. The binary, the loader
and every ELF library are still stripped.
