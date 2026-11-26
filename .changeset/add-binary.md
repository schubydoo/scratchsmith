---
default: minor
---

#### `pack --add-binary` adds a program with its shared libraries

`--add-file` copies an ELF program as a plain file, so a program added that way, such as a shell, failed in the image until each of its libraries was named with `--include`. The new `--add-binary SRC[:DST]` flag, or `add-binary` in `scratchsmith.toml`, copies the program and resolves its libraries with the same `ld.so` rules as the packed binary. A library both need is staged once, and `ld.so.cache`, the library policy, the SBOM and `--packages` cover the added libraries. An added ELF built for another architecture or loader fails the pack with a clear error.
