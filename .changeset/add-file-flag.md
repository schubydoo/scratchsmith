---
default: minor
---

#### `--add-file`: copy any host file into the image

`pack --add-file SRC:DST` copies a host file into the image at `DST`. A bare absolute
`--add-file SRC` keeps the host path. Until now `--ca-certs` and `--tz` each added one fixed
file, and there was no way to add another. A program that reads a configuration file or a data
file at runtime now packs without a wrapper step. The flag repeats and takes regular files
only. The `add-file` key in `scratchsmith.toml` takes the same list. A missing source, a
directory, or a `DST` that is already in the image fails the pack and names the path. In an
image the file lands owned by uid 0 at mode `0644`, or `0755` when the source is executable,
because the layer writer canonicalizes modes.
