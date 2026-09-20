---
default: minor
---

#### `--symlinks`: keep a named symlink as a symlink

Scratchsmith copies the content of a symlink you name, so the image gets a regular file and
not the link. That loses the path itself. Packing `/usr/bin/python3`, a link to `python3.13`,
produced an image with the real file and nothing at `/usr/bin/python3`. A container that ran
the name rather than the target then failed to start.

`pack --symlinks <mode>` chooses what happens. `copy-all` copies the content to the named
path, which is the default and what every earlier release did. `preserve` recreates the link.
`copy-unsafe` recreates a link whose target is in the image and copies the content for one
whose target is not. `skip-unsafe` recreates the safe link and stages nothing for the other.
A dangling or skipped link warns and names the target.

The mode covers the packed binary's own path and each `--add-file` source. Resolved libraries
are not in scope, because the loader decides those and the stager already recreates the soname
links it needs. Preserving a link never pulls its target into the image, so an image still
gains only what you asked for. The packed binary is the exception: its real file is always
staged, so a preserved link to it always resolves. The `symlinks` key in `scratchsmith.toml`
takes the same value.

A mode other than `copy-all` relaxes two `--add-file` rules, and only for a source that is
itself a symlink. A preserved link is staged as a link, so a link to a directory no longer
fails. Under `skip-unsafe` an entry the pack cannot honor stages nothing and warns. Every link
the stager writes carries a relative value, so a staged tree resolves inside itself.
