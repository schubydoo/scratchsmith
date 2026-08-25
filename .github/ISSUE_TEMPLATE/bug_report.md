---
name: Bug Report
about: A binary won't pack, or the packed image is broken
title: '[BUG] '
labels: bug
assignees: ''
---

## What happened

A clear description of the bug, and what you expected instead.

## Steps to reproduce

1. Run `scratchsmith pack ...` on '...'
2. Run the image with '...'
3. See '...'

## The binary being packed

- What is it? [e.g. curl, ffmpeg, a closed-source vendor binary]
- `scratchsmith lint <binary>` output (PIE/RELRO/NX/…), if relevant
- glibc or musl? (musl is out of scope by design)
- Does it `dlopen` plugins? [yes / no / unsure]

> Please don't attach proprietary binaries. `scratchsmith lint`/`pack -n -o <dir>`
> output, or a tiny reproducer built from the sample C in `tests/`, is ideal.

## Environment

- Scratchsmith version: [e.g. v0.2.0, or `cargo install` from a commit]
- Install method: [prebuilt binary / cargo / from source]
- OS & arch: [e.g. Debian 13 amd64]
- glibc / `ldconfig --version` (first line): [e.g. 2.41]
- `docker --version` (if the Docker sink is used): [e.g. 27.x]
- `scratchsmith doctor` output (which external tools are present)

## Logs

The pack output (run with `RUST_LOG=debug` for more). Redact any private paths.

```
paste output here
```

## Additional context

Anything else that might help.
