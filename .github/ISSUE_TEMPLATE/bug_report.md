---
name: Bug Report
about: A binary will not pack, or the packed image is broken
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

- What is it? [for example: curl, ffmpeg, a closed-source vendor binary]
- If it is relevant, the `scratchsmith lint <binary>` output (PIE/RELRO/NX/…)
- glibc or musl? (musl is out of scope by design)
- Does it `dlopen` plugins? [yes / no / unsure]

> Please do not attach proprietary binaries. Send the output of `scratchsmith lint` or
> `pack -n -o <dir>` instead. A tiny reproducer built from the sample C in `tests/` is
> also ideal.

## Environment

- Scratchsmith version: [the output of `scratchsmith --version`]
- Install method: [prebuilt binary / cargo / from source]
- OS & arch: [for example: Debian 13 amd64]
- glibc / `ldconfig --version` (first line): [for example: 2.41]
- `docker --version` (if the Docker sink is used): [for example: 27.x]
- `scratchsmith doctor` output (which external tools are present)

## Logs

The pack output (run with `RUST_LOG=debug` for more). Redact any private paths.

```
paste output here
```

## Additional context

Anything else that helps us fix the bug.
