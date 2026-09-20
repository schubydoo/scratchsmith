---
default: minor
---

#### `locale` and `symlinks` GitHub Action inputs

The action now exposes `--locale` and `--symlinks` as first-class inputs. `locale` takes one
locale name per line and stages each compiled locale at `/usr/lib/locale`. `symlinks` takes one
mode: `copy-all`, `preserve`, `copy-unsafe`, or `skip-unsafe`. Both pass straight to the pack
flag of the same name, so the rules do not change.

Until now these two flags were reachable only through the `args` escape hatch. Both shipped in
the CLI in v1.4.0. The action packs with the latest release, so an input can be proven only
after a release carries its flag.

The `add-file` input description changed with them. It stated that a directory source always
fails the pack. That holds only while the action cannot reach `--symlinks`. A preserved link is
staged as a link, so a link to a directory no longer fails, and the description now says so. A
`DST` already in the image still fails under every mode, which the description now says as
well.
