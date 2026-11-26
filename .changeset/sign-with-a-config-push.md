---
default: patch
---

#### `--sign` and `--push-untagged` take a `push` target from the config

With `push` set in `scratchsmith.toml`, `pack --sign` and `pack --push-untagged` failed with exit 2 and asked for `--push`, though the config's `push` is the push target. They now use it, as the docs say. With no push target anywhere, both flags still fail with exit 2, and the message now says to drop the flag.
