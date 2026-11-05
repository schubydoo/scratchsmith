---
default: major
---

#### `--label` and `--env` now require `NAME=value`

`scratchsmith pack --label build` and `--env LOG_LEVEL` used to warn and pack anyway. They now fail with a usage error that names the `NAME=value` form. The `label` and `env` keys in `scratchsmith.toml` fail too, with the same exit code 2. To set an empty value on purpose, write the `=` and stop there: `--label build=`.
