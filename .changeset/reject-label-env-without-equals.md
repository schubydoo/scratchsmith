---
default: major
---

#### `--label` and `--env` now require `NAME=value`

`scratchsmith pack --label build` and `--env LOG_LEVEL` used to warn and pack anyway, but now they fail with exit code 2. The `label` and `env` keys in `scratchsmith.toml` fail the same way. A config error names every bad entry, with its file and profile. To set an empty value on purpose, write the `=` and stop there: `--label build=`.
