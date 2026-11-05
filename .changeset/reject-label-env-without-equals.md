---
default: major
---

#### `--label` and `--env` now require `NAME=value`

`scratchsmith pack --label build` and `--env LOG_LEVEL` used to warn and pack anyway, but now they fail with exit code 2. The `label` and `env` keys in `scratchsmith.toml` fail the same way. The error names the `NAME=value` form and each bad entry, and for a config entry its file and profile. To set an empty value on purpose, write the `=` and stop there: `--label build=`.
