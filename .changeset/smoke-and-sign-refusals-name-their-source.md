---
default: patch
---

# The `smoke` and `sign` refusals say where the key is set and what helps

`pack --no-build` with `smoke = true` in the config told you to set `smoke = false` in the
profile. A profile can't turn off a boolean the base config sets, so that didn't work. A
config `sign = true` without a push target told you to set `push` in the config, but
`--oci-archive` or `--no-build` on the command line beats a config `push`. Both refusals now
name where the key is set: the config file, its `[profile.NAME]`, or both. The advice fits
that: remove the key there, drop `--no-build` and `-o`, or, for `sign`, drop the
command-line sink and pass `--push`.
