---
default: major
---

# A refused command line exits 2

A command line that scratchsmith refuses after it parses the flags now exits `2`, the same code
as a parse error. Examples are `--watch --format json`, `--packages none,report`, `pack` with no
binary, and `smoke = true` in the config with `--no-build`. In 1.x these exited `1`, the code for
a failed pack. A script that checks for `1` on these refusals must now check for `2`.
