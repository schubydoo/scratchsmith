---
default: minor
---

#### `lint --format json` prints the hardening report as JSON

`lint` takes `--format json`, like `graph` and `diff`. It prints one object with the binary's path, its `hardening` checks (`relro` as `"full"`, `"partial"` or `"none"`), the `--fail-on` gates asked for, and the `violations` among them, in the `--fail-on` spelling. A failing gate still prints the whole report, then exits `1` as before. The text output is unchanged.
