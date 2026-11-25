---
default: patch
---

#### `--sign` shows cosign's keyless login prompt

`pack --push --sign` and `index --sign` ran cosign with standard input closed and standard error captured. Outside CI, keyless signing prints a login URL on standard error and can read a code from standard input, so the prompt never showed and the run waited or failed. cosign now signs and attests with the terminal's standard input and standard error. Its standard output stays captured, so `--format json` is unchanged.
