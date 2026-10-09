---
default: minor
---

#### `index` and `pack --push` work on a host with no certificate store

On a host with no CA trust store, such as a `FROM scratch` container, `index` and `pack --push`
failed before they reached the registry. They now fall back to the Mozilla root certificates
compiled into the binary, and print one warning to standard error to say so. A host that has a
store sees no change. If `SSL_CERT_FILE` or `SSL_CERT_DIR` is set, your choice holds and there
is no fallback.
