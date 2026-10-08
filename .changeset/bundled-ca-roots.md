---
default: minor
---

#### `index` and `pack --push` work on a host with no certificate store

On a host with no CA trust store, such as a `FROM scratch` container, `index` and `pack --push`
failed before they reached the registry. They now fall back to the Mozilla root certificates
compiled into the binary, and print one note to standard error to say so. A host that has a
store sees no change, and `SSL_CERT_FILE` still selects your own certificates.
