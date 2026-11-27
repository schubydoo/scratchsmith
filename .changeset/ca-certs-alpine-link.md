---
default: patch
---

#### `--ca-certs` links `/etc/ssl/cert.pem` to the CA bundle

`--ca-certs` staged the bundle only at `/etc/ssl/certs/ca-certificates.crt`. Alpine's OpenSSL and curl read `/etc/ssl/cert.pem` instead, so a packed Alpine program failed every TLS connection unless it was given the bundle's path by hand. `--ca-certs` now also stages `/etc/ssl/cert.pem` as a relative link to the bundle, as Alpine does. A file that `--add-file` puts at `/etc/ssl/cert.pem` is kept, and no link is made.
