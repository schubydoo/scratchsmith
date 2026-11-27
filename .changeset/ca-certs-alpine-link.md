---
default: patch
---

#### `--ca-certs` links `/etc/ssl/cert.pem` to the CA bundle

`--ca-certs` now also stages `/etc/ssl/cert.pem` as a relative link to the bundle at `/etc/ssl/certs/ca-certificates.crt`, as Alpine does. Alpine's OpenSSL and curl read that path, so a packed musl program finds the bundle without being told where it is. Every `--ca-certs` image gains the link, glibc images included. A file that `--add-file` puts at `/etc/ssl/cert.pem` is kept, and no link is made.
