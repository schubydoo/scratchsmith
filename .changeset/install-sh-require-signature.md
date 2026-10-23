---
default: security
---

#### `install.sh` stops when cosign is installed and the signature bundle is missing

With cosign installed, `install.sh` warned and installed anyway when it could not fetch `checksums.txt.sigstore.json`. An attacker who swaps the tarball and the checksums can also withhold the bundle. The script now stops the install in that case. Set `INSECURE_ALLOW_MISSING_SIGNATURE=1` to install with the SHA-256 check only.
