---
default: security
---

#### `--sign` signs the manifest digest that scratchsmith pushed

`pack --push --sign` and `index --sign` signed the digest that the registry named in its `Location` header. A hostile or broken registry could name a different image, and scratchsmith then signed and attested that image. Scratchsmith now hashes the exact manifest bytes it uploads, signs that digest, and exits `1` when the registry names a different one. A push without `--sign` behaves as before.
