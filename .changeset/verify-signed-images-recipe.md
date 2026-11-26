---
default: patch
---

#### The docs show how to verify an image that `pack --sign` signed

`docs/verifying.md` now has a `cosign verify` and `cosign verify-attestation` recipe for images that `pack --push --sign` signs and `--sbom --sign` attests. It names the identity and issuer to pass for a GitHub Actions signer and for a terminal signer, the `--type` for each SBOM format, and how to read the attested SBOM.
