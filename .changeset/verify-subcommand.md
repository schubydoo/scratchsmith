---
default: minor
---

#### New `verify` subcommand checks the signature that `--sign` made

`scratchsmith verify <IMAGE>` checks an image's keyless cosign signature against the signer you expect, with cosign's own `--certificate-identity` or `--certificate-identity-regexp` and `--certificate-oidc-issuer`. `--sbom` also checks the SBOM attestation, of the type `--sbom-format` names. A tag is read once and cosign checks the digest it pointed to, which the report prints. An index that `index --sign` signed is checked by its own signature, and `--sbom` is refused for it. A pattern must start with `^`, since cosign matches it anywhere in the identity. It exits `0` when the checks pass, `1` when one fails, and `2` for a refused command line, and `--format json` prints the result for a CI gate. It needs cosign.
