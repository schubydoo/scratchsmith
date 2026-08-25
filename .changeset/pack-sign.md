---
default: minor
---

#### `--sign` — cosign-sign the image `pack` produces

`scratchsmith pack --push <ref> --sign` keyless-signs the pushed image **by digest** with
cosign, and `--sbom --sign` additionally attaches the SBOM as a signed `cosign attest`
attestation (CycloneDX or SPDX, matching `--sbom-format`). Signing targets the exact digest the
push returns, so it's immune to a tag being moved afterwards. `--sign` requires `--push` (cosign
signs a registry image), and the signature is `cosign verify`-able — proven end-to-end by the
`push-auth-smoke` workflow. This closes the last gap in the supply-chain story: not just signed
release *artifacts*, but a signature on the image scratchsmith itself builds.
