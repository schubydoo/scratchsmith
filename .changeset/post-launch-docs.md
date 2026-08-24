---
default: patch
---

#### Docs — install from signed releases, verification steps, and post-launch status

The README and docs site now cover installing from the signed release binaries (amd64/arm64) and
the GHCR image, add a **Verifying releases** section (`cosign` + `gh attestation verify`), and
correct the pre-release "not published / signing planned" wording now that v0.1 ships signed,
published releases. The remaining "signing" gap — signing the image `pack` itself produces — is
called out precisely (it needs the daemonless registry push).
