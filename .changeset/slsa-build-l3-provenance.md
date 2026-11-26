---
default: minor
---

#### Release provenance is SLSA Build Level 3

The release binaries are now built and attested inside a reusable workflow, `release-binaries.yml`, so their SLSA provenance meets Build Level 3. `gh attestation verify` takes `--signer-workflow schubydoo/scratchsmith/.github/workflows/release-binaries.yml` to check that the provenance came from that workflow. `docs/verifying.md` has the full command.
