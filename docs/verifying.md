# Verifying releases

Release artifacts are keyless-signed (cosign) and carry a SLSA build-provenance attestation.
Each release also ships a CycloneDX SBOM of Scratchsmith's own dependency graph
(`scratchsmith-v<ver>.cdx.json`), listed in `checksums.txt` so the signature and provenance
cover it too. It reflects the full `Cargo.lock` graph, so it includes build- and
dev-dependencies, not only the crates that link into the shipped binary.

Replace `<ver>` with the bare version you downloaded, no leading `v` (the tarball adds the
`v` prefix; the image tag doesn't).

```sh
# SLSA provenance — the simplest, ref-agnostic check
gh attestation verify scratchsmith-v<ver>-linux-amd64.tar.gz --repo schubydoo/scratchsmith

# Checksums signature (one cosign signature covers every tarball through its hash)
cosign verify-blob checksums.txt \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp '^https://github\.com/schubydoo/scratchsmith/\.github/workflows/knope-release\.yml@' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
sha256sum -c checksums.txt        # then check the tarball + SBOM hashes

# The signed GHCR image
cosign verify ghcr.io/schubydoo/scratchsmith:<ver> \
  --certificate-identity-regexp '^https://github\.com/schubydoo/scratchsmith/\.github/workflows/release\.yml@refs/tags/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

## Signing the image `pack` produces

The commands above verify Scratchsmith's own **release artifacts**. To sign an image Scratchsmith
*builds* for you, `pack --push --sign` cosign-signs the pushed image by digest (keyless), and
`--sbom --sign` attaches the SBOM as a signed attestation. Both only apply to the registry-push
sink, since cosign signs a registry image — see [Usage](usage.md).
