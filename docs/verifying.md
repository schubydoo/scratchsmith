# Verifying releases

Release artifacts are keyless-signed (cosign) and carry a SLSA build-provenance attestation, at Build
Level 3 from v2.2.0 on.
Each release from v1.0.0 on also ships a CycloneDX SBOM of Scratchsmith's own dependency graph. That file is
`scratchsmith-v<ver>.cdx.json`, and it is listed in `checksums.txt`, so the signature and
provenance cover it too. It reflects the full `Cargo.lock` graph, so it includes build- and
dev-dependencies, not only the crates that link into the shipped binary.

The release also carries `scratchsmith.intoto.jsonl`, the SLSA provenance bundle. You do not need
to download it, because `gh attestation verify` reads the attestation from GitHub. That needs `gh`
signed in (`gh auth login`). To check against the bundle instead, see
[Verifying from the bundle](#verifying-from-the-bundle).

Replace `<ver>` with the bare version you downloaded, no leading `v` (the tarball adds the
`v` prefix, but the image tag does not).

The provenance is Build Level 3 because the binaries are built and attested inside a reusable
workflow, `release-binaries.yml`, which signs the provenance with its own identity. The release
workflow that calls it can't add steps to its jobs. `--signer-workflow` checks for that identity, so
a provenance signed by any other workflow in the repository fails the check. v2.2.0 is the first
release built this way. v2.1.0 and older carry Build Level 2 provenance, signed by
`knope-release.yml`. For those, leave out `--signer-workflow`.

The Build Level 3 provenance covers the tarballs and the SBOM, not the GHCR image. The image packs
the same release binaries. It carries its own cosign signature, which the `cosign verify` command
below checks, and BuildKit provenance and SBOM attestations in the registry, which are not Level 3.

```sh
# SLSA Build L3 provenance — the simplest, ref-agnostic check
gh attestation verify scratchsmith-v<ver>-linux-amd64.tar.gz --repo schubydoo/scratchsmith \
  --signer-workflow schubydoo/scratchsmith/.github/workflows/release-binaries.yml

# Checksums signature (one cosign signature covers every tarball through its hash)
cosign verify-blob checksums.txt \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp '^https://github\.com/schubydoo/scratchsmith/\.github/workflows/knope-release\.yml@' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
sha256sum -c --ignore-missing checksums.txt   # then check the hashes of the files you downloaded

# The signed GHCR image
cosign verify ghcr.io/schubydoo/scratchsmith:<ver> \
  --certificate-identity-regexp '^https://github\.com/schubydoo/scratchsmith/\.github/workflows/release\.yml@refs/tags/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

### Verifying from the bundle

To check the provenance against the `scratchsmith.intoto.jsonl` that ships in the release, instead
of fetching it from GitHub, pass it with `--bundle`:

```sh
gh attestation verify scratchsmith-v<ver>-linux-amd64.tar.gz --repo schubydoo/scratchsmith \
  --bundle scratchsmith.intoto.jsonl \
  --signer-workflow schubydoo/scratchsmith/.github/workflows/release-binaries.yml
```

`gh` still fetches Sigstore's trusted root. For a machine with no network, save it first on one
that has it, with `gh attestation trusted-root > trusted_root.jsonl`, and add
`--custom-trusted-root trusted_root.jsonl`.

## Rebuilding a release binary

Release binaries from v2.2.0 on are reproducible. For every such release, a CI job rebuilds both
binaries from the tag and checks that they match the published ones byte for byte. To run the same check
yourself, follow [REPRODUCE.md](https://github.com/schubydoo/scratchsmith/blob/main/REPRODUCE.md).

## Verifying an image you signed with `pack`

The commands above verify Scratchsmith's own **release artifacts**. To sign an image Scratchsmith
*builds* for you, `pack --push --sign` cosign-signs the pushed image by digest (keyless), and
`--sbom --sign` attaches the SBOM as a signed attestation. Both only apply to the registry-push
sink, since cosign signs a registry image. See [Usage](usage.md).

Scratchsmith runs `cosign sign` and `cosign attest` with no key, so the signature carries the
OIDC identity of whoever ran `--sign`. Verify with the identity and issuer of that signer:

| Where `--sign` ran | `--certificate-identity` | `--certificate-oidc-issuer` |
|---|---|---|
| GitHub Actions (`id-token: write`) | `https://github.com/<owner>/<repo>/.github/workflows/<file>@<ref>` | `https://token.actions.githubusercontent.com` |
| Your terminal, signed in with Google | your email address | `https://accounts.google.com` |

For a terminal login with another provider, the identity is still your email, and the issuer is
that provider's. Sigstore's [verification cheat sheet](https://docs.sigstore.dev/quickstart/verification-cheat-sheet/)
lists them. In CI, `--certificate-identity-regexp` lets one check hold for every branch or tag
of the workflow.

```sh
IMAGE=ghcr.io/you/app:latest   # or the @sha256:... reference that the pack printed

# The signature that --sign made
cosign verify "$IMAGE" \
  --certificate-identity-regexp '^https://github\.com/you/app/\.github/workflows/release\.yml@' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

# The SBOM attestation that --sbom --sign made (CycloneDX, the default --sbom-format)
cosign verify-attestation "$IMAGE" --type cyclonedx \
  --certificate-identity-regexp '^https://github\.com/you/app/\.github/workflows/release\.yml@' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com > /dev/null
```

With `--sbom-format spdx-json`, use `--type spdxjson`. Pass a tag only if you trust it not to
move. The digest reference that the pack printed (`signed ...@sha256:...`, or the `signed` field
in `--format json`) pins the exact image. To read the attested SBOM, drop the `> /dev/null` and
decode its payload:

```sh
cosign verify-attestation "$IMAGE" --type cyclonedx <identity flags as above> \
  | jq -r .payload | base64 -d | jq .predicate
```

Scratchsmith's `push-auth-smoke` workflow runs the same `cosign verify` and
`cosign verify-attestation` checks, with its own workflow identity, against an image it packs,
pushes to GHCR and signs.
