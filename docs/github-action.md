# GitHub Action

Pack in CI with no shell glue. The composite action downloads the signed release binary for the
runner, verifies it against the release checksums, and runs `pack`:

```yaml
- uses: schubydoo/scratchsmith@v<ver>   # pin to a release tag
  with:
    binary: ./dist/app         # your prebuilt dynamic glibc binary
    sbom: true                 # needs syft on the runner
    strip: true
    smoke: true                # fail the job if the packed image can't start
```

Outputs `image` (the loaded tag), `rootfs` (with `output:`), and the full JSON `report`. To publish
the built image, log in first and set `push`:

```yaml
- uses: docker/login-action@v3
  with: { registry: ghcr.io, username: ${{ github.actor }}, password: ${{ secrets.GITHUB_TOKEN }} }
- uses: schubydoo/scratchsmith@v<ver>   # pin to a release tag
  with:
    binary: ./dist/app
    push: ghcr.io/${{ github.repository }}:latest
```

Pin `@v<ver>` to a specific release tag (or a commit SHA) — the same supply-chain hygiene the tool
itself practices. `version:` overrides which scratchsmith release the action runs (defaults to the
pinned tag, else `latest`).

The `with:` keys map to the `pack` flags documented in [Configuration](configuration.md); see
[Usage](usage.md) for the equivalent command-line recipes.
