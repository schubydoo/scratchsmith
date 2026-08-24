---
default: minor
---

#### GitHub Action — `pack` in CI with no shell glue

A composite `schubydoo/scratchsmith` action downloads the signed release binary for the runner,
verifies it against the release checksums, and runs `pack`. Inputs map to the real pack flags —
`sbom`, `strip`, `user` (non-root by default), `output`, `smoke`, `ca-certs`/`tz`/`init`, `include`,
plus an `args` escape hatch — and it exposes `image`, `rootfs`, and the full JSON `report` as
outputs. An optional `push` input tags and pushes the built image (after your own registry login).

```yaml
- uses: schubydoo/scratchsmith@v0.1.2
  with:
    binary: ./dist/app
    strip: true
    smoke: true
```
