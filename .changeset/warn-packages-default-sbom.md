---
default: minor
---

#### A pack whose SBOM 2.0 changes now warns

For a pack with `--sbom` or `--scan` and no `--packages` value, `pack` prints one warning line
to standard error. It does so only on a host with a dpkg or rpm database. Scratchsmith 2.0 adds `sbom` to the
default `--packages`, so the SBOM and the scan will see the bundled packages. The run still
succeeds and the exit code does not change.
