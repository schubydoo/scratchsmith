---
default: minor
---

#### The daemonless & supply-chain features, under their intended version

The daemonless output (`--oci-archive`, `--push`), Docker identity-token authentication, and
image signing (`--push --sign`) are the substance of this release. They first shipped in 0.1.4,
which was cut in error under a patch version; 0.2.0 re-releases the identical code under the
minor version those features warrant. **No code changed between 0.1.4 and 0.2.0** — pin to
0.2.0 (or later).
