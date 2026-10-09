---
default: minor
---

#### The JSON pack report carries the time of each phase

`pack --format json` gains a `timings` object: the milliseconds spent to resolve, stage, generate
the SBOM, scan, deliver, smoke-run and sign, plus the total. A phase that did not run is `null`.
Use it to find the slow part of a pack in CI, or to build trace spans from it. The text report
does not change.
