---
default: minor
---

`pack --label KEY=VALUE` writes OCI image labels and `pack --healthcheck <cmd>` sets the image `HEALTHCHECK` (exec form — it runs inside the scratch image, so it must name an executable present there). Both are repeatable and config-settable (`label` / `healthcheck`).
