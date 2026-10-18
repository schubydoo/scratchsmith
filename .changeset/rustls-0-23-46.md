---
default: security
---

#### rustls 0.23.46 for registry TLS

The TLS library that `--push` uses to talk to a registry moves from rustls 0.23.45 to 0.23.46.
That release fixes RUSTSEC-2026-0346, RUSTSEC-2026-0347, RUSTSEC-2026-0348 and
RUSTSEC-2026-0349. The worst of them is rated medium.
