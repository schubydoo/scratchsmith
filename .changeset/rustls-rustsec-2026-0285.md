---
default: security
---

#### rustls 0.23.45 (RUSTSEC-2026-0285)

The shipped binary now links rustls 0.23.45. Version 0.23.44 accepts TLS 1.3 handshake
messages across encryption level boundaries (RUSTSEC-2026-0285, medium, 5.3). rustls
arrives through `reqwest`, so only `Cargo.lock` changes.
