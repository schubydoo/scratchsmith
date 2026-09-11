---
default: minor
---

#### `nss`, `deny`, and `require` GitHub Action inputs

The action now exposes three more pack options as first-class inputs. `nss` selects the NSS
modules to stage. If a listed library ships, `deny` fails the pack. If a listed library is
absent, `require` fails the pack. Each input maps to the pack flag of the same name.
