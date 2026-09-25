---
default: patch
---

#### `install.sh` no longer stops silently when it resolves the latest release

Without `VERSION`, the installer sometimes exited with no message right after "resolving the latest
release". The cause was a race in a shell pipe. The installer now reads the full GitHub answer
before it parses the tag. If GitHub cannot be reached, it prints an error that names `VERSION`.
