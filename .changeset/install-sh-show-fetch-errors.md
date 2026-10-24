---
default: patch
---

#### `install.sh` says why a download failed

With wget, `install.sh` hid the reason a download failed, so a missing release, a proxy and a dead network looked the same. It now prints wget's last error lines when a fetch fails, and stays quiet when it works. The cosign signature bundle download no longer hides its error with either tool, so a refusal over a missing bundle shows why the fetch failed.
