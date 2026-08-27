---
default: minor
---

Added a one-line installer. `curl -fsSL https://raw.githubusercontent.com/schubydoo/scratchsmith/main/install.sh | bash` downloads the signed Linux release binary (amd64/arm64), verifies its SHA-256 against the cosign-signed `checksums.txt` (and checks the cosign signature itself when cosign is installed), and installs it. Linux only — macOS/Windows fail fast with guidance to use a container or WSL2.
