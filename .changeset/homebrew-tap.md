---
default: minor
---

#### Homebrew tap — `brew install schubydoo/scratchsmith/scratchsmith`

Scratchsmith is now installable via a Homebrew tap (Linux amd64/arm64, from the signed
release tarballs). The formula (`Formula/scratchsmith.rb`) is regenerated from each
release's cosign-verified `checksums.txt` by `packaging-bump.yml`, which opens an
auto-merging PR; that merge dispatches the [tap](https://github.com/schubydoo/homebrew-scratchsmith)
to mirror it — so `brew upgrade` tracks releases hands-free.
