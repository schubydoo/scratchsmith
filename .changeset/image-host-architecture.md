---
default: patch
---

#### Stamp the host architecture into the image config

The generated image config previously always recorded `architecture: amd64`. Packing on an
arm64 host therefore produced an image mislabeled as amd64, which runtimes could refuse to run
and which broke multi-arch image indexes. Scratchsmith now records the real host architecture
(`amd64`, `arm64`, …), so a per-arch CI matrix produces correctly-labeled images.
