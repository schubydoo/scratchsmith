---
default: patch
---

#### --sign checks cosign before the push

`pack --push --sign` and `index --sign` now check that cosign runs before they push anything, so a missing cosign no longer leaves a public image that is not signed. When the registry's answer names no digest, `--sign` now signs the digest of the manifest that scratchsmith sent, where it used to refuse. A digest that the registry names and that differs is still refused. If signing fails after the push, the error now says that the image was pushed but is not signed.
