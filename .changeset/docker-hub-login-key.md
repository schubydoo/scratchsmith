---
default: patch
---

#### A Docker Hub login kept in a credential helper is found

`--push` and `index` asked a `credsStore` or `credHelpers` helper for `docker.io`, but `docker login` stores the Docker Hub login under `https://index.docker.io/v1/`. The pass, secretservice, osxkeychain and wincred helpers match that key exactly, so they answered "not found", and the push went out anonymous. A Docker Hub reference now asks for `https://index.docker.io/v1/` first, then `docker.io`, so a login kept under either key is found.
