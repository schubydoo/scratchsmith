---
default: patch
---

#### `unpack` reads an OCI archive whose entries start with `./`

`tar -cf img.tar .` inside an OCI layout directory stores `./index.json` and `./blobs/sha256/…`. `unpack` failed on such an archive with "archive has no index.json". It now reads those entries as the same files.
