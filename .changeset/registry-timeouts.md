---
default: patch
---

#### `--push` and `index` stop waiting on a registry that never answers

The registry clients had no connect timeout, so a registry or token host that never answered blocked `pack --push` and `index` with no output. A connect now fails after 30 seconds with an error that names the endpoint. The identity-token exchange also fails when the token host goes quiet for 60 seconds. The registry client gets no read timeout, so a slow upload of a large layer is not cut off.
