---
default: security
---

#### The identity-token exchange sends the token only over https

With an identity token in the Docker config, `--push` and `index` posted the refresh token to whatever realm the registry named, plain `http` included, and followed a redirect from it with the token in the body. The realm must now be `https`. The one exception is a loopback realm for a local registry. A redirect from the token endpoint is refused, not followed. A failed exchange used to print the token host's whole answer as it was. It now shows at most 1 KiB of it, with control characters escaped. A token response is read up to 1 MiB.
