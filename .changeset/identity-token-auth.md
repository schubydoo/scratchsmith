---
default: minor
---

#### `--push` now authenticates with Docker identity-token credentials

Registries that hand out an **identity token** at `docker login` (an OAuth2 refresh token)
now work with `--push`. Previously only username/password credentials were used and an
identity token fell back to an anonymous, failing push. Scratchsmith now runs the
`grant_type=refresh_token` exchange against the registry's token endpoint itself — reading the
`WWW-Authenticate` realm from `/v2/` and trading the identity token for a short-lived bearer
access token — because `oci-client` only performs that exchange for Basic credentials. The
common username/password path is unchanged.
