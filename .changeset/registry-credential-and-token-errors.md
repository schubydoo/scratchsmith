---
default: patch
---

#### A broken credential helper no longer pushes anonymously

Looking up the registry credential treated every failure as "there is no credential here", and
the push went ahead anonymously. Against a registry that needs a login, you saw an opaque 401
instead of the real cause. Against a registry that accepts anonymous writes, the push worked,
under an identity you did not choose.

When a credential for the registry exists and something about using it breaks, the push now
stops and names the registry.

A missing credential is still anonymous, because pushing to a public or local registry without
a login is a supported thing to do. Two cases that read like failures are part of that
unchanged group. A machine with no Docker configuration file is one. A credential store that
reports no entry for the registry is the other, because a store reports that by failing.

Separately, a token response body that cannot be read is no longer reported as a token decoding
problem. A connection that drops in the middle of the response now says so.
