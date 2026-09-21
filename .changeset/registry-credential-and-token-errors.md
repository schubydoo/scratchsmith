---
default: patch
---

#### A broken credential helper no longer pushes anonymously

A failed credential lookup counted as "no credential here", so the push went ahead anonymously.
You saw a bare 401, or a push that worked under an identity you did not choose.

A lookup that fails now stops the push and names the registry. No credential is still anonymous,
which is how you push to a public or local registry.

Separately, a token response body that cannot be read now reports the dropped connection instead
of a token-decoding problem.
