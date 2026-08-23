# Security Policy

## Supported Versions

Scratchsmith is pre-1.0. Only the **latest** release receives security fixes; there are
no backports to older 0.x versions.

| Version  | Supported          |
| -------- | ------------------ |
| latest   | :white_check_mark: |
| < latest | :x:                |

## Reporting a Vulnerability

**Do not open a public issue for security vulnerabilities.**

Report privately, either:

- **Preferred** — GitHub's private vulnerability reporting: the **Security** tab →
  *Report a vulnerability* (if enabled on the repo), or
- **Email** — [schuuby@proton.me](mailto:schuuby@proton.me).

### What to include

- The type of vulnerability and its impact
- Affected file paths and a commit/tag/branch reference
- Step-by-step reproduction, and a proof-of-concept if you have one

### What to expect

- An acknowledgement within a few days (best-effort; this is a solo, side-project OSS tool)
- Updates as the fix progresses, and notification when it ships
- Credit in the advisory if you'd like it

## Scope notes

Scratchsmith packs **third-party binaries you provide** into container images. It does
not sandbox or vet those binaries — a malicious input binary produces a malicious image.
Relevant security-relevant behaviour to report includes: the resolver staging files
outside the intended set, path-traversal in staging, the smoke-run or hardening lint
giving a false "safe" signal, or the release pipeline producing unsigned/mis-attested
artifacts.
