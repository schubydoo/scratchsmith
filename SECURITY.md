# Security Policy

## Supported Versions

Only the **latest** release receives security fixes. There are no backports to earlier
releases.

| Version  | Supported          |
| -------- | ------------------ |
| latest   | :white_check_mark: |
| < latest | :x:                |

## Reporting a Vulnerability

**Do not open a public issue for security vulnerabilities.**

Report privately, either:

- **Preferred:** GitHub's private vulnerability reporting through the **Security** tab →
  *Report a vulnerability* (if enabled on the repo), or
- **Email:** [schuuby@proton.me](mailto:schuuby@proton.me).

### What to include

- The type of vulnerability and its impact
- Affected file paths and a commit/tag/branch reference
- Step-by-step reproduction, and any proof-of-concept you have

### What to expect

- An acknowledgement within a few days (best-effort, because this is a solo, side-project OSS tool)
- Updates as the fix progresses, and a notification once it ships
- Credit in the advisory, on request

## Scope notes

Scratchsmith packs **third-party binaries you provide** into container images. It does
not sandbox or vet those binaries. A malicious input binary produces a malicious image.
Report security-relevant behavior such as the following: the resolver stages files outside
the intended set, or staging does a path traversal. Also report a false "safe" signal from the
smoke-run or the hardening lint, or a release pipeline that produces unsigned/mis-attested
artifacts.
