# Contributing to Scratchsmith

Thanks for your interest! Scratchsmith is a Rust CLI that packs a prebuilt **dynamic
glibc Linux** ELF binary (plus its resolved shared libraries) into a minimal
`FROM scratch` OCI image. This guide covers how to propose changes.

Report bugs and request features through the [issue tracker][issues] first — for a bug,
use the Bug Report template; for an idea, the Feature Request template.

[issues]: https://github.com/schubydoo/scratchsmith/issues

## Scope

Scratchsmith deliberately targets prebuilt **dynamic glibc** binaries. It does **not**
resolve musl/Alpine binaries, do cross-arch resolution, or replace static linking for
binaries you can rebuild static. Please check a proposal against that scope.

## Development setup

You need a stable Rust toolchain (the crate builds on MSRV **1.96**). Some integration
tests need Linux tools that are auto-skipped when absent:

- `ldconfig` (glibc `libc-bin`) — required for a real `pack`
- a C compiler (`cc`), `musl-gcc` — build the resolver/lint/musl fixtures
- Docker — the end-to-end pack/run tests
- `syft`, `strip`, `tini` — SBOM / `--strip` / `--init` paths

```sh
git clone https://github.com/schubydoo/scratchsmith
cd scratchsmith
cargo build
cargo test            # Docker/cc tests skip if those tools are absent
cargo run -- doctor   # shows which external tools are present
```

## The invariants

A change that breaks one of these is wrong even if tests pass:

- **Fail loud, never silently.** A missing library/loader, a musl binary, or a missing
  external tool exits non-zero with a fix hint — never a silent skip that ships a broken
  image.
- **Determinism over host-trust.** Resolution emulates `ld.so`; it never scrapes host
  `ldd` / `ld.so.cache` / `LD_LIBRARY_PATH`.
- **Non-root + reproducible by default.** Images default to a non-root user; layers are
  built deterministically.
- **Don't overstate.** Docs must not claim a capability the code doesn't have.

## Making a change

1. **Branch from `main`** — all PRs target `main`. Use a short prefixed name
   (`feat/…`, `fix/…`, `docs/…`, `ci/…`).
2. **Keep it green** before pushing:
   ```sh
   cargo fmt --all --check
   cargo clippy --all-targets --all-features -- -D warnings
   cargo test --all-features
   typos                 # spelling; false positives go in _typos.toml
   cargo deny check      # licenses/advisories
   ```
   CI runs all of these plus an MSRV build, coverage (**≥ 90%** lines), and
   `cargo audit`.
3. **Add a changeset** for any user-facing change (see below).
4. Open the PR and fill in the template.

## Conventional PR titles

The repo **squash-merges**, so the PR **title** becomes the commit subject and must
follow [Conventional Commits][cc] — CI enforces it. Allowed types: `feat`, `fix`,
`perf`, `security`, `revert`, `docs`, `chore`, `ci`, `build`, `test`, `refactor`,
`style`. Example: `feat: add --sbom-format spdx-json`.

[cc]: https://www.conventionalcommits.org

## Changesets (release notes)

Releases are **changesets-only**, driven by [knope][knope]: every user-facing change
ships a `.changeset/*.md` fragment, and those fragments (not commit messages) drive both
the version bump and `CHANGELOG.md`.

```sh
knope document-change    # scaffolds .changeset/<slug>.md
```

…or hand-write a fragment with front-matter `default: patch|minor|major|perf|security`
and a one-line summary. **Pre-1.0**, a `major` (breaking) change maps to a *minor* bump —
0.x never auto-bumps to 1.0.

Internal-only PRs (CI, refactor, tests, non-user-facing docs) need no fragment — apply
the **`no-changelog`** label instead. Never hand-edit `CHANGELOG.md`; it is generated.

[knope]: https://knope.tech

## Review

A maintainer reviews every PR; you can also request a second-opinion pass by commenting
`@claude review` (maintainer-only). Address review threads and resolve them — the repo
requires resolved threads before merge. Be kind; see the [Code of Conduct](CODE_OF_CONDUCT.md).
