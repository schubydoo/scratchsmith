# Contributing to Scratchsmith

Thanks for your interest! Scratchsmith is a Rust CLI that packs a prebuilt **dynamic
glibc or musl Linux** ELF binary (plus its resolved shared libraries) into a minimal
`FROM scratch` OCI image. This guide covers how to propose changes.

Report bugs and request features through the [issue tracker][issues] first. For a bug,
use the Bug Report template. For an idea, use the Feature Request template.

[issues]: https://github.com/schubydoo/scratchsmith/issues

## Scope

Scratchsmith deliberately targets prebuilt **dynamic** binaries: glibc, and musl/Alpine on
x86_64. It does **not** do cross-arch resolution, pack musl binaries for other
architectures, or replace static linking for binaries you can rebuild static. Please check a
proposal against that scope.

## Development setup

You need a stable Rust toolchain (the crate builds on MSRV **1.96**). **One** external tool is
required for `cargo test` to pass. The suite *fails* (not skips) without it:

- **`ldconfig`** (glibc `libc-bin`): the glibc stager/pack tests regenerate the loader cache
  and bail without it. It is normally already present on any glibc system, so this rarely
  bites. A stripped container image is one place it can be missing. A musl pack never calls
  it, since musl reads no loader cache.

On your own machine, everything else is optional. If the tool is absent, these tests **skip**
and `cargo test` still passes:

- a C compiler (`cc`) and `musl-gcc`: build the resolver / lint / musl fixtures
- Docker: the end-to-end pack/run tests
- `strip` (binutils): the `--strip` test
- `upx`: the compression tests
- `tini`: the `--init` test. With `tini` absent, a companion test instead checks that
  `--init` *fails loudly*.
- unprivileged user namespaces (`unshare -r`): the differential pack-and-run tests

**In CI, some of those stop being optional.** A skipped test is recorded as a pass. A runner
that loses a tool then reports a green suite having run nothing.

These are strict in CI: `cc`, `musl-gcc` and musl's loader at `/lib`, `strip`, `upx`, Docker,
`getent`, `localedef`, `mkfifo`, `sleep`, `syft`, `unshare -r`, the binaries `/usr/bin/id`,
`/usr/bin/bash` and `/usr/bin/touch`, a host `libc.so.6`, a dpkg database (`dpkg-query` with `/var/lib/dpkg/status`), and a non-root
user. A missing one **fails** the test instead of skipping it. The workflow
installs or guarantees all of them, so a miss there is a broken runner. If the `CI` environment variable holds
anything other than an opt-out word, the strict gate turns on. The opt-out words are `0`, `false`, `no`, `off` and the empty
string, in any case.

`tini`, the `registry:2` pull, the host locale sources, the host's `os-release`, the host
timezone (`/etc/localtime`) and the host CA bundle stay optional everywhere. The
x86_64-only `$PLATFORM` CPU-name test skips on other architectures.

If your own machine has `CI` set for an unrelated reason, set `SCRATCHSMITH_NO_CI_GATE=1` to
get the local behavior back. That variable reads by the same opt-out words, so an empty value
does not turn the gate off. The gate lives in `src/test_support.rs`, which the unit tests and
`tests/common` share.

The `--sbom` test is a special case. It runs with `syft` and without it. With `syft` present,
the test asserts success. With `syft` absent, it asserts a clean "missing syft must fail"
error. On your own machine the suite is green either way. The `--packages` tests need `syft`
for the SBOM, so in CI a missing `syft` fails them.

`tests/differential.rs` uses the real glibc loader as the reference. It compiles random library
layouts with `cc`, packs each one, and runs the packed rootfs in a chroot. If `pack` exits 0, the
program must start. Every PR runs 64 fixed cases, and the nightly `differential.yml` workflow
runs thousands from a new seed. A failure prints the seed of each broken case. To repeat one,
set `SCRATCHSMITH_DIFF_SEED=<seed>` and `SCRATCHSMITH_DIFF_CASES=1`.

`tests/differential_musl.rs` does the same for musl, with `musl-gcc` and musl's own loader as the
reference. Its layouts reach the musl rules that real Alpine programs almost never use, such as
an inherited RUNPATH, an object with both RPATH and RUNPATH (musl reads only RUNPATH), a libc
alias like `libpthread.so.0`, and a search path dropped for a `$LIB` token. On each case that
musl runs, `graph` must also resolve exactly the files that `ld-musl-x86_64.so.1 --list` maps.
The nightly workflow sweeps it too, and the same two variables repeat a case.

```sh
git clone https://github.com/schubydoo/scratchsmith
cd scratchsmith
cargo build
cargo test            # ldconfig required; other tool-specific tests skip if absent
                      # (in CI they fail instead — see above)
cargo run -- doctor   # shows which external tools are present
```

## The invariants

A change that breaks one of these is wrong, even with every test green:

- **Fail loud, never silently.** A missing library/loader, a musl binary on an architecture
  other than x86_64, glibc and musl mixed in one image, or a missing external tool exits
  non-zero with a fix hint. It is never a silent skip that ships a broken image.
- **Determinism over host-trust.** Resolution emulates the binary's loader, glibc's `ld.so` or
  musl's. It never scrapes host `ldd` / `ld.so.cache` / `LD_LIBRARY_PATH`.
- **Non-root + reproducible by default.** Images default to a non-root user, and layers are
  built deterministically.
- **Do not overstate.** Docs must not claim a capability the code does not have.
- **Do not break the contract silently.** The CLI flags, `scratchsmith.toml` keys, `--format
  json` fields, and exit codes are SemVer-stable within a major version. Change them
  additively in a minor. A removal, rename, or default change is a **major** change, and it
  first goes through the deprecation cycle (keep it working, warn on stderr). See
  **[COMPATIBILITY.md](COMPATIBILITY.md)**.

## Making a change

1. **Branch from `main`.** All PRs target `main`. Use a short prefixed name
   (`feat/…`, `fix/…`, `docs/…`, `ci/…`). External contributors: **fork** the repo and
   branch there. You do not have push access here. The `no-changelog` label needs
   triage rights, so a maintainer applies it for you.
2. **Keep it green** before pushing:
   ```sh
   cargo fmt --all --check
   cargo clippy --all-targets --all-features -- -D warnings
   RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features --document-private-items
   cargo test --all-features
   typos                 # spelling; false positives go in _typos.toml
   cargo deny check      # licenses/advisories
   ```
   CI runs all of these plus an MSRV build, coverage (**≥ 90%** lines), and `cargo audit`. It
   also builds the static musl binary, runs ShellCheck on `install.sh`, checks that the fuzz
   targets compile, tests the shell completions, and packs and runs three real third-party tools
   (`pack real tools`). `pack on Alpine (musl)` runs the static binary in Alpine, checks its
   graphs against musl's loader, and packs and runs curl with `--ca-certs`. It rejects a
   hand-rolled test skip: use `skip_required` or `skip_optional` from `src/test_support.rs`. The
   secret scan, workflow audit and CodeQL gates run too.
3. **Add a changeset** for any user-facing change (see below).
4. Open the PR and fill in the template.

## Conventional PR titles

The repo **squash-merges**, so the PR **title** becomes the commit subject. It must
follow [Conventional Commits][cc], and CI enforces that. Allowed types: `feat`, `fix`,
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

…or hand-write a fragment with front-matter `default: patch|minor|major|perf|security|deprecated`
and a one-line summary. A `major` fragment bumps the major version, so read
[COMPATIBILITY.md](COMPATIBILITY.md) before you write one. A deprecation ships two fragments:
one `minor` for the warning that it adds, and one `deprecated` for the notice.

Internal-only PRs (CI, refactor, tests, non-user-facing docs) need no fragment. Apply
the **`no-changelog`** label instead. Never hand-edit `CHANGELOG.md`. It is generated.

> Releases are **live** (the `KNOPE_ENABLED` flow is on). The `chore: prepare release …` PR
> picks up a merged fragment, and that fragment ships once the PR merges. The changeset
> check itself is **advisory**: a non-blocking sticky-comment nudge. Add a fragment anyway,
> because fragments are the source of truth for the version bump and `CHANGELOG.md`.

[knope]: https://knope.tech

## Review

Every PR runs CI. To request a second-opinion pass, comment `@claude review`
(maintainer-only). Merge does **not** require an approving review
(`required_approving_review_count: 0`, because this is a solo project). Merge **does**
require all review threads resolved and the required checks green. Be kind, and see the
[Code of Conduct](CODE_OF_CONDUCT.md).

## License

By contributing, you agree that your contributions are licensed under the project's
[MIT License](LICENSE) (inbound = outbound).
