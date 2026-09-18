# Scratchsmith — agent guide

Daemonless supply-chain packager. It takes a prebuilt **dynamic glibc** Linux ELF and
produces a minimal, non-root `FROM scratch` OCI image with an SBOM and an ELF-hardening
lint. On `--push` it also signs the image with cosign. Rust CLI. See `README.md` for the
product story and `CONTRIBUTING.md` for the flow.

## Critical commands

- **Test**: `cargo nextest run` (or `cargo test`). Docker integration tests pack `/usr/bin/id`.
- **Lint gates (all required in CI)**: `cargo fmt --all --check` · `cargo clippy --all-targets --all-features -- -D warnings` · `cargo deny check` · `typos`.
- **Coverage**: `cargo llvm-cov --fail-under-lines 90`. Patch target 80%. Run **`/patch-coverage`** before every PR push. NOTE: `cargo llvm-cov --lib` badly understates `pack.rs` (~13% vs ~92%) because it skips the integration tests. Trust the codecov patch number.
- **musl-static build** (the shipped artifact): `cargo zigbuild --target x86_64-unknown-linux-musl --release` (needs `cargo-zigbuild` + `ziglang`).
- **MSRV**: 1.96. Build with the pinned toolchain, not just stable.

## Architecture map

- `src/resolver.rs`: `ld.so`-faithful dependency resolution (RPATH/RUNPATH/`$ORIGIN`, interpreter, sonames). Never scrapes host `ldd`/cache.
- `src/stager.rs`: copies interpreter + libs, recreates soname symlinks, regenerates `ld.so.cache`, stages glibc NSS/passwd.
- `src/image.rs`: reproducible layer/config, plus `docker load` and `write_oci_archive`.
- `src/registry.rs`: daemonless `--push` via `oci-client`. Docker-config auth includes the identity-token OAuth2 exchange.
- `src/pack.rs`: orchestration. Delivery goes through a `Sink` enum (`Rootfs`/`DockerLoad`/`OciArchive`/`Push`).
- `src/supplychain.rs`: SBOM (syft) + image signing/attestation (cosign), shelled out.
- `src/{cli,lint,doctor,report,config}.rs` · `tests/`: integration tests.

## Hard rules

- **IMPORTANT: Every change is a PR.** Never commit to `main`. Squash-merge, use a **conventional PR title**, and **resolve every review thread** (the ruleset blocks merge otherwise). Label CI/docs-only PRs `no-changelog`.
- **YOU MUST keep the musl-static build working**: TLS is **rustls + aws-lc-rs only, never OpenSSL or native-tls**. Add a networking dep only with oci-client's exact TLS feature. Then check the build with `cargo zigbuild` (musl).
- **IMPORTANT: never Renovate-bump the MSRV.** To raise it, change three things together: `Cargo.toml` `rust-version`, the `msrv` CI job, and the README badge. Never raise it through a CI dep bump.
- **Never hand-edit `CHANGELOG.md`**. knope generates it from `.changeset/*.md` fragments, one per user-facing change. A `.changeset/README.md` aborts `prepare-release`.
- **Release footgun (shipped v0.1.4 by mistake): `knope-prepare` runs on every push to `main` without the override**. To cut a release with `override_version`, merge the release PR **alone**. Any other merge in between re-runs prep and downgrades it. The `release-pinned` label now guards this. Re-dispatch to change a pinned PR.
- If `audit · deny` CI fails with a RustSec advisory-db **fetch** error, that is a transient flake. Run `gh run rerun <id> --failed`. It is not a real advisory.
- **Use `command grep` for repo-wide or negative searches**. The shimmed `grep` silently skips gitignored paths (`scratch/`, `.claude/`), so a plain `grep` cannot prove a negative.
- All GitHub Actions are **SHA-pinned** (enforced). Renovate auto-merges github-actions minor/patch/digest. Its rules live in the shared `schubydoo/renovate-config` preset, not here.
- **Fuzz the untrusted-input boundary.** Some `pub fn` items consume untrusted external bytes, such as `resolver::parse_elf_info`, `lint::hardening_from_bytes` and `resolver::resolve_with`. A new one gets a fuzz target added or extended under `fuzz/fuzz_targets/` in the **same PR**. Put token literals in a `fuzz/<target>.dict` for code that branches on specific strings. `fuzz/` is a **detached workspace** that the main build never compiles. So the required **`fuzz harness check`** job (`cargo check` on it) is what catches a fuzz target broken by an API change. The weekly `cflite_cron` report tracks reach. Do not gate on the percentage, because it drifts with the corpus.
- **Do not silently break the v1.0 contract** (`COMPATIBILITY.md`). The stable surfaces are the CLI flags (names/shorts/defaults/`multiple`/enum values), `scratchsmith.toml` keys, `--format json` fields, and exit codes. In a **minor/patch** these change **additively only**. These are **major** changes: removing or renaming a flag or key, dropping a short, changing a default, tightening validation, or removing an enum value. A flag that becomes newly required is **major** too. A **major** change starts with a **deprecation**. Keep the old surface working, warn on **stderr**, and leave the exit code unchanged. Hold that deprecation for at least the rest of the major line, then remove the surface in the next major. The **`cli_surface`** golden test flags any surface change. A needed `BLESS=1` regen is the cue to check that the change is not breaking. The Rust **library API is not a contract** (`cargo-semver-checks` runs informationally only).

## Workflow preferences

- **Surgical changes**: touch only what the task needs, match surrounding style, minimal diffs for small fixes.
- **Check before reporting**: read `git log`, `gh`, or the code itself. A status line in a doc is a cache, not truth. If tests fail, say so.
- Deferred todos go in the `scratch/` backlog. **Do not open GitHub issues unasked**.
- Code comments: terse, explain the non-obvious *why*, then stop.

## What NOT to include here

Per-release state, open-PR status, and one-off task notes belong in the maintainer's scratch notes, not this file. No file-by-file dumps or generated API docs (link instead). Do not restate things an agent learns in-session.
