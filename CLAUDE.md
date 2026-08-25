# Scratchsmith — agent guide

Daemonless supply-chain packager: takes a prebuilt **dynamic glibc** Linux ELF and produces a
minimal, non-root `FROM scratch` OCI image with an SBOM, ELF-hardening lint, and (on `--push`)
cosign signing. Rust CLI. See `README.md` for the product story, `CONTRIBUTING.md` for the flow.

## Critical commands

- **Test**: `cargo nextest run` (or `cargo test`). Docker integration tests pack `/usr/bin/id`.
- **Lint gates (all required in CI)**: `cargo fmt --all --check` · `cargo clippy --all-targets --all-features -- -D warnings` · `cargo deny check` · `typos`.
- **Coverage**: `cargo llvm-cov --fail-under-lines 90`. Patch target 80%. Run **`/patch-coverage`** before every PR push. NOTE: `cargo llvm-cov --lib` badly understates `pack.rs` (~13% vs ~92%) — it skips the integration tests; trust codecov's patch number.
- **musl-static build** (the shipped artifact): `cargo zigbuild --target x86_64-unknown-linux-musl --release` (needs `cargo-zigbuild` + `ziglang`).
- **MSRV**: 1.96 — build with the pinned toolchain, not just stable.

## Architecture map

- `src/resolver.rs` — `ld.so`-faithful dependency resolution (RPATH/RUNPATH/`$ORIGIN`, interpreter, sonames). Never scrapes host `ldd`/cache.
- `src/stager.rs` — copies interpreter + libs, recreates soname symlinks, regenerates `ld.so.cache`, stages glibc NSS/passwd.
- `src/image.rs` — reproducible layer/config; `docker load` + `write_oci_archive`.
- `src/registry.rs` — daemonless `--push` via `oci-client`; Docker-config auth incl. identity-token OAuth2 exchange.
- `src/pack.rs` — orchestration; delivery via a `Sink` enum (`Rootfs`/`DockerLoad`/`OciArchive`/`Push`).
- `src/supplychain.rs` — SBOM (syft) + image signing/attestation (cosign), shelled out.
- `src/{cli,lint,doctor,report,config}.rs` · `tests/` — integration tests.

## Hard rules

- **IMPORTANT: Every change is a PR** — never commit to `main`. Squash-merge, **conventional PR title**, and **resolve every review thread** (the ruleset blocks merge otherwise). Label CI/docs-only PRs `no-changelog`.
- **YOU MUST keep the musl-static build working**: TLS is **rustls + aws-lc-rs only — never OpenSSL/native-tls**. Add a networking dep only with oci-client's exact TLS feature, then verify with `cargo zigbuild` (musl).
- **IMPORTANT: never Renovate-bump the MSRV.** To raise it, change `Cargo.toml` `rust-version` + the `msrv` CI job + the README badge together — never via a CI dep bump.
- **Never hand-edit `CHANGELOG.md`** — it's knope-generated from `.changeset/*.md` fragments (one per user-facing change; a `.changeset/README.md` aborts `prepare-release`).
- **Release footgun (cost a mis-shipped v0.1.4): `knope-prepare` runs on every push to `main` without the override.** When cutting via `override_version`, merge the release PR **alone** — any other merge in between re-runs prep and downgrades it. The `release-pinned` label now guards this; re-dispatch to change a pinned PR.
- If `audit · deny` CI fails with a RustSec advisory-db **fetch** error, it's a transient flake — `gh run rerun <id> --failed`, not a real advisory.
- **Use `command grep` for repo-wide/negative searches** — the shimmed `grep` silently skips gitignored paths (`scratch/`, `.claude/`), so a plain `grep` can't prove a negative.
- All GitHub Actions are **SHA-pinned** (enforced). Renovate auto-merges github-actions minor/patch/digest; its rules live in the shared `schubydoo/renovate-config` preset, not here.

## Workflow preferences

- **Surgical changes**: touch only what the task needs, match surrounding style, minimal diffs for small fixes.
- **Verify before reporting**: confirm against `git log` / `gh` / the code — a status line in a doc is a cache, not truth. If tests fail, say so.
- Deferred todos go in the `scratch/` backlog — **do not open GitHub issues unasked**.
- Code comments: terse, explain the non-obvious *why*, then stop.

## What NOT to include here

Per-release state, open-PR status, and one-off task notes belong in the maintainer's scratch notes, not this file. No file-by-file dumps or generated API docs (link instead). Don't restate things Claude learns in-session.

## Token Efficiency
- Never re-read files you just wrote or edited. You know the contents.
- Never re-run commands to "verify" unless the outcome was uncertain.
- Don't echo back large blocks of code or file contents unless asked.
- Batch related edits into single operations. Don't make 5 edits when 1 handles it.
- Skip confirmations like "I'll continue..." Just do it.
- If a task needs 1 tool call, don't use 3. Plan before acting.
- Do not summarize what you just did unless the result is ambiguous or you need additional input.
