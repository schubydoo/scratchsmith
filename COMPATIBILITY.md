# Compatibility & deprecation policy

Scratchsmith follows [Semantic Versioning](https://semver.org/) for every release. You can
drive it from a script, a GitHub Action, or an on-prem CI pipeline. This document is the
promise you rely on there. It states two things: **what stays stable across a minor/patch
upgrade, and how we change it**.

## What is a stable contract (frozen within a major version)

A breaking change to any of these requires a new **major** version. See the
[Architecture → Stability](docs/architecture.md) reference for the authoritative list.

- **CLI surface**: the names and meaning of `pack` / `lint` / `doctor` / `index` / `graph` /
  `diff` / `unpack` flags and positionals, and the top-level `--completions`. The contract
  also covers their short aliases, their defaults, and whether they take a value or are
  repeatable. It covers the accepted **enum values** too (for example
  `--sbom-format cyclonedx-json`, `--scan-fail-on high`).
- **`scratchsmith.toml`**: the config keys and their types.
- **`--format json`**: the field names and types of the `pack`, `index`, `graph`, `diff`, and
  `unpack` reports (the schema CI gates consume).
- **Exit codes**: `0` on success, `2` on an argument/usage error, non-zero on any other failure.

## What is *not* a contract (can change in any release)

- **The Rust library API.** The `scratchsmith` crate exposes `pub` items so its own tests can
  reach them. It is **not** a supported library. Do not depend on `scratchsmith::…` as an API.
  Drive the CLI instead. (A `cargo-semver-checks` CI job surfaces `pub`-API changes for
  information only, never as a gate.)
- Human-readable text: help wording, warnings, log output, `doctor`'s phrasing, error messages.
- The exact bytes of the produced image. Layers stay reproducible for identical inputs, but
  that is a property, not a frozen API.

## Classifying a change

| Change | Bump | Rule |
|--------|------|------|
| **Additive**: a new flag, subcommand, optional config key, or JSON field | **minor** | Never breaks anyone. Ship it. |
| **Deprecation**: mark something as going away *while keeping it working* | **minor** | The warning is itself additive. It is the on-ramp to a removal. |
| **Breaking**: remove/rename a flag or config key, drop a short alias, or change a default. Also breaking: make a flag newly required, tighten validation, remove/rename a JSON field, remove an enum value, or change an exit code | **major only** | Never in a minor/patch. |

## The deprecation cycle

We do **not** remove things out from under you. Anything on the way out first goes through a
deprecation cycle:

1. **In a minor release**, the old flag / config key / behavior keeps working exactly as before.
   Using it prints a single line to **stderr**:
   ```
   warning: --old-flag is deprecated; use --new-flag instead. It will be removed in 3.0.
   ```
   The **exit code is unchanged**. A deprecated-but-successful run still exits `0`.
2. The deprecation is announced in the **CHANGELOG** (a `Deprecated:` entry) and listed in a
   **Deprecations** section of the docs, with the migration path.
3. It stays for a real window: **at minimum the rest of the current major line.**
4. It is removed only in the **next major version**, called out in the migration notes.

**Why stderr, never stdout:** stdout is the machine contract (`--format json`, the piped pack
report). A warning on stdout corrupts a JSON parse or a downstream pipe. Warnings go to
stderr, which never breaks a consumer.

**Defaults are special:** a default value cannot be cleanly "deprecated". **A changed default
is always a major change.** We do not try to warn our way around it.

## How this is enforced

Each surface is guarded by a test that lands with this policy, and the library API by an
informational CI job. A breaking change fails a check rather than landing silently. That
failure is the cue to either fix the regression or make it a deliberate, reviewed major
change:

- **CLI surface**: a golden snapshot of the whole flag tree, `tests/cli_surface.rs` →
  `tests/cli_surface.txt`. Any surface change fails until the golden is regenerated
  (`BLESS=1 cargo test --test cli_surface`).
- **Config keys**: `parses_a_full_config` exercises every key, and `#[serde(deny_unknown_fields)]`
  rejects a renamed/removed key.
- **`--format json`**: `json_report_schema_is_stable`, `index_report_schema_is_stable`,
  `dep_graph_json_schema_is_stable`, `diff_report_schema_is_stable`, and
  `unpack_report_schema_is_stable` pin the exact key sets.
- **Exit codes**: the exit-code tests in `tests/cli.rs` pin `0` / `2` / non-zero.
- **Library API**: a non-blocking `cargo-semver-checks` CI job surfaces `pub`-API changes as a
  heads-up. It is not a gate, because the library is out of contract.

## Reporting a compatibility regression

If an upgrade within a major version breaks a documented CLI flag, config key, JSON field, or
exit code, that is a bug. Please
[open an issue](https://github.com/schubydoo/scratchsmith/issues) with the failing invocation
and the versions involved.
