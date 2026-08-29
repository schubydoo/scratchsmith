# Compatibility & deprecation policy

Scratchsmith follows [Semantic Versioning](https://semver.org/). If you drive it from a script,
a GitHub Action, or an on-prem CI pipeline, this document is the promise you can rely on: **what
stays stable across a minor/patch upgrade, and how we change it when we must.**

## What is a stable contract (frozen within a major version)

A breaking change to any of these requires a new **major** version. See the
[Architecture → Stability](docs/architecture.md) reference for the authoritative list.

- **CLI surface** — the names and meaning of `pack` / `lint` / `doctor` / `index` flags and
  positionals, their short aliases, their defaults, whether they take a value or are repeatable,
  and the accepted **enum values** (e.g. `--sbom-format cyclonedx-json`, `--scan-fail-on high`).
- **`scratchsmith.toml`** — the config keys and their types.
- **`--format json`** — the field names and types of the `pack` and `index` reports (the schema
  CI gates consume).
- **Exit codes** — `0` on success, `2` on an argument/usage error, non-zero on any other failure.

## What is *not* a contract (may change in any release)

- **The Rust library API.** The `scratchsmith` crate exposes `pub` items so its own tests can
  reach them; it is **not** a supported library. Do not depend on `scratchsmith::…` as an API —
  drive the CLI instead. (CI runs `cargo-semver-checks` only informationally, to surface changes.)
- Human-readable text: help wording, warnings, log output, `doctor`'s phrasing, error messages.
- The exact bytes of the produced image (layers stay reproducible for identical inputs — that's a
  property, not a frozen API).

## Classifying a change

| Change | Bump | Rule |
|--------|------|------|
| **Additive** — a new flag, subcommand, optional config key, or JSON field | **minor** | Never breaks anyone; ship it. |
| **Deprecation** — mark something as going away *while keeping it working* | **minor** | The warning is itself additive; it's the on-ramp to a removal. |
| **Breaking** — remove/rename a flag or config key, drop a short alias, change a default, make a flag newly required, tighten validation, remove/rename a JSON field, remove an enum value, or change an exit code | **major only** | Never in a minor/patch. |

## The deprecation cycle

We do **not** remove things out from under you. Anything on the way out first goes through a
deprecation cycle:

1. **In a minor release**, the old flag / config key / behavior keeps working exactly as before.
   Using it prints a single line to **stderr**:
   ```
   warning: --old-flag is deprecated; use --new-flag instead. It will be removed in 3.0.
   ```
   The **exit code is unchanged** — a deprecated-but-successful run still exits `0`.
2. The deprecation is announced in the **CHANGELOG** (a `Deprecated:` entry) and listed in a
   **Deprecations** section of the docs, with the migration path.
3. It stays for a real window — **at minimum the rest of the current major line.**
4. It is removed only in the **next major version**, called out in the migration notes.

**Why stderr, never stdout:** stdout is the machine contract (`--format json`, the piped pack
report). A warning on stdout would corrupt a JSON parse or a downstream pipe. Warnings go to
stderr, which never breaks a consumer.

**Defaults are special:** a default value can't be cleanly "deprecated", so **a changed default is
always a major change.** We don't try to warn our way around it.

## How this is enforced

The contract is guarded by tests, so a breaking change can't land unnoticed — it makes a test
fail, which is the cue to either fix the regression or make it a deliberate, reviewed major change:

- **CLI surface** — `tests/cli_surface.rs` snapshots the whole flag tree to `tests/cli_surface.txt`.
  Any surface change fails until the golden is regenerated (`BLESS=1 cargo test --test cli_surface`).
- **Config keys** — `parses_a_full_config` exercises every key, and `#[serde(deny_unknown_fields)]`
  rejects a renamed/removed key.
- **`--format json`** — `json_report_schema_is_stable` / `index_report_schema_is_stable` pin the
  exact key sets.
- **Exit codes** — `exit_codes_follow_the_v1_contract` pins `0` / `2` / non-zero.
- **Library API** — an informational `cargo-semver-checks` CI job surfaces `pub`-API changes (not
  a gate; the library is out of contract).

## Reporting a compatibility regression

If an upgrade within a major version breaks a documented CLI flag, config key, JSON field, or exit
code, that's a bug — please [open an issue](https://github.com/schubydoo/scratchsmith/issues) with
the failing invocation and the versions involved.
