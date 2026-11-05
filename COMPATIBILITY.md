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
- **Exit codes**: `0` on success. `2` on a usage error, which is any refusal of the command
  line. That is an argument-parse error from clap, or a refusal made after the parse. Examples
  are `--watch --format json`, `pack` with no binary, and a config value that conflicts with a
  flag. `1` on any other failure, such as a failed pack. Before 2.0.0, a refusal made after the parse
  exited `1`. That change is a 2.0.0 break. It had no deprecation cycle, because 1.x promised only
  a non-zero code for these refusals. The 2.0.0 migration notes in
  [docs/deprecations.md](docs/deprecations.md) list it.
  For `scratchsmith.toml` the same rule holds. A value that parses and is then refused exits `2`,
  for example a `label` with no `=`. A file that cannot be read or parsed exits `1`, for example a
  value of the wrong type or an unknown key. A nested `[profile.a.profile.b]` table is refused
  when the file loads, so it exits `1` too.

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

**Security exceptions:** some input is the attack itself, such as an ELF that names a host
secret as a library to copy into the image. A minor/patch can refuse that input without a
deprecation cycle. The changelog lists each one under **Security**, and
[Deprecations](docs/deprecations.md) names what changed. We use this only for input that no
working image depends on.

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
- **Exit codes**: the exit-code tests in `tests/cli.rs` pin `0` / `2` / `1`.
  `post_parse_usage_refusals_exit_2` covers each refusal made after the parse.
- **Library API**: a non-blocking `cargo-semver-checks` CI job surfaces `pub`-API changes as a
  heads-up. It is not a gate, because the library is out of contract.

## Breaking changes in 2.0.0

Each item below warned on stderr before 2.0, from the release that the Deprecations page names,
with five exceptions. The `--no-build` output directory that cannot be listed had no warning.
An `--include` file that is not a regular file and starts like an ELF had no warning.
A program or an `--include` library at a package record path had no warning.
A library that `ldconfig` does not cache in a directory whose name holds `:` had no warning.
The last item changed an exit code with no warning.
The [Deprecations](docs/deprecations.md) page lists what to write instead.

- A library that sits only in an inherited `RPATH` directory, needed by an object that has
  `RUNPATH`, is now reported as missing. `pack` and `graph` fail, as the loader does.
- A nested `[profile.a.profile.b]` table in `scratchsmith.toml` is now an error, with exit code 1.
  Before, scratchsmith warned and ignored the table. Move it to a top-level `[profile.b]` table.
- `--label NAME` and `--env NAME` with no `=` are now a usage error, with exit code 2. Before,
  they warned and packed anyway. Write `NAME=value`, or `NAME=` for an empty value.
- A `label` or `env` entry with no `=` in `scratchsmith.toml` is now a usage error, with exit code 2.
  Write each entry as `NAME=value`.
- The default `--packages` selection (the `packages` key) is now `report,sbom`, not `report`. In
  1.9, scratchsmith warned when `--sbom` or `--scan` ran with no `--packages` value on a host with
  a dpkg or rpm database. Now the SBOM and the scan see the packages, and a `--scan-fail-on` gate
  can find more. Write `--packages report` for the 1.x result.
- `pack --no-build --output DIR` into a `DIR` that is not empty is now an error, with exit code 1.
  The error comes before any file is staged. Before, scratchsmith warned and merged into the old
  tree. Use a new or empty directory. A `DIR` that scratchsmith cannot list is now an error too,
  because it cannot prove that the directory is empty. 1.x did not warn for it and packed into it.
- `$PLATFORM` in an `RPATH` or `RUNPATH` entry, on an architecture other than `x86_64` or
  `aarch64`, is now an error. `pack` and `graph` exit with code 1. Before, scratchsmith warned and
  searched the path with the token removed. Write the directory name in the path.
- A program interpreter (`PT_INTERP`) that starts like an ELF and cannot be parsed is now an
  error, with exit code 1. Before, `pack` and `graph` warned and went on. Replace the damaged
  loader with an intact copy.
- A library that starts like an ELF and cannot be parsed is now an error, with exit code 1.
  Before, `pack` and `graph` warned and kept it, and the libraries that it needs did not reach
  the image. Replace the damaged file with an intact copy. An `--include` file that is not a
  regular file, such as a FIFO, and starts like an ELF now fails `graph` too. 1.x did not warn
  for it.
- The packed program or an `--include` library can be at a package record path on the host, such
  as `/var/lib/dpkg/status.d/libc6`. An explicit `--packages` value with `sbom` or `image` then
  fails, with exit code 1. Before, the pack exited 0, but the record replaced the file,
  and with `sbom` the pack then deleted it. 1.x did not warn for it. Remove `sbom` and `image`
  from `--packages`, or move the file on the host.
- A library can sit only in a directory whose name holds `:`, such as `x:y` from `RUNPATH`
  `$ORIGIN/x:y`. If `ldconfig` does not cache it under the needed name, it is now missing.
  `ldconfig` caches a name that starts with `lib` or `ld-` and holds `.so`. It also caches a name
  that starts with `ld.so.` or `ld64.so.`. The library's soname must be that name, or absent.
  `pack` and `graph` fail with exit code 1 and a `note:` line. Before, the pack exited 0, and the
  image exited 127 at start. 1.x did not warn for it. Move the library to a directory with no `:`
  in its name.
- A command line that scratchsmith refuses only after the parse now exits 2, not 1. Examples are
  `--watch --format json`, `pack` with no binary, and one `--add-file` image path given twice.
  This had no warning before 2.0. A script that tests for exactly `1` must also accept `2`.

## Reporting a compatibility regression

If an upgrade within a major version breaks a documented CLI flag, config key, JSON field, or
exit code, that is a bug. Please
[open an issue](https://github.com/schubydoo/scratchsmith/issues) with the failing invocation
and the versions involved.
