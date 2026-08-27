# Architecture

## How it works

1. **Resolve** — emulate the `ld.so` search order from the ELF itself (RPATH is transitive,
   RUNPATH is not, `$ORIGIN` is per-object). It never scrapes the host's `ldd`, `ld.so.cache`,
   or `LD_LIBRARY_PATH`, so the result is deterministic.
2. **Stage** — copy the interpreter to its verbatim path, mirror the libraries, recreate
   versioned-soname symlinks, regenerate `ld.so.cache`, and add the glibc NSS pieces.
3. **Assemble** — build a non-root image with reproducible layers (sorted entries, zeroed
   mtime/uid/gid; the uncompressed `diff_id` and the gzip layer digest are computed separately,
   avoiding the classic unpullable-image bug).

## Stability

Scratchsmith follows [Semantic Versioning](https://semver.org/). As of **1.0**, these surfaces are a
stable contract — a breaking change to any of them requires a new major version:

- **CLI flags** — the names and meaning of `pack` / `lint` / `doctor` flags. New flags arrive in minor
  releases; a removed or renamed flag, or a changed default, is a major change.
- **`scratchsmith.toml`** — the config keys and their types (the [Configuration](configuration.md) reference).
- **`--format json`** — the field names and types of the pack report (the schema CI gates consume). It is
  pinned by a golden test, so a change is always deliberate.
- **Exit codes** — `0` on success, `2` on an argument-parse error, and non-zero on any other failure.

**Not** frozen (may change in any release): human-readable text and warning wording, log output, `doctor`'s
exact phrasing, and the exact bytes of the produced image — layers stay reproducible for identical inputs,
but that is a property, not a frozen API.
