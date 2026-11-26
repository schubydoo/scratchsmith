# Architecture

## How it works

1. **Resolve**: emulate the `ld.so` search order from the ELF itself (RPATH is transitive,
   RUNPATH is not, `$ORIGIN` is per-object). An object that has RUNPATH searches no RPATH,
   neither its own nor one it inherits. A name that an object loaded earlier already carries,
   as the name it was needed by or as its `DT_SONAME`, resolves to that object with no search,
   as `ld.so` does. A library found through a symlink expands `$ORIGIN` to the directory that
   holds the symlink, as `ld.so` does, and stages from its real file. Each RPATH or RUNPATH
   string is a `:` list, and its entries are searched in order. A file of another ELF class or
   machine than the binary, such as a 32-bit copy in `lib` ahead of the 64-bit one in `lib64`,
   is skipped and the search goes on, as `ld.so` skips it. When every copy is of another arch,
   or the binary names the file by path, that file still stages, and a warning says the image
   cannot load it. An empty entry means the directory the program starts in.
   A build cannot know that directory, so Scratchsmith does not search an empty entry. If the
   split entries miss, a string that holds `:` is also tried whole as one directory, before the
   default directories. The loader finds a `DT_NEEDED` library there only through the image's
   `ld.so.cache`. If `ldconfig` does not cache the library under the needed name, Scratchsmith
   does not take it. The name must start with `lib` or `ld-` and hold `.so`, or start with
   `ld.so.` or `ld64.so.`. The library's own soname must be that name, or absent. An `--include`
   file in that directory stages with no such check. Three kinds of entry are searched here as
   they always were, though `ld.so` does not search them: a wholly empty string (read as
   `$ORIGIN`), a relative entry (read against the object's directory, where `ld.so` reads it
   against the working directory), and a name glued to a token, such as `$ORIGINX` or
   `$ORIGIN_x` (expanded, where `ld.so` keeps it literal). A library found only through such an
   entry loads from the image's `ld.so.cache`, if `ldconfig` caches it under the needed name by
   the rule above. `pack` prints one note on stderr for the entry, and the note names any
   library that the cache does not list, which the image then cannot load. On x86_64,
   `$PLATFORM` is read as `x86_64`. glibc reads it as `haswell` or `xeon_phi` on some Intel CPUs,
   but those copies are optimized builds that not every CPU can run, so they never stage. A
   library missing as `x86_64` but present under such a name gets a hint, and a library that
   ships while `ld.so` on such a CPU would load such a copy gets a note on stderr. `$LIB` takes
   the value the glibc in the host root uses, read from the directory where the first
   `libc.so.6` of the binary's arch sits, without a leading `usr/`: `lib/x86_64-linux-gnu` on
   Debian and Ubuntu, `lib64` on Fedora, `lib` on Arch. When that value is not `lib64` (`lib`
   for a 32-bit binary), that old fixed value is searched next, so a library found there before
   still resolves. A string that holds `:`, tried whole, uses the glibc value only. With no such
   `libc.so.6`, the old value is the only one. Scratchsmith never
   scrapes the host's `ldd`, `ld.so.cache`, or `LD_LIBRARY_PATH`, so the result is deterministic.
2. **Stage**: copy the interpreter to its verbatim path, mirror the libraries, recreate
   versioned-soname symlinks, regenerate `ld.so.cache`, and add the glibc NSS pieces.
3. **Assemble**: build a non-root image with reproducible layers (sorted entries, zeroed
   mtime/uid/gid). The uncompressed `diff_id` and the gzip layer digest are computed
   separately, which avoids the classic unpullable-image bug.

## Stability

Scratchsmith follows [Semantic Versioning](https://semver.org/). As of **1.0**, these surfaces are a
stable contract. A breaking change to any of them requires a new major version:

- **CLI flags**: the names and meaning of `pack` / `lint` / `doctor` / `index` / `graph` / `diff` /
  `unpack` flags, and the top-level `--completions` and `--verbose`. New flags arrive in minor
  releases. A removed or renamed flag, or a changed default, is a major change.
- **`scratchsmith.toml`**: the configuration keys and their types (the [Configuration](configuration.md) reference).
- **`--format json`**: the field names and types of the `pack`, `index`, `graph`, `diff`, and `unpack`
  reports (the schema CI gates consume). Each is pinned by a golden test, so a change is always deliberate.
- **Exit codes**: `0` on success. `2` on a usage error: an argument-parse error, or a command line
  that scratchsmith refuses after the parse, such as `--watch --format json` or `pack` with no
  binary. `1` on any other failure, such as a failed pack. Before 2.0.0, a refusal made after the
  parse exited `1`.
  For `scratchsmith.toml` the same rule holds. A value that parses and is then refused exits `2`,
  for example a `label` with no `=`. A file that cannot be read or parsed exits `1`, for example a
  value of the wrong type or an unknown key. A nested `[profile.a.profile.b]` table is refused
  when the file loads, so it exits `1` too.

**Not** frozen (these can change in any release): human-readable text and warning wording, log
output, `doctor`'s exact phrasing, the Rust **library API**, and the exact bytes of the produced
image. The crate's `pub` items exist for its own tests, not as a supported API. Layers stay
reproducible for identical inputs, but that is a property, not a frozen API.

**[COMPATIBILITY.md](https://github.com/schubydoo/scratchsmith/blob/main/COMPATIBILITY.md)** covers
how the contract changes over time. It describes the deprecation cycle (keep it working, warn on
stderr, remove only in the next major), and how a test guards each surface.
