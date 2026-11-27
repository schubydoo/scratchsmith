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
   `$PLATFORM` is read as `x86_64`, and on aarch64 as `aarch64`. On any other architecture the
   token has no value, and a search path that holds it fails the pack wherever the loader
   would search it. glibc reads it as `haswell` or `xeon_phi` on some Intel CPUs,
   but those copies are optimized builds that not every CPU can run, so they never stage. A
   library missing as `x86_64` but present under such a name gets a hint, and a library that
   ships while `ld.so` on such a CPU would load such a copy gets a note on stderr. `$LIB` takes
   the value the glibc in the host root uses, read from the directory where the first
   `libc.so.6` of the binary's arch sits, without a leading `usr/`: `lib/x86_64-linux-gnu` on
   Debian and Ubuntu, `lib64` on Fedora, `lib` on Arch. When that value is not `lib64` (`lib`
   for a 32-bit binary), that old fixed value is searched next, so a library found there before
   still resolves. `ld.so` does not search that old value, so `pack` prints a note on stderr for
   a library found only there: at run time, only the image's `ld.so.cache` can find it. A
   string that holds `:`, tried whole, uses the glibc value only. With no such `libc.so.6`, the
   old value is the only one. Scratchsmith never scrapes the host's `ldd`, `ld.so.cache`, or
   `LD_LIBRARY_PATH`, so the result is deterministic.
2. **Stage**: copy the interpreter to its verbatim path (another path to the loader becomes a
   relative symlink to that copy), mirror the libraries, recreate versioned-soname symlinks,
   regenerate `ld.so.cache`, and add the glibc NSS pieces. A musl binary gets no cache and no
   NSS (see [The musl backend](#the-musl-backend)).
3. **Assemble**: build a non-root image with reproducible layers (sorted entries, zeroed
   mtime/uid/gid). The uncompressed `diff_id` and the gzip layer digest are computed
   separately, which avoids the classic unpullable-image bug.

## The musl backend

The binary's program interpreter (`PT_INTERP`) picks the rules. A loader named `ld-musl-*`
selects musl's rules for the whole graph, and any other loader selects the glibc rules above,
which do not change. musl's loader (1.2.5) differs from glibc's in these ways, and Scratchsmith
copies each one:

1. **No cache.** musl has no `ld.so.cache` and no `ldconfig`, so `pack` writes neither and never
   runs `ldconfig`. musl opens a library only at the path its search found. When that path is
   a link into another directory, or passes through a directory link, the image gets a link
   at that path to the staged file.
2. **libc is the loader.** A needed name of `lib` plus `c.`, `pthread.`, `rt.`, `m.`, `dl.`,
   `util.` or `xnet.`, such as `libc.so`, `libc.musl-x86_64.so.1` or `libm.so`, is the loader
   itself, found with no search. So is a name equal to the `PT_INTERP` string.
3. **Search order.** A name with no `/` matches an object already loaded under that name first.
   Then come the search path of the object that needs it, of the object that needed that one,
   and so on up to the program, then the system path.
4. **RPATH and RUNPATH are one value.** RUNPATH wins when both are set, and either one is
   inherited by every dependency below it.
5. **Only `$ORIGIN` expands.** A search path that holds any other `$` token, such as `$LIB`,
   is dropped whole for that object, and `pack` prints a note.
6. **The system path** comes from `<prefix>/etc/ld-musl-<arch>.path` in the host root, split on
   `:` and on newlines. The prefix is the `PT_INTERP` path less its last two parts. With no such
   file, it is `/lib:/usr/local/lib:/usr/lib`. When a library came from a directory outside
   those defaults, the image gets its own path file that lists those directories and the
   defaults.
7. **"Already loaded" goes by file name.** musl never reads `DT_SONAME`. A name matches an
   object found under the same file name, or the same file by device and inode.
8. **A glibc libc is not loaded.** musl takes a library that defines `__libc_start_main` and
   `stdin` for its own libc. Scratchsmith fails the pack on a glibc libc in a musl graph, and
   maps a copy of musl's libc to the loader.

musl has no NSS: it reads `/etc/passwd`, `/etc/group`, `/etc/hosts` and `/etc/resolv.conf`
directly. A musl image always gets the minimal `/etc/passwd` and `/etc/group`, and no
`nsswitch.conf` or NSS module. One image has one libc, so an `--add-binary` program of the other
libc fails the pack.

## Stability

Scratchsmith follows [Semantic Versioning](https://semver.org/). As of **1.0**, these surfaces are a
stable contract. A breaking change to any of them requires a new major version:

- **CLI flags**: the names and meaning of `pack` / `lint` / `doctor` / `index` / `graph` / `diff` /
  `unpack` flags, and the top-level `--completions` and `--verbose`. New flags arrive in minor
  releases. A removed or renamed flag, or a changed default, is a major change.
- **`scratchsmith.toml`**: the configuration keys and their types (the [Configuration](configuration.md) reference).
- **`--format json`**: the field names and types of the `pack`, `index`, `graph`, `diff`, `unpack`,
  and `lint` reports (the schema CI gates consume). Each is pinned by a golden test, so a change is always deliberate.
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
