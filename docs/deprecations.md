# Deprecations

Scratchsmith keeps the version 1.0 contract in
[COMPATIBILITY.md](https://github.com/schubydoo/scratchsmith/blob/main/COMPATIBILITY.md).
Nothing on that contract disappears without notice. This page lists everything on the way out,
and what you write instead.

This page has one list for each kind of change. Three kinds change only in a major version:
deprecated input shapes, tolerances, and changing defaults. Refused input is a fourth kind,
because a minor release can refuse input that is the attack itself. The last list, Removed in
2.0.0, shows what version 2.0.0 changed after its deprecation cycle ended. Most inputs there now
fail, and one gets a new default. It also shows two changes in 2.0.0 with no warning first: an
exit code, and an output directory that cannot be listed. It says why for each.

A deprecated input shape still works. Scratchsmith accepts it, prints one warning line to
standard error, and exits with the same code as before. The next major version refuses it.

A tolerance is different. Scratchsmith accepts input today that it cannot use in full, and the
result can be an image with a part absent. The next major version reports it as an error. Each
tolerance prints one warning line to standard error, and the exit code stays the same.

## Deprecated input shapes

No input shape is deprecated now. Version 2.0.0 removed the 1.x deprecations, and the list
[Removed in 2.0.0](#removed-in-200) names each one.

## Refused without a deprecation cycle

Some input was the attack itself. COMPATIBILITY.md allows a minor or patch release to refuse
such input with no deprecation cycle, and this section lists each case.

### A library that is not a regular file

A `DT_NEEDED` name can resolve to a FIFO, a device, or a socket. Through 1.7.2, the read of a
FIFO waited forever for a writer, or read a writer's stream with no end. Now `pack` and `graph`
refuse such a library before they open it, and exit `1`. No library is a FIFO, so no working
image depends on one.

### A file that is not an ELF, named by the binary or a library

A `DT_NEEDED` entry in the binary or in a library names a file. The binary's program
interpreter (`PT_INTERP`) names a file too. Through 1.7.2, scratchsmith staged that file, and
it did not check that the file was an ELF. The name can point at any file on the host, such as
`~/.docker/config.json`, and that file shipped in the image.

Now `pack` and `graph` refuse such a file and exit `1`. The loader cannot start a binary that
needs it, so no working image depends on it. A data file that you name with `--include` still
stages. A library deeper in the tree that names the same file then resolves to that staged copy.

### An ELF that the loader cannot load, named by the binary or a library

The same names can point at a host file that is an ELF but not a library, such as a core dump.
Through 1.7.2, scratchsmith staged that file. A core dump holds the memory of a crashed
process, which can include secrets.

Now `pack` and `graph` refuse such a file and exit `1`. A library must be a shared object
(`ET_DYN`). glibc refuses any other type with "cannot dynamically load executable", so no
working image depends on one. A program interpreter must be `ET_DYN` or `ET_EXEC`, because the
kernel loads both.

This check reads the ELF type only. A PIE executable is `ET_DYN` too, so a name that points at
one still stages it. A core dump, an object file (`ET_REL`), and an executable built without
PIE do not. A file that you name with `--include` stages as before. If the binary itself also
names that file, the refusal comes first.

### An archive entry or a piped archive with no size limit

`unpack` holds every blob of an image archive in memory. Through 1.7.2, a large or sparse
archive file let one entry fill memory, and an archive read from a pipe had no total limit.

Now `unpack` refuses an entry larger than 2 GiB plus 2 MiB, and a pipe that yields more than
16 GiB in all, and exits `1`. A gzip layer that decompresses past 2 GiB was already refused, so
an uncompressed layer over 2 GiB is now refused too. An archive file on disk keeps its own size
as the total limit.

There is no way around this limit. `unpack` cannot read a layer over 2 GiB of either type, and
gzipping the layer does not help, because a gzip layer stops at the same limit.

## Tolerances ending in 2.0

| Input | Warns since | Error in | What to do |
|---|---|---|---|
| A program interpreter that starts like an ELF and cannot be parsed | 1.8.0 | 2.0.0 | Replace the damaged file |

This warning comes from `pack` and from `graph`, because both resolve the same dependency tree.

The interpreter warning stays only when no library lists the loader as `DT_NEEDED`. On a usual
glibc sysroot `libc.so.6` lists it, so the dependency walk reads the loader as a library and the
pack fails with the unparsable-ELF error.

## Removed in 2.0.0

| Input | Warned since | Now | Write this instead |
|---|---|---|---|
| A nested `[profile.a.profile.b]` table | 1.5.0 | An error. `pack` exits `1` | A top-level `[profile.b]` table, with the keys it relied on repeated |
| `--label NAME` with no `=` | 1.5.0 | A usage error, exit code 2 | `--label NAME=value`, or `--label NAME=` for an empty value |
| `--env NAME` with no `=` | 1.5.0 | A usage error, exit code 2 | `--env NAME=value` |
| A `label` or `env` entry with no `=` in `scratchsmith.toml` | 1.5.0 | A usage error, exit code 2 | `"NAME=value"` |
| A library that starts like an ELF and cannot be parsed | 1.6.0 | An error. `pack` and `graph` exit `1` and name the file. 1.x did not warn for a file that is not a regular file, such as a FIFO named with `--include`, so that case fails now with no earlier warning | Replace the damaged file with an intact copy |
| A library found only through an inherited `RPATH`, by an object that has `RUNPATH` | 1.6.0 | Reported as missing, and `pack` and `graph` fail | Give that object the directory in its own `RUNPATH` |
| A command line refused after the parse, such as `--watch --format json` | Not warned | A usage error, exit code 2. 1.x exited 1 | Fix the command line. A script that tests for exactly `1` must also accept `2` |
| `--packages` (the `packages` key) with no value | 1.9.0 | The default is `report,sbom`, so `--sbom` and `--scan` see the packages and a `--scan-fail-on` gate can find more | `--packages report` (or `packages = ["report"]`) for the 1.x result |
| `pack --no-build --output DIR` into a `DIR` that is not empty | 1.6.0 | An error before any file is staged. `pack` exits `1` | A new or empty directory, or `rm -rf DIR` first |
| `pack --no-build --output DIR` into a `DIR` that cannot be listed | Not warned | An error. `pack` exits `1` | A directory that you can read, or a new one |
| `$PLATFORM` in a search path, on an architecture with no value for it | 1.6.0 | An error. `pack` and `graph` exit `1` and name the file that holds the search path | Write the directory name in the path |

### A library found only through an inherited `RPATH`

An `RPATH` is inherited: a library that the program loads also searches the program's `RPATH`.
A library that has its own `RUNPATH` does not search any inherited `RPATH` for the libraries
that it needs. Scratchsmith now applies that rule with no fallback, so the library is missing,
as it is for the loader. A `note:` line on stderr names the directory and the library that
needs the file. To fix it, link the library that needs the file with a `RUNPATH` that
holds the directory:

```console
$ cc -shared -fPIC -Wl,--enable-new-dtags -Wl,-rpath,/opt/app/lib -o libmid.so mid.c -lleaf
```

### A command line refused after the parse exits 2

Scratchsmith refuses some command lines only after the parse, because the refusal needs a
second flag or the config. Examples are `--watch --format json`, `pack` with no binary, and one
`--add-file` image path given twice. In 1.x these refusals exited `1`, the code for a failed
pack, and printed no warning about a change. In 2.0.0 they exit `2`, the same code as an
argument-parse error. This change had no deprecation cycle, because the 1.x contract promised
only a non-zero code for these refusals. A script that tests for exactly `1` must also accept
`2`.

### An output directory that cannot be listed

`pack --no-build --output DIR` checks that `DIR` is empty. In 1.x the check skipped a `DIR`
that it had no permission to list, so it printed no warning and packed into it. Version 2.0.0 refuses
that `DIR`, because it cannot prove that the directory is empty. This change had no warning
before 2.0. Give the pack a directory that you can read, or a new one.

### `$PLATFORM` with no value

A library search path is an `RPATH` or a `RUNPATH` entry in the binary, or in a library that the
binary needs. It can contain the token `$PLATFORM`, and the loader replaces that token with the
name of the processor type. Scratchsmith knows that name for `x86_64` and `aarch64` only.

On any other architecture, the token has no value. Through 1.9, scratchsmith removed the token
and searched what was left, so `/opt/app/lib/$PLATFORM` became the parent directory
`/opt/app/lib/`. A library with the same name in that directory then shipped in place of the
correct one. Now `pack` and `graph` stop with exit `1` where 1.x warned, and the error names the
file that holds the search path. A search path that the loader never reads still passes, for
example an `RPATH` in a file that also has `RUNPATH`. When you link that file, write the
directory name in the search path and do not use the token:

```console
$ cc -Wl,-rpath,/opt/app/lib/riscv64 -o myapp main.c
```
