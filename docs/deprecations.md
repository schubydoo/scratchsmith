# Deprecations

Scratchsmith keeps the version 1.0 contract in
[COMPATIBILITY.md](https://github.com/schubydoo/scratchsmith/blob/main/COMPATIBILITY.md).
Nothing on that contract disappears without notice. This page lists everything on the way out,
and what you write instead.

This page has three lists, because three different things change in a major version.

A deprecated input shape still works. Scratchsmith accepts it, prints one warning line to
standard error, and exits with the same code as before. The next major version refuses it.

A tolerance is different. Scratchsmith accepts input today that it cannot use in full, and the
result can be an image with a part absent. The next major version reports it as an error. Each
tolerance prints one warning line to standard error, and the exit code stays the same.

A changing default is the third. The input stays valid, and the next major version gives it a
different result. Scratchsmith prints one warning line to standard error where the result will
change, and the exit code stays the same.

## Deprecated input shapes

| Input | Deprecated in | Removed in | Write this instead |
|---|---|---|---|
| `--label NAME` with no `=` | 1.5.0 | 2.0.0 | `--label NAME=value` |
| `--env NAME` with no `=` | 1.5.0 | 2.0.0 | `--env NAME=value` |
| A nested `[profile.a.profile.b]` table | 1.5.0 | 2.0.0 | A top-level `[profile.b]` table |

### A label or an environment variable with no equals sign

`--label` and `--env` take a `NAME=value` pair. Scratchsmith accepts a bare name.

A bare `--label build` writes the label `build` with an empty value. That is legal in an image
configuration, and it is almost never what you meant. A bare `--env build` is worse: the OCI image
specification defines `Env` as a list of `KEY=VALUE` strings, so an entry with no `=` is not a
valid environment variable. A runtime can drop it, or pass it on as a name with no value.

A bare `--env PATH` is worse than a stray entry. Scratchsmith keys each entry on the text before
the first `=`, so `PATH` matches the default `PATH` entry and replaces it. The image then ships
with no usable `PATH` at all.

The same applies to the `label` and `env` keys in `scratchsmith.toml`, which take the same
strings.

Add the `=` and the value you meant:

```console
$ scratchsmith pack --label build=ci --env LOG_LEVEL=info ./myapp
```

To set an empty value on purpose, write the `=` and stop there: `--label build=`.

### A nested profile table

A profile is a `[profile.<name>]` table that layers over the base configuration. A profile can
itself contain a `[profile.<name>]` table, because a profile has the same shape as the base
configuration. Scratchsmith parses `[profile.a.profile.b]` and then drops it. No `--profile`
value reaches it, so the keys inside it never apply.

Move the inner table up to the top level:

Before. The keys under `profile.release.profile.signed` never apply:

```toml
[profile.release]
sign = true

[profile.release.profile.signed]
push = "ghcr.io/me/app:latest"
```

After. `--profile signed` now reaches them:

```toml
[profile.release]
sign = true

[profile.signed]
sign = true
push = "ghcr.io/me/app:latest"
```

Profiles do not inherit from each other, so repeat the keys the inner table relied on.

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
| A library that starts like an ELF and cannot be parsed | 1.6.0 | 2.0.0 | Replace the damaged file |
| A program interpreter that starts like an ELF and cannot be parsed | 1.8.0 | 2.0.0 | Replace the damaged file |
| `$PLATFORM` in a search path, on an architecture with no value for it | 1.6.0 | 2.0.0 | Write the directory name in the path |
| A library found only through an inherited `RPATH`, by an object that has `RUNPATH` | 1.6.0 | 2.0.0 | Give that object the directory in its own `RUNPATH` |
| `--no-build` into an output directory that is not empty | 1.6.0 | 2.0.0 | Use a new directory, or empty it first |

The first four warnings come from `pack` and from `graph`, because both resolve the same
dependency tree. The last one comes from `pack` only.

### A library that cannot be parsed

Scratchsmith reads each library that the binary needs, and then resolves the libraries that
library needs in turn. A file that you name with `--include` and that is not an ELF at all has
no dependencies, so scratchsmith stages it and continues. That stays true in 2.0.

A truncated or corrupt library is a different case. The file starts with the ELF signature, and
scratchsmith cannot read its list of dependencies. Today scratchsmith stages the damaged file
and resolves nothing below it. The image can then ship without libraries that the program needs
at run time, and the pack still exits `0`.

Replace the file with an intact copy. Reinstall the package that owns it, or rebuild it.

### `$PLATFORM` with no value

A library search path is an `RPATH` or a `RUNPATH` entry in the binary, or in a library that the
binary needs. It can contain the token `$PLATFORM`, and the loader replaces that token with the
name of the processor type. Scratchsmith knows that name for `x86_64` and `aarch64` only.

On any other architecture, scratchsmith removes the token and searches what is left. A path
such as `/opt/app/lib/$PLATFORM` becomes `/opt/app/lib/`, which is the parent directory. A
library with the same name in that directory then ships in place of the correct one.

The warning names the file that holds the search path. When you link that file, write the
directory name in the search path and do not use the token:

```console
$ cc -Wl,-rpath,/opt/app/lib/riscv64 -o myapp main.c
```

### A library found only through an inherited `RPATH`

A binary can list directories where the loader looks for its libraries. There are two kinds of
list. An `RPATH` is inherited: a library that the program loads also searches the program's
`RPATH`. A `RUNPATH` is not inherited.

The loader has one more rule. A library that has its own `RUNPATH` does not search any inherited
`RPATH` for the libraries that it needs.

Earlier versions of scratchsmith did not apply that rule. Scratchsmith now searches the way the
loader does. If that search finds the library, scratchsmith stages that copy, which is the copy
that the program uses on the host.

If that search finds nothing, scratchsmith falls back to the old search, stages what it finds,
and prints the warning. The copy that it stages is not the copy that the loader uses. On most
hosts the loader finds no copy at all, and the program does not start there. The image can
still run, because the loader cache in the image knows where the file is. Scratchsmith 2.0
reports the library as missing.

To fix it, link the library that needs the file with a `RUNPATH` that holds the directory:

```console
$ cc -shared -fPIC -Wl,--enable-new-dtags -Wl,-rpath,/opt/app/lib -o libmid.so mid.c -lleaf
```

### An output directory that is not empty

`pack --no-build --output <dir>` stages the files of the image into a directory and builds no
image. Scratchsmith does not empty that directory first. A second pack into the same directory
merges with the files from the first.

A file that the second pack stages replaces the old copy. A file that the second pack does not
stage stays in the directory. For example, pack once with `--ca-certs` and once without it, and
the certificate file is still there. The directory then holds more than the flags describe, and
an SBOM or a scan of it includes the old file.

One case goes the other way. Pack once with `--packages image`, and the package records are in
the directory. Pack again with `--packages sbom --sbom`, and scratchsmith removes those records
after the SBOM run, because that output never leaves them in the tree. `--packages sbom` on its
own stages no records and removes none, because nothing reads the tree.

Two flags stop a second pack. `--add-file` and `--locale` do not replace a file that is already
in the directory, so the pack ends with an error.

Scratchsmith 2.0 refuses a directory that is not empty. Give each pack a new directory, or
remove the old one first:

```console
$ rm -rf ./rootfs
$ scratchsmith pack --no-build --output ./rootfs ./app
```

## Defaults changing in 2.0

| Setting | Today | In 2.0 | Warns since | Keep today's result |
|---|---|---|---|---|
| `--packages` (the `packages` key) with no value | `report` | `report,sbom` | 1.9.0 | `--packages report` |

The warning comes from `pack` only.

### The `--packages` default adds `sbom`

`--packages` decides where scratchsmith records the distribution packages that own the bundled
files. Today the default is `report` alone. Then `--sbom` and `--scan` see a bare tree with no
package database, so the SBOM names few of the libraries in the image.

In 2.0 the default adds `sbom`. The SBOM and the scan then see the packages, for example glibc
and openssl. A `--scan-fail-on` gate can then report findings in those packages, and a pack that
passes the gate today can fail it after the upgrade.

The warning appears only where the result changes. That is a pack that runs `--sbom` or
`--scan` on a host with a dpkg or rpm database. It also needs no `--packages` value on the
command line and no `packages` key in `scratchsmith.toml`. An empty list, `packages = []`, counts
as no value, because 2.0 gives it the new default too. Any value that names an output stops the
warning.

To keep today's result, set the value:

```console
$ scratchsmith pack --sbom --packages report ./app
```

In `scratchsmith.toml`, write `packages = ["report"]`. To take the 2.0 default now, set
`--packages report,sbom`.
