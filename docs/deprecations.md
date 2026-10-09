# Deprecations

Scratchsmith keeps the version 1.0 contract in
[COMPATIBILITY.md](https://github.com/schubydoo/scratchsmith/blob/main/COMPATIBILITY.md).
Nothing on that contract disappears without notice. This page lists everything on the way out,
and what you write instead.

This page has two lists, because two different things end in a major version.

A deprecated input shape still works. Scratchsmith accepts it, prints one warning line to
standard error, and exits with the same code as before. The next major version refuses it.

A tolerance is different. Scratchsmith accepts input today that it cannot use in full, and the
result can be an image with a part absent. The next major version reports it as an error. Each
tolerance prints one warning line to standard error, and the exit code stays the same.

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

## Tolerances ending in 2.0

| Input | Warns since | Error in | What to do |
|---|---|---|---|
| A library that starts like an ELF and cannot be parsed | 1.6.0 | 2.0.0 | Replace the damaged file |
| `$PLATFORM` in a search path, on an architecture with no value for it | 1.6.0 | 2.0.0 | Write the directory name in the path |
| A library found only through an inherited `RPATH`, by an object that has `RUNPATH` | 1.6.0 | 2.0.0 | Give that object the directory in its own `RUNPATH` |

The warnings come from `pack` and from `graph`, because both resolve the same dependency tree.

### A library that cannot be parsed

Scratchsmith reads each library that the binary needs, and then resolves the libraries that
library needs in turn. A file that is not an ELF at all has no dependencies, so scratchsmith
stages it and continues. That stays true in 2.0.

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

If that search finds nothing, the program cannot start on the build host. Scratchsmith then
falls back to the old search, stages what it finds, and prints the warning. The image can still
run, because the loader cache in the image knows where the file is. Scratchsmith 2.0 reports the
library as missing.

To fix it, link the library that needs the file with a `RUNPATH` that holds the directory:

```console
$ cc -shared -Wl,-rpath,/opt/app/lib -o libmid.so mid.c -lleaf
```
