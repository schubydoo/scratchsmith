# Deprecations

Scratchsmith keeps its contract in
[COMPATIBILITY.md](https://github.com/schubydoo/scratchsmith/blob/main/COMPATIBILITY.md).
Only a major version can change it, and nothing on it disappears without notice. This page lists everything on the way out,
and what you write instead.

This page has one list for each kind of change. Two kinds change only in a major version:
deprecated input shapes and tolerances. Refused input is a third kind, because a minor release
can refuse input that is the attack itself. The last list, Removed in 2.0.0, shows what version
2.0.0 changed after its deprecation cycle ended. Most inputs there now fail, and one gets a new
default. It also shows five changes in 2.0.0 with no warning first:

- an exit code
- an output directory that cannot be listed
- an `--include` file that is not a regular file
- a program or a library at a package record path
- a `DT_NEEDED` library in a directory whose name holds `:`

A deprecated input shape still works. Scratchsmith accepts it, prints one warning line to
standard error, and exits with the same code as before. The next major version refuses it.

A tolerance is different. Scratchsmith accepts input today that it cannot use in full, and the
result can be an image with a part absent. The next major version reports it as an error. Each
tolerance prints one warning line to standard error, and the exit code stays the same.

## Deprecated input shapes

Version 2.0.0 removed the 1.x deprecations, and the list [Removed in 2.0.0](#removed-in-200)
names each one.

| Input | Warned since | In 3.0 | Write this instead |
|---|---|---|---|
| A digest in the `--push` reference (or the `push` key), such as `ghcr.io/owner/app@sha256:…` | 2.1.0 | Refused | A tag, such as `ghcr.io/owner/app:1.0` |
| A `diff` argument that is not a directory, such as `diff a.tar b.tar` | 2.1.0 | Refused | Two rootfs directories, such as from `pack --no-build --output` or `unpack` |

A registry stores a manifest only under that manifest's own digest. A push to any other digest
fails at the registry, and nobody knows the right digest before the image is built. With
`--sign`, scratchsmith already signs the image by the digest that the push stored. Through
2.0.3, a push to a digest could also crash scratchsmith when the registry answered without a
`Location` header, as AWS ECR does. That crash is fixed, and the push still goes to the digest.

`diff` compares two directory trees. It reads a file argument as an empty tree, so
`diff --exit-code a.tar b.tar` prints no changes and exits 0 for two different archives. Through
2.0.3 it did so with no warning. To compare two OCI archives, `unpack` each one into a directory
and compare those.

## Refused without a deprecation cycle

Some input was the attack itself. COMPATIBILITY.md allows a minor or patch release to refuse
such input with no deprecation cycle, and this section lists each case.

### A library that is not a regular file

A `DT_NEEDED` name can resolve to a FIFO, a device, or a socket. Through 1.7.2, the read of a
FIFO waited forever for a writer, or read a writer's stream with no end. Now `pack` and `graph`
refuse such a library before they open it, and exit `1`. No library is a FIFO, so no working
image depends on one.

A FIFO that you name with `--include` is still read, so `graph --include <(cat libplugin.so)`
works. `pack` reads it too, but then it refuses to stage it, because it is not a regular file, and
exits `1`. Both commands open the FIFO and wait for a writer, as `cat` does. With no writer they
wait until you stop them, and that is accepted behavior.

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

### A gzip layer of more than one member

A gzip layer can hold several gzip members, one after another, as `cat a.gz b.gz` writes.
Docker reads every member. Through 2.0.0, `unpack` read only the first, so a second member
could carry files that the image installs and the audit never showed.

Now `unpack` reads every member. Bytes after the last member that do not start another member
make `unpack` fail with exit `1`. Docker refuses those bytes too, so no working image has them.

### A layer with data after its end, or cut short

A layer's tar ends with a block of zeros. Through 2.0.0, `unpack` stopped there and ignored what
followed. A reader that skips zero blocks would find entries hidden after it. `unpack` also
deleted a lower layer's files for a layer's whiteouts before it found that the layer was cut
short.

Now `unpack` refuses a layer with any byte other than zero after that block, and exits `1`.
Zeros there are only padding, and still pass. A layer cut short inside an entry fails before
`unpack` writes or deletes any file for that layer. The layers before it are already applied.

### A sparse entry in a layer

A sparse tar entry stores only part of a file, and the reader fills the holes with zeros. A
few header bytes can then claim a file of any size, and fill the disk. Through 2.0.0, `unpack`
wrote such an entry from a layer. It already refused one in the outer archive.

Now `unpack` refuses a sparse entry in a layer, in GNU or PAX form, and exits `1`. It refuses
the layer before it writes any file from it. Docker and BuildKit write layers with Go's tar
library, which cannot write a sparse entry, so no working image has one.

### A malformed PAX record in a layer

A PAX record is a line in a tar header that holds extra details for the next entry, such as a
long name. Through 2.0.0, `unpack` skipped a record that it could not parse, and wrote the
entry anyway.

Now `unpack` refuses a layer with a malformed PAX record, and exits `1`. It refuses the layer
before it writes any file from it, and the error names the entry. Docker's tar reader refuses
such a record too, so no working image has one.

### An image whose layers decompress past 16 GiB in all

Each layer stops at 2 GiB once decompressed, but a manifest can list the same layer many
times. Through 2.0.1, one small gzip layer listed N times decompressed N times, and `unpack`
wrote up to N times 2 GiB to the target.

Now `unpack` refuses an image whose layers hold more than 16 GiB in all once decompressed, and
exits `1`. A layer listed twice counts twice, and an uncompressed layer counts at its own size.
The error names the limit. The layers before the one that crosses it are already applied.

### A whiteout that climbs above the image root

A whiteout marker is a layer entry named `.wh.<name>`, which deletes `<name>` from the layers
below. Through 2.0.2, `unpack` skipped a marker whose path had a `..` part, and applied the rest
of the layer. That missed a marker like `etc/../etc/.wh.keep`, which Docker cleans to
`etc/.wh.keep` and honors, so the unpacked tree kept a file that the image deletes.

Now `unpack` cleans the marker's path as Docker does, and deletes what it names. A rooted path
stops at `/`, so `/../etc/.wh.keep` deletes `etc/keep`. A relative path whose `..` climbs
above the root, such as `../.wh.x`, makes `unpack` refuse the layer and exit `1`. It refuses
the layer before it writes or deletes any file for it. Docker refuses that marker too, so no
working image has one.

### An OCI archive with two `index.json` files

An OCI archive holds one `index.json`, which names the image. A tar file can still hold two
entries with that name, or `index.json` and `./index.json`. Through 2.0.2, `unpack` kept the
last one and said nothing. Another tool that keeps the first would show a different image from
the same archive.

Now `unpack` refuses the archive and exits `1`. The error names the second entry as it is
stored. It refuses before it reads that entry. No OCI layout writer puts two `index.json`
files in one archive, so no working image has one.

### An identity token sent to an `http` realm, or across a redirect

A Docker config can hold a login as an identity token, a refresh token that `--push` and
`index` exchange for an access token at the realm that the registry names. Through 2.0.2, the
exchange posted the refresh token to that realm over plain `http` too, and followed a redirect
from it with the token in the body. A registry, or anyone on the network path, could then read
the refresh token.

Now the realm must be `https`, and a redirect from it is refused, not followed. Either one makes
`--push` or `index` fail with exit `1`. The one exception is an `http` realm on a loopback
address, for a registry at `localhost`, `127.0.0.1` or `::1`, which scratchsmith already
reaches over `http`. Hosted registries such as Docker Hub and GHCR name an `https` realm, and
a local test registry keeps working, so no working push depends on the refused realm.

## Tolerances ending in 2.0

No tolerance is left now. Version 2.0.0 ended the 1.x tolerances, and the list
[Removed in 2.0.0](#removed-in-200) names each one.

## Removed in 2.0.0

| Input | Warned since | Now | Write this instead |
|---|---|---|---|
| A nested `[profile.a.profile.b]` table | 1.5.0 | An error. `pack` exits `1` | A top-level `[profile.b]` table, with the keys it relied on repeated |
| `--label NAME` with no `=` | 1.5.0 | A usage error, exit code 2 | `--label NAME=value`, or `--label NAME=` for an empty value |
| `--env NAME` with no `=` | 1.5.0 | A usage error, exit code 2 | `--env NAME=value`, or `--env NAME=` for an empty value |
| A `label` or `env` entry with no `=` in `scratchsmith.toml` | 1.5.0 | A usage error, exit code 2 | `"NAME=value"`, or `"NAME="` for an empty value |
| A library that starts like an ELF and cannot be parsed | 1.6.0 | An error. `pack` and `graph` exit `1` and name the file. 1.x did not warn for a file that is not a regular file, such as a FIFO named with `--include`. `graph` now fails on it with no earlier warning. `pack` already refused it in 1.x | Replace the damaged file with an intact copy |
| A library found only through an inherited `RPATH`, by an object that has `RUNPATH` | 1.6.0 | Reported as missing, and `pack` and `graph` fail | Give that object the directory in its own `RUNPATH` |
| A command line refused after the parse, such as `--watch --format json` | Not warned | A usage error, exit code 2. 1.x exited 1 | Fix the command line. A script that tests for exactly `1` must also accept `2` |
| `--packages` (the `packages` key) with no value | 1.9.0 | The default is `report,sbom`, so `--sbom` and `--scan` see the packages and a `--scan-fail-on` gate can find more | `--packages report` (or `packages = ["report"]`) for the 1.x result |
| `pack --no-build --output DIR` into a `DIR` that is not empty | 1.6.0 | An error before any file is staged. `pack` exits `1` | A new or empty directory, or `rm -rf DIR` first |
| `pack --no-build --output DIR` into a `DIR` that cannot be listed | Not warned | An error. `pack` exits `1` | A directory that you can read, or a new one |
| `$PLATFORM` in a search path, on an architecture with no value for it | 1.6.0 | An error. `pack` and `graph` exit `1` and name the file that holds the search path | Write the directory name in the path |
| A program interpreter (`PT_INTERP`) that starts like an ELF and cannot be parsed | 1.8.0 | An error. `pack` and `graph` exit `1` and name the file | Replace the damaged loader with an intact copy |
| The program or an `--include` library at a package record path on the host. This applies to an explicit `image` in `--packages`, or an explicit `sbom` with `--sbom` or `--scan` | Not warned | An error. `pack` exits `1` and names the path. 1.x exited 0, and the record replaced the file | Remove `sbom` and `image` from `--packages`, or move the file on the host |
| A `DT_NEEDED` library only in a directory whose name holds `:`, which `ldconfig` does not cache | Not warned | Missing. `pack` and `graph` exit `1`, and a `note:` line names the directory. 1.x exited 0, and the image exited 127 at start. An `--include` file there still stages | Move the library to a directory with no `:` in its name |

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
