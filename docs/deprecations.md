# Deprecations

Scratchsmith keeps the version 1.0 contract in
[COMPATIBILITY.md](https://github.com/schubydoo/scratchsmith/blob/main/COMPATIBILITY.md).
Nothing on that contract disappears without notice. This page lists everything on the way out,
and what you write instead.

This page has two lists, because two different things end in a major version.

A deprecated input shape still works. Scratchsmith accepts it, prints one warning line to
standard error, and exits with the same code as before. The next major version refuses it.

A tolerance is different. Scratchsmith accepts input today that it cannot use, and says nothing.
The next major version reports it as an error. A tolerance is not a deprecation, because there
is no warning to act on yet.

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

This list is empty today.
