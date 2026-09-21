<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/logo-mark-white.svg">
    <img alt="" src="assets/logo-mark-black.svg" width="96">
  </picture>
</p>

# Scratchsmith

**The daemonless supply-chain packager for prebuilt dynamic Linux binaries.**

Point Scratchsmith at a dynamically linked glibc ELF binary and get a minimal `FROM scratch`
OCI image. You need no Dockerfile and no static-linking prerequisite. It resolves the binary's
shared libraries the way `ld.so` does (RPATH/RUNPATH/`$ORIGIN`, the interpreter, versioned
soname symlinks). It stages the glibc pieces nothing else remembers (NSS modules, a working
`nsswitch.conf`, minimal `passwd`/`group`). Then it assembles a **non-root** image with
reproducible layers.

<img src="demo/scratchsmith.svg" alt="Scratchsmith packing a dynamic glibc binary into a minimal FROM scratch image with an SBOM and a smoke-run, then running it">

## Why not just static-link + `FROM scratch`?

If you can rebuild your service as a static binary (`CGO_ENABLED=0`, musl), **do that**. You
need no packer. Scratchsmith is built for the binaries that static linking *cannot* help:

- **Closed-source or vendor binaries** you cannot recompile.
- **glibc binaries** that rely on **NSS**, **`dlopen`**, or **locale** behavior. Static glibc
  breaks these quietly, often only in production.
- Anything where "just rebuild it static" is not on the table.

That is the wedge, and it is not a fence. Scratchsmith **already packs a static binary too**,
because the resolver detects it and stages the single file. When you want an SBOM, a hardening
report, a non-root image, and no Dockerfile, it is equally handy. More:
[Comparison & limitations](comparison.md).

## What works today

<!-- The capability table lives in README.md; mkdocs pulls it in via pymdownx.snippets. -->
--8<-- "README.md:capabilities"

## Next

- [Installation](installation.md): one-line install, packages, release binaries, and completions.
- [Usage](usage.md): pack recipes and daemonless output.
- [GitHub Action](github-action.md): pack in a CI workflow with the composite action.
- [Configuration](configuration.md): the `scratchsmith.toml` key reference and profiles.
- [Verifying releases](verifying.md): cosign signatures, SLSA provenance, and the SBOM.
- [Comparison & limitations](comparison.md): how it compares, and what it does not do.
- [Architecture](architecture.md): how resolve → stage → assemble works, and the 1.0 stability contract.
