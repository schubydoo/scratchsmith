# Scratchsmith

> **Status: pre-alpha scaffold.** Nothing is functional yet — the CLI parses and
> reports "not yet implemented". Follow the milestones below.

The daemonless supply-chain packager for prebuilt **dynamic** Linux binaries.

Point Scratchsmith at a dynamically linked ELF binary and (once built) get a minimal
`FROM scratch` OCI image — no Docker daemon, no Dockerfile, no static-linking
prerequisite. Aimed at the binaries static linking *can't* help: closed-source or
vendor binaries, and glibc binaries that rely on NSS, `dlopen`, or locale behavior.

Not for greenfield Go/Rust services that can build a static binary and `COPY` it into
scratch — those need no dependency resolver.

## Install

Not yet published. Build from source:

```sh
cargo build --release
```

## Status

| Capability | State |
|------------|-------|
| CLI skeleton (`pack` / `lint` / `doctor`) | scaffolded (stubs) |
| Dependency resolution | not started |
| Scratch image assembly | not started |
| SBOM / signing / hardening lint | not started |

## License

MIT — see [LICENSE](LICENSE).
