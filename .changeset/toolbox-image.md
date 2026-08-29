---
default: minor
---

#### `:toolbox` image — run `pack` inside a container

A new `ghcr.io/schubydoo/scratchsmith:toolbox` image bundles the full `pack` toolchain (ldconfig,
strip, syft, grype, cosign, upx, tini, and the docker CLI) on a Wolfi base, so `scratchsmith pack`
runs *inside* a container — unlike the minimal `FROM scratch` release image, which can only run
`--version`/`lint`/`doctor`. It's cosign-signed and multi-arch, published on release with
`:toolbox` / `:X.Y.Z-toolbox` tags. Prefer the daemonless `--push` / `--oci-archive` sinks in CI;
the default `docker load` sink needs a mounted (root-equivalent) docker socket.
