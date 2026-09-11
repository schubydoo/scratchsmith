# Fuzzing

Scratchsmith fuzzes every entry point that parses untrusted external bytes. The `fuzz/`
crate is a detached workspace the main build never compiles. Run a target with cargo-fuzz on
nightly:

```sh
cargo +nightly fuzz run <target>
```

## Targets

| Target | Entry point | What it reaches |
|---|---|---|
| `parse_elf_info` | `resolver::parse_elf_info` | ELF header and dynamic-section parse (goblin). |
| `analyze_hardening` | `lint::hardening_from_bytes` | ELF hardening read (PIE, RELRO, NX, canary, fortify). |
| `resolve_graph` | `resolver::resolve_with` | `ld.so` search: RPATH, RUNPATH, `$ORIGIN`, soname lookup. Structured input. |
| `unpack` | `unpack::run` | The outer OCI-archive parse (tar, gzip, JSON) on raw bytes. |
| `unpack_structured` | `unpack::run` | Layer application, whiteout deletion and its symlink containment, digest checks, media dispatch. Structured input. |
| `registry_parse` | `registry::parse_child_manifest`, `parse_child_config`, `select_token` | Registry manifest, config blob, and token-response JSON parse. |

The `unpack` target feeds raw bytes, which rarely form a valid archive, so it covers the
outer parse. The `unpack_structured` target assembles a real OCI-layout archive from
`Arbitrary` layers, so it reaches the layer and whiteout code the raw target cannot. `tar`
refuses to write a `..` entry, so neither builder reaches the escaping-entry bail in
`unpack::run`. The unit tests cover that path instead. Keep both targets.

## Seeds

A target whose entry point parses a concrete format starts from a seed corpus. The
`Arbitrary`-driven targets (`resolve_graph`, `unpack_structured`) synthesize their own
structure, so they take no seed. `.clusterfuzzlite/build.sh` generates the seeds in CI, and
they are not committed:

- `parse_elf_info` and `analyze_hardening`: a real dynamic executable plus link-variant ELFs
  (RPATH, RUNPATH with `$ORIGIN`, a shared object, a static PIE, and a full-RELRO build).
- `unpack`: a real OCI-layout archive whose blob digests match.
- `registry_parse`: a valid child manifest, config blob, and token response.

`fuzz/corpus/` is gitignored, and ClusterFuzzLite persists the accumulated corpus in the
`scratchsmith-fuzz-corpus` repo. To seed a local run, copy inputs into the target's corpus
first:

```sh
mkdir -p fuzz/corpus/parse_elf_info
cp /usr/bin/id fuzz/corpus/parse_elf_info/
cargo +nightly fuzz run parse_elf_info -- -max_total_time=60
```

## Coverage reports

There are two coverage views: the weekly published report and a local replay.

The weekly `cflite_cron` run builds an HTML report over the whole stored corpus, across every
target. The report lists every linked file. Rust links each crate into the fuzzer, so the
crates, the C dependencies, and the toolchain all appear next to our source. ClusterFuzzLite
blanks `COVERAGE_EXTRA_ARGS` before it runs the coverage step, so there is no in-pipeline hook
to narrow the report to `src/`. The corpus repo is private, so GitHub Pages cannot serve the
report. The run uploads it as the `fuzz-coverage-report` artifact instead. To read it, open
the latest `ClusterFuzzLite cron` run, download the artifact, unzip it, and open `index.html`.

For a view of only `src/`, use the local replay. It needs no ClusterFuzzLite run, but it
covers only the byte-in targets. `cargo llvm-cov` excludes dependencies by default. Grow each
corpus first, then read it:

```sh
cargo +nightly fuzz run parse_elf_info -- -max_total_time=60
cargo +nightly fuzz run unpack -- -max_total_time=60
cargo llvm-cov --test fuzz_corpus_replay -- --ignored
```

`tests/fuzz_corpus_replay.rs` replays the byte-in corpora from `fuzz/corpus/`. It is
`#[ignore]`d, so a normal `cargo test` and CI skip it. The `resolve_graph` and
`unpack_structured` targets take structured input, so the local replay skips them. The weekly
report covers them, because it replays every target's stored corpus.

## Checking it compiles

The required `fuzz harness check` CI job type-checks this crate, so an API change that breaks
a target fails a required check. Run the same command locally:

```sh
RUSTFLAGS="-D warnings" cargo check --manifest-path fuzz/Cargo.toml
```
