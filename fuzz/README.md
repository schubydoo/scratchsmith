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
| `unpack_structured` | `unpack::run` | Layer application, whiteouts, path containment, digest verify, media dispatch. Structured input. |

The `unpack` target feeds raw bytes, which rarely form a valid archive, so it exercises the
outer parse. The `unpack_structured` target assembles a real OCI-layout archive from
`Arbitrary` layers, so it reaches the layer and whiteout logic the raw target cannot. Keep
both.

## Seeds

`parse_elf_info` and `analyze_hardening` parse ELF bytes, and random input rarely forms a
valid ELF, so seed them from a real ELF:

```sh
cargo +nightly fuzz run parse_elf_info fuzz/seeds/elf
cargo +nightly fuzz run analyze_hardening fuzz/seeds/elf
```

`resolve_graph` and `unpack_structured` build their own structured input, so they need no
seed. `fuzz/corpus/` is gitignored (ClusterFuzzLite persists the real corpus in the
`scratchsmith-fuzz-corpus` repo), so committed seeds live in `fuzz/seeds/`.

## Coverage, scoped to our source

The ClusterFuzzLite HTML report lists every dependency, because Rust links each crate into
the fuzzer. For a view of only `src/`, replay a grown corpus under `cargo llvm-cov`,
which excludes dependencies by default. First grow the corpus, then read it:

```sh
cargo +nightly fuzz run parse_elf_info fuzz/seeds/elf -- -max_total_time=60
cargo +nightly fuzz run unpack -- -max_total_time=60
cargo llvm-cov --test fuzz_corpus_replay -- --ignored
```

`tests/fuzz_corpus_replay.rs` replays the byte-in corpora (it is `#[ignore]`d, so a normal
`cargo test` and CI skip it). The `resolve_graph` and `unpack_structured` targets take
structured input, so measure those with `cargo +nightly fuzz coverage <target>`.

## Does it still compile

The required `fuzz harness check` CI job runs `cargo check` on this crate, which catches a
target broken by an API change. Run it locally with:

```sh
cd fuzz && cargo check
```
