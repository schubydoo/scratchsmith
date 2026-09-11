//! Coverage-audit helper (not run by default). Replays each fuzz target's on-disk corpus
//! through its real entry point so `cargo llvm-cov` reports what the fuzzers reach, scoped to
//! our own source (llvm-cov excludes dependencies by default — unlike the ClusterFuzzLite
//! HTML, which lists every linked crate). The tests are `#[ignore]`d so a normal `cargo test`
//! or CI run skips them (a fresh checkout has no `fuzz/corpus`).
//!
//! Grow a corpus, then read it:
//!   cargo +nightly fuzz run parse_elf_info -- -max_total_time=60
//!   cargo llvm-cov --test fuzz_corpus_replay -- --ignored
//!
//! Only the byte-in targets are replayable here; `resolve_graph` and `unpack_structured`
//! take `Arbitrary`-structured input, so measure those with `cargo +nightly fuzz coverage`.

use std::fs;
use std::path::Path;

fn corpus(name: &str) -> Vec<Vec<u8>> {
    fs::read_dir(Path::new("fuzz/corpus").join(name))
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| fs::read(e.path()).ok())
        .collect()
}

#[test]
#[ignore = "coverage audit; needs a grown fuzz/corpus"]
fn replay_parse_elf_info() {
    for b in corpus("parse_elf_info") {
        let _ = scratchsmith::resolver::parse_elf_info(&b);
    }
}

#[test]
#[ignore = "coverage audit; needs a grown fuzz/corpus"]
fn replay_analyze_hardening() {
    for b in corpus("analyze_hardening") {
        let _ = scratchsmith::lint::hardening_from_bytes(&b);
    }
}

#[test]
#[ignore = "coverage audit; needs a grown fuzz/corpus"]
fn replay_unpack() {
    let tmp = tempfile::tempdir().unwrap();
    for (i, b) in corpus("unpack").into_iter().enumerate() {
        let archive = tmp.path().join(format!("a{i}.tar"));
        if fs::write(&archive, &b).is_ok() {
            let _ = scratchsmith::unpack::run(&archive, &tmp.path().join(format!("d{i}")));
        }
    }
}
