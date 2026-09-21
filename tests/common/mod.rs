//! Helpers shared by the integration tests.
//!
//! Each file under `tests/` compiles as its OWN crate, so anything they share has to live in a
//! module they each declare with `mod common;`. `tests/fixtures.rs` is a test file despite its
//! name, not a shared module, which is why these helpers had drifted into one copy per crate:
//! `walk_contains` twice byte-for-byte, `cc_available` twice, `small_fixture` twice with two
//! different return types.
//!
//! Not every helper is used by every crate, so `#![allow(dead_code)]` is load-bearing here: a
//! helper no crate calls is dead code in that crate, and `-D warnings` would otherwise fail the
//! build.
#![allow(dead_code)]

use std::path::Path;
use std::process::Command;

/// A tiny dynamic-glibc binary to pack in tests that exercise delivery or config rather than
/// the binary itself.
///
/// `/usr/bin/id` is ~50 KB and packs almost instantly, where packing the ~130 MB debug binary
/// dominated their runtime (30-45s each in CI). It is dynamically linked against glibc,
/// exercises the NSS staging, and prints a checkable `uid=`.
///
/// `None` when absent, so a caller skips rather than panicking on a minimal host. The one
/// dogfood test still packs scratchsmith itself, to prove the real binary works.
pub fn small_fixture() -> Option<&'static Path> {
    ["/usr/bin/id", "/bin/id"]
        .into_iter()
        .map(Path::new)
        .find(|p| p.exists())
}

/// `small_fixture` as a `&str`, for building argv.
///
/// A second accessor rather than a second fixture: the candidate paths stay defined once, so
/// the two crates that want different types cannot drift apart on WHICH binary they pack.
/// `to_str` cannot return `None` here, because the candidates are ASCII literals.
pub fn small_fixture_str() -> Option<&'static str> {
    small_fixture().and_then(Path::to_str)
}

/// Is a C compiler on PATH? The fixture builders need one to compile real ELFs at test time.
pub fn cc_available() -> bool {
    tool_available("cc")
}

/// Is `strip` on PATH? `stage`'s strip pass needs it.
pub fn strip_available() -> bool {
    tool_available("strip")
}

/// Is `upx` on PATH? The compression tests need it.
pub fn upx_available() -> bool {
    tool_available("upx")
}

/// Is `syft` on PATH? `syft` answers a bare `version` subcommand, not `--version`.
pub fn syft_available() -> bool {
    tool_runs("syft", &["version"])
}

/// Is `grype` on PATH? Same bare `version` subcommand as `syft`.
pub fn grype_available() -> bool {
    tool_runs("grype", &["version"])
}

/// Is a usable Docker daemon reachable? `docker info` rather than `docker --version`, because
/// the client can be installed with no daemon behind it.
pub fn docker_available() -> bool {
    tool_runs("docker", &["info"])
}

/// Does `root` contain a file named `name`, at any depth?
///
/// An unreadable directory reads as "not here" rather than an error: callers use this to assert
/// a file IS present, so the false answer already fails them with a useful message.
pub fn walk_contains(root: &Path, name: &str) -> bool {
    let Ok(entries) = std::fs::read_dir(root) else {
        return false;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if walk_contains(&path, name) {
                return true;
            }
        } else if path.file_name().is_some_and(|n| n == name) {
            return true;
        }
    }
    false
}

/// Does `tool` answer `--version`? The generic probe, for a tool with no named helper here.
pub fn tool_available(tool: &str) -> bool {
    tool_runs(tool, &["--version"])
}

// Shared by the tool probes above: a tool counts as present only when it RUNS successfully,
// not merely when the binary exists.
fn tool_runs(bin: &str, args: &[&str]) -> bool {
    Command::new(bin)
        .args(args)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Report that a test cannot run, for a thing the CI workflow guarantees. Panics under `CI`.
///
/// nextest records an early `return` as a **pass**, so a runner that loses Docker or `cc`
/// reports a green suite having run nothing. Measured against CI run 35544425984, the workflow
/// guarantees six:
///
/// - `cc`, `strip` and `/usr/bin/id` ship on `ubuntu-latest`.
/// - `getent` ships in `libc-bin`, which is `Essential: yes` — the same package as `ldconfig`,
///   which `CONTRIBUTING.md` already names as the suite's one hard prerequisite.
/// - `docker info` answers on the runner.
/// - `ci.yml` installs `upx-ucl` for the test and coverage jobs, which are the only two jobs
///   that run the suite.
///
/// A miss is therefore a broken runner rather than a host to tolerate.
///
/// `reason` is the text that follows `skipping: `, so each call site keeps its own wording.
#[track_caller]
pub fn skip_required(reason: &str) {
    assert!(
        !in_ci(),
        "{reason} — and CI is set. The workflow guarantees this, so a missing one is a broken \
         runner, not a host to tolerate. nextest would otherwise record this test as passed."
    );
    eprintln!("skipping: {reason}");
}

/// Report that a test cannot run, for a thing CI does not guarantee. Skips everywhere.
///
/// Three shapes:
///
/// - **Absent on the runner.** `musl-gcc` and `tini` are absent on `ubuntu-latest` and no
///   workflow step adds them, proven by CI run 35544425984: both gated tests returned in 0.05s
///   or less while their neighbors took seconds. The host locale sources are the same, at
///   0.029s.
/// - **Needs the network or the host's own data at test time.** The `registry:2` pull. A miss
///   there is an outage, not a broken runner.
/// - **The inverse gate.** `init_without_tini_fails_clearly` skips because tini IS present. The
///   test proves the failure path, so it runs only where the tool is missing.
pub fn skip_optional(reason: &str) {
    eprintln!("skipping: {reason}");
}

// GitHub Actions sets CI=true. `SCRATCHSMITH_NO_CI_GATE` is the documented escape hatch
// (`CONTRIBUTING.md`), for a machine that has CI set for an unrelated reason.
//
// Both go through one value test, because presence is wrong in BOTH directions. `CI=false` is a
// deliberate opt-out in several toolchains, so presence would hand someone the strict gate they
// were avoiding. An empty `SCRATCHSMITH_NO_CI_GATE`, which is what a workflow writes for an
// unset input, would turn the gate off with no signal at all, quietly re-opening the hole this
// module exists to close.
fn in_ci() -> bool {
    env_truthy("CI") && !env_truthy("SCRATCHSMITH_NO_CI_GATE")
}

/// Is `name` set to something other than an opt-out word? Unset, empty, `0`, `false`, `no` and
/// `off` are all false, in any case and ignoring surrounding space.
fn env_truthy(name: &str) -> bool {
    match std::env::var(name) {
        Ok(value) => !matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "" | "0" | "false" | "no" | "off"
        ),
        Err(_) => false,
    }
}
