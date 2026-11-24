//! The two ways a test may skip, shared by the library's unit tests and the integration tests.
//!
//! `src/lib.rs` declares this module under `cfg(test)`, and `tests/common` includes the same
//! file by path, so both kinds of test skip the same way. CI rejects a bare
//! `eprintln!("skipping …")` anywhere in `src/` or `tests/`, which leaves these two as the only
//! ways to skip.
#![allow(dead_code)]

/// Report that a test cannot run, for a thing the CI workflow guarantees. Panics under `CI`.
///
/// nextest records an early `return` as a **pass**, so a runner that loses Docker or `cc`
/// reports a green suite having run nothing. Measured against CI run 35544425984, the workflow
/// guarantees the first seven below. The rest came later:
///
/// - `cc`, `strip` and `/usr/bin/id` ship on `ubuntu-latest`.
/// - `getent` ships in `libc-bin`, which is `Essential: yes` — the same package as `ldconfig`,
///   which `CONTRIBUTING.md` already names as the suite's one hard prerequisite.
/// - `docker info` answers on the runner.
/// - `ci.yml` installs `upx-ucl` and `syft` for the test and coverage jobs, which are the
///   only two jobs that run the suite.
/// - `ci.yml` allows unprivileged user namespaces in those two jobs, so `unshare -r` works for
///   `tests/differential.rs`.
/// - A dpkg database (`dpkg-query` and `/var/lib/dpkg/status`) ships on `ubuntu-latest`, which
///   both suite jobs use. The `--packages` tests read it.
/// - `localedef` ships in `libc-bin`, the same package as `getent`.
/// - `mkfifo` ships in `coreutils`, which is `Essential: yes`.
/// - Both suite jobs run as the runner's non-root user, so a directory with mode `000` is
///   unreadable.
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
/// - **Absent on the runner.** `musl-gcc` and `tini` are absent on `ubuntu-latest`, proven by
///   CI run 35544425984: both gated tests returned in 0.05s or less while their neighbors took
///   seconds. The host locale sources are the same, at 0.029s. Since then the coverage job
///   installs tini and the test job does not, so each job runs one of the two tini tests.
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
