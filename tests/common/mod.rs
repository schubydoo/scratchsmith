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

/// The stub `syft` for `fake_tools`: it writes `{}` to the path after `=` in its `-o` argument.
pub const FAKE_SYFT: &str = r#"for a; do case "$a" in *=*) echo '{}' > "${a#*=}";; esac; done"#;

/// A `PATH` whose first directory holds one executable script per `(name, body)`, made under
/// `dir`. The host `PATH` follows, so a fake shadows the real tool and everything else stays.
pub fn fake_tools(dir: &Path, tools: &[(&str, &str)]) -> std::ffi::OsString {
    use std::os::unix::fs::PermissionsExt;
    let bin = dir.join("tools");
    std::fs::create_dir_all(&bin).unwrap();
    for (name, body) in tools {
        let path = bin.join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let mut path = bin.into_os_string();
    if let Some(host) = std::env::var_os("PATH") {
        path.push(":");
        path.push(host);
    }
    path
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

// The skip helpers live in `src/` so that the library's own unit tests can use them too. A path
// include rather than a crate dependency: `src/` keeps the module behind `cfg(test)`, and each
// integration test crate gets its own copy, as with every other helper here.
#[path = "../../src/test_support.rs"]
mod test_support;
// Not every crate calls both, and `dead_code` does not cover an unused re-export.
#[allow(unused_imports)]
pub use test_support::{skip_optional, skip_required};
