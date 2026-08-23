//! End-to-end checks against the built binary: exit codes and top-level output.
//! These pin the contract Task 1.1 promises (help lists subcommands, version works,
//! stubs fail loudly) independent of the library's internals.

use std::process::{Command, Output};

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_scratchsmith"))
        .args(args)
        .output()
        .expect("failed to run scratchsmith binary")
}

#[test]
fn version_prints_and_exits_zero() {
    let out = run(&["--version"]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.starts_with("scratchsmith "), "got: {stdout}");
}

#[test]
fn help_lists_all_three_subcommands() {
    let out = run(&["--help"]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    for cmd in ["pack", "lint", "doctor"] {
        assert!(stdout.contains(cmd), "help missing `{cmd}`: {stdout}");
    }
}

#[test]
fn no_subcommand_is_a_usage_error() {
    let out = run(&[]);
    assert!(!out.status.success());
    // Clap uses exit code 2 for argument/usage errors.
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn unknown_subcommand_is_a_usage_error() {
    let out = run(&["bogus"]);
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn doctor_exits_zero_and_reports_tools() {
    let out = run(&["doctor"]);
    // doctor always exits 0; missing tools are informational, not failures.
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    // ldconfig is present wherever the tests build, so it should report ok.
    assert!(stdout.contains("ldconfig"), "got: {stdout}");
}

#[test]
fn pack_of_a_missing_binary_fails_cleanly() {
    // A nonexistent path fails at resolution with a non-zero exit and a real message,
    // without touching Docker.
    let out = run(&["pack", "/nonexistent/scratchsmith-xyz"]);
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("scratchsmith-xyz"), "got: {stderr}");
}

#[test]
fn lint_stub_exits_one_and_explains() {
    let out = run(&["lint", "/bin/ls"]);
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("lint: not yet implemented"),
        "got: {stderr}"
    );
}
