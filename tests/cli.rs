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
fn lint_reports_hardening_for_a_real_binary() {
    let out = run(&["lint", "/bin/sh"]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    for field in ["PIE:", "RELRO:", "NX:", "Canary:", "Fortify:"] {
        assert!(stdout.contains(field), "missing {field} in: {stdout}");
    }
}

#[test]
fn pack_oci_archive_writes_the_file() {
    // Exercises the `--oci-archive` sink through the CLI (daemonless — no Docker needed).
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("cli.oci.tar");
    let bin = env!("CARGO_BIN_EXE_scratchsmith");
    let output = run(&["pack", "--oci-archive", out.to_str().unwrap(), bin]);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        std::fs::metadata(&out)
            .map(|m| m.len() > 0)
            .unwrap_or(false),
        "archive not written"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("wrote OCI archive"), "got: {stdout}");
}
