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

// A tiny dynamic-glibc binary to PACK in the sink/profile tests — they exercise the
// delivery/config logic, not the binary itself. `/usr/bin/id` (~50 KB) packs almost
// instantly, whereas packing the ~130 MB debug binary dominated their runtime (30–45s
// each in CI). Returns None when absent so the test skips rather than panicking on a
// minimal host (parity with tests/pack.rs::small_fixture).
fn small_fixture() -> Option<&'static str> {
    ["/usr/bin/id", "/bin/id"]
        .into_iter()
        .find(|p| std::path::Path::new(p).exists())
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
    let Some(bin) = small_fixture() else {
        eprintln!("skipping: no id binary to pack");
        return;
    };
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("cli.oci.tar");
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

#[test]
fn profile_selects_options_and_reports_unknown() {
    let Some(bin) = small_fixture() else {
        eprintln!("skipping: no id binary to pack");
        return;
    };
    let tmp = tempfile::tempdir().unwrap();
    let cfg = tmp.path().join("scratchsmith.toml");
    std::fs::write(
        &cfg,
        format!("[profile.ci]\nbinary = \"{bin}\"\nstrip = true\n"),
    )
    .unwrap();

    // --profile requires --config (clap).
    let out = run(&["pack", bin, "--profile", "ci"]);
    assert!(!out.status.success(), "profile without config should fail");

    // An undefined profile is a clear error naming the defined ones.
    let out = run(&[
        "pack",
        "--config",
        cfg.to_str().unwrap(),
        "--profile",
        "prod",
    ]);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("prod") && stderr.contains("ci"),
        "got: {stderr}"
    );

    // The profile supplies the binary and strip; the pack succeeds via the daemonless sink.
    let archive = tmp.path().join("profile.oci.tar");
    let out = run(&[
        "pack",
        "--config",
        cfg.to_str().unwrap(),
        "--profile",
        "ci",
        "--oci-archive",
        archive.to_str().unwrap(),
    ]);
    assert!(
        out.status.success(),
        "profile pack failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(archive.exists(), "archive not written from profile");
}

#[test]
fn profile_sign_without_a_push_target_errors() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = tmp.path().join("scratchsmith.toml");
    let bin = env!("CARGO_BIN_EXE_scratchsmith");
    // A profile sets `sign` but no push target; delivering to a non-push sink must fail loud
    // (cosign signs a registry image by digest) rather than silently dropping the request.
    std::fs::write(
        &cfg,
        format!("[profile.p]\nbinary = \"{bin}\"\nsign = true\n"),
    )
    .unwrap();
    let archive = tmp.path().join("x.oci.tar");
    let out = run(&[
        "pack",
        "--config",
        cfg.to_str().unwrap(),
        "--profile",
        "p",
        "--oci-archive",
        archive.to_str().unwrap(),
    ]);
    assert!(!out.status.success(), "sign without push should fail");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("sign") && stderr.contains("push"),
        "got: {stderr}"
    );
}

#[test]
fn cli_delivery_sink_beats_a_config_push_target() {
    let Some(bin) = small_fixture() else {
        eprintln!("skipping: no id binary to pack");
        return;
    };
    let tmp = tempfile::tempdir().unwrap();
    let cfg = tmp.path().join("scratchsmith.toml");
    // A profile sets a push target, but an explicit --oci-archive on the CLI must win — a local
    // pack must never be turned into a registry publish by a config default.
    std::fs::write(
        &cfg,
        format!("[profile.ci]\nbinary = \"{bin}\"\npush = \"ghcr.io/nope/nope:latest\"\n"),
    )
    .unwrap();
    let archive = tmp.path().join("out.oci.tar");
    let out = run(&[
        "pack",
        "--config",
        cfg.to_str().unwrap(),
        "--profile",
        "ci",
        "--oci-archive",
        archive.to_str().unwrap(),
    ]);
    assert!(
        out.status.success(),
        "--oci-archive should win over a config push: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        archive.exists(),
        "archive not written — config push hijacked the sink"
    );
}

#[test]
fn config_smoke_with_no_build_fails_loud() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = tmp.path().join("scratchsmith.toml");
    let bin = env!("CARGO_BIN_EXE_scratchsmith");
    // clap blocks --smoke --no-build, but `smoke` can arrive from the config; with no image to
    // run it must fail loud, not silently skip the smoke-run.
    std::fs::write(
        &cfg,
        format!("[profile.p]\nbinary = \"{bin}\"\nsmoke = true\n"),
    )
    .unwrap();
    let rootfs = tmp.path().join("rootfs");
    let out = run(&[
        "pack",
        "--config",
        cfg.to_str().unwrap(),
        "--profile",
        "p",
        "--no-build",
        "-o",
        rootfs.to_str().unwrap(),
    ]);
    assert!(
        !out.status.success(),
        "config smoke + --no-build should fail"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("smoke") && stderr.contains("no-build"),
        "got: {stderr}"
    );
}
