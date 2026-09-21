//! End-to-end checks against the built binary: exit codes and top-level output.
//! These pin the contract Task 1.1 promises (help lists subcommands, version works,
//! stubs fail loudly) independent of the library's internals.

use std::process::{Command, Output};

mod common;
use common::small_fixture_str as small_fixture;

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
fn help_lists_all_subcommands() {
    let out = run(&["--help"]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    for cmd in ["pack", "lint", "doctor", "index", "graph", "diff", "unpack"] {
        assert!(stdout.contains(cmd), "help missing `{cmd}`: {stdout}");
    }
}

#[test]
fn exit_codes_follow_the_v1_contract() {
    // The exit-code contract (COMPATIBILITY.md): 0 on success, 2 on an argument/usage error
    // (clap), non-zero on any other failure. Pinned here so a change is deliberate — a script
    // gating on `$?` must not break on an upgrade.
    assert!(run(&["--version"]).status.success(), "0: --version");
    assert!(run(&["--help"]).status.success(), "0: --help");
    assert!(run(&["doctor"]).status.success(), "0: doctor");
    assert_eq!(run(&[]).status.code(), Some(2), "2: no subcommand");
    assert_eq!(
        run(&["bogus"]).status.code(),
        Some(2),
        "2: unknown subcommand"
    );
    assert_eq!(
        run(&["pack", "--nope"]).status.code(),
        Some(2),
        "2: unknown flag"
    );
    // A real runtime failure (missing binary) is non-zero, and specifically not a usage error.
    let missing = run(&["pack", "/nonexistent/scratchsmith-xyz"])
        .status
        .code();
    assert!(
        matches!(missing, Some(c) if c != 0 && c != 2),
        "non-zero (not 2) on a runtime failure, got {missing:?}"
    );
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
fn graph_prints_a_dependency_tree() {
    let Some(bin) = small_fixture() else {
        eprintln!("skipping: no id binary to inspect");
        return;
    };
    let out = run(&["graph", bin]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    // The root is the binary, libc is a resolved dependency, and the loader is noted.
    assert!(stdout.contains("id "), "root missing: {stdout}");
    assert!(stdout.contains("libc.so"), "libc missing: {stdout}");
    assert!(stdout.contains("interpreter:"), "loader missing: {stdout}");
}

#[test]
fn graph_json_is_valid_and_lists_nodes() {
    let Some(bin) = small_fixture() else {
        eprintln!("skipping: no id binary to inspect");
        return;
    };
    let out = run(&["graph", "--format", "json", bin]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("valid json");
    // root is the binary's real path; the first node is the root, named by its file name.
    assert!(
        v["root"].as_str().unwrap().ends_with("id"),
        "root should be the id binary path: {v}"
    );
    assert_eq!(v["nodes"][0]["name"], "id");
    assert!(
        v["nodes"].as_array().map(|a| a.len() >= 2).unwrap_or(false),
        "expected the binary plus libraries: {v}"
    );
}

#[test]
fn diff_flags_drift_with_exit_code() {
    let tmp = tempfile::tempdir().unwrap();
    let a = tmp.path().join("a");
    let b = tmp.path().join("b");
    std::fs::create_dir_all(&a).unwrap();
    std::fs::create_dir_all(&b).unwrap();
    std::fs::write(a.join("f"), "one").unwrap();
    std::fs::write(b.join("f"), "two").unwrap();
    let out = run(&[
        "diff",
        "--exit-code",
        a.to_str().unwrap(),
        b.to_str().unwrap(),
    ]);
    assert!(!out.status.success(), "--exit-code must fail on drift");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("~ f"), "{stdout}");
}

#[test]
fn diff_identical_dirs_report_no_changes() {
    let tmp = tempfile::tempdir().unwrap();
    let a = tmp.path().join("a");
    let b = tmp.path().join("b");
    std::fs::create_dir_all(&a).unwrap();
    std::fs::create_dir_all(&b).unwrap();
    std::fs::write(a.join("f"), "same").unwrap();
    std::fs::write(b.join("f"), "same").unwrap();
    let out = run(&[
        "diff",
        "--exit-code",
        a.to_str().unwrap(),
        b.to_str().unwrap(),
    ]);
    assert!(
        out.status.success(),
        "identical dirs must pass even with --exit-code"
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("no changes"));
}

#[test]
fn pack_deny_gate_fails_when_library_present() {
    // `id` links libc, so `--deny libc.so.6` must fail the pack (a CI policy gate). Uses the
    // daemonless -n -o sink — the policy check runs before staging, so no Docker is needed.
    let Some(bin) = small_fixture() else {
        eprintln!("skipping: no id binary to pack");
        return;
    };
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("rootfs");
    let output = run(&[
        "pack",
        "--deny",
        "libc.so.6",
        "--no-build",
        "-o",
        out.to_str().unwrap(),
        bin,
    ]);
    assert!(
        !output.status.success(),
        "deny of libc should fail the pack"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("library policy failed") && stderr.contains("libc.so.6"),
        "{stderr}"
    );
}

#[test]
fn pack_deny_gate_covers_nss_modules() {
    // `id` does DNS lookups, so `libresolv.so.2` is staged as an NSS module — outside the
    // resolved dependency graph. The gate must still catch it (regression for the split
    // between resolution.libs and the default-includes).
    let Some(bin) = small_fixture() else {
        eprintln!("skipping: no id binary to pack");
        return;
    };
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("rootfs");
    let output = run(&[
        "pack",
        "--deny",
        "libresolv.so.2",
        "--no-build",
        "-o",
        out.to_str().unwrap(),
        bin,
    ]);
    assert!(
        !output.status.success(),
        "deny of a staged NSS module should fail the pack"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("library policy failed") && stderr.contains("libresolv.so.2"),
        "{stderr}"
    );
}

// Whether any file under `root` is named `name`.
fn tree_has(root: &std::path::Path, name: &str) -> bool {
    walkdir::WalkDir::new(root)
        .into_iter()
        .filter_map(|e| e.ok())
        .any(|e| e.file_name().to_string_lossy() == name)
}

#[test]
fn unpack_round_trips_an_oci_archive() {
    // Pack daemonlessly to an OCI archive, then unpack it and confirm the rootfs is back.
    let Some(bin) = small_fixture() else {
        eprintln!("skipping: no id binary to pack");
        return;
    };
    let tmp = tempfile::tempdir().unwrap();
    let archive = tmp.path().join("img.oci.tar");
    let packed = run(&["pack", "--oci-archive", archive.to_str().unwrap(), bin]);
    assert!(
        packed.status.success(),
        "pack: {}",
        String::from_utf8_lossy(&packed.stderr)
    );
    let dest = tmp.path().join("unpacked");
    let out = run(&["unpack", archive.to_str().unwrap(), dest.to_str().unwrap()]);
    assert!(
        out.status.success(),
        "unpack: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        tree_has(&dest, "id"),
        "packed binary missing from unpacked rootfs"
    );
    assert!(
        tree_has(&dest, "libc.so.6"),
        "libc missing from unpacked rootfs"
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("unpacked"));
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
fn pack_nss_files_only_through_the_cli() {
    // Exercises `--nss` from the command line (the CLI-supplied selection path in dispatch)
    // via the daemonless -n -o sink — no Docker needed.
    let Some(bin) = small_fixture() else {
        eprintln!("skipping: no id binary to pack");
        return;
    };
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("rootfs");
    let output = run(&[
        "pack",
        "--nss",
        "files",
        "--no-build",
        "-o",
        out.to_str().unwrap(),
        bin,
    ]);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let nsswitch = std::fs::read_to_string(out.join("etc/nsswitch.conf")).unwrap();
    assert!(nsswitch.contains("hosts:          files\n"), "{nsswitch}");
    assert!(!nsswitch.contains("dns"), "dns must be dropped: {nsswitch}");
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

#[test]
fn a_label_without_an_equals_sign_warns_but_still_packs() {
    // The deprecation contract: the old shape keeps working, the warning goes to stderr, and
    // the exit code does not move. Run through the CLI because the warning is an eprintln!,
    // not a report field. The OCI-archive sink needs no Docker.
    let Some(bin) = small_fixture() else {
        eprintln!("skipping: no id binary to pack");
        return;
    };
    let tmp = tempfile::tempdir().unwrap();
    let archive = tmp.path().join("img.tar");
    let out = run(&[
        "pack",
        "--label",
        "build",
        "--oci-archive",
        archive.to_str().unwrap(),
        bin,
    ]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "pack should still succeed: {stderr}");
    assert!(archive.exists(), "archive not written");
    assert!(
        stderr.contains("a label with no `=` is deprecated")
            && stderr.contains("`build` lands with an empty value"),
        "label deprecation warning missing from stderr: {stderr}"
    );
}

#[test]
fn an_env_entry_without_an_equals_sign_warns_but_still_packs() {
    let Some(bin) = small_fixture() else {
        eprintln!("skipping: no id binary to pack");
        return;
    };
    let tmp = tempfile::tempdir().unwrap();
    let archive = tmp.path().join("img.tar");
    let out = run(&[
        "pack",
        "--env",
        "LOG_LEVEL",
        "--oci-archive",
        archive.to_str().unwrap(),
        bin,
    ]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "pack should still succeed: {stderr}");
    assert!(
        stderr.contains("an env entry with no `=` is deprecated")
            && stderr.contains("`LOG_LEVEL` is not KEY=VALUE"),
        "env deprecation warning missing from stderr: {stderr}"
    );
}

#[test]
fn a_label_with_an_equals_sign_is_quiet() {
    // The warning must not fire on the shape we are steering people towards, including the
    // deliberate empty value `build=`.
    let Some(bin) = small_fixture() else {
        eprintln!("skipping: no id binary to pack");
        return;
    };
    let tmp = tempfile::tempdir().unwrap();
    let archive = tmp.path().join("img.tar");
    let out = run(&[
        "pack",
        "--label",
        "build=ci",
        "--label",
        "empty=",
        "--env",
        "LOG_LEVEL=info",
        "--oci-archive",
        archive.to_str().unwrap(),
        bin,
    ]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "pack should succeed: {stderr}");
    assert!(
        !stderr.contains("is deprecated"),
        "a well-formed pair must not warn: {stderr}"
    );
}

#[test]
fn a_nested_profile_warns_but_still_packs() {
    // [profile.a.profile.b] parses and is then dropped, so the keys inside never apply.
    // Warn, keep packing, leave the exit code alone.
    let Some(bin) = small_fixture() else {
        eprintln!("skipping: no id binary to pack");
        return;
    };
    let tmp = tempfile::tempdir().unwrap();
    let cfg = tmp.path().join("scratchsmith.toml");
    std::fs::write(
        &cfg,
        format!("binary = \"{bin}\"\n\n[profile.release]\nstrip = true\n\n[profile.release.profile.signed]\nstrip = false\n"),
    )
    .unwrap();
    let rootfs = tmp.path().join("rootfs");
    let out = run(&[
        "pack",
        "--config",
        cfg.to_str().unwrap(),
        "--profile",
        "release",
        "--no-build",
        "-o",
        rootfs.to_str().unwrap(),
    ]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "pack should still succeed: {stderr}");
    assert!(
        stderr.contains("a nested profile is deprecated")
            && stderr.contains("under [profile.release]"),
        "nested-profile warning missing from stderr: {stderr}"
    );
}

#[test]
fn a_bare_label_warns_on_the_rootfs_sink_too() {
    // The rootfs sink builds no image, so an earlier placement inside the image path missed it
    // entirely. `--label` carries no conflicts_with for --no-build, so this invocation is valid
    // and the user is exactly the one 2.0 would break without notice.
    let Some(bin) = small_fixture() else {
        eprintln!("skipping: no id binary to pack");
        return;
    };
    let tmp = tempfile::tempdir().unwrap();
    let rootfs = tmp.path().join("rootfs");
    let out = run(&[
        "pack",
        "--label",
        "build",
        "--label",
        "build",
        "--env",
        "PATH",
        "--no-build",
        "-o",
        rootfs.to_str().unwrap(),
        bin,
    ]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "pack should still succeed: {stderr}");
    assert!(
        stderr.matches("`build` lands with an empty value").count() == 1,
        "a repeated entry must warn exactly once: {stderr}"
    );
    assert!(
        stderr.contains("replaces the image's default PATH"),
        "a bare PATH must say what it replaces: {stderr}"
    );
    // The `latest/` segment is the whole point: mike versions the site, so the bare path 404s.
    assert!(
        stderr.contains("https://schubydoo.github.io/scratchsmith/latest/deprecations/"),
        "the warning must point at the versioned Deprecations page: {stderr}"
    );
}
