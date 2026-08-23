//! Verify the hardening analyzer against binaries compiled with known flags.
//! Skipped when no C compiler is available.

use scratchsmith::lint::{analyze, Relro};
use std::path::Path;
use std::process::Command;

fn cc_available() -> bool {
    Command::new("cc")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn compile(dir: &Path, name: &str, extra: &[&str]) -> std::path::PathBuf {
    let src = dir.join("m.c");
    // printf with a format string yields a __printf_chk under _FORTIFY_SOURCE.
    std::fs::write(
        &src,
        "#include <stdio.h>\nint main(void){printf(\"%d\\n\", 42);return 0;}",
    )
    .unwrap();
    let out = dir.join(name);
    let mut args: Vec<String> = vec![
        src.to_string_lossy().into(),
        "-o".into(),
        out.to_string_lossy().into(),
    ];
    args.extend(extra.iter().map(|s| s.to_string()));
    let status = Command::new("cc").args(&args).output().expect("run cc");
    assert!(
        status.status.success(),
        "cc failed: {}",
        String::from_utf8_lossy(&status.stderr)
    );
    out
}

#[test]
fn hardened_binary_reports_all_mitigations() {
    if !cc_available() {
        eprintln!("skipping: no C compiler");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let bin = compile(
        tmp.path(),
        "hardened",
        &[
            "-O2",
            "-fPIE",
            "-pie",
            "-fstack-protector-all",
            "-D_FORTIFY_SOURCE=2",
            "-Wl,-z,relro,-z,now",
        ],
    );
    let h = analyze(&bin).unwrap();
    assert!(h.pie, "should be PIE");
    assert_eq!(h.relro, Relro::Full, "-z now should give full RELRO");
    assert!(h.nx, "stack should be non-executable");
    assert!(h.canary, "stack-protector-all should add a canary");
    assert!(h.fortify, "_FORTIFY_SOURCE should add _chk symbols");
}

#[test]
fn unhardened_binary_reports_missing_mitigations() {
    if !cc_available() {
        eprintln!("skipping: no C compiler");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let bin = compile(
        tmp.path(),
        "weak",
        &[
            "-O0",
            "-no-pie",
            "-fno-stack-protector",
            "-U_FORTIFY_SOURCE",
            "-Wl,-z,norelro",
            "-Wl,-z,execstack",
        ],
    );
    let h = analyze(&bin).unwrap();
    assert!(!h.pie, "no-pie should not be PIE");
    assert_eq!(h.relro, Relro::None, "norelro should give no RELRO");
    assert!(!h.nx, "execstack should leave the stack executable");
    assert!(!h.canary, "no stack protector => no canary");
}

#[test]
fn fail_on_gate_controls_the_exit_code() {
    if !cc_available() {
        eprintln!("skipping: no C compiler");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let weak = compile(tmp.path(), "weak", &["-no-pie", "-Wl,-z,norelro"]);
    let ss = env!("CARGO_BIN_EXE_scratchsmith");

    // With the gate, a no-RELRO binary fails and names the check.
    let gated = Command::new(ss)
        .args(["lint", "--fail-on", "no-relro", weak.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(gated.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&gated.stderr).contains("hardening gate failed"));

    // Without a gate, lint only reports and exits 0.
    let ungated = Command::new(ss)
        .args(["lint", weak.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(ungated.status.success());
}
