//! Full pipeline against a real binary: resolve the scratchsmith binary, stage it,
//! and confirm the rootfs has the loader, libc, and a regenerated ld.so.cache.
//! Requires ldconfig (present on any glibc host, including CI).

use scratchsmith::resolver::{resolve, Sysroot};
use scratchsmith::stager::{stage, stage_default_includes, strip_and_measure};
use std::path::Path;
use std::process::Command;

fn strip_available() -> bool {
    Command::new("strip")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[test]
fn stages_a_real_binary_into_a_runnable_tree() {
    let bin = Path::new(env!("CARGO_BIN_EXE_scratchsmith"));
    let resolution = resolve(bin, &Sysroot::new("/")).expect("resolution");
    assert!(resolution.missing.is_empty(), "deps must resolve first");

    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path().join("rootfs");
    let tree = stage(bin, &resolution, &dest).expect("staging should succeed");

    // The loader must exist at its verbatim PT_INTERP path, or the image won't exec.
    let interp = resolution.interpreter.as_ref().unwrap();
    let staged_loader = dest.join(interp.image_path.strip_prefix("/").unwrap());
    assert!(staged_loader.exists(), "loader missing at PT_INTERP path");

    // libc must be present somewhere in the staged tree.
    assert!(
        resolution
            .libs
            .iter()
            .any(|l| dest.join(l.path.strip_prefix("/").unwrap()).exists()),
        "no resolved library was staged"
    );

    // The regenerated cache must exist and be non-empty.
    let cache = dest.join("etc/ld.so.cache");
    assert!(cache.exists(), "ld.so.cache was not generated");
    assert!(
        std::fs::metadata(&cache).unwrap().len() > 0,
        "ld.so.cache is empty"
    );

    // The entrypoint is the binary's own path, and it was staged there.
    assert!(dest
        .join(tree.entrypoint.strip_prefix("/").unwrap())
        .exists());
}

#[test]
fn default_includes_add_nss_and_passwd_from_host() {
    let bin = Path::new(env!("CARGO_BIN_EXE_scratchsmith"));
    let resolution = resolve(bin, &Sysroot::new("/")).expect("resolution");

    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path().join("rootfs");
    let report = stage_default_includes(&resolution, &dest).expect("includes");

    assert!(dest.join("etc/nsswitch.conf").exists(), "nsswitch missing");
    assert!(dest.join("etc/passwd").exists(), "passwd missing");
    // The version-matched NSS module for DNS must land beside the staged libc.
    assert!(
        walk_contains(&dest, "libnss_dns.so.2"),
        "libnss_dns.so.2 was not staged (warnings: {:?})",
        report.warnings
    );
}

// Small recursive check so the test does not hard-code the libc directory triplet.
fn walk_contains(root: &Path, name: &str) -> bool {
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

#[test]
fn strip_reduces_payload_size() {
    if !strip_available() {
        eprintln!("skipping strip_reduces_payload_size: no strip");
        return;
    }
    let bin = Path::new(env!("CARGO_BIN_EXE_scratchsmith"));
    let resolution = resolve(bin, &Sysroot::new("/")).expect("resolution");

    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path().join("rootfs");
    let tree = stage(bin, &resolution, &dest).expect("stage");

    let report = strip_and_measure(&dest, &tree, &resolution, true, false).expect("strip+measure");
    assert!(report.stripped);
    assert!(!report.entries.is_empty(), "should measure staged files");
    assert!(
        report.total_after < report.total_before,
        "strip should shrink the payload: {} -> {}",
        report.total_before,
        report.total_after
    );
}

fn upx_available() -> bool {
    Command::new("upx")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[test]
fn upx_compresses_the_binary_only() {
    // /usr/bin/id is a small real dynamic binary — fast to compress and present on any glibc
    // host — so this stays quick where a 40 MB self-pack would not.
    let bin = Path::new("/usr/bin/id");
    if !upx_available() || !bin.exists() {
        eprintln!("skipping upx_compresses_the_binary_only: no upx or no /usr/bin/id");
        return;
    }
    let resolution = resolve(bin, &Sysroot::new("/")).expect("resolution");

    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path().join("rootfs");
    let tree = stage(bin, &resolution, &dest).expect("stage");

    let report = strip_and_measure(&dest, &tree, &resolution, false, true).expect("upx");
    assert!(report.upx, "report should flag upx");
    // The binary is the first target; UPX must shrink it. The loader/libs (later entries)
    // are deliberately left uncompressed, so the binary is the only one that changes.
    let binary = &report.entries[0];
    assert!(
        binary.after < binary.before,
        "upx should shrink the binary: {} -> {}",
        binary.before,
        binary.after
    );
}
