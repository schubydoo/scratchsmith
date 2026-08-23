//! Real-ELF fixtures compiled at test time. Task 1.3 exercises the search logic with
//! scripted dependency graphs; these confirm the goblin-backed parser and resolver
//! agree with what an actual linker emits (DT_RPATH vs DT_RUNPATH, $ORIGIN, versioned
//! sonames). Skipped when no C compiler is available.

use scratchsmith::resolver::{read_elf_info, resolve, Sysroot};
use std::path::{Path, PathBuf};
use std::process::Command;

fn tool_available(tool: &str) -> bool {
    Command::new(tool)
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn cc_available() -> bool {
    Command::new("cc")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn cc(args: &[&str]) {
    let out = Command::new("cc").args(args).output().expect("run cc");
    assert!(
        out.status.success(),
        "cc {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// Build libfoo (real file libfoo.so.1.2.3 + soname symlink libfoo.so.1) and an app
// that needs it, linked with the given dtag flag so RPATH or RUNPATH is emitted.
// Returns the app path.
fn build_fixture(dir: &Path, app_name: &str, dtag_flag: &str) -> PathBuf {
    std::fs::write(dir.join("foo.c"), "int foo(void){return 42;}").unwrap();
    std::fs::write(
        dir.join("main.c"),
        "extern int foo(void); int main(void){return foo()==42?0:1;}",
    )
    .unwrap();

    let real = dir.join("libfoo.so.1.2.3");
    cc(&[
        "-shared",
        "-fPIC",
        "-Wl,-soname,libfoo.so.1",
        "-o",
        real.to_str().unwrap(),
        dir.join("foo.c").to_str().unwrap(),
    ]);
    let soname_link = dir.join("libfoo.so.1");
    if soname_link.symlink_metadata().is_err() {
        std::os::unix::fs::symlink("libfoo.so.1.2.3", &soname_link).unwrap();
    }

    // The source object must precede the library on the command line, and RPATH is
    // $ORIGIN so the app finds libfoo beside itself at runtime.
    let app = dir.join(app_name);
    cc(&[
        dtag_flag,
        "-Wl,-rpath,$ORIGIN",
        dir.join("main.c").to_str().unwrap(),
        "-L",
        dir.to_str().unwrap(),
        "-l:libfoo.so.1",
        "-o",
        app.to_str().unwrap(),
    ]);
    app
}

#[test]
fn goblin_reads_rpath_and_runpath_as_the_linker_emits_them() {
    if !cc_available() {
        eprintln!("skipping: no C compiler");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();

    let rpath_app = build_fixture(tmp.path(), "app_rpath", "-Wl,--disable-new-dtags");
    let info = read_elf_info(&rpath_app).unwrap();
    assert_eq!(info.rpaths, vec!["$ORIGIN".to_string()]);
    assert!(info.runpaths.is_empty(), "old dtags => RPATH only");

    let runpath_app = build_fixture(tmp.path(), "app_runpath", "-Wl,--enable-new-dtags");
    let info = read_elf_info(&runpath_app).unwrap();
    assert_eq!(info.runpaths, vec!["$ORIGIN".to_string()]);
    assert!(info.rpaths.is_empty(), "new dtags => RUNPATH only");
}

#[test]
fn resolves_a_real_binary_via_origin_rpath_and_versioned_soname() {
    if !cc_available() {
        eprintln!("skipping: no C compiler");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let app = build_fixture(tmp.path(), "app", "-Wl,--disable-new-dtags");

    // Resolve against the host so libc/loader are found; libfoo comes via $ORIGIN.
    let res = resolve(&app, &Sysroot::new("/")).unwrap();

    let foo = res
        .libs
        .iter()
        .find(|l| l.soname == "libfoo.so.1")
        .expect("libfoo.so.1 should resolve via $ORIGIN RPATH");
    assert!(
        foo.path.ends_with("libfoo.so.1.2.3"),
        "soname symlink should follow to the real versioned file, got {:?}",
        foo.path
    );
    assert!(
        res.libs.iter().any(|l| l.soname.contains("libc")),
        "libc should resolve from the host default paths"
    );
    assert!(
        res.missing.is_empty(),
        "unexpected missing: {:?}",
        res.missing
    );
}

#[test]
fn musl_binaries_are_detected_and_pack_hard_fails() {
    if !tool_available("musl-gcc") {
        eprintln!("skipping: no musl-gcc");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("m.c");
    std::fs::write(&src, "int main(void){return 0;}").unwrap();
    let app = tmp.path().join("musl_app");
    let out = Command::new("musl-gcc")
        .args([src.to_str().unwrap(), "-o", app.to_str().unwrap()])
        .output()
        .expect("run musl-gcc");
    assert!(
        out.status.success(),
        "musl-gcc failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // The interpreter marks it as musl, and packing must refuse loudly.
    let info = read_elf_info(&app).unwrap();
    assert!(
        info.is_musl(),
        "expected musl interpreter, got {:?}",
        info.interpreter
    );

    let dest = tmp.path().join("rootfs");
    let err = scratchsmith::pack::stage_only(&app, &dest, false, None).unwrap_err();
    assert!(err.to_string().contains("musl"), "got: {err}");
}
