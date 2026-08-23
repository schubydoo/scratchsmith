//! Real-ELF fixtures compiled at test time. Task 1.3 exercises the search logic with
//! scripted dependency graphs; these confirm the goblin-backed parser and resolver
//! agree with what an actual linker emits (DT_RPATH vs DT_RUNPATH, $ORIGIN, versioned
//! sonames). Skipped when no C compiler is available.

use scratchsmith::pack::PackOptions;
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
    let err = scratchsmith::pack::stage_only(&app, &dest, &PackOptions::default()).unwrap_err();
    assert!(err.to_string().contains("musl"), "got: {err}");
}

#[test]
fn dlopen_use_is_detected() {
    if !cc_available() {
        eprintln!("skipping: no C compiler");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    // A dlopen user imports the symbol; a plain binary does not.
    std::fs::write(
        tmp.path().join("dl.c"),
        "#include <dlfcn.h>\nint main(void){return dlopen(\"x\",2)?0:0;}",
    )
    .unwrap();
    let dl = tmp.path().join("dluser");
    let out = Command::new("cc")
        .args([
            tmp.path().join("dl.c").to_str().unwrap(),
            "-o",
            dl.to_str().unwrap(),
            "-ldl",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "cc: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        read_elf_info(&dl).unwrap().uses_dlopen,
        "dlopen user should be flagged"
    );

    let plain = build_fixture(tmp.path(), "plain", "-Wl,--disable-new-dtags");
    assert!(
        !read_elf_info(&plain).unwrap().uses_dlopen,
        "plain binary is not a dlopen user"
    );
}

#[test]
fn pack_warns_about_dlopen_and_include_stages_extra_libs() {
    if !cc_available() {
        eprintln!("skipping: no C compiler");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(
        tmp.path().join("dl.c"),
        "#include <dlfcn.h>\nint main(void){return dlopen(\"x\",2)?0:0;}",
    )
    .unwrap();
    let dl = tmp.path().join("dluser");
    Command::new("cc")
        .args([
            tmp.path().join("dl.c").to_str().unwrap(),
            "-o",
            dl.to_str().unwrap(),
            "-ldl",
        ])
        .output()
        .unwrap();

    // The report warns about dlopen, and --include force-stages an extra library.
    let out = tmp.path().join("rootfs");
    let opts = PackOptions {
        includes: vec!["libz.so.1".to_string()],
        ..Default::default()
    };
    let report = scratchsmith::pack::stage_only(&dl, &out, &opts).expect("stage dlopen user");
    assert!(
        report.warnings.iter().any(|w| w.contains("dlopen")),
        "expected a dlopen warning, got {:?}",
        report.warnings
    );
    assert!(
        walk_contains(&out, "libz.so.1"),
        "--include libz.so.1 should be staged"
    );
}

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
