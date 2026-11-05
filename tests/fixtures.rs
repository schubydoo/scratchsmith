//! Real-ELF fixtures compiled at test time. The unit tests in `src/resolver.rs` drive the
//! search logic through scripted dependency graphs; these confirm the goblin-backed parser
//! and resolver agree with what an actual linker emits (DT_RPATH vs DT_RUNPATH, $ORIGIN,
//! versioned sonames). Skipped when no C compiler is available.

use scratchsmith::pack::PackOptions;
use scratchsmith::resolver::{read_elf_info, resolve, Sysroot};
use std::path::{Path, PathBuf};
use std::process::Command;

mod common;
use common::{cc_available, skip_optional, skip_required, tool_available, walk_contains};

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
        skip_required("no C compiler");
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
        skip_required("no C compiler");
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
        skip_optional("no musl-gcc");
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
        skip_required("no C compiler");
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
        skip_required("no C compiler");
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

#[test]
fn a_missing_library_shows_in_the_graph_and_stops_the_pack() {
    if !cc_available() {
        skip_required("no C compiler");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let app = build_fixture(tmp.path(), "app", "-Wl,--enable-new-dtags");
    std::fs::remove_file(tmp.path().join("libfoo.so.1")).unwrap();
    std::fs::remove_file(tmp.path().join("libfoo.so.1.2.3")).unwrap();

    let bin = env!("CARGO_BIN_EXE_scratchsmith");
    let graph = Command::new(bin)
        .args(["graph", "--format", "json", app.to_str().unwrap()])
        .output()
        .expect("run");
    assert!(!graph.status.success(), "an incomplete graph must fail");
    let report: serde_json::Value = serde_json::from_slice(&graph.stdout).unwrap();
    let missing: Vec<&str> = report["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|n| n["missing"].as_array().unwrap())
        .filter_map(|s| s.as_str())
        .collect();
    assert_eq!(missing, ["libfoo.so.1"], "{report}");

    let rootfs = tmp.path().join("rootfs");
    let pack = Command::new(bin)
        .args([
            "pack",
            "-n",
            "-o",
            rootfs.to_str().unwrap(),
            app.to_str().unwrap(),
        ])
        .output()
        .expect("run");
    let stderr = String::from_utf8_lossy(&pack.stderr);
    assert!(!pack.status.success(), "pack must refuse: {stderr}");
    assert!(
        stderr.contains("cannot pack: unresolved dependencies: \"libfoo.so.1\""),
        "{stderr}"
    );
}

#[test]
fn a_truncated_library_fails_both_graph_and_pack() {
    // A resolved library that claims to be an ELF and will not parse has unknown DT_NEEDED
    // entries, so `graph` and `pack` refuse it alike, and nothing stages.
    if !cc_available() {
        skip_required("no C compiler");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let app = build_fixture(tmp.path(), "app", "-Wl,--enable-new-dtags");
    let lib = tmp.path().join("libfoo.so.1.2.3");
    std::fs::write(&lib, b"\x7fELF and then the file ends").unwrap();

    let bin = env!("CARGO_BIN_EXE_scratchsmith");
    let rootfs = tmp.path().join("rootfs");
    let runs: [Vec<&str>; 2] = [
        vec!["graph", "--format", "json", app.to_str().unwrap()],
        vec![
            "pack",
            "--format",
            "json",
            "-n",
            "-o",
            rootfs.to_str().unwrap(),
            app.to_str().unwrap(),
        ],
    ];
    for args in runs {
        let out = Command::new(bin).args(&args).output().expect("run");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(1), "{args:?} must fail: {stderr}");
        assert!(
            stderr.contains("libfoo.so.1.2.3 starts like an ELF and cannot be parsed")
                && stderr.contains("Replace it with an intact copy")
                && !stderr.contains("warning: "),
            "{args:?}: the error must name the file and the fix: {stderr}"
        );
        assert!(out.stdout.is_empty(), "{args:?}: no report on a failure");
    }
    assert!(
        !walk_contains(&rootfs, "libfoo.so.1.2.3"),
        "the damaged file must not stage"
    );
}

#[test]
fn a_library_with_runpath_resolves_like_the_loader_not_through_an_inherited_rpath() {
    // Built with a real linker, because the two dynamic tags are the whole point: the exe
    // carries DT_RPATH, and libmid carries DT_RUNPATH. glibc then ignores the exe's RPATH when
    // it looks for what libmid needs.
    if !cc_available() {
        skip_required("no C compiler");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let libs = dir.join("libs");
    std::fs::create_dir(&libs).unwrap();
    let write = |name: &str, body: &str| std::fs::write(dir.join(name), body).unwrap();
    write("leaf.c", "int leaf(void){return 7;}");
    write(
        "mid.c",
        "extern int leaf(void); int mid(void){return leaf();}",
    );
    write(
        "main.c",
        "extern int mid(void); int main(void){return mid()==7?0:1;}",
    );
    let p = |name: &str| dir.join(name).to_str().unwrap().to_string();
    let lib = |name: &str| libs.join(name).to_str().unwrap().to_string();
    let l = format!("-L{}", libs.display());

    cc(&[
        "-shared",
        "-fPIC",
        "-Wl,-soname,libleaf.so",
        "-o",
        &lib("libleaf.so"),
        &p("leaf.c"),
    ]);
    cc(&[
        "-shared",
        "-fPIC",
        "-Wl,-soname,libmid.so",
        "-Wl,--enable-new-dtags",
        "-Wl,-rpath,/nonexistent-runpath",
        "-o",
        &lib("libmid.so"),
        &p("mid.c"),
        &l,
        "-lleaf",
    ]);
    cc(&[
        "-Wl,--disable-new-dtags",
        &format!("-Wl,-rpath,{}", libs.display()),
        &format!("-Wl,-rpath-link,{}", libs.display()),
        "-o",
        &p("app"),
        &p("main.c"),
        &l,
        "-lmid",
    ]);
    let app = dir.join("app");

    // The ground truth: the real loader cannot start this program.
    let ran = Command::new(&app).output().expect("run the fixture");
    assert!(
        !ran.status.success(),
        "the fixture is wrong: the loader must NOT find libleaf through the inherited RPATH"
    );

    // scratchsmith agrees with the loader: libleaf is unresolved, and graph and pack fail.
    let bin = env!("CARGO_BIN_EXE_scratchsmith");
    let out = Command::new(bin)
        .args(["graph", "--format", "json"])
        .arg(&app)
        .output()
        .expect("run");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "an incomplete graph must fail");
    // Both commands name the cause and the fix, not only "missing".
    let real_libs = std::fs::canonicalize(&libs).unwrap();
    let hint = format!(
        "note: `libleaf.so` is in {}, an RPATH that {} inherits from a parent.",
        real_libs.display(),
        real_libs.join("libmid.so").display()
    );
    let fix = format!("a RUNPATH that lists {}.", real_libs.display());
    assert!(stderr.contains(&hint) && stderr.contains(&fix), "{stderr}");
    let graph: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let missing: Vec<&str> = graph["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|n| n["missing"].as_array().unwrap())
        .filter_map(|s| s.as_str())
        .collect();
    assert_eq!(missing, ["libleaf.so"], "{graph}");

    let rootfs = dir.join("rootfs");
    let pack = Command::new(bin)
        .args(["pack", "-n", "-o", rootfs.to_str().unwrap()])
        .arg(&app)
        .output()
        .expect("run");
    let stderr = String::from_utf8_lossy(&pack.stderr);
    assert!(!pack.status.success(), "pack must refuse: {stderr}");
    assert!(
        stderr.contains("cannot pack: unresolved dependencies: \"libleaf.so\""),
        "{stderr}"
    );
    assert!(stderr.contains(&hint) && stderr.contains(&fix), "{stderr}");
}

#[test]
fn a_truncated_top_level_binary_gives_graph_and_pack_the_same_error() {
    let tmp = tempfile::tempdir().unwrap();
    let app = tmp.path().join("app");
    let full = std::fs::read(std::env::current_exe().unwrap()).unwrap();
    std::fs::write(&app, &full[..600]).unwrap();

    let bin = env!("CARGO_BIN_EXE_scratchsmith");
    let rootfs = tmp.path().join("rootfs");
    let mut msgs = Vec::new();
    for args in [
        vec!["graph", app.to_str().unwrap()],
        vec![
            "pack",
            "-n",
            "-o",
            rootfs.to_str().unwrap(),
            app.to_str().unwrap(),
        ],
    ] {
        let out = Command::new(bin).args(&args).output().expect("run");
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        assert_eq!(out.status.code(), Some(1), "{args:?}: {stderr}");
        assert!(
            stderr.contains("starts like an ELF and cannot be parsed")
                && stderr.contains("Rebuild the binary")
                && stderr.contains("not a valid ELF binary:")
                && !stderr.contains("reinstall"),
            "{args:?}: {stderr}"
        );
        msgs.push(stderr);
    }
    assert_eq!(msgs[0], msgs[1], "graph and pack must print the same error");
}

#[test]
fn a_platform_search_path_on_an_unnamed_arch_fails_both_graph_and_pack() {
    // A real RUNPATH of `$ORIGIN/$PLATFORM`, on an ELF relabelled as RISC-V, an arch with no
    // `$PLATFORM` value. The token would expand to nothing, so libfoo beside the app would
    // stage in place of an arch-specific copy.
    if !cc_available() {
        skip_required("no C compiler");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    std::fs::write(dir.join("foo.c"), "int foo(void){return 42;}").unwrap();
    std::fs::write(
        dir.join("main.c"),
        "extern int foo(void); int main(void){return foo()==42?0:1;}",
    )
    .unwrap();
    let p = |name: &str| dir.join(name).to_str().unwrap().to_string();
    cc(&["-shared", "-fPIC", "-o", &p("libfoo.so"), &p("foo.c")]);
    cc(&[
        "-Wl,--enable-new-dtags",
        "-Wl,-rpath,$ORIGIN/$PLATFORM",
        "-o",
        &p("app"),
        &p("main.c"),
        &format!("-L{}", dir.display()),
        "-lfoo",
    ]);
    // e_machine is the little-endian u16 at offset 18 of the ELF header.
    let mut bytes = std::fs::read(dir.join("app")).unwrap();
    bytes[18..20].copy_from_slice(&243u16.to_le_bytes()); // EM_RISCV
    std::fs::write(dir.join("app"), bytes).unwrap();

    let bin = env!("CARGO_BIN_EXE_scratchsmith");
    let rootfs = dir.join("rootfs");
    let app = p("app");
    let runs: [Vec<&str>; 3] = [
        vec!["graph", &app],
        vec!["graph", "--format", "json", &app],
        vec![
            "pack",
            "--format",
            "json",
            "-n",
            "-o",
            rootfs.to_str().unwrap(),
            &app,
        ],
    ];
    let real_app = std::fs::canonicalize(dir.join("app")).unwrap();
    for args in runs {
        let out = Command::new(bin).args(&args).output().expect("run");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(1), "{args:?} must fail: {stderr}");
        assert!(
            stderr.contains("`$PLATFORM` has no value for this architecture (RISCV)")
                && stderr.contains("`$ORIGIN/$PLATFORM`")
                && stderr.contains(&real_app.display().to_string())
                && stderr.contains("Write the directory name")
                && !stderr.contains("warning: "),
            "{args:?}: the error must name the entry, the file and the fix: {stderr}"
        );
        assert!(out.stdout.is_empty(), "{args:?}: no report on a failure");
    }
    assert!(
        !walk_contains(&rootfs, "libfoo.so"),
        "the library from the wrong directory must not stage"
    );
}

#[test]
fn a_colon_separated_search_path_resolves_like_the_loader() {
    // ld joins several -rpath flags into one RPATH or RUNPATH string, and ld.so searches
    // each ':' entry in order. A missing first entry must not hide `$ORIGIN`.
    if !cc_available() {
        skip_required("no C compiler");
        return;
    }
    let bin = env!("CARGO_BIN_EXE_scratchsmith");
    for dtags in ["-Wl,--enable-new-dtags", "-Wl,--disable-new-dtags"] {
        for list in ["/opt/none:$ORIGIN", "$ORIGIN:/opt/none"] {
            let tmp = tempfile::tempdir().unwrap();
            let dir = tmp.path();
            std::fs::write(dir.join("foo.c"), "int foo(void){return 42;}").unwrap();
            std::fs::write(
                dir.join("main.c"),
                "extern int foo(void); int main(void){return foo()==42?0:1;}",
            )
            .unwrap();
            let p = |name: &str| dir.join(name).to_str().unwrap().to_string();
            cc(&["-shared", "-fPIC", "-o", &p("libfoo.so"), &p("foo.c")]);
            cc(&[
                dtags,
                &format!("-Wl,-rpath,{list}"),
                "-o",
                &p("app"),
                &p("main.c"),
                &format!("-L{}", dir.display()),
                "-lfoo",
            ]);
            // The real loader is the reference: the program starts, from another directory.
            let run = Command::new(p("app"))
                .current_dir("/")
                .env_remove("LD_LIBRARY_PATH")
                .output()
                .unwrap();
            assert!(run.status.success(), "{dtags} {list}: the loader runs it");

            let graph = Command::new(bin)
                .args(["graph", "--format", "json", &p("app")])
                .output()
                .expect("run");
            let stderr = String::from_utf8_lossy(&graph.stderr);
            assert!(graph.status.success(), "{dtags} {list}: graph: {stderr}");
            let report: serde_json::Value = serde_json::from_slice(&graph.stdout).unwrap();
            assert!(report.to_string().contains("libfoo.so"), "{report}");

            let rootfs = dir.join("rootfs");
            let pack = Command::new(bin)
                .args(["pack", "-n", "-o", rootfs.to_str().unwrap(), &p("app")])
                .output()
                .expect("run");
            let stderr = String::from_utf8_lossy(&pack.stderr);
            assert!(pack.status.success(), "{dtags} {list}: pack: {stderr}");
            assert!(walk_contains(&rootfs, "libfoo.so"), "{dtags} {list}");
        }
    }
}

#[test]
fn a_library_in_a_directory_named_with_a_colon_still_packs() {
    // RUNPATH `$ORIGIN/x:y` with libfoo in a directory literally named `x:y`. ld.so splits the
    // string and misses it, but the staged ld.so.cache lists `x:y`, so a 1.9 image of this
    // program starts. The split must not turn that pack into a failure.
    if !cc_available() {
        skip_required("no C compiler");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let libdir = dir.join("x:y");
    std::fs::create_dir(&libdir).unwrap();
    std::fs::write(dir.join("foo.c"), "int foo(void){return 42;}").unwrap();
    std::fs::write(
        dir.join("main.c"),
        "extern int foo(void); int main(void){return foo()==42?0:1;}",
    )
    .unwrap();
    let p = |name: &str| dir.join(name).to_str().unwrap().to_string();
    cc(&["-shared", "-fPIC", "-o", &p("x:y/libfoo.so"), &p("foo.c")]);
    cc(&[
        "-Wl,--enable-new-dtags",
        "-Wl,-rpath,$ORIGIN/x:y",
        "-o",
        &p("app"),
        &p("main.c"),
        &format!("-L{}", libdir.display()),
        "-lfoo",
    ]);

    let bin = env!("CARGO_BIN_EXE_scratchsmith");
    let rootfs = dir.join("rootfs");
    let pack = Command::new(bin)
        .args(["pack", "-n", "-o", rootfs.to_str().unwrap(), &p("app")])
        .output()
        .expect("run");
    let stderr = String::from_utf8_lossy(&pack.stderr);
    assert!(pack.status.success(), "pack: {stderr}");
    let staged = rootfs.join(libdir.canonicalize().unwrap().strip_prefix("/").unwrap());
    assert!(staged.join("libfoo.so").is_file(), "{stderr}");
}

#[test]
fn a_truncated_program_interpreter_gives_graph_and_pack_the_same_error() {
    // libc.so.6 lists the host loader as DT_NEEDED, not this copy, so only PT_INTERP reaches it.
    if !cc_available() {
        skip_required("no C compiler");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let host_loader = read_elf_info(Path::new("/usr/bin/id"))
        .unwrap()
        .interpreter
        .expect("/usr/bin/id has PT_INTERP");
    let full = std::fs::read(&host_loader).unwrap();
    let loader = dir.join("ld-damaged.so.2");
    std::fs::write(&loader, &full[..600]).unwrap();
    std::fs::write(dir.join("main.c"), "int main(void){return 0;}").unwrap();
    let app = dir.join("app");
    cc(&[
        &format!("-Wl,--dynamic-linker={}", loader.display()),
        "-o",
        app.to_str().unwrap(),
        dir.join("main.c").to_str().unwrap(),
    ]);

    let bin = env!("CARGO_BIN_EXE_scratchsmith");
    let rootfs = dir.join("rootfs");
    let app = app.to_str().unwrap();
    let rootfs = rootfs.to_str().unwrap();
    let mut msgs = Vec::new();
    for args in [
        vec!["graph", app],
        vec!["graph", "--format", "json", app],
        vec!["pack", "-n", "-o", rootfs, app],
        vec!["pack", "--format", "json", "-n", "-o", rootfs, app],
    ] {
        let out = Command::new(bin).args(&args).output().expect("run");
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        assert_eq!(out.status.code(), Some(1), "{args:?} must fail: {stderr}");
        assert!(
            stderr.contains("the program interpreter (PT_INTERP)")
                && stderr.contains("ld-damaged.so.2 starts like an ELF and cannot be parsed")
                && stderr.contains("Replace it with an intact copy")
                && stderr.contains("not a valid ELF binary:")
                && !stderr.contains("warning: "),
            "{args:?}: the error must name the file, the fix and the cause: {stderr}"
        );
        assert!(out.stdout.is_empty(), "{args:?}: no report on a failure");
        msgs.push(stderr);
    }
    assert!(
        msgs.iter().all(|m| m == &msgs[0]),
        "graph and pack must print the same error: {msgs:?}"
    );
    assert!(
        !walk_contains(Path::new(rootfs), "ld-damaged.so.2"),
        "the damaged loader must not stage"
    );
}
