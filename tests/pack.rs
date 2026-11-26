//! End-to-end against a live Docker daemon: pack real binaries into scratch images
//! and smoke-run them. Skipped when no Docker daemon is reachable (e.g. minimal CI).

use scratchsmith::image::{smoke_run, ImageConfig, Runtime};
use scratchsmith::pack::PackOptions;
use scratchsmith::resolver::{resolve, Sysroot};
use scratchsmith::stager::{AddFile, RuntimeExtras};
use std::path::Path;
use std::process::Command;
use std::sync::Mutex;

mod common;
use common::{
    docker_available, fake_tools, grype_available, skip_optional, skip_required, small_fixture,
    strip_available, syft_available, upx_available, FAKE_SYFT,
};

// Docker tests pack the same binary into the same derived tag, so they must not run
// concurrently or one test's cleanup deletes another's image. Serialize them.
static DOCKER: Mutex<()> = Mutex::new(());

fn docker_lock() -> std::sync::MutexGuard<'static, ()> {
    DOCKER.lock().unwrap_or_else(|e| e.into_inner())
}

fn rmi(tag: &str) {
    let _ = Command::new("docker").args(["rmi", "-f", tag]).output();
}

fn find_tini_exists() -> bool {
    [
        "/usr/bin/tini",
        "/sbin/tini",
        "/usr/bin/tini-static",
        "/sbin/tini-static",
        "/bin/tini",
    ]
    .iter()
    .any(|p| Path::new(p).exists())
}

#[test]
fn sbom_is_generated_or_fails_with_a_clear_error() {
    // The -n -o path needs no Docker. Whether syft is present or not, --sbom must
    // never silently skip: it writes the SBOM, or it fails with an install hint.
    let bin = env!("CARGO_BIN_EXE_scratchsmith");
    let tmp = tempfile::tempdir().unwrap();
    let rootfs = tmp.path().join("rf");
    let sbom = tmp.path().join("sbom.json");
    let out = Command::new(bin)
        .args([
            "pack",
            "-n",
            "-o",
            rootfs.to_str().unwrap(),
            "--sbom",
            "--sbom-file",
            sbom.to_str().unwrap(),
            bin,
        ])
        .output()
        .unwrap();
    if syft_available() {
        assert!(out.status.success(), "pack --sbom should succeed with syft");
        assert!(sbom.exists(), "SBOM file should be written");
    } else {
        assert!(!out.status.success(), "missing syft must fail, not skip");
        assert!(String::from_utf8_lossy(&out.stderr).contains("syft not found"));
    }
}

#[test]
fn scan_runs_or_fails_with_a_clear_error() {
    // The -n -o path needs no Docker. Whether grype is present or not, --scan must never
    // silently skip: it scans the rootfs and reports counts, or it fails with an install hint.
    let bin = env!("CARGO_BIN_EXE_scratchsmith");
    let tmp = tempfile::tempdir().unwrap();
    let rootfs = tmp.path().join("rf");
    let out = Command::new(bin)
        .args(["pack", "-n", "-o", rootfs.to_str().unwrap(), "--scan", bin])
        .output()
        .unwrap();
    if grype_available() {
        assert!(
            out.status.success(),
            "pack --scan should succeed with grype"
        );
        assert!(String::from_utf8_lossy(&out.stdout).contains("vulnerabilities:"));
    } else {
        assert!(!out.status.success(), "missing grype must fail, not skip");
        assert!(String::from_utf8_lossy(&out.stderr).contains("grype not found"));
    }
}

#[test]
fn max_size_gate_fails_when_over_and_passes_when_under() {
    // The -n -o path needs no Docker: it stages + measures, then the size gate runs.
    let bin = env!("CARGO_BIN_EXE_scratchsmith");
    let Some(fixture) = small_fixture() else {
        skip_required("no id binary to pack");
        return;
    };
    let packed = fixture.to_str().unwrap();
    let tmp = tempfile::tempdir().unwrap();

    // A 1-byte budget can't fit any real binary → fail loud, naming the limit.
    let over = Command::new(bin)
        .args([
            "pack",
            "-n",
            "-o",
            tmp.path().join("over").to_str().unwrap(),
            "--max-size",
            "1",
            packed,
        ])
        .output()
        .unwrap();
    assert!(!over.status.success(), "a 1-byte --max-size must fail");
    assert!(String::from_utf8_lossy(&over.stderr).contains("max-size"));

    // A generous budget passes.
    let under = Command::new(bin)
        .args([
            "pack",
            "-n",
            "-o",
            tmp.path().join("under").to_str().unwrap(),
            "--max-size",
            "10GB",
            packed,
        ])
        .output()
        .unwrap();
    assert!(
        under.status.success(),
        "a 10GB --max-size should pass: {}",
        String::from_utf8_lossy(&under.stderr)
    );
}

#[test]
fn runtime_extras_stage_ca_and_tz_without_docker() {
    // --ca-certs and --tz copy host files into the rootfs (no Docker needed).
    let bin = Path::new(env!("CARGO_BIN_EXE_scratchsmith"));
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("rootfs");
    let opts = PackOptions {
        extras: RuntimeExtras {
            ca_certs: true,
            tz: true,
            init: false,
            tmp: false,
        },
        ..Default::default()
    };
    scratchsmith::pack::stage_only(bin, &out, &opts).expect("stage with extras");
    assert!(
        out.join("etc/ssl/certs/ca-certificates.crt").exists(),
        "CA bundle not staged"
    );
    assert!(out.join("etc/localtime").exists(), "localtime not staged");
}

#[test]
fn tmp_stages_an_empty_sticky_tmp_without_docker() {
    use std::os::unix::fs::PermissionsExt;
    let bin = Path::new(env!("CARGO_BIN_EXE_scratchsmith"));
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("rootfs");
    let opts = PackOptions {
        extras: RuntimeExtras {
            tmp: true,
            ..Default::default()
        },
        ..Default::default()
    };
    scratchsmith::pack::stage_only(bin, &out, &opts).expect("stage with --tmp");
    let meta = std::fs::symlink_metadata(out.join("tmp")).unwrap();
    assert!(meta.is_dir());
    assert_eq!(meta.permissions().mode() & 0o7777, 0o1777);
    assert_eq!(std::fs::read_dir(out.join("tmp")).unwrap().count(), 0);

    // Without the flag there is no /tmp, as before.
    let bare = tmp.path().join("bare");
    scratchsmith::pack::stage_only(bin, &bare, &PackOptions::default()).unwrap();
    assert!(!bare.join("tmp").exists());
}

#[test]
fn add_binary_stages_the_added_elf_with_its_libraries() {
    let Some(fixture) = small_fixture() else {
        skip_required("no id binary to pack");
        return;
    };
    let bash = Path::new("/usr/bin/bash");
    if !bash.exists() {
        skip_required("no /usr/bin/bash to add");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("rootfs");
    let opts = PackOptions {
        add_binaries: vec![AddFile::parse("/usr/bin/bash:/bin/bash").unwrap()],
        ..Default::default()
    };
    scratchsmith::pack::stage_only(fixture, &out, &opts).expect("stage with --add-binary");
    assert!(out.join("bin/bash").is_file(), "bash not staged");
    // Every library bash needs is in the tree, at the path it was resolved to.
    let theirs = resolve(bash, &Sysroot::new("/")).unwrap();
    assert!(!theirs.libs.is_empty());
    for lib in &theirs.libs {
        let image = out.join(lib.path.strip_prefix("/").unwrap());
        assert!(image.exists(), "{} not staged", lib.path.display());
    }
    // Without the flag, bash's own libraries (libtinfo on Debian and Ubuntu) do not ship.
    let bare = tmp.path().join("bare");
    scratchsmith::pack::stage_only(fixture, &bare, &PackOptions::default()).unwrap();
    let id_libs = resolve(fixture, &Sysroot::new("/")).unwrap().libs;
    for lib in theirs.libs.iter().filter(|l| !id_libs.contains(l)) {
        assert!(!bare.join(lib.path.strip_prefix("/").unwrap()).exists());
    }
}

#[test]
fn add_binary_refuses_a_file_that_is_not_an_elf() {
    let Some(fixture) = small_fixture() else {
        skip_required("no id binary to pack");
        return;
    };
    let tmp = tempfile::tempdir().unwrap();
    let script = tmp.path().join("run.sh");
    std::fs::write(&script, b"#!/bin/sh\necho hi\n").unwrap();
    let opts = PackOptions {
        add_binaries: vec![AddFile {
            src: script.clone(),
            dst: "/run.sh".into(),
        }],
        ..Default::default()
    };
    let err =
        scratchsmith::pack::stage_only(fixture, &tmp.path().join("rootfs"), &opts).unwrap_err();
    let err = format!("{err:#}");
    assert!(
        err.contains("is not an ELF file: add it with --add-file"),
        "{err}"
    );

    // A mistyped path is not told to use --add-file.
    let opts = PackOptions {
        add_binaries: vec![AddFile {
            src: tmp.path().join("missing"),
            dst: "/missing".into(),
        }],
        ..Default::default()
    };
    let err =
        scratchsmith::pack::stage_only(fixture, &tmp.path().join("rootfs2"), &opts).unwrap_err();
    let err = format!("{err:#}");
    assert!(!err.contains("--add-file"), "{err}");
}

#[test]
fn add_binary_copies_a_symlinked_program_whatever_symlinks_says() {
    let Some(fixture) = small_fixture() else {
        skip_required("no id binary to pack");
        return;
    };
    let tmp = tempfile::tempdir().unwrap();
    let link = tmp.path().join("my-id");
    std::os::unix::fs::symlink(fixture, &link).unwrap();
    let out = tmp.path().join("rootfs");
    let opts = PackOptions {
        add_binaries: vec![AddFile {
            src: link,
            dst: "/bin/my-id".into(),
        }],
        symlinks: scratchsmith::stager::SymlinkMode::Preserve,
        ..Default::default()
    };
    scratchsmith::pack::stage_only(fixture, &out, &opts).expect("stage with a linked --add-binary");
    let meta = std::fs::symlink_metadata(out.join("bin/my-id")).unwrap();
    assert!(meta.is_file(), "the added program is a file, not a link");
}

#[test]
fn add_file_copies_host_files_into_the_rootfs() {
    // The -n -o path needs no Docker: --add-file copies land beside the staged libs.
    let bin = env!("CARGO_BIN_EXE_scratchsmith");
    let Some(fixture) = small_fixture() else {
        skip_required("no id binary to pack");
        return;
    };
    let packed = fixture.to_str().unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("app.conf");
    std::fs::write(&src, b"threads = 4").unwrap();
    let out = tmp.path().join("rootfs");

    let relocated = format!("{}:/etc/app/app.conf", src.display());
    // A bare SRC is its own destination, so this one mirrors its host path.
    let mirrored = src.display().to_string();
    let staged = Command::new(bin)
        .args([
            "pack",
            "-n",
            "-o",
            out.to_str().unwrap(),
            "--add-file",
            relocated.as_str(),
            "--add-file",
            mirrored.as_str(),
            packed,
        ])
        .output()
        .unwrap();
    assert!(
        staged.status.success(),
        "--add-file pack failed: {}",
        String::from_utf8_lossy(&staged.stderr)
    );
    assert_eq!(
        std::fs::read(out.join("etc/app/app.conf")).unwrap(),
        b"threads = 4",
        "SRC:DST did not land at DST"
    );
    assert!(
        out.join(src.strip_prefix("/").unwrap()).exists(),
        "a bare SRC did not mirror its host path"
    );

    // A directory is refused by name rather than silently skipped — the image would
    // otherwise ship without what the user asked for.
    let dir_spec = format!("{}:/etc", tmp.path().display());
    let refused = Command::new(bin)
        .args([
            "pack",
            "-n",
            "-o",
            tmp.path().join("rootfs-dir").to_str().unwrap(),
            "--add-file",
            dir_spec.as_str(),
            packed,
        ])
        .output()
        .unwrap();
    assert!(
        !refused.status.success(),
        "--add-file of a directory must fail"
    );
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(stderr.contains("is a directory"), "{stderr}");
}

#[test]
fn symlinks_preserve_puts_the_named_binary_path_back() {
    // Packing a symlinked binary stages the REAL file and, by default, nothing else: the
    // path the user typed is gone from the image. --symlinks puts it back as a link.
    let bin = env!("CARGO_BIN_EXE_scratchsmith");
    let Some(fixture) = small_fixture() else {
        skip_required("no id binary to pack");
        return;
    };
    let tmp = tempfile::tempdir().unwrap();
    let real = tmp.path().join("real/id-real");
    std::fs::create_dir_all(real.parent().unwrap()).unwrap();
    std::fs::copy(fixture, &real).unwrap();
    let link = tmp.path().join("bin/id-link");
    std::fs::create_dir_all(link.parent().unwrap()).unwrap();
    std::os::unix::fs::symlink("../real/id-real", &link).unwrap();

    let pack = |mode: Option<&str>, out: &Path| {
        let mut args = vec!["pack", "-n", "-o", out.to_str().unwrap()];
        if let Some(m) = mode {
            args.push("--symlinks");
            args.push(m);
        }
        args.push(link.to_str().unwrap());
        let done = Command::new(bin).args(&args).output().unwrap();
        assert!(
            done.status.success(),
            "pack failed: {}",
            String::from_utf8_lossy(&done.stderr)
        );
    };

    // Default: the real file only, exactly as every release before this one packed it.
    let flat = tmp.path().join("flat");
    pack(None, &flat);
    let named = flat.join(link.strip_prefix("/").unwrap());
    assert!(
        flat.join(real.strip_prefix("/").unwrap()).exists(),
        "the real binary must always be staged"
    );
    assert!(
        named.symlink_metadata().is_err(),
        "copy-all must not create the named path"
    );

    // preserve: the named path is back, as a link, and its target is the staged real file.
    let kept = tmp.path().join("kept");
    pack(Some("preserve"), &kept);
    let named = kept.join(link.strip_prefix("/").unwrap());
    let md = named
        .symlink_metadata()
        .expect("preserve must create the named path");
    assert!(md.file_type().is_symlink(), "the named path must be a link");
    // The value must be RELATIVE. An absolute one resolves against the host root, so
    // `named.exists()` alone would pass on the host file whether or not the staged copy is
    // there, which measures nothing. Resolve it by hand inside the staging tree instead.
    let value = std::fs::read_link(&named).unwrap();
    assert!(
        value.is_relative(),
        "the link value must be relative, got {}",
        value.display()
    );
    let staged_real = kept.join(real.strip_prefix("/").unwrap());
    assert_eq!(
        named.parent().unwrap().join(&value).canonicalize().unwrap(),
        staged_real.canonicalize().unwrap(),
        "the link must resolve to the staged binary, not to the host one"
    );
}

#[test]
fn a_dotdot_binary_path_packs_in_every_symlinks_mode() {
    // `pack ../app` from a sibling directory: the `..` must not reach the image path. It
    // failed with "File exists" in every mode but copy-all, because the link for the name
    // landed on the staged binary itself.
    let bin = env!("CARGO_BIN_EXE_scratchsmith");
    let Some(fixture) = small_fixture() else {
        skip_required("no id binary to pack");
        return;
    };
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().canonicalize().unwrap();
    let real = root.join("app");
    std::fs::copy(fixture, &real).unwrap();
    std::fs::create_dir_all(root.join("build")).unwrap();
    std::fs::create_dir_all(root.join("bin")).unwrap();
    let link = root.join("bin/link");
    std::os::unix::fs::symlink("../app", &link).unwrap();

    for mode in ["copy-all", "preserve", "copy-unsafe", "skip-unsafe"] {
        for (arg, tag) in [("../app", "plain"), ("../bin/link", "link")] {
            let out = root.join(format!("out-{mode}-{tag}"));
            let done = Command::new(bin)
                .current_dir(root.join("build"))
                .args([
                    "pack",
                    "-n",
                    "-o",
                    out.to_str().unwrap(),
                    "--symlinks",
                    mode,
                    arg,
                ])
                .output()
                .unwrap();
            assert!(
                done.status.success(),
                "{mode} {arg}: {}",
                String::from_utf8_lossy(&done.stderr)
            );
            let staged_real = out.join(real.strip_prefix("/").unwrap());
            assert!(
                staged_real.is_file(),
                "{mode} {arg}: the real binary is staged"
            );
            if tag == "plain" {
                continue;
            }
            // The name the user gave comes back as a link, outside copy-all, and its
            // relative value resolves to the staged binary, not past it.
            let named = out.join(link.strip_prefix("/").unwrap());
            if mode == "copy-all" {
                assert!(named.symlink_metadata().is_err(), "{mode}: no named link");
                continue;
            }
            let value = std::fs::read_link(&named).unwrap();
            assert_eq!(value, Path::new("../app"), "{mode}");
            assert_eq!(
                named.parent().unwrap().join(&value).canonicalize().unwrap(),
                staged_real.canonicalize().unwrap(),
                "{mode}: the link must resolve to the staged binary"
            );
        }
    }
}

#[test]
fn the_report_names_the_loader_the_image_carries() {
    // The loader's path is chosen by the binary's PT_INTERP, not by scratchsmith, so a pack
    // that does not name it leaves the one host-dependent path in the image unrecorded.
    let bin = env!("CARGO_BIN_EXE_scratchsmith");
    let Some(fixture) = small_fixture() else {
        skip_required("no id binary to pack");
        return;
    };
    let tmp = tempfile::tempdir().unwrap();
    let out = Command::new(bin)
        .args([
            "pack",
            "-n",
            "-o",
            tmp.path().join("rootfs").to_str().unwrap(),
            "--format",
            "json",
            fixture.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "pack failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let interp = report["interpreter"]
        .as_str()
        .expect("a dynamic binary must report its loader");
    // The reported path must be the one actually staged, not a guess.
    assert!(
        tmp.path()
            .join("rootfs")
            .join(interp.trim_start_matches('/'))
            .exists(),
        "the reported loader {interp} is not in the staged rootfs"
    );
}

// Pick a locale this host can actually stage: one already built as a directory, else one
// localedef can compile from /usr/share/i18n. Both are absent on a minimal container, and a
// host that cannot supply locale data cannot prove anything about staging it.
fn stageable_locale() -> Option<String> {
    let root = Path::new("/usr/lib/locale");
    if let Ok(entries) = std::fs::read_dir(root) {
        for entry in entries.flatten() {
            if entry.file_type().is_ok_and(|t| t.is_dir()) {
                return Some(entry.file_name().to_string_lossy().into_owned());
            }
        }
    }
    let have_localedef = ["/usr/bin/localedef", "/bin/localedef"]
        .iter()
        .any(|p| Path::new(p).exists());
    (have_localedef && Path::new("/usr/share/i18n/locales/en_US").exists())
        .then(|| "en_US.UTF-8".to_string())
}

#[test]
fn locale_stages_one_locale_and_never_the_archive() {
    // The -n -o path needs no Docker. Whichever source the host offers, the locale must land
    // under /usr/lib/locale, and the host's locale-archive must stay out of the image.
    let bin = env!("CARGO_BIN_EXE_scratchsmith");
    let Some(fixture) = small_fixture() else {
        skip_required("no id binary to pack");
        return;
    };
    let Some(locale) = stageable_locale() else {
        skip_optional("host has no locale directory and no localedef sources");
        return;
    };
    let packed = fixture.to_str().unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("rootfs");

    let staged = Command::new(bin)
        .args([
            "pack",
            "-n",
            "-o",
            out.to_str().unwrap(),
            "--locale",
            locale.as_str(),
            packed,
        ])
        .output()
        .unwrap();
    assert!(
        staged.status.success(),
        "--locale pack failed: {}",
        String::from_utf8_lossy(&staged.stderr)
    );
    let dir = out.join("usr/lib/locale").join(&locale);
    assert!(dir.join("LC_CTYPE").exists(), "{locale} has no LC_CTYPE");
    // Count the entries rather than name the archive: "no locale-archive" holds by
    // construction today, so asserting only its absence cannot fail. One entry for one
    // requested locale catches a later change that copies the whole /usr/lib/locale root,
    // archive or not.
    let entries: Vec<_> = std::fs::read_dir(out.join("usr/lib/locale"))
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(
        entries.len(),
        1,
        "one --locale must stage exactly one entry, got {entries:?}"
    );
    assert_eq!(entries[0].to_string_lossy(), locale);
    // Nothing selects the locale, so the pack says so rather than shipping a silent no-op.
    let text = String::from_utf8_lossy(&staged.stdout);
    assert!(text.contains("LANG"), "no LANG warning in: {text}");

    // A locale name is a directory name, never a path out of the staging root.
    let refused = Command::new(bin)
        .args([
            "pack",
            "-n",
            "-o",
            tmp.path().join("rootfs-escape").to_str().unwrap(),
            "--locale",
            "../../etc",
            packed,
        ])
        .output()
        .unwrap();
    assert!(!refused.status.success(), "--locale with a path must fail");
}

#[test]
fn init_wraps_the_entrypoint_with_tini_and_still_runs() {
    if !docker_available() {
        skip_required("no Docker daemon");
        return;
    }
    if !Path::new("/usr/bin/tini").exists() {
        skip_optional("no tini");
        return;
    }
    let _g = docker_lock();
    let bin = Path::new(env!("CARGO_BIN_EXE_scratchsmith"));
    let opts = PackOptions {
        extras: RuntimeExtras {
            init: true,
            ..Default::default()
        },
        ..Default::default()
    };
    let tag = scratchsmith::pack::run(bin, &opts)
        .expect("pack --init")
        .tag
        .unwrap();

    // Entrypoint is wrapped so tini is pid 1.
    let ep = Command::new("docker")
        .args(["inspect", "--format", "{{json .Config.Entrypoint}}", &tag])
        .output()
        .unwrap();
    let ep = String::from_utf8_lossy(&ep.stdout);
    assert!(ep.contains("/tini"), "entrypoint not wrapped: {ep}");

    // And the wrapped binary still runs under tini.
    let run = Command::new("docker")
        .args(["run", "--rm", &tag, "--version"])
        .output()
        .unwrap();
    assert!(run.status.success(), "tini-wrapped run failed: {run:?}");
    assert!(String::from_utf8_lossy(&run.stdout).contains("scratchsmith"));
    rmi(&tag);
}

#[test]
fn a_tmp_image_lets_the_default_user_create_a_file_in_tmp() {
    if !docker_available() {
        skip_required("no Docker daemon");
        return;
    }
    // touch is a dynamic glibc binary on every host that runs these tests, and it writes the
    // file itself: a scratch image has no shell to do it.
    let touch = Path::new("/usr/bin/touch");
    if !touch.exists() {
        skip_required("no /usr/bin/touch to pack");
        return;
    }
    let _g = docker_lock();
    let touch_in_tmp = |tmp: bool| {
        let opts = PackOptions {
            extras: RuntimeExtras {
                tmp,
                ..Default::default()
            },
            ..Default::default()
        };
        let tag = scratchsmith::pack::run(touch, &opts)
            .expect("pack touch")
            .tag
            .unwrap();
        // No --tmpfs and no --user: the image's own /tmp, as the default non-root user.
        let run = Command::new("docker")
            .args(["run", "--rm", &tag, "/tmp/ok"])
            .output()
            .unwrap();
        rmi(&tag);
        run
    };
    let with = touch_in_tmp(true);
    assert!(with.status.success(), "touch /tmp/ok with --tmp: {with:?}");
    let without = touch_in_tmp(false);
    assert!(
        !without.status.success(),
        "a scratch image with no --tmp has no /tmp: {without:?}"
    );
}

#[test]
fn an_added_bash_runs_in_the_image_with_no_include() {
    if !docker_available() {
        skip_required("no Docker daemon");
        return;
    }
    let Some(fixture) = small_fixture() else {
        skip_required("no id binary to pack");
        return;
    };
    if !Path::new("/usr/bin/bash").exists() {
        skip_required("no /usr/bin/bash to add");
        return;
    }
    let _g = docker_lock();
    let opts = PackOptions {
        add_binaries: vec![AddFile::parse("/usr/bin/bash:/bin/bash").unwrap()],
        ..Default::default()
    };
    let tag = scratchsmith::pack::run(fixture, &opts)
        .expect("pack id with bash added")
        .tag
        .unwrap();
    let run = Command::new("docker")
        .args([
            "run",
            "--rm",
            "--entrypoint",
            "/bin/bash",
            &tag,
            "-c",
            "echo ok",
        ])
        .output()
        .unwrap();
    rmi(&tag);
    assert!(run.status.success(), "bash -c in the image: {run:?}");
    assert_eq!(String::from_utf8_lossy(&run.stdout).trim(), "ok");
}

#[test]
fn init_without_tini_fails_clearly() {
    // Only meaningful where tini is absent; --init must fail loud, not silently skip.
    if find_tini_exists() {
        skip_optional("tini is installed");
        return;
    }
    let bin = Path::new(env!("CARGO_BIN_EXE_scratchsmith"));
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("rootfs");
    let opts = PackOptions {
        extras: RuntimeExtras {
            init: true,
            ..Default::default()
        },
        ..Default::default()
    };
    let err = scratchsmith::pack::stage_only(bin, &out, &opts).unwrap_err();
    assert!(err.to_string().contains("tini"), "got: {err}");
}

#[test]
fn stage_only_writes_a_rootfs_without_docker() {
    // The -n -o path needs no Docker: it just stages the tree to a directory.
    let bin = Path::new(env!("CARGO_BIN_EXE_scratchsmith"));
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("rootfs");
    let report =
        scratchsmith::pack::stage_only(bin, &out, &PackOptions::default()).expect("stage-only");

    // Binary at its entrypoint path, the loader, the cache, and the includes.
    assert!(out
        .join(
            std::path::Path::new(&report.entrypoint)
                .strip_prefix("/")
                .unwrap()
        )
        .exists());
    assert!(out.join("etc/ld.so.cache").exists(), "cache missing");
    assert!(out.join("etc/nsswitch.conf").exists(), "nsswitch missing");
    assert!(out.join("etc/passwd").exists(), "passwd missing");
    assert!(
        out.join("lib64").exists() || out.join("lib").exists(),
        "no loader dir"
    );
}

#[test]
fn packs_a_binary_that_runs_in_docker() {
    if !docker_available() {
        skip_required("no Docker daemon");
        return;
    }
    let _g = docker_lock();
    let bin = Path::new(env!("CARGO_BIN_EXE_scratchsmith"));
    let tag = scratchsmith::pack::run(bin, &PackOptions::default())
        .expect("pack should succeed")
        .tag
        .unwrap();

    let run = Command::new("docker")
        .args(["run", "--rm", &tag, "--version"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&run.stdout);
    assert!(run.status.success(), "container run failed: {run:?}");
    assert!(stdout.contains("scratchsmith"), "got: {stdout}");

    // FROM scratch: no shell, so an sh entrypoint must fail.
    let shell = Command::new("docker")
        .args([
            "run",
            "--rm",
            "--entrypoint",
            "/bin/sh",
            &tag,
            "-c",
            "echo hi",
        ])
        .output()
        .unwrap();
    assert!(!shell.status.success(), "scratch image must have no shell");
    rmi(&tag);
}

#[test]
fn index_in_a_container_with_no_ca_store_uses_the_bundled_roots() {
    // The real thing, not a simulation: scratchsmith packs itself, and the packed image has
    // no CA trust store and no SSL_CERT_FILE, like the published FROM scratch image. `index`
    // there used to fail before it reached the registry. It must now build its clients on
    // the roots compiled into the binary, say so, and go on to the network.
    //
    // `--network none` keeps it hermetic: the registry is a closed local port, so getting
    // as far as "pulling the manifest" is the proof that the clients were built.
    if !docker_available() {
        skip_required("no Docker daemon");
        return;
    }
    let _g = docker_lock();
    let bin = Path::new(env!("CARGO_BIN_EXE_scratchsmith"));
    let tag = scratchsmith::pack::run(bin, &PackOptions::default())
        .expect("pack should succeed")
        .tag
        .unwrap();

    let run = Command::new("docker")
        .args(["run", "--rm", "--network", "none", "--read-only", &tag])
        .args(["index", "127.0.0.1:1/x/y:1", "127.0.0.1:1/x/y:1-amd64"])
        .output()
        .unwrap();
    rmi(&tag);
    let stderr = String::from_utf8_lossy(&run.stderr);
    assert_eq!(
        run.status.code(),
        Some(1),
        "the closed port is a plain failure: {stderr}"
    );
    assert!(!stderr.contains("panicked"), "must not panic: {stderr}");
    assert!(
        stderr.contains("warning: the system CA trust store could not be used")
            && stderr.contains("Mozilla root certificates bundled with scratchsmith"),
        "the fallback must be announced: {stderr}"
    );
    assert!(
        stderr.contains("pulling the manifest for 127.0.0.1:1/x/y:1-amd64"),
        "the command must get past client construction to the registry: {stderr}"
    );
}

// A Fedora image, pinned by digest, for the rpm half of `--packages`. Docker Hub and not
// quay.io: quay.io removed the manifest behind its moving tag within two days of the tag
// moving on, and the pin to it then failed with "manifest unknown". Docker Hub is expected
// to keep an old digest of an official image.
//
// Docker pulls by the digest and ignores the tag. The tag is there for a reader, and for the
// Renovate regex manager in the shared `scratchsmith.json` preset, which moves this pin.
//
// This is Fedora 44 with rpm 6.0.2, and the script below depends on more than the pull: the
// sqlite database at usr/lib/sysimage/rpm/rpmdb.sqlite, the `pkg:rpm/fedora/` purl prefix,
// and a `ca-certificates` package in the base image. A move to a release that changes one
// of those fails in an assertion, not in the pull.
const FEDORA: &str =
    "docker.io/library/fedora:44@sha256:43b29f65a41eb9c35e1cd5323e3bdf3b655c2357a9f4f1ff2f9c2798e5045d80";

#[test]
fn packages_on_an_rpm_host_fill_the_report_the_sbom_and_the_image() {
    // The build host of this suite is Debian-based, so the rpm path runs where rpm is real:
    // the test binary is mounted into a Fedora container and packs Fedora's own /usr/bin/id.
    if !docker_available() {
        skip_required("no Docker daemon");
        return;
    }
    let _g = docker_lock();
    let bin = env!("CARGO_BIN_EXE_scratchsmith");
    // syft is one static file, so the host's copy runs in the container as it is.
    let syft = Command::new("sh")
        .args(["-c", "readlink -f \"$(command -v syft)\""])
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|p| !p.is_empty());
    let Some(syft) = syft else {
        skip_required("no syft to generate the SBOM");
        return;
    };
    // Each step prints one marked line; the assertions below read them.
    let script = r#"
set -eu
cd /tmp
host_before="$(rpm -qa | sort | sha256sum)"
scratchsmith pack -n -o report --format json /usr/bin/id > report.json
echo "REPORT $(tr -d ' \n' < report.json | grep -o '"name":"glibc","version":"[^"]*","arch":"[^"]*","source":"glibc","type":"rpm"' | head -1)"
scratchsmith pack -n -o sbom --packages report,sbom --sbom --sbom-file /tmp/sbom.json /usr/bin/id > /dev/null
echo "SBOM $(grep -o 'pkg:rpm/fedora/glibc@[^"?]*' sbom.json | head -1)"
echo "SBOM_LEFT $(find sbom -name 'rpmdb*' | wc -l) $(test -e sbom/etc/os-release && echo os-release || echo none)"
scratchsmith pack -n -o image --packages image --ca-certs /usr/bin/id > /dev/null
scratchsmith pack -n -o again --packages image --ca-certs /usr/bin/id > /dev/null
echo "IMAGE_FILES $(cd image && find . -path '*rpm*' -type f | sort | tr '\n' ' ')"
echo "IMAGE_DB $(rpm --root /tmp/image -qa --qf '%{NAME}\n' | sort | tr '\n' ' ')"
echo "IMAGE_DUPLICATES $(rpm --root /tmp/image -qa --qf '%{NAME}\n' | sort | uniq -d | wc -l)"
echo "SAME_BYTES $(sha256sum image/usr/lib/sysimage/rpm/rpmdb.sqlite again/usr/lib/sysimage/rpm/rpmdb.sqlite | cut -d' ' -f1 | sort -u | wc -l)"
echo "HOST_SAME $([ "$host_before" = "$(rpm -qa | sort | sha256sum)" ] && echo yes || echo no)"
mkdir -p mine && echo mine > mine/db
if scratchsmith pack -n -o clash --packages image --add-file /tmp/mine/db:/usr/lib/sysimage/rpm/rpmdb.sqlite /usr/bin/id > /dev/null 2> clash.err; then echo "CLASH packed"; else echo "CLASH refused $(grep -c -- '--add-file' clash.err)"; fi
"#;
    let mut docker = Command::new("docker");
    docker
        .args(["run", "--rm"])
        .args(["-v", &format!("{bin}:/usr/local/bin/scratchsmith:ro")])
        .args(["-v", &format!("{syft}:/usr/local/bin/syft:ro")]);
    // Under `cargo llvm-cov` every process that runs the test binary writes a profile to the
    // path in LLVM_PROFILE_FILE. A container inherits neither the variable nor the
    // directory, so the rpm code would run here and count as never run. Hand both over, and
    // run as the current user so the profiles are not left root-owned in the target dir.
    if let Some(profile) = std::env::var_os("LLVM_PROFILE_FILE") {
        let profile = std::path::PathBuf::from(profile);
        if let Some(dir) = profile.parent().filter(|d| d.is_absolute() && d.is_dir()) {
            let id = |flag: &str| {
                let out = Command::new("id").arg(flag).output().expect("run id");
                String::from_utf8_lossy(&out.stdout).trim().to_string()
            };
            docker
                .args(["--user", &format!("{}:{}", id("-u"), id("-g"))])
                .args(["-v", &format!("{0}:{0}", dir.display())])
                .args(["-e", &format!("LLVM_PROFILE_FILE={}", profile.display())]);
        }
    }
    let out = docker
        .args([FEDORA, "bash", "-c", script])
        .output()
        .expect("run the Fedora container");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stdout}\n{stderr}");
    let line = |tag: &str| {
        stdout
            .lines()
            .find_map(|l| l.strip_prefix(tag))
            .unwrap_or_else(|| panic!("no {tag} line in:\n{stdout}"))
            .trim()
            .to_string()
    };

    // The report names the rpm package, with its source package and the `rpm` type.
    assert!(line("REPORT ").contains(r#""type":"rpm""#), "{stdout}");
    // The SBOM names it with a distribution, so a scanner can match it...
    assert!(
        line("SBOM ").starts_with("pkg:rpm/fedora/glibc@"),
        "{stdout}"
    );
    // ...and `sbom` alone leaves no database and no os-release in the image.
    assert_eq!(line("SBOM_LEFT "), "0 none", "{stdout}");
    // `image` keeps one file: the database, with no lock and no sqlite working files.
    let files = line("IMAGE_FILES ");
    assert!(files.ends_with("rpmdb.sqlite"), "{files}");
    assert_eq!(
        files.split_whitespace().count(),
        1,
        "one file only: {files}"
    );
    // That database holds the owners and nothing else: far fewer packages than the host's.
    let db = line("IMAGE_DB ");
    assert!(db.contains("glibc") && db.contains("coreutils"), "{db}");
    // `--ca-certs` credits the bundle to `ca-certificates` by convention, through `rpm -q`.
    // That package is `noarch`, so this is also the proof that such a header is found.
    assert!(db.contains("ca-certificates"), "{db}");
    assert!(
        db.split_whitespace().count() < 12,
        "only the owning packages: {db}"
    );
    // The database holds each package once.
    assert_eq!(line("IMAGE_DUPLICATES "), "0", "{stdout}");
    // Two packs give the same database, byte for byte: one distinct checksum.
    assert_eq!(line("SAME_BYTES "), "1", "{stdout}");
    // The host's own database is read and never written: its package list is unchanged.
    assert_eq!(line("HOST_SAME "), "yes", "{stdout}");
    // A file the user added where the database goes is theirs. The pack must refuse, and
    // name the flag, and not replace it.
    assert_eq!(line("CLASH "), "refused 1", "{stdout}");
}

#[test]
fn upx_packed_image_smoke_runs() {
    if !docker_available() {
        skip_required("no Docker daemon");
        return;
    }
    if !upx_available() {
        skip_required("no upx");
        return;
    }
    let Some(bin) = small_fixture() else {
        skip_required("no id binary to pack");
        return;
    };
    let _g = docker_lock();
    // upx compresses the binary; smoke:true runs the image once and bails if the loader could
    // not start it — so a successful return proves the compressed image still starts.
    let opts = PackOptions {
        upx: true,
        smoke: true,
        ..Default::default()
    };
    let report = scratchsmith::pack::run(bin, &opts).expect("upx pack + smoke-run should succeed");
    assert_eq!(report.smoke_ok, Some(true));
    assert!(report.size.upx, "size report should flag upx");
    rmi(report.tag.as_deref().unwrap_or(""));
}

#[test]
fn image_config_is_reflected_in_docker_inspect() {
    if !docker_available() {
        skip_required("no Docker daemon");
        return;
    }
    let _g = docker_lock();
    let Some(bin) = small_fixture() else {
        skip_required("no id binary to pack");
        return;
    };
    let cfg = ImageConfig {
        entrypoint: vec![],
        cmd: vec!["--version".into()],
        env: vec!["FOO=bar".into()],
        workdir: Some("/work".into()),
        user: None,
        labels: vec!["role=api".into()],
        healthcheck: vec!["/health".into(), "--now".into()],
    };
    let tag = scratchsmith::pack::run(
        bin,
        &PackOptions {
            image: cfg,
            ..Default::default()
        },
    )
    .expect("pack")
    .tag
    .unwrap();

    let inspect = |fmt: &str| {
        let out = Command::new("docker")
            .args(["inspect", "--format", fmt, &tag])
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout).into_owned()
    };
    assert!(inspect("{{json .Config.Env}}").contains("FOO=bar"));
    assert!(inspect("{{json .Config.Cmd}}").contains("--version"));
    assert!(inspect("{{.Config.WorkingDir}}").contains("/work"));
    // Non-root by default.
    assert!(inspect("{{.Config.User}}").contains("65532"));
    // Labels + healthcheck (exec form) reach the image config.
    assert!(inspect("{{index .Config.Labels \"role\"}}").contains("api"));
    assert!(inspect("{{json .Config.Healthcheck.Test}}").contains("/health"));
    rmi(&tag);
}

#[test]
fn config_file_applies_and_cli_overrides_it() {
    if !docker_available() {
        skip_required("no Docker daemon");
        return;
    }
    let _g = docker_lock();
    let bin = env!("CARGO_BIN_EXE_scratchsmith"); // the CLI to invoke
    let Some(fixture) = small_fixture() else {
        skip_required("no id binary to pack");
        return;
    };
    let packed = fixture.to_str().unwrap(); // the (small) binary to pack
    let tag = "scratchsmith/id:packed"; // derived from the packed binary's name
    let tmp = tempfile::tempdir().unwrap();
    let toml = tmp.path().join("scratchsmith.toml");
    std::fs::write(
        &toml,
        "env = [\"CFGONLY=1\"]\nuser = \"1234:1234\"\nlabel = [\"cfgrole=cfg\"]\nhealthcheck = [\"/id\"]\n",
    )
    .unwrap();

    // Config only: values come from the file.
    let ok = Command::new(bin)
        .args(["pack", "--config", toml.to_str().unwrap(), packed])
        .status()
        .unwrap();
    assert!(ok.success());
    let inspect = |tag: &str| {
        let out = Command::new("docker")
            .args([
                "inspect",
                "--format",
                "{{.Config.User}} {{json .Config.Env}} {{json .Config.Labels}} {{json .Config.Healthcheck.Test}}",
                tag,
            ])
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout).into_owned()
    };
    let out = inspect(tag);
    assert!(out.contains("1234:1234"), "config user not applied: {out}");
    assert!(out.contains("CFGONLY=1"), "config env not applied: {out}");
    assert!(out.contains("cfgrole"), "config label not applied: {out}");
    assert!(out.contains("/id"), "config healthcheck not applied: {out}");
    rmi(tag);

    // CLI --user and --label override the config values (a non-empty CLI list replaces).
    Command::new(bin)
        .args([
            "pack",
            "--config",
            toml.to_str().unwrap(),
            "--user",
            "9999:9999",
            "--label",
            "clirole=cli",
            packed,
        ])
        .status()
        .unwrap();
    let out = inspect(tag);
    assert!(
        out.contains("9999:9999"),
        "CLI should override config user: {out}"
    );
    assert!(
        out.contains("clirole") && !out.contains("cfgrole"),
        "CLI label should replace the config label: {out}"
    );
    rmi(tag);
}

#[test]
fn smoke_run_passes_for_a_plain_binary() {
    if !docker_available() {
        skip_required("no Docker daemon");
        return;
    }
    let _g = docker_lock();
    let Some(bin) = small_fixture() else {
        skip_required("no id binary to pack");
        return;
    };
    let tag = scratchsmith::pack::run(bin, &PackOptions::default())
        .expect("pack")
        .tag
        .unwrap();

    // `id` with no args prints `uid=…` — proves the smoke-run mechanism starts the binary.
    let outcome = smoke_run(Runtime::Docker, &tag, &[], 15).expect("smoke run");
    assert!(
        !outcome.loader_failed(),
        "loader failed: {}",
        outcome.stderr
    );
    assert!(outcome.stdout.contains("uid="), "got: {}", outcome.stdout);
    rmi(&tag);
}

#[test]
fn a_smoke_run_of_a_pid_1_that_ignores_sigterm_ends_at_the_limit() {
    // TASK-211. `sleep` as PID 1 has no SIGTERM handler, so it ignores the signal the CLI
    // forwards. The smoke run must still end near its limit and leave no container.
    if !docker_available() {
        skip_required("no Docker daemon");
        return;
    }
    let _g = docker_lock();
    let sleep = Path::new("/usr/bin/sleep");
    if !sleep.exists() {
        skip_required("sleep not present");
        return;
    }
    let tag = scratchsmith::pack::run(sleep, &PackOptions::default())
        .expect("pack sleep")
        .tag
        .unwrap();
    let start = std::time::Instant::now();
    let outcome = smoke_run(Runtime::Docker, &tag, &["600"], 3).expect("smoke run");
    let took = start.elapsed();
    let left = Command::new("docker")
        .args(["ps", "-aq", "--filter", &format!("ancestor={tag}")])
        .output()
        .unwrap();
    let left = String::from_utf8_lossy(&left.stdout).trim().to_string();
    if !left.is_empty() {
        let _ = Command::new("docker").args(["rm", "-f", &left]).output();
    }
    rmi(&tag);
    assert!(took < std::time::Duration::from_secs(30), "took {took:?}");
    assert_eq!(outcome.code, None, "{outcome:?}");
    assert!(!outcome.loader_failed(), "{outcome:?}");
    assert!(left.is_empty(), "a container was left: {left}");
}

#[test]
fn smoke_run_proves_nss_lookups_work_in_image() {
    if !docker_available() {
        skip_required("no Docker daemon");
        return;
    }
    let _g = docker_lock();
    // getent is a dynamic glibc binary that resolves names through NSS. Packing it
    // and resolving `localhost` exercises the whole default-include chain (nsswitch
    // + libnss_files) inside the scratch image — the DNS-using-binary case.
    let getent = Path::new("/usr/bin/getent");
    if !getent.exists() {
        skip_required("getent not present");
        return;
    }
    let tag = scratchsmith::pack::run(getent, &PackOptions::default())
        .expect("pack getent")
        .tag
        .unwrap();

    let outcome = smoke_run(Runtime::Docker, &tag, &["hosts", "localhost"], 15).expect("smoke run");
    assert!(
        !outcome.loader_failed(),
        "loader failed: {}",
        outcome.stderr
    );
    assert!(
        outcome.stdout.contains("127.0.0.1") || outcome.stdout.contains("::1"),
        "NSS name lookup did not resolve localhost in the image; stdout={:?} stderr={:?}",
        outcome.stdout,
        outcome.stderr
    );
    rmi(&tag);
}

// --- Sink dispatch. The OCI-archive and rootfs sinks need no Docker daemon. ---

#[test]
fn oci_archive_sink_writes_daemonless() {
    let Some(bin) = small_fixture() else {
        skip_required("no id binary to pack");
        return;
    };
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("img.oci.tar");
    let report = scratchsmith::pack::pack(
        bin,
        &PackOptions::default(),
        scratchsmith::pack::Sink::OciArchive(out.clone()),
    )
    .expect("oci-archive pack should succeed");
    assert_eq!(report.archive.as_deref(), Some(out.to_str().unwrap()));
    assert!(report.tag.is_none(), "no image is loaded for --oci-archive");
    assert!(
        std::fs::metadata(&out)
            .map(|m| m.len() > 0)
            .unwrap_or(false),
        "archive not written"
    );
}

#[test]
fn smoke_with_oci_archive_is_rejected() {
    let bin = Path::new(env!("CARGO_BIN_EXE_scratchsmith"));
    let tmp = tempfile::tempdir().unwrap();
    let opts = PackOptions {
        smoke: true,
        ..Default::default()
    };
    let err = scratchsmith::pack::pack(
        bin,
        &opts,
        scratchsmith::pack::Sink::OciArchive(tmp.path().join("x.tar")),
    )
    .unwrap_err();
    assert!(err.to_string().contains("smoke"), "got: {err}");
}

#[test]
fn strip_leaves_a_non_elf_include_alone_and_still_strips_the_binary() {
    if !strip_available() {
        skip_required("no strip");
        return;
    }
    // The debug test binary carries symbols, so a strip that ran must shrink it.
    let bin = env!("CARGO_BIN_EXE_scratchsmith");
    let tmp = tempfile::tempdir().unwrap();
    let conf = tmp.path().canonicalize().unwrap().join("app.conf");
    let body = b"listen = 8080\n";
    std::fs::write(&conf, body).unwrap();
    let rootfs = tmp.path().join("rf");

    let out = Command::new(bin)
        .args([
            "pack",
            "-n",
            "-o",
            rootfs.to_str().unwrap(),
            "--strip",
            "--include",
            conf.to_str().unwrap(),
            bin,
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "--strip with a data --include must pack: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let staged_conf = rootfs.join(conf.strip_prefix("/").unwrap());
    assert_eq!(std::fs::read(&staged_conf).unwrap(), body);
    let real_bin = Path::new(bin).canonicalize().unwrap();
    let staged_bin = rootfs.join(real_bin.strip_prefix("/").unwrap());
    let before = std::fs::metadata(&real_bin).unwrap().len();
    let after = std::fs::metadata(&staged_bin).unwrap().len();
    assert!(
        after < before,
        "the binary was not stripped: {before} -> {after}"
    );
}

#[test]
fn rootfs_sink_stages_without_an_image() {
    let bin = Path::new(env!("CARGO_BIN_EXE_scratchsmith"));
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("rootfs");
    let report = scratchsmith::pack::pack(
        bin,
        &PackOptions::default(),
        scratchsmith::pack::Sink::Rootfs(out.clone()),
    )
    .expect("rootfs sink");
    assert!(report.tag.is_none() && report.archive.is_none());
    assert_eq!(report.staged_dir.as_deref(), Some(out.to_str().unwrap()));
}

#[test]
fn root_user_warns_but_still_packs() {
    // `--user 0` warns (the non-root default is recommended) but must not fail. The warning
    // is a report warning, so a gate on the JSON `warnings` array sees it (TASK-219), and the
    // text report prints it. The daemonless OCI-archive sink needs no Docker.
    let Some(bin) = small_fixture() else {
        skip_required("no id binary to pack");
        return;
    };
    let tmp = tempfile::tempdir().unwrap();
    for format in ["text", "json"] {
        let archive = tmp.path().join(format!("img-{format}.tar"));
        let out = Command::new(env!("CARGO_BIN_EXE_scratchsmith"))
            .args(["pack", "--user", "0", "--format", format, "--oci-archive"])
            .arg(&archive)
            .arg(bin)
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(out.status.success(), "pack should succeed: {stderr}");
        assert!(archive.exists(), "archive not written");
        if format == "json" {
            let report: serde_json::Value = serde_json::from_str(&stdout).unwrap();
            assert!(
                report["warnings"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|w| w.as_str().unwrap().contains("runs the image as root")),
                "root warning missing from the JSON warnings: {stdout}"
            );
        } else {
            assert!(
                stdout.contains("warning: --user 0 runs the image as root"),
                "root warning missing from the text report: {stdout}{stderr}"
            );
        }
        // Said once, in the report, not again on stderr.
        assert!(!stderr.contains("runs the image as root"), "{stderr}");
    }
}

#[test]
fn docker_load_sink_via_pack() {
    if !docker_available() {
        skip_required("no Docker daemon");
        return;
    }
    let _g = docker_lock();
    let Some(bin) = small_fixture() else {
        skip_required("no id binary to pack");
        return;
    };
    let tag = scratchsmith::pack::pack(
        bin,
        &PackOptions::default(),
        scratchsmith::pack::Sink::DockerLoad,
    )
    .expect("docker-load sink")
    .tag
    .expect("an image tag");
    rmi(&tag);
}

#[test]
fn smoke_with_push_is_rejected() {
    let bin = Path::new(env!("CARGO_BIN_EXE_scratchsmith"));
    let opts = PackOptions {
        smoke: true,
        ..Default::default()
    };
    let err = scratchsmith::pack::pack(
        bin,
        &opts,
        scratchsmith::pack::Sink::Push("localhost:5000/x:v1".into()),
    )
    .unwrap_err();
    assert!(err.to_string().contains("smoke"), "got: {err}");
}

// Runs `docker <args>` for each entry on drop, so a failed assertion (a panic) still removes
// the test registry and its loopback port binding.
struct DockerCleanup(Vec<Vec<String>>);

impl Drop for DockerCleanup {
    fn drop(&mut self) {
        for args in &self.0 {
            let _ = Command::new("docker").args(args).output();
        }
    }
}

fn docker_args(what: &[&str]) -> Vec<String> {
    what.iter().map(|s| s.to_string()).collect()
}

// A PATH whose cosign logs its arguments to $ASKED, and whose syft writes an empty SBOM.
fn signing_path(dir: &Path) -> std::ffi::OsString {
    fake_tools(
        dir,
        &[("cosign", r#"echo "$*" >> "$ASKED""#), ("syft", FAKE_SYFT)],
    )
}

// A mock registry for repository `app` that accepts any blob and manifest, so a push
// succeeds with no Docker daemon. A manifest PUT answers with its own digest.
fn mock_registry() -> (tokio::runtime::Runtime, wiremock::MockServer) {
    mock_registry_with(true)
}

// As `mock_registry`, but with `location: false` a manifest PUT answers 201 with no
// `Location`, as AWS ECR does.
fn mock_registry_with(location: bool) -> (tokio::runtime::Runtime, wiremock::MockServer) {
    use sha2::Digest;
    use wiremock::matchers::{method, path, path_regex};
    use wiremock::{Mock, ResponseTemplate};
    // wiremock serves from a thread of its own, so the CLI child process reaches it while
    // this runtime sits idle.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let server = rt.block_on(async {
        let server = wiremock::MockServer::start().await;
        let upload = |status| ResponseTemplate::new(status).insert_header("Location", "/upload");
        for (verb, at, status) in [
            ("POST", "/v2/app/blobs/uploads/", 202),
            ("PATCH", "/upload", 202),
            ("PUT", "/upload", 201),
        ] {
            Mock::given(method(verb))
                .and(path(at))
                .respond_with(upload(status))
                .mount(&server)
                .await;
        }
        Mock::given(method("PUT"))
            .and(path_regex("^/v2/app/manifests/"))
            .respond_with(move |req: &wiremock::Request| {
                let hex: String = sha2::Sha256::digest(&req.body)
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect();
                let digest = format!("sha256:{hex}");
                let created = ResponseTemplate::new(201);
                if location {
                    created
                        .insert_header("Location", format!("/v2/app/manifests/{digest}").as_str())
                } else {
                    created
                }
            })
            .mount(&server)
            .await;
        server
    });
    (rt, server)
}

fn received(rt: &tokio::runtime::Runtime, server: &wiremock::MockServer) -> usize {
    rt.block_on(server.received_requests()).unwrap().len()
}

#[test]
fn a_digest_in_push_warns_and_never_panics_when_the_registry_sends_no_location() {
    // TASK-241. oci-client 0.18.0 panicked on a push to a digest when the manifest PUT came
    // back with no `Location`. The push still goes to the digest, and it warns.
    let Some(bin) = small_fixture() else {
        skip_required("no id binary to pack");
        return;
    };
    let (rt, server) = mock_registry_with(false);
    let host = server.address().to_string();
    let tmp = tempfile::tempdir().unwrap();
    let digest = format!("sha256:{}", "0".repeat(64));
    for reference in [format!("{host}/app@{digest}"), format!("{host}/app:1")] {
        let out = Command::new(env!("CARGO_BIN_EXE_scratchsmith"))
            .args(["pack", "--packages", "none", "--push"])
            .arg(&reference)
            .arg(bin)
            .env("HOME", tmp.path())
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(0), "{reference}: {stderr}");
        assert!(!stderr.contains("panicked"), "{reference}: {stderr}");
        let warned = stderr.contains(&format!(
            "warning: a digest in the --push reference ({digest}) is deprecated"
        ));
        assert_eq!(warned, reference.contains('@'), "{reference}: {stderr}");
    }
    let manifests: Vec<String> = rt
        .block_on(server.received_requests())
        .unwrap()
        .iter()
        .filter(|r| r.method.as_str() == "PUT" && r.url.path().starts_with("/v2/app/manifests/"))
        .map(|r| r.url.path().to_string())
        .collect();
    assert_eq!(
        manifests,
        [
            format!("/v2/app/manifests/{digest}"),
            "/v2/app/manifests/1".to_string()
        ]
    );
}

#[test]
fn a_missing_cosign_fails_sign_before_anything_is_pushed() {
    // TASK-232. A PATH with no cosign, and a registry that records every request.
    let Some(bin) = small_fixture() else {
        skip_required("no id binary to pack");
        return;
    };
    let (rt, server) = mock_registry();
    let host = server.address().to_string();
    let tmp = tempfile::tempdir().unwrap();
    let empty = tmp.path().join("empty");
    std::fs::create_dir(&empty).unwrap();
    let pack = [
        "pack",
        "--push",
        &format!("{host}/app:1"),
        "--sign",
        bin.to_str().unwrap(),
    ];
    let index = [
        "index",
        "--sign",
        &format!("{host}/app:multi"),
        &format!("{host}/app:1"),
    ];
    for args in [&pack[..], &index[..]] {
        let out = Command::new(env!("CARGO_BIN_EXE_scratchsmith"))
            .args(args)
            .env("PATH", &empty)
            .env("HOME", tmp.path())
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(1), "{args:?}: {stderr}");
        assert!(
            stderr.contains("--sign needs cosign, so nothing was pushed")
                && stderr.contains("cosign not found"),
            "{args:?}: {stderr}"
        );
        assert_eq!(received(&rt, &server), 0, "{args:?} reached the registry");
    }
}

#[test]
fn a_signing_that_fails_after_the_push_says_the_image_is_not_signed() {
    // TASK-232. cosign answers `version`, then fails to sign the pushed image. With --sbom, a
    // sign that works and an attest that fails says the image is signed but not attested.
    let Some(bin) = small_fixture() else {
        skip_required("no id binary to pack");
        return;
    };
    let (rt, server) = mock_registry();
    let host = server.address().to_string();
    let tmp = tempfile::tempdir().unwrap();
    let sbom = tmp.path().join("sbom.json");
    for (fails, extra, says) in [
        ("sign", &[][..], "app:1 was pushed, but it is not signed"),
        (
            "attest",
            &["--sbom", "--sbom-file", sbom.to_str().unwrap()][..],
            "app:1 was pushed and signed, but its SBOM attestation failed",
        ),
    ] {
        let dir = tmp.path().join(fails);
        let tools = fake_tools(
            &dir,
            &[
                (
                    "cosign",
                    &format!(r#"[ "$1" = {fails} ] || exit 0; echo "no OIDC token" >&2; exit 1"#),
                ),
                ("syft", FAKE_SYFT),
            ],
        );
        let reference = format!("{host}/app:1");
        let out = Command::new(env!("CARGO_BIN_EXE_scratchsmith"))
            .args(["pack", "--packages", "none", "--push"])
            .arg(&reference)
            .arg("--sign")
            .args(extra)
            .arg(bin)
            .env("PATH", tools)
            .env("HOME", tmp.path())
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(1), "{fails}: {stderr}");
        assert!(
            // TASK-233: cosign writes to scratchsmith's own stderr, so its message shows
            // as it is, and the error points to it.
            stderr.contains(&format!("{host}/{says}"))
                && stderr.contains("no OIDC token\n")
                && stderr.contains("cosign failed (exit status: 1); its messages are above"),
            "{fails}: {stderr}"
        );
    }
    assert!(
        received(&rt, &server) > 0,
        "the push never reached the registry"
    );
}

// The digest the registry serves for `repo:tag`, read with a plain HTTP HEAD, so the test
// runs the image the push stored and not whatever the daemon holds under that tag.
fn registry_digest(port: u16, repo: &str, tag: &str) -> String {
    use std::io::{Read, Write};
    let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    // A response that kept the socket open would hang the test, and a killed test runs no
    // cleanup guard.
    s.set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .unwrap();
    write!(
        s,
        "HEAD /v2/{repo}/manifests/{tag} HTTP/1.1\r\nHost: localhost:{port}\r\n\
         Accept: application/vnd.oci.image.manifest.v1+json, \
         application/vnd.oci.image.index.v1+json\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut resp = String::new();
    s.read_to_string(&mut resp).unwrap();
    resp.lines()
        .find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.eq_ignore_ascii_case("docker-content-digest")
                .then(|| value.trim().to_string())
        })
        .unwrap_or_else(|| panic!("the registry reported no digest: {resp}"))
}

// The throwaway registry for the push tests, pinned by digest like `FEDORA`: `registry:2` is a
// tag that moves. The digest is the multi-arch index, so the pin pulls on any host arch. Same
// pin as `action-selftest.yml`, and the same Renovate regex manager moves it.
const REGISTRY: &str =
    "docker.io/library/registry:2@sha256:a3d8aaa63ed8681a604f1dea0aa03f100d5895b6a58ace528858a7b332415373";

#[test]
fn push_to_local_registry_is_pullable_and_runnable() {
    if !docker_available() {
        skip_required("no Docker daemon");
        return;
    }
    // Checked BEFORE the registry starts: under CI this is a panic, and the cleanup guard
    // exists only once the registry does.
    let Some(bin) = small_fixture() else {
        skip_required("no id binary to pack");
        return;
    };
    let _g = docker_lock();
    // A throwaway registry:2 for a real push → pull round-trip. The push path itself
    // contacts no Docker daemon; docker is only used here to run the registry + verify.
    let _ = Command::new("docker")
        .args(["rm", "-f", "ss-test-reg"])
        .output();
    let up = Command::new("docker")
        .args([
            "run",
            "-d",
            "--name",
            "ss-test-reg",
            // Loopback only: a published port bypasses the host firewall, and this
            // unauthenticated registry serves the tag the test later pulls and runs.
            "-p",
            "127.0.0.1:5099:5000",
            REGISTRY,
        ])
        .output()
        .unwrap();
    if !up.status.success() {
        skip_optional("could not start registry:2");
        return;
    }
    let reference = "localhost:5099/scratchsmith/test:v1";
    // Declared after the lock, so it runs before the lock is released.
    let mut cleanup = DockerCleanup(vec![docker_args(&["rm", "-f", "ss-test-reg"])]);
    // Wait for the registry port to accept connections.
    for _ in 0..40 {
        if std::net::TcpStream::connect("127.0.0.1:5099").is_ok() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(300));
    }

    let report = scratchsmith::pack::pack(
        bin,
        &PackOptions::default(),
        scratchsmith::pack::Sink::Push(reference.into()),
    )
    .expect("push should succeed");
    assert_eq!(report.pushed.as_deref(), Some(reference));
    assert!(report.tag.is_none() && report.archive.is_none());

    // HEAD-skip: pushing the identical image again reuses the blobs and still succeeds.
    scratchsmith::pack::pack(
        bin,
        &PackOptions::default(),
        scratchsmith::pack::Sink::Push(reference.into()),
    )
    .expect("re-push should succeed (blobs already present)");

    // The `--push` flag path through the CLI (a distinct tag on the same registry).
    let cli_ref = "localhost:5099/scratchsmith/test:cli";
    let cli = Command::new(env!("CARGO_BIN_EXE_scratchsmith"))
        .args(["pack", "--push", cli_ref, bin.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        cli.status.success(),
        "cli --push failed: {}",
        String::from_utf8_lossy(&cli.stderr)
    );
    assert!(String::from_utf8_lossy(&cli.stdout).contains("pushed"));

    // `--sign` signs the pushed digest and attaches the SBOM, with cosign and syft as
    // scripts that log their arguments.
    let tmp = tempfile::tempdir().unwrap();
    let log = tmp.path().join("asked");
    let sbom = tmp.path().join("sbom.json");
    let signed_ref = "localhost:5099/scratchsmith/test:signed";
    let signed = Command::new(env!("CARGO_BIN_EXE_scratchsmith"))
        .args([
            "pack",
            "--push",
            signed_ref,
            "--sign",
            "--sbom",
            "--sbom-file",
        ])
        .arg(&sbom)
        .arg(bin)
        .env("PATH", signing_path(tmp.path()))
        .env("ASKED", &log)
        .output()
        .unwrap();
    assert!(
        signed.status.success(),
        "cli --push --sign failed: {}",
        String::from_utf8_lossy(&signed.stderr)
    );
    let digest = registry_digest(5099, "scratchsmith/test", "signed");
    let by_digest = format!("localhost:5099/scratchsmith/test@{digest}");
    assert_eq!(
        std::fs::read_to_string(&log).unwrap(),
        format!(
            "version\nsign --yes {by_digest}\nattest --yes --type cyclonedx --predicate {} {by_digest}\n",
            sbom.display()
        )
    );

    // The pushed image pulls and runs, by the digest the registry stored for the tag.
    let (repo_ref, tag) = reference.rsplit_once(':').unwrap();
    let repo = repo_ref.split_once('/').unwrap().1;
    let by_digest = format!("{repo_ref}@{}", registry_digest(5099, repo, tag));
    cleanup.0.push(docker_args(&["rmi", "-f", &by_digest]));
    let pull = Command::new("docker")
        .args(["pull", &by_digest])
        .output()
        .unwrap();
    assert!(
        pull.status.success(),
        "pull failed: {}",
        String::from_utf8_lossy(&pull.stderr)
    );
    let run = Command::new("docker")
        .args(["run", "--rm", &by_digest])
        .output()
        .unwrap();
    assert!(run.status.success(), "run failed: {run:?}");
    assert!(String::from_utf8_lossy(&run.stdout).contains("uid="));
}

#[test]
fn index_assembles_a_pushed_image_into_an_index() {
    if !docker_available() {
        skip_required("no Docker daemon");
        return;
    }
    // Checked BEFORE the registry starts: under CI this is a panic, and the cleanup guard
    // exists only once the registry does.
    let Some(bin) = small_fixture() else {
        skip_required("no id binary to pack");
        return;
    };
    let _g = docker_lock();
    // A throwaway registry:2 (distinct name/port from the push test above) for a real
    // push -> index round-trip. The index path contacts no Docker daemon.
    let _ = Command::new("docker")
        .args(["rm", "-f", "ss-test-reg-idx"])
        .output();
    let up = Command::new("docker")
        .args([
            "run",
            "-d",
            "--name",
            "ss-test-reg-idx",
            // Loopback only, as above: keep the unauthenticated registry off the LAN.
            "-p",
            "127.0.0.1:5098:5000",
            REGISTRY,
        ])
        .output()
        .unwrap();
    if !up.status.success() {
        skip_optional("could not start registry:2");
        return;
    }
    let _cleanup = DockerCleanup(vec![docker_args(&["rm", "-f", "ss-test-reg-idx"])]);
    for _ in 0..40 {
        if std::net::TcpStream::connect("127.0.0.1:5098").is_ok() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(300));
    }

    // Push a per-arch image, then assemble it into an index. One child here: the full
    // pull -> assemble -> push path is what this exercises end-to-end; multi-child assembly
    // is unit-tested in registry.rs (a second real arch needs cross-arch hardware).
    let child = "localhost:5098/scratchsmith/idx:host";
    scratchsmith::pack::pack(
        bin,
        &PackOptions::default(),
        scratchsmith::pack::Sink::Push(child.into()),
    )
    .expect("pushing the child image should succeed");

    let target = "localhost:5098/scratchsmith/idx:multi";
    let outcome = scratchsmith::registry::push_index(target, &[child.to_string()])
        .expect("assembling and pushing the index should succeed");
    assert_eq!(outcome.entries.len(), 1);
    assert_eq!(outcome.entries[0].source, child);
    assert!(
        outcome.entries[0].platform.starts_with("linux/"),
        "unexpected platform: {}",
        outcome.entries[0].platform
    );
    assert!(
        matches!(
            outcome.digest_ref,
            scratchsmith::registry::PushedDigest::Confirmed(_)
        ),
        "the registry should report the pushed index digest"
    );

    // The target is a real, readable multi-arch index (best-effort: only if buildx is present).
    if let Ok(out) = Command::new("docker")
        .args(["buildx", "imagetools", "inspect", target])
        .output()
    {
        if out.status.success() {
            let s = String::from_utf8_lossy(&out.stdout);
            assert!(s.contains("linux/"), "index should list a platform: {s}");
        }
    }

    // Drive the same thing through the CLI `index` subcommand (covers the dispatch arm,
    // report building, and text output — the direct call above skips them).
    let cli_target = "localhost:5098/scratchsmith/idx:cli";
    let cli = Command::new(env!("CARGO_BIN_EXE_scratchsmith"))
        .args(["index", cli_target, child])
        .output()
        .unwrap();
    assert!(
        cli.status.success(),
        "cli index failed: {}",
        String::from_utf8_lossy(&cli.stderr)
    );
    assert!(String::from_utf8_lossy(&cli.stdout).contains("pushed index"));

    // Without `--sign`, the JSON report still carries `signed`, as null.
    let unsigned = Command::new(env!("CARGO_BIN_EXE_scratchsmith"))
        .args(["index", "--format", "json", cli_target, child])
        .output()
        .unwrap();
    assert!(
        unsigned.status.success(),
        "cli index --format json failed: {}",
        String::from_utf8_lossy(&unsigned.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&unsigned.stdout).unwrap();
    assert_eq!(
        report.get("signed"),
        Some(&serde_json::Value::Null),
        "{report}"
    );
    // Only an unsigned run can carry a digest mismatch as a warning; registry:2 returns none.
    assert_eq!(report["warnings"], serde_json::json!([]), "{report}");

    // `--sign` signs the index by digest; the JSON report names what it signed.
    let tmp = tempfile::tempdir().unwrap();
    let log = tmp.path().join("asked");
    let signed = Command::new(env!("CARGO_BIN_EXE_scratchsmith"))
        .args(["index", "--sign", "--format", "json", cli_target, child])
        .env("PATH", signing_path(tmp.path()))
        .env("ASKED", &log)
        .output()
        .unwrap();
    assert!(
        signed.status.success(),
        "cli index --sign failed: {}",
        String::from_utf8_lossy(&signed.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&signed.stdout).unwrap();
    // docs/usage.md lists these fields, so pin the set against this real push.
    let keys = |v: &serde_json::Value| {
        let mut k: Vec<String> = v.as_object().unwrap().keys().cloned().collect();
        k.sort();
        k
    };
    assert_eq!(
        keys(&report),
        ["manifests", "pushed", "signed", "warnings"],
        "{report}"
    );
    assert_eq!(report["pushed"], cli_target, "{report}");
    let manifest = &report["manifests"][0];
    assert_eq!(keys(manifest), ["digest", "platform", "source"], "{report}");
    assert_eq!(manifest["source"], child, "{report}");
    assert!(
        manifest["platform"].as_str().unwrap().starts_with("linux/"),
        "{report}"
    );
    assert!(
        manifest["digest"].as_str().unwrap().starts_with("sha256:"),
        "{report}"
    );
    let by_digest = format!(
        "localhost:5098/scratchsmith/idx@{}",
        registry_digest(5098, "scratchsmith/idx", "cli")
    );
    assert_eq!(report["signed"], by_digest.as_str(), "{report}");
    assert_eq!(
        std::fs::read_to_string(&log).unwrap(),
        format!("version\nsign --yes {by_digest}\n")
    );

    // Passing an index as a source is rejected — the pushed `:multi` is an index, so feeding
    // it back in must fail with a clear message (covers the media-type guard).
    let err = scratchsmith::registry::push_index(
        "localhost:5098/scratchsmith/idx:nested",
        &[target.to_string()],
    )
    .expect_err("an index passed as a source must be rejected");
    assert!(
        format!("{err:#}").contains("multi-arch index"),
        "got: {err}"
    );
}
