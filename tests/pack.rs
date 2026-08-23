//! End-to-end against a live Docker daemon: pack real binaries into scratch images
//! and smoke-run them. Skipped when no Docker daemon is reachable (e.g. minimal CI).

use scratchsmith::image::{smoke_run, ImageConfig};
use std::path::Path;
use std::process::Command;
use std::sync::Mutex;

// Docker tests pack the same binary into the same derived tag, so they must not run
// concurrently or one test's cleanup deletes another's image. Serialize them.
static DOCKER: Mutex<()> = Mutex::new(());

fn docker_lock() -> std::sync::MutexGuard<'static, ()> {
    DOCKER.lock().unwrap_or_else(|e| e.into_inner())
}

fn docker_available() -> bool {
    Command::new("docker")
        .arg("info")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn rmi(tag: &str) {
    let _ = Command::new("docker").args(["rmi", "-f", tag]).output();
}

#[test]
fn stage_only_writes_a_rootfs_without_docker() {
    // The -n -o path needs no Docker: it just stages the tree to a directory.
    let bin = Path::new(env!("CARGO_BIN_EXE_scratchsmith"));
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("rootfs");
    let tree = scratchsmith::pack::stage_only(bin, &out).expect("stage-only");

    // Binary at its entrypoint path, the loader, the cache, and the includes.
    assert!(out
        .join(tree.entrypoint.strip_prefix("/").unwrap())
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
        eprintln!("skipping: no Docker daemon");
        return;
    }
    let _g = docker_lock();
    let bin = Path::new(env!("CARGO_BIN_EXE_scratchsmith"));
    let tag =
        scratchsmith::pack::run(bin, false, &ImageConfig::default()).expect("pack should succeed");

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
fn image_config_is_reflected_in_docker_inspect() {
    if !docker_available() {
        eprintln!("skipping: no Docker daemon");
        return;
    }
    let _g = docker_lock();
    let bin = Path::new(env!("CARGO_BIN_EXE_scratchsmith"));
    let cfg = ImageConfig {
        entrypoint: vec![],
        cmd: vec!["--version".into()],
        env: vec!["FOO=bar".into()],
        workdir: Some("/work".into()),
    };
    let tag = scratchsmith::pack::run(bin, false, &cfg).expect("pack");

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
    rmi(&tag);
}

#[test]
fn smoke_run_passes_for_a_plain_binary() {
    if !docker_available() {
        eprintln!("skipping: no Docker daemon");
        return;
    }
    let _g = docker_lock();
    let bin = Path::new(env!("CARGO_BIN_EXE_scratchsmith"));
    let tag = scratchsmith::pack::run(bin, false, &ImageConfig::default()).expect("pack");

    let outcome = smoke_run(&tag, &["--version"], 15).expect("smoke run");
    assert!(
        !outcome.loader_failed(),
        "loader failed: {}",
        outcome.stderr
    );
    assert!(
        outcome.stdout.contains("scratchsmith"),
        "got: {}",
        outcome.stdout
    );
    rmi(&tag);
}

#[test]
fn smoke_run_proves_nss_lookups_work_in_image() {
    if !docker_available() {
        eprintln!("skipping: no Docker daemon");
        return;
    }
    let _g = docker_lock();
    // getent is a dynamic glibc binary that resolves names through NSS. Packing it
    // and resolving `localhost` exercises the whole default-include chain (nsswitch
    // + libnss_files) inside the scratch image — the DNS-using-binary case.
    let getent = Path::new("/usr/bin/getent");
    if !getent.exists() {
        eprintln!("skipping: getent not present");
        return;
    }
    let tag = scratchsmith::pack::run(getent, false, &ImageConfig::default()).expect("pack getent");

    let outcome = smoke_run(&tag, &["hosts", "localhost"], 15).expect("smoke run");
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
