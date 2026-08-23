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

fn syft_available() -> bool {
    Command::new("syft")
        .arg("version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
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
fn stage_only_writes_a_rootfs_without_docker() {
    // The -n -o path needs no Docker: it just stages the tree to a directory.
    let bin = Path::new(env!("CARGO_BIN_EXE_scratchsmith"));
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("rootfs");
    let report = scratchsmith::pack::stage_only(bin, &out, false, None).expect("stage-only");

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
        eprintln!("skipping: no Docker daemon");
        return;
    }
    let _g = docker_lock();
    let bin = Path::new(env!("CARGO_BIN_EXE_scratchsmith"));
    let tag = scratchsmith::pack::run(bin, false, false, None, &ImageConfig::default())
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
        user: None,
    };
    let tag = scratchsmith::pack::run(bin, false, false, None, &cfg)
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
    // Non-root by default (Task 2.3).
    assert!(inspect("{{.Config.User}}").contains("65532"));
    rmi(&tag);
}

#[test]
fn config_file_applies_and_cli_overrides_it() {
    if !docker_available() {
        eprintln!("skipping: no Docker daemon");
        return;
    }
    let _g = docker_lock();
    let bin = env!("CARGO_BIN_EXE_scratchsmith");
    let tmp = tempfile::tempdir().unwrap();
    let toml = tmp.path().join("scratchsmith.toml");
    std::fs::write(&toml, "env = [\"CFGONLY=1\"]\nuser = \"1234:1234\"\n").unwrap();

    // Config only: values come from the file.
    let ok = Command::new(bin)
        .args(["pack", "--config", toml.to_str().unwrap(), bin])
        .status()
        .unwrap();
    assert!(ok.success());
    let user = |tag: &str| {
        let out = Command::new("docker")
            .args([
                "inspect",
                "--format",
                "{{.Config.User}} {{json .Config.Env}}",
                tag,
            ])
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout).into_owned()
    };
    let out = user("scratchsmith/scratchsmith:packed");
    assert!(out.contains("1234:1234"), "config user not applied: {out}");
    assert!(out.contains("CFGONLY=1"), "config env not applied: {out}");
    rmi("scratchsmith/scratchsmith:packed");

    // CLI --user overrides the config value.
    Command::new(bin)
        .args([
            "pack",
            "--config",
            toml.to_str().unwrap(),
            "--user",
            "9999:9999",
            bin,
        ])
        .status()
        .unwrap();
    let out = user("scratchsmith/scratchsmith:packed");
    assert!(
        out.contains("9999:9999"),
        "CLI should override config user: {out}"
    );
    rmi("scratchsmith/scratchsmith:packed");
}

#[test]
fn smoke_run_passes_for_a_plain_binary() {
    if !docker_available() {
        eprintln!("skipping: no Docker daemon");
        return;
    }
    let _g = docker_lock();
    let bin = Path::new(env!("CARGO_BIN_EXE_scratchsmith"));
    let tag = scratchsmith::pack::run(bin, false, false, None, &ImageConfig::default())
        .expect("pack")
        .tag
        .unwrap();

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
    let tag = scratchsmith::pack::run(getent, false, false, None, &ImageConfig::default())
        .expect("pack getent")
        .tag
        .unwrap();

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
