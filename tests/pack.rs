//! End-to-end against a live Docker daemon: pack real binaries into scratch images
//! and smoke-run them. Skipped when no Docker daemon is reachable (e.g. minimal CI).

use scratchsmith::image::{smoke_run, ImageConfig};
use scratchsmith::pack::PackOptions;
use scratchsmith::stager::RuntimeExtras;
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

fn upx_available() -> bool {
    Command::new("upx")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn grype_available() -> bool {
    Command::new("grype")
        .arg("version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn find_tini_exists() -> bool {
    [
        "/usr/bin/tini",
        "/sbin/tini",
        "/usr/bin/tini-static",
        "/bin/tini",
    ]
    .iter()
    .any(|p| Path::new(p).exists())
}

// A small dynamic-glibc system binary for the docker/registry tests that don't need to
// dogfood scratchsmith itself. Packing the 40 MB debug binary dominates their runtime;
// `id` is tiny, dynamically linked against glibc, exercises the NSS staging, and prints a
// checkable `uid=`. Returns None when absent so callers skip gracefully (parity with the
// getent/tini optional-tool tests) rather than panicking on a minimal host. The one dogfood
// test (packs_a_binary_that_runs_in_docker) still packs scratchsmith to prove the real
// binary works.
fn small_fixture() -> Option<&'static Path> {
    ["/usr/bin/id", "/bin/id"]
        .into_iter()
        .map(Path::new)
        .find(|p| p.exists())
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
        eprintln!("skipping: no id binary to pack");
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
fn init_wraps_the_entrypoint_with_tini_and_still_runs() {
    if !docker_available() {
        eprintln!("skipping: no Docker daemon");
        return;
    }
    if !Path::new("/usr/bin/tini").exists() {
        eprintln!("skipping: no tini");
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
fn init_without_tini_fails_clearly() {
    // Only meaningful where tini is absent; --init must fail loud, not silently skip.
    if find_tini_exists() {
        eprintln!("skipping: tini is installed");
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
        eprintln!("skipping: no Docker daemon");
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
fn upx_packed_image_smoke_runs() {
    if !docker_available() || !upx_available() {
        eprintln!("skipping upx_packed_image_smoke_runs: no docker or no upx");
        return;
    }
    let Some(bin) = small_fixture() else {
        eprintln!("skipping upx_packed_image_smoke_runs: no small fixture");
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
        eprintln!("skipping: no Docker daemon");
        return;
    }
    let _g = docker_lock();
    let Some(bin) = small_fixture() else {
        eprintln!("skipping: no id binary to pack");
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
    // Non-root by default (Task 2.3).
    assert!(inspect("{{.Config.User}}").contains("65532"));
    // Labels + healthcheck (exec form) reach the image config.
    assert!(inspect("{{index .Config.Labels \"role\"}}").contains("api"));
    assert!(inspect("{{json .Config.Healthcheck.Test}}").contains("/health"));
    rmi(&tag);
}

#[test]
fn config_file_applies_and_cli_overrides_it() {
    if !docker_available() {
        eprintln!("skipping: no Docker daemon");
        return;
    }
    let _g = docker_lock();
    let bin = env!("CARGO_BIN_EXE_scratchsmith"); // the CLI to invoke
    let Some(fixture) = small_fixture() else {
        eprintln!("skipping: no id binary to pack");
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
        eprintln!("skipping: no Docker daemon");
        return;
    }
    let _g = docker_lock();
    let Some(bin) = small_fixture() else {
        eprintln!("skipping: no id binary to pack");
        return;
    };
    let tag = scratchsmith::pack::run(bin, &PackOptions::default())
        .expect("pack")
        .tag
        .unwrap();

    // `id` with no args prints `uid=…` — proves the smoke-run mechanism starts the binary.
    let outcome = smoke_run(&tag, &[], 15).expect("smoke run");
    assert!(
        !outcome.loader_failed(),
        "loader failed: {}",
        outcome.stderr
    );
    assert!(outcome.stdout.contains("uid="), "got: {}", outcome.stdout);
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
    let tag = scratchsmith::pack::run(getent, &PackOptions::default())
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

// --- Sink dispatch (Task 5.1). The OCI-archive and rootfs sinks need no Docker daemon. ---

#[test]
fn oci_archive_sink_writes_daemonless() {
    let Some(bin) = small_fixture() else {
        eprintln!("skipping: no id binary to pack");
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
    // `--user 0` prints a warning (the non-root default is recommended) but must not
    // fail. Run via the CLI so we can assert the warning on stderr (it's an eprintln!,
    // not a report field); the daemonless OCI-archive sink needs no Docker.
    let Some(bin) = small_fixture() else {
        eprintln!("skipping: no id binary to pack");
        return;
    };
    let tmp = tempfile::tempdir().unwrap();
    let archive = tmp.path().join("img.tar");
    let out = Command::new(env!("CARGO_BIN_EXE_scratchsmith"))
        .args([
            "pack",
            "--user",
            "0",
            "--oci-archive",
            archive.to_str().unwrap(),
            bin.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "pack should succeed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(archive.exists(), "archive not written");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("runs the image as root"),
        "root warning missing from stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn docker_load_sink_via_pack() {
    if !docker_available() {
        eprintln!("skipping: no Docker daemon");
        return;
    }
    let _g = docker_lock();
    let Some(bin) = small_fixture() else {
        eprintln!("skipping: no id binary to pack");
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

#[test]
fn push_to_local_registry_is_pullable_and_runnable() {
    if !docker_available() {
        eprintln!("skipping: no Docker daemon");
        return;
    }
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
            "-p",
            "5099:5000",
            "registry:2",
        ])
        .output()
        .unwrap();
    if !up.status.success() {
        eprintln!("skipping: could not start registry:2");
        return;
    }
    // Wait for the registry port to accept connections.
    for _ in 0..40 {
        if std::net::TcpStream::connect("127.0.0.1:5099").is_ok() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(300));
    }

    // pack the small fixture, not the 40 MB debug binary
    let Some(bin) = small_fixture() else {
        eprintln!("skipping: no id binary to pack");
        return;
    };
    let reference = "localhost:5099/scratchsmith/test:v1";
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

    // The pushed image pulls and runs.
    let pull = Command::new("docker")
        .args(["pull", reference])
        .output()
        .unwrap();
    assert!(
        pull.status.success(),
        "pull failed: {}",
        String::from_utf8_lossy(&pull.stderr)
    );
    let run = Command::new("docker")
        .args(["run", "--rm", reference])
        .output()
        .unwrap();
    assert!(run.status.success(), "run failed: {run:?}");
    assert!(String::from_utf8_lossy(&run.stdout).contains("uid="));

    let _ = Command::new("docker")
        .args(["rm", "-f", "ss-test-reg"])
        .output();
    let _ = Command::new("docker")
        .args(["rmi", "-f", reference])
        .output();
}

#[test]
fn index_assembles_a_pushed_image_into_an_index() {
    if !docker_available() {
        eprintln!("skipping: no Docker daemon");
        return;
    }
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
            "-p",
            "5098:5000",
            "registry:2",
        ])
        .output()
        .unwrap();
    if !up.status.success() {
        eprintln!("skipping: could not start registry:2");
        return;
    }
    for _ in 0..40 {
        if std::net::TcpStream::connect("127.0.0.1:5098").is_ok() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(300));
    }

    let Some(bin) = small_fixture() else {
        eprintln!("skipping: no id binary to pack");
        return;
    };
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
        outcome.digest_ref.is_some(),
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

    let _ = Command::new("docker")
        .args(["rm", "-f", "ss-test-reg-idx"])
        .output();
}
