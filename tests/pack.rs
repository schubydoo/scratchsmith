//! End-to-end: pack the scratchsmith binary into a scratch image, run it under
//! Docker, and confirm it executes and carries no base OS. Skipped when no Docker
//! daemon is reachable (e.g. minimal CI).

use std::path::Path;
use std::process::Command;

fn docker_available() -> bool {
    Command::new("docker")
        .arg("info")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[test]
fn packs_a_binary_that_runs_in_docker() {
    if !docker_available() {
        eprintln!("skipping packs_a_binary_that_runs_in_docker: no Docker daemon");
        return;
    }

    let bin = Path::new(env!("CARGO_BIN_EXE_scratchsmith"));
    let tag = scratchsmith::pack::run(bin).expect("pack should succeed");

    // The packed binary runs inside the scratch image and its deps resolve.
    let run = Command::new("docker")
        .args(["run", "--rm", &tag, "--version"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&run.stdout);
    assert!(run.status.success(), "container run failed: {:?}", run);
    assert!(stdout.contains("scratchsmith"), "got: {stdout}");

    // The image is FROM scratch: no shell, so an sh entrypoint must fail.
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
    assert!(
        !shell.status.success(),
        "scratch image must not contain a shell"
    );

    let _ = Command::new("docker").args(["rmi", "-f", &tag]).output();
}
