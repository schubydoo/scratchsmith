//! Assemble the staged rootfs into a container image. Task 1.6 targets the local
//! Docker daemon via a docker-archive tarball (the POC output sink); pure-Rust OCI
//! archive output and registry push come in Sprint 5. Reproducible layers are 2.9.

use crate::stager::StagedTree;
use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::Path;
use std::process::Command;

/// Assemble `staged` into an image and load it into the local Docker daemon as `tag`.
pub fn load_into_docker(staged: &StagedTree, tag: &str) -> Result<()> {
    let work = tempfile::tempdir().context("temp dir for image archive")?;
    let archive = work.path().join("image.tar");
    build_docker_archive(staged, tag, &archive)?;
    docker_load(&archive)?;
    Ok(())
}

// A docker-archive is a tar of: the image config, the single rootfs layer tar, and
// a manifest.json tying them together. `docker load` reads exactly this shape.
fn build_docker_archive(staged: &StagedTree, tag: &str, out: &Path) -> Result<()> {
    let work = tempfile::tempdir()?;
    let layer_path = work.path().join("layer.tar");
    let diff_id = write_layer_tar(&staged.root, &layer_path)?;

    let config = image_config(&staged.entrypoint, &diff_id);
    let config_bytes = serde_json::to_vec(&config)?;
    let config_name = format!("{}.json", hex(Sha256::digest(&config_bytes)));

    let manifest = serde_json::json!([{
        "Config": config_name,
        "RepoTags": [tag],
        "Layers": [format!("{diff_id}/layer.tar")],
    }]);
    let manifest_bytes = serde_json::to_vec(&manifest)?;

    let mut ar = tar::Builder::new(std::fs::File::create(out)?);
    append_bytes(&mut ar, &config_name, &config_bytes)?;
    append_path(&mut ar, &format!("{diff_id}/layer.tar"), &layer_path)?;
    append_bytes(&mut ar, "manifest.json", &manifest_bytes)?;
    ar.finish().context("finishing image archive")?;
    Ok(())
}

// Tar the staged rootfs with symlinks preserved (soname links must survive), and
// return the tar's sha256 as the layer diff_id. No gzip yet, so the compressed
// layer digest equals this; reproducible ordering/mtimes are Task 2.9.
fn write_layer_tar(root: &Path, out: &Path) -> Result<String> {
    let mut builder = tar::Builder::new(std::fs::File::create(out)?);
    builder.follow_symlinks(false);
    builder
        .append_dir_all(".", root)
        .context("adding staged rootfs to layer")?;
    builder.finish()?;
    drop(builder);
    let bytes = std::fs::read(out)?;
    Ok(hex(Sha256::digest(&bytes)))
}

fn image_config(entrypoint: &Path, diff_id: &str) -> serde_json::Value {
    serde_json::json!({
        // Host-arch only at v1; multi-arch is Task 5.4.
        "architecture": "amd64",
        "os": "linux",
        "config": {
            "Entrypoint": [entrypoint.to_string_lossy()],
            "Env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],
        },
        "rootfs": { "type": "layers", "diff_ids": [format!("sha256:{diff_id}")] },
        "history": [{ "created": "1970-01-01T00:00:00Z", "created_by": "scratchsmith" }],
    })
}

/// The result of running a packed image once.
#[derive(Debug, Clone)]
pub struct SmokeOutcome {
    /// Process exit code, or `None` if the container was killed (e.g. timeout).
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

impl SmokeOutcome {
    /// True when the dynamic loader failed to start the binary — a missing library,
    /// missing interpreter, or bad exec. This is the staging failure a smoke-run
    /// exists to catch, distinct from the app's own non-zero exit.
    pub fn loader_failed(&self) -> bool {
        matches!(self.code, Some(126) | Some(127))
            || self.stderr.contains("error while loading shared libraries")
            || self.stderr.contains("cannot open shared object file")
            || self.stderr.contains("no such file or directory")
    }
}

/// Run the packed image once (`docker run --rm <tag> <args>`) under a timeout, so a
/// missing-library or missing-loader failure is caught before the image is trusted.
/// A timeout is treated as "started" — a long-running entrypoint is not a failure.
pub fn smoke_run(tag: &str, args: &[&str], timeout_secs: u32) -> Result<SmokeOutcome> {
    let out = Command::new("timeout")
        .arg(timeout_secs.to_string())
        .args(["docker", "run", "--rm", tag])
        .args(args)
        .output()
        .context("running docker run for the smoke test")?;
    Ok(SmokeOutcome {
        code: out.status.code().filter(|&c| c != 124), // 124 = timeout killed it
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    })
}

fn docker_load(archive: &Path) -> Result<()> {
    let out = Command::new("docker")
        .arg("load")
        .arg("-i")
        .arg(archive)
        .output()
        .context("running docker load (is the Docker daemon running?)")?;
    if !out.status.success() {
        bail!(
            "docker load failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

fn append_bytes<W: Write>(ar: &mut tar::Builder<W>, name: &str, data: &[u8]) -> Result<()> {
    let mut header = tar::Header::new_gnu();
    header.set_size(data.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    ar.append_data(&mut header, name, data)?;
    Ok(())
}

fn append_path<W: Write>(ar: &mut tar::Builder<W>, name: &str, path: &Path) -> Result<()> {
    let mut file = std::fs::File::open(path)?;
    ar.append_file(name, &mut file)?;
    Ok(())
}

fn hex(digest: impl AsRef<[u8]>) -> String {
    use std::fmt::Write as _;
    digest.as_ref().iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layer_tar_is_written_and_hashed() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("root");
        std::fs::create_dir_all(root.join("usr/lib")).unwrap();
        std::fs::write(root.join("usr/lib/libx.so"), b"x").unwrap();
        let out = tmp.path().join("layer.tar");

        let diff_id = write_layer_tar(&root, &out).unwrap();
        assert_eq!(diff_id.len(), 64, "sha256 hex is 64 chars");
        assert!(out.exists() && std::fs::metadata(&out).unwrap().len() > 0);
    }

    #[test]
    fn config_names_the_entrypoint_and_layer() {
        let cfg = image_config(Path::new("/opt/app"), "abc123");
        assert_eq!(cfg["config"]["Entrypoint"][0], "/opt/app");
        assert_eq!(cfg["rootfs"]["diff_ids"][0], "sha256:abc123");
    }

    fn outcome(code: Option<i32>, stderr: &str) -> SmokeOutcome {
        SmokeOutcome {
            code,
            stdout: String::new(),
            stderr: stderr.into(),
        }
    }

    #[test]
    fn loader_failure_is_detected_by_exit_code_or_message() {
        // A missing library shows up as exit 127 and/or the loader's message.
        assert!(outcome(Some(127), "").loader_failed());
        assert!(
            outcome(Some(1), "error while loading shared libraries: libz.so.1").loader_failed()
        );
        assert!(outcome(Some(126), "").loader_failed());
    }

    #[test]
    fn an_app_nonzero_exit_is_not_a_loader_failure() {
        // The binary started fine and chose to exit non-zero (e.g. bad args).
        assert!(!outcome(Some(2), "error: missing subcommand").loader_failed());
        // A timeout (code None) means it started and kept running.
        assert!(!outcome(None, "").loader_failed());
    }
}
