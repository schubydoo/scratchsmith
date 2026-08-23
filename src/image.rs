//! Assemble the staged rootfs into a container image. Task 1.6 targets the local
//! Docker daemon via a docker-archive tarball (the POC output sink); pure-Rust OCI
//! archive output and registry push come in Sprint 5. Reproducible layers are 2.9.

use crate::stager::StagedTree;
use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::Path;
use std::process::Command;

/// User-configurable image metadata (Task 2.2). Empty fields fall back to defaults:
/// the entrypoint defaults to the packed binary, and PATH is always present.
#[derive(Debug, Clone, Default)]
pub struct ImageConfig {
    /// Overrides the default entrypoint (the packed binary) when non-empty.
    pub entrypoint: Vec<String>,
    /// Default arguments (`Cmd`) appended to the entrypoint.
    pub cmd: Vec<String>,
    /// Extra environment entries (`KEY=VALUE`); override PATH by key if given.
    pub env: Vec<String>,
    /// Working directory inside the image.
    pub workdir: Option<String>,
}

/// Assemble `staged` into an image and load it into the local Docker daemon as `tag`.
pub fn load_into_docker(staged: &StagedTree, tag: &str, cfg: &ImageConfig) -> Result<()> {
    let work = tempfile::tempdir().context("temp dir for image archive")?;
    let archive = work.path().join("image.tar");
    build_docker_archive(staged, tag, cfg, &archive)?;
    docker_load(&archive)?;
    Ok(())
}

// A docker-archive is a tar of: the image config, the single rootfs layer tar, and
// a manifest.json tying them together. `docker load` reads exactly this shape.
fn build_docker_archive(
    staged: &StagedTree,
    tag: &str,
    cfg: &ImageConfig,
    out: &Path,
) -> Result<()> {
    let work = tempfile::tempdir()?;
    let layer_path = work.path().join("layer.tar");
    let diff_id = write_layer_tar(&staged.root, &layer_path)?;

    let config = image_config(&staged.entrypoint, &diff_id, cfg);
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

const DEFAULT_PATH: &str = "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

fn image_config(default_entrypoint: &Path, diff_id: &str, cfg: &ImageConfig) -> serde_json::Value {
    let entrypoint = if cfg.entrypoint.is_empty() {
        vec![default_entrypoint.to_string_lossy().into_owned()]
    } else {
        cfg.entrypoint.clone()
    };

    let mut config = serde_json::json!({
        "Entrypoint": entrypoint,
        "Env": merged_env(&cfg.env),
    });
    if !cfg.cmd.is_empty() {
        config["Cmd"] = serde_json::json!(cfg.cmd);
    }
    if let Some(wd) = &cfg.workdir {
        config["WorkingDir"] = serde_json::json!(wd);
    }

    serde_json::json!({
        // Host-arch only at v1; multi-arch is Task 5.4.
        "architecture": "amd64",
        "os": "linux",
        "config": config,
        "rootfs": { "type": "layers", "diff_ids": [format!("sha256:{diff_id}")] },
        "history": [{ "created": "1970-01-01T00:00:00Z", "created_by": "scratchsmith" }],
    })
}

// Start from the default PATH, then apply user env entries, overriding by key so a
// user-supplied PATH replaces the default rather than duplicating it.
fn merged_env(user: &[String]) -> Vec<String> {
    let key_of = |e: &str| e.split('=').next().unwrap_or(e).to_string();
    let mut env = vec![DEFAULT_PATH.to_string()];
    for entry in user {
        let key = key_of(entry);
        match env.iter_mut().find(|e| key_of(e) == key) {
            Some(slot) => *slot = entry.clone(),
            None => env.push(entry.clone()),
        }
    }
    env
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
    fn config_defaults_to_the_packed_binary_entrypoint() {
        let cfg = image_config(Path::new("/opt/app"), "abc123", &ImageConfig::default());
        assert_eq!(cfg["config"]["Entrypoint"][0], "/opt/app");
        assert_eq!(cfg["rootfs"]["diff_ids"][0], "sha256:abc123");
        // PATH is always present; no Cmd/WorkingDir unless set.
        assert!(cfg["config"]["Env"][0]
            .as_str()
            .unwrap()
            .starts_with("PATH="));
        assert!(cfg["config"]["Cmd"].is_null());
    }

    #[test]
    fn config_applies_entrypoint_cmd_env_and_workdir() {
        let opts = ImageConfig {
            entrypoint: vec!["/bin/tool".into()],
            cmd: vec!["--serve".into()],
            env: vec!["FOO=bar".into()],
            workdir: Some("/work".into()),
        };
        let cfg = image_config(Path::new("/opt/app"), "d", &opts);
        assert_eq!(cfg["config"]["Entrypoint"][0], "/bin/tool");
        assert_eq!(cfg["config"]["Cmd"][0], "--serve");
        assert_eq!(cfg["config"]["WorkingDir"], "/work");
        let env: Vec<&str> = cfg["config"]["Env"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert!(env.contains(&"FOO=bar"));
    }

    #[test]
    fn user_path_overrides_the_default_instead_of_duplicating() {
        let env = merged_env(&["PATH=/only".to_string()]);
        assert_eq!(env, vec!["PATH=/only".to_string()]);
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
