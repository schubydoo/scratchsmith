//! Orchestrate a pack: resolve → stage → default-includes → assemble → load.
//! This is the glue behind `scratchsmith pack`.

use crate::image::{self, ImageConfig};
use crate::resolver::{self, Sysroot};
use crate::stager::{self, StagedTree};
use anyhow::{bail, Result};
use std::path::Path;

/// How long to let a smoke-run's entrypoint run before treating it as "started".
const SMOKE_TIMEOUT_SECS: u32 = 15;

// Resolve `binary` and build its complete rootfs (libs, loader, cache, NSS/passwd
// includes) under `dest`. The shared core of every pack path.
fn build_rootfs(binary: &Path, dest: &Path) -> Result<StagedTree> {
    // Resolve against the host root for now; a pinned sysroot is future work.
    let resolution = resolver::resolve(binary, &Sysroot::new("/"))?;
    if !resolution.missing.is_empty() {
        bail!(
            "cannot pack: unresolved dependencies: {}",
            resolution.missing.join(", ")
        );
    }

    let tree = stager::stage(binary, &resolution, dest)?;
    let report = stager::stage_default_includes(&resolution, dest)?;
    // The orchestrator is the app boundary, so surfacing warnings here is correct.
    for warning in &report.warnings {
        eprintln!("warning: {warning}");
    }
    Ok(tree)
}

/// Stage `binary`'s rootfs into `out_dir` and stop — no image is built (`-n -o`).
pub fn stage_only(binary: &Path, out_dir: &Path) -> Result<StagedTree> {
    build_rootfs(binary, out_dir)
}

/// Pack `binary` into a scratch image loaded in the local Docker daemon; return the
/// tag. When `smoke` is set, run the image once afterwards and fail if the dynamic
/// loader could not start it — the guard against a silently broken image.
pub fn run(binary: &Path, smoke: bool, cfg: &ImageConfig) -> Result<String> {
    let work = tempfile::tempdir()?;
    let dest = work.path().join("rootfs");
    let tree = build_rootfs(binary, &dest)?;

    if let Some(user) = &cfg.user {
        if image::is_root_user(user) {
            eprintln!("warning: --user {user} runs the image as root; the default non-root user is recommended");
        }
    }

    let tag = image_tag(binary);
    image::load_into_docker(&tree, &tag, cfg)?;

    if smoke {
        let outcome = image::smoke_run(&tag, &[], SMOKE_TIMEOUT_SECS)?;
        if outcome.loader_failed() {
            bail!(
                "smoke-run failed: the image could not start the binary.\n{}",
                outcome.stderr.trim()
            );
        }
        eprintln!("smoke-run ok: the binary starts inside the image");
    }

    Ok(tag)
}

// A valid, lowercase Docker tag derived from the binary name.
fn image_tag(binary: &Path) -> String {
    let name = binary
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("image")
        .to_lowercase();
    format!("scratchsmith/{name}:packed")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tag_is_lowercase_and_namespaced() {
        assert_eq!(
            image_tag(Path::new("/usr/bin/MyApp")),
            "scratchsmith/myapp:packed"
        );
    }
}
