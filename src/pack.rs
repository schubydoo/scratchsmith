//! Orchestrate a pack: resolve → stage → default-includes → assemble → load.
//! This is the glue Task 1.6 wires behind `scratchsmith pack`.

use crate::image;
use crate::resolver::{self, Sysroot};
use crate::stager;
use anyhow::{bail, Result};
use std::path::Path;

/// How long to let a smoke-run's entrypoint run before treating it as "started".
const SMOKE_TIMEOUT_SECS: u32 = 15;

/// Pack `binary` into a scratch image loaded in the local Docker daemon; return the
/// tag. When `smoke` is set, run the image once afterwards and fail if the dynamic
/// loader could not start it — the guard against a silently broken image.
pub fn run(binary: &Path, smoke: bool) -> Result<String> {
    // Resolve against the host root for now; a pinned sysroot is future work.
    let resolution = resolver::resolve(binary, &Sysroot::new("/"))?;
    if !resolution.missing.is_empty() {
        bail!(
            "cannot pack: unresolved dependencies: {}",
            resolution.missing.join(", ")
        );
    }

    let work = tempfile::tempdir()?;
    let dest = work.path().join("rootfs");
    let tree = stager::stage(binary, &resolution, &dest)?;
    let report = stager::stage_default_includes(&resolution, &dest)?;
    // The orchestrator is the app boundary, so surfacing warnings here is correct.
    for warning in &report.warnings {
        eprintln!("warning: {warning}");
    }

    let tag = image_tag(binary);
    image::load_into_docker(&tree, &tag)?;

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
