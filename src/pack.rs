//! Orchestrate a pack: resolve → stage → default-includes → assemble → load.
//! This is the glue behind `scratchsmith pack`.

use crate::image::{self, ImageConfig};
use crate::resolver::{self, Sysroot};
use crate::stager::{self, RuntimeExtras, SizeReport, StagedTree};
use crate::supplychain::{self, SbomRequest};
use anyhow::{bail, Result};
use serde::Serialize;
use std::path::Path;

/// How long to let a smoke-run's entrypoint run before treating it as "started".
const SMOKE_TIMEOUT_SECS: u32 = 15;

/// The outcome of a pack, emitted as text or JSON (Task 2.8). Fields are stable so
/// the JSON can gate CI.
#[derive(Debug, Clone, Serialize)]
pub struct PackReport {
    /// Image tag when an image was built.
    pub tag: Option<String>,
    /// Staging directory when `-n -o` was used instead of building an image.
    pub staged_dir: Option<String>,
    /// Entrypoint path inside the image.
    pub entrypoint: String,
    /// Per-file and total payload sizes.
    pub size: SizeReport,
    /// Best-effort include warnings (e.g. an absent NSS module).
    pub warnings: Vec<String>,
    /// Smoke-run result: `Some(true)` if started, `None` if not run.
    pub smoke_ok: Option<bool>,
    /// Path of the generated SBOM, if `--sbom` was requested.
    pub sbom: Option<String>,
}

// Generate the SBOM of the staged rootfs if requested, returning its path.
fn maybe_sbom(rootfs: &Path, sbom: Option<&SbomRequest>) -> Result<Option<String>> {
    match sbom {
        Some(req) => {
            supplychain::generate_sbom(rootfs, req.format, &req.path)?;
            Ok(Some(req.path.display().to_string()))
        }
        None => Ok(None),
    }
}

impl PackReport {
    /// Human-readable rendering (the `--format text` output).
    pub fn to_text(&self) -> String {
        let mut out = String::new();
        for w in &self.warnings {
            out.push_str(&format!("warning: {w}\n"));
        }
        out.push_str("payload size:\n");
        out.push_str(&format!("{}\n", self.size));
        if let Some(tag) = &self.tag {
            out.push_str(&format!("loaded image {tag}\n"));
        }
        if let Some(dir) = &self.staged_dir {
            out.push_str(&format!("staged to {dir}\n"));
        }
        if let Some(sbom) = &self.sbom {
            out.push_str(&format!("sbom: {sbom}\n"));
        }
        if self.smoke_ok == Some(true) {
            out.push_str("smoke-run ok: the binary starts inside the image\n");
        }
        out.trim_end().to_string()
    }
}

// Resolve `binary` and build its complete rootfs (libs, loader, cache, NSS/passwd
// includes) under `dest`, optionally stripping. The shared core of every pack path.
// Returns the tree, the size report, and any include warnings (no printing).
fn build_rootfs(
    binary: &Path,
    dest: &Path,
    strip: bool,
) -> Result<(StagedTree, SizeReport, Vec<String>)> {
    // Reject musl up front rather than staging a subtly broken image (Task 2.5).
    resolver::ensure_glibc(&resolver::read_elf_info(binary)?)?;

    // Resolve against the host root for now; a pinned sysroot is future work.
    let resolution = resolver::resolve(binary, &Sysroot::new("/"))?;
    if !resolution.missing.is_empty() {
        bail!(
            "cannot pack: unresolved dependencies: {}",
            resolution.missing.join(", ")
        );
    }

    let tree = stager::stage(binary, &resolution, dest)?;
    let includes = stager::stage_default_includes(&resolution, dest)?;
    let sizes = stager::strip_and_measure(dest, &tree, &resolution, strip)?;
    Ok((tree, sizes, includes.warnings))
}

/// Everything a pack needs beyond the binary itself. A struct (rather than a long
/// argument list) so new options — sbom, runtime extras, later push/upx — don't keep
/// widening every call site.
#[derive(Debug, Default, Clone)]
pub struct PackOptions {
    pub smoke: bool,
    pub strip: bool,
    pub sbom: Option<SbomRequest>,
    pub extras: RuntimeExtras,
    pub image: ImageConfig,
}

/// Stage `binary`'s rootfs into `out_dir` and stop — no image is built (`-n -o`).
pub fn stage_only(binary: &Path, out_dir: &Path, opts: &PackOptions) -> Result<PackReport> {
    let (tree, size, warnings) = build_rootfs(binary, out_dir, opts.strip)?;
    stager::stage_runtime_extras(out_dir, &opts.extras)?;
    let sbom = maybe_sbom(out_dir, opts.sbom.as_ref())?;
    Ok(PackReport {
        tag: None,
        staged_dir: Some(tree.root.display().to_string()),
        entrypoint: tree.entrypoint.display().to_string(),
        size,
        warnings,
        smoke_ok: None,
        sbom,
    })
}

/// Pack `binary` into a scratch image loaded in the local Docker daemon. With
/// `opts.smoke`, run the image once afterwards and fail if the dynamic loader could
/// not start it — the guard against a silently broken image.
pub fn run(binary: &Path, opts: &PackOptions) -> Result<PackReport> {
    let work = tempfile::tempdir()?;
    let dest = work.path().join("rootfs");
    let (tree, size, warnings) = build_rootfs(binary, &dest, opts.strip)?;
    let extras = stager::stage_runtime_extras(&dest, &opts.extras)?;
    // Generate the SBOM while the staged rootfs still exists (dest is temporary).
    let sbom = maybe_sbom(&dest, opts.sbom.as_ref())?;

    // Effective image config: if --init staged tini, wrap the entrypoint so tini is
    // pid 1 and reaps/forwards for the real binary.
    let mut cfg = opts.image.clone();
    if let Some(tini) = &extras.tini_image_path {
        let base = if cfg.entrypoint.is_empty() {
            vec![tree.entrypoint.display().to_string()]
        } else {
            cfg.entrypoint.clone()
        };
        cfg.entrypoint = init_entrypoint(tini, base);
    }

    if let Some(user) = &cfg.user {
        if image::is_root_user(user) {
            eprintln!("warning: --user {user} runs the image as root; the default non-root user is recommended");
        }
    }

    let tag = image_tag(binary);
    image::load_into_docker(&tree, &tag, &cfg)?;

    let mut smoke_ok = None;
    if opts.smoke {
        let outcome = image::smoke_run(&tag, &[], SMOKE_TIMEOUT_SECS)?;
        if outcome.loader_failed() {
            bail!(
                "smoke-run failed: the image could not start the binary.\n{}",
                outcome.stderr.trim()
            );
        }
        smoke_ok = Some(true);
    }

    Ok(PackReport {
        tag: Some(tag),
        staged_dir: None,
        entrypoint: tree.entrypoint.display().to_string(),
        size,
        warnings,
        smoke_ok,
        sbom,
    })
}

// Wrap the entrypoint so tini is pid 1: [tini, --, <original entrypoint...>].
fn init_entrypoint(tini: &str, base: Vec<String>) -> Vec<String> {
    [tini.to_string(), "--".to_string()]
        .into_iter()
        .chain(base)
        .collect()
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

    #[test]
    fn init_wraps_the_entrypoint_with_tini() {
        assert_eq!(
            init_entrypoint("/tini", vec!["/app".into(), "--serve".into()]),
            vec!["/tini", "--", "/app", "--serve"]
        );
    }

    fn sample_report() -> PackReport {
        PackReport {
            tag: Some("scratchsmith/app:packed".into()),
            staged_dir: None,
            entrypoint: "/opt/app".into(),
            size: SizeReport {
                entries: vec![],
                total_before: 200,
                total_after: 123,
                stripped: true,
            },
            warnings: vec!["NSS module not found: libnss_dns.so.2".into()],
            smoke_ok: Some(true),
            sbom: Some("sbom.json".into()),
        }
    }

    #[test]
    fn json_report_has_stable_fields() {
        let json = serde_json::to_value(sample_report()).unwrap();
        assert_eq!(json["tag"], "scratchsmith/app:packed");
        assert_eq!(json["entrypoint"], "/opt/app");
        assert_eq!(json["size"]["total_after"], 123);
        assert_eq!(json["size"]["stripped"], true);
        assert!(json["staged_dir"].is_null());
        assert!(json["warnings"].is_array());
        assert_eq!(json["smoke_ok"], true);
    }

    #[test]
    fn text_report_renders_the_key_lines() {
        let text = sample_report().to_text();
        assert!(text.contains("warning: NSS module not found"));
        assert!(text.contains("loaded image scratchsmith/app:packed"));
        assert!(text.contains("smoke-run ok"));
        assert!(text.contains("200 -> 123"));
    }
}
