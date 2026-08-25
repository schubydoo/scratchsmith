//! Orchestrate a pack: resolve → stage → default-includes → assemble → load.
//! This is the glue behind `scratchsmith pack`.

use crate::image::{self, ImageConfig};
use crate::resolver::{self, Sysroot};
use crate::stager::{self, RuntimeExtras, SizeReport, StagedTree};
use crate::supplychain::{self, SbomRequest};
use anyhow::{bail, Result};
use serde::Serialize;
use std::path::{Path, PathBuf};

/// How long to let a smoke-run's entrypoint run before treating it as "started".
const SMOKE_TIMEOUT_SECS: u32 = 15;

/// The outcome of a pack, emitted as text or JSON (Task 2.8). Fields are stable so
/// the JSON can gate CI.
#[derive(Debug, Clone, Serialize)]
pub struct PackReport {
    /// Image tag when an image was built (loaded into Docker).
    pub tag: Option<String>,
    /// Path of the OCI archive when `--oci-archive` was used (daemonless).
    pub archive: Option<String>,
    /// The pushed image reference when `--push` was used (daemonless).
    pub pushed: Option<String>,
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
        if let Some(archive) = &self.archive {
            out.push_str(&format!("wrote OCI archive {archive}\n"));
        }
        if let Some(reference) = &self.pushed {
            out.push_str(&format!("pushed {reference}\n"));
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
    includes: &[String],
) -> Result<(StagedTree, SizeReport, Vec<String>)> {
    let info = resolver::read_elf_info(binary)?;
    // Reject musl up front rather than staging a subtly broken image (Task 2.5).
    resolver::ensure_glibc(&info)?;

    let mut warnings = Vec::new();
    // dlopen'd plugins are invisible to the static graph; warn and point at the fix.
    if info.uses_dlopen {
        warnings.push(
            "binary references dlopen; runtime-loaded plugins are not in the dependency \
             graph — add them with --include <lib> if the image is missing libraries"
                .to_string(),
        );
    }

    // Resolve against the host root for now; a pinned sysroot is future work.
    let resolution = resolver::resolve_with_includes(binary, &Sysroot::new("/"), includes)?;
    if !resolution.missing.is_empty() {
        bail!(
            "cannot pack: unresolved dependencies: {}",
            resolution.missing.join(", ")
        );
    }

    let tree = stager::stage(binary, &resolution, dest)?;
    let default_includes = stager::stage_default_includes(&resolution, dest)?;
    warnings.extend(default_includes.warnings);
    let sizes = stager::strip_and_measure(dest, &tree, &resolution, strip)?;
    Ok((tree, sizes, warnings))
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
    /// Extra libraries (sonames or paths) to force-stage, e.g. dlopen'd plugins.
    pub includes: Vec<String>,
    pub image: ImageConfig,
}

/// Where a pack delivers its result. Every sink shares the resolve → stage pipeline and
/// differs only in delivery, so adding one (the daemonless OCI archive / registry push
/// are the next two) is a new variant + a `pack` arm, not a new top-level entry point.
pub enum Sink {
    /// Stage the rootfs into this directory and build no image (`--no-build --output`).
    Rootfs(PathBuf),
    /// Build the image and load it into the local Docker daemon (the default sink).
    DockerLoad,
    /// Write a daemonless OCI-archive tarball to this path (`--oci-archive`).
    OciArchive(PathBuf),
    /// Push the image straight to this registry reference, daemonless (`--push`).
    Push(String),
}

/// Pack `binary` and deliver it via `sink` — the single entry point the CLI dispatches
/// to. `Rootfs` stops after staging; the image sinks build the scratch image and deliver.
pub fn pack(binary: &Path, opts: &PackOptions, sink: Sink) -> Result<PackReport> {
    match sink {
        Sink::Rootfs(dir) => stage_only(binary, &dir, opts),
        Sink::DockerLoad => run(binary, opts),
        Sink::OciArchive(out) => to_oci_archive(binary, opts, &out),
        Sink::Push(reference) => to_push(binary, opts, &reference),
    }
}

/// Stage `binary`'s rootfs into `out_dir` and stop — no image is built (`-n -o`).
pub fn stage_only(binary: &Path, out_dir: &Path, opts: &PackOptions) -> Result<PackReport> {
    let (tree, size, warnings) = build_rootfs(binary, out_dir, opts.strip, &opts.includes)?;
    stager::stage_runtime_extras(out_dir, &opts.extras)?;
    let sbom = maybe_sbom(out_dir, opts.sbom.as_ref())?;
    Ok(PackReport {
        tag: None,
        archive: None,
        pushed: None,
        staged_dir: Some(tree.root.display().to_string()),
        entrypoint: tree.entrypoint.display().to_string(),
        size,
        warnings,
        smoke_ok: None,
        sbom,
    })
}

// The shared prep for every image sink: resolve → stage → runtime extras → SBOM →
// effective image config (tini wrap, root warning) → tag. The temp dir is held in the
// return value so the staged rootfs outlives the delivery step.
struct StagedImage {
    _work: tempfile::TempDir,
    tree: StagedTree,
    cfg: ImageConfig,
    tag: String,
    size: SizeReport,
    warnings: Vec<String>,
    sbom: Option<String>,
}

fn stage_for_image(binary: &Path, opts: &PackOptions) -> Result<StagedImage> {
    let work = tempfile::tempdir()?;
    let dest = work.path().join("rootfs");
    let (tree, size, warnings) = build_rootfs(binary, &dest, opts.strip, &opts.includes)?;
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
    Ok(StagedImage {
        _work: work,
        tree,
        cfg,
        tag,
        size,
        warnings,
        sbom,
    })
}

/// Pack `binary` into a scratch image loaded in the local Docker daemon. With
/// `opts.smoke`, run the image once afterwards and fail if the dynamic loader could
/// not start it — the guard against a silently broken image.
pub fn run(binary: &Path, opts: &PackOptions) -> Result<PackReport> {
    let s = stage_for_image(binary, opts)?;
    image::load_into_docker(&s.tree, &s.tag, &s.cfg)?;

    let mut smoke_ok = None;
    if opts.smoke {
        let outcome = image::smoke_run(&s.tag, &[], SMOKE_TIMEOUT_SECS)?;
        if outcome.loader_failed() {
            bail!(
                "smoke-run failed: the image could not start the binary.\n{}",
                outcome.stderr.trim()
            );
        }
        smoke_ok = Some(true);
    }

    Ok(PackReport {
        tag: Some(s.tag),
        archive: None,
        pushed: None,
        staged_dir: None,
        entrypoint: s.tree.entrypoint.display().to_string(),
        size: s.size,
        warnings: s.warnings,
        smoke_ok,
        sbom: s.sbom,
    })
}

/// Pack `binary` into a daemonless OCI-archive tarball at `out` (Task 5.1). No Docker
/// daemon is contacted; `docker load` / `skopeo copy oci-archive:<out>` accept the result.
fn to_oci_archive(binary: &Path, opts: &PackOptions, out: &Path) -> Result<PackReport> {
    if opts.smoke {
        bail!("--smoke needs a running image, so it isn't supported with --oci-archive; load the archive (docker load / skopeo) and run it separately, or drop --smoke");
    }
    let s = stage_for_image(binary, opts)?;
    image::write_oci_archive(&s.tree, &s.tag, &s.cfg, out)?;
    Ok(PackReport {
        tag: None,
        archive: Some(out.display().to_string()),
        pushed: None,
        staged_dir: None,
        entrypoint: s.tree.entrypoint.display().to_string(),
        size: s.size,
        warnings: s.warnings,
        smoke_ok: None,
        sbom: s.sbom,
    })
}

/// Pack `binary` and push it straight to a registry reference (Task 5.2) — no Docker
/// daemon. Credentials come from the local Docker config; blobs the registry already has
/// are skipped.
fn to_push(binary: &Path, opts: &PackOptions, reference: &str) -> Result<PackReport> {
    if opts.smoke {
        bail!("--smoke needs a running image, so it isn't supported with --push; pull the pushed image and run it separately, or drop --smoke");
    }
    let s = stage_for_image(binary, opts)?;
    image::push_to_registry(&s.tree, reference, &s.cfg)?;
    Ok(PackReport {
        tag: None,
        archive: None,
        pushed: Some(reference.to_string()),
        staged_dir: None,
        entrypoint: s.tree.entrypoint.display().to_string(),
        size: s.size,
        warnings: s.warnings,
        smoke_ok: None,
        sbom: s.sbom,
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
            archive: None,
            pushed: None,
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
