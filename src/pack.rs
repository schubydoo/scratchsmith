//! Orchestrate a pack: resolve → stage → default-includes → assemble → load.
//! This is the glue behind `scratchsmith pack`.

use crate::image::{self, ImageConfig};
use crate::report::PackReport;
use crate::resolver::{self, Sysroot};
use crate::stager::{self, RuntimeExtras, SizeReport, StagedTree};
use crate::supplychain::{self, SbomRequest};
use anyhow::{bail, Result};
use std::path::{Path, PathBuf};

/// How long to let a smoke-run's entrypoint run before treating it as "started".
const SMOKE_TIMEOUT_SECS: u32 = 15;

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
    /// Sign the pushed image with cosign (and attest the SBOM, if any). `--push` only.
    pub sign: bool,
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
        signed: None,
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
        signed: None,
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
        signed: None,
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
    let digest_ref = crate::registry::push_to_registry(&s.tree, reference, &s.cfg)?;
    let signed = opts
        .sign
        .then(|| sign_pushed(&digest_ref, opts))
        .transpose()?;
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
        signed,
    })
}

// cosign-sign the pushed image by digest, and — if an SBOM was generated — attach it as a
// signed attestation. Signing by digest (not tag) pins the exact image just pushed. Returns
// the signed digest reference for the report.
fn sign_pushed(digest_ref: &str, opts: &PackOptions) -> Result<String> {
    supplychain::cosign_sign(digest_ref)?;
    if let Some(req) = &opts.sbom {
        supplychain::cosign_attest(digest_ref, &req.path, req.format.cosign_predicate_type())?;
    }
    Ok(digest_ref.to_string())
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
}
