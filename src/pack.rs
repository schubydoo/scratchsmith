//! Orchestrate a pack: resolve → stage → default-includes → assemble → load.
//! This is the glue behind `scratchsmith pack`.

use crate::image::{self, ImageConfig};
use crate::report::PackReport;
use crate::resolver::{self, Sysroot};
use crate::stager::{self, AddFile, NssSelection, RuntimeExtras, SizeReport, StagedTree};
use crate::supplychain::{self, SbomRequest, ScanRequest, ScanSource, ScanSummary};
use anyhow::{bail, Context, Result};
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

// Vulnerability-scan the staged rootfs with grype when requested, reusing the SBOM syft
// wrote if there is one (else scanning the rootfs directly). A `fail_on` gate turns a
// finding at or above that severity into a hard error, before anything is delivered.
fn maybe_scan(
    rootfs: &Path,
    sbom_path: Option<&str>,
    scan: Option<&ScanRequest>,
) -> Result<Option<ScanSummary>> {
    let Some(req) = scan else { return Ok(None) };
    let source = match sbom_path {
        Some(p) => ScanSource::Sbom(PathBuf::from(p)),
        None => ScanSource::Rootfs(rootfs.to_path_buf()),
    };
    let summary = supplychain::run_grype(&source)?;
    if let Some(threshold) = req.fail_on {
        let n = summary.at_or_above(threshold);
        if n > 0 {
            bail!(
                "vulnerability scan failed: {n} finding(s) at or above {threshold:?} \
                 (critical={}, high={}, medium={}, low={}, negligible={})",
                summary.critical,
                summary.high,
                summary.medium,
                summary.low,
                summary.negligible
            );
        }
    }
    Ok(Some(summary))
}

// Enforce the library allow/deny policy (`--require` / `--deny`) against everything that
// actually ships as a shared object: the resolved libraries, the loader, and the staged
// NSS modules (which are copied in outside the dependency graph). Matches by soname — the
// name `graph` shows — or by staged file name. A denied library present, or a required one
// absent, fails the pack.
fn check_lib_policy(
    resolution: &resolver::Resolution,
    staged_includes: &[PathBuf],
    require: &[String],
    deny: &[String],
) -> Result<()> {
    if require.is_empty() && deny.is_empty() {
        return Ok(());
    }
    let mut present: std::collections::HashSet<String> = std::collections::HashSet::new();
    for lib in &resolution.libs {
        present.insert(lib.soname.clone());
        if let Some(name) = lib.path.file_name() {
            present.insert(name.to_string_lossy().into_owned());
        }
    }
    // The loader lives in `interpreter`, not `libs`, but it still ships.
    if let Some(interp) = &resolution.interpreter {
        if let Some(name) = interp.image_path.file_name() {
            present.insert(name.to_string_lossy().into_owned());
        }
    }
    // The default-includes report also carries nsswitch/passwd/group; keep shared objects.
    for path in staged_includes {
        if path.to_string_lossy().contains(".so") {
            if let Some(name) = path.file_name() {
                present.insert(name.to_string_lossy().into_owned());
            }
        }
    }
    let denied: Vec<&str> = deny
        .iter()
        .map(String::as_str)
        .filter(|d| present.contains(*d))
        .collect();
    let missing: Vec<&str> = require
        .iter()
        .map(String::as_str)
        .filter(|r| !present.contains(*r))
        .collect();
    let mut parts = Vec::new();
    if !denied.is_empty() {
        parts.push(format!("denied library present: {}", denied.join(", ")));
    }
    if !missing.is_empty() {
        parts.push(format!("required library missing: {}", missing.join(", ")));
    }
    if parts.is_empty() {
        Ok(())
    } else {
        bail!("library policy failed: {}", parts.join(" and "))
    }
}

/// What `build_rootfs` produced. A struct rather than a tuple because the pieces are
/// unrelated to each other and every sink threads all of them into its report. Named
/// `StagedRootfs`, not `Rootfs`: `Sink::Rootfs` in this module is the sink that stages a
/// rootfs and builds no image, and `stage_for_image` (an image sink) destructures this.
struct StagedRootfs {
    tree: StagedTree,
    size: SizeReport,
    warnings: Vec<String>,
    /// The loader's image path (`PT_INTERP`), or `None` for a static binary.
    interpreter: Option<String>,
}

// Resolve `binary` and build its complete rootfs (libs, loader, cache, NSS/passwd
// includes) under `dest`, optionally stripping. The shared core of every pack path.
// Returns the tree, the size report, the loader path and any include warnings (no printing).
fn build_rootfs(binary: &Path, dest: &Path, opts: &PackOptions) -> Result<StagedRootfs> {
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
    // UPX self-decompresses at runtime, but it can break a binary that dlopen's by path or
    // self-modifies — surface the caveat whenever compression is on, and point at --smoke
    // unless the caller already asked for it.
    if opts.upx {
        let mut msg = "--upx compresses the binary; it self-decompresses at runtime but can \
                       break a binary that dlopen's by path or self-modifies"
            .to_string();
        if !opts.smoke {
            msg.push_str(" — verify the packed image with --smoke");
        }
        warnings.push(msg);
    }

    // Resolve against the host root for now; a pinned sysroot is future work.
    let resolution = resolver::resolve_with_includes(binary, &Sysroot::new("/"), &opts.includes)?;
    if !resolution.missing.is_empty() {
        bail!(
            "cannot pack: unresolved dependencies: {}",
            resolution.missing.join(", ")
        );
    }
    let tree = stager::stage(binary, &resolution, dest, opts.symlinks)?;
    let default_includes = stager::stage_default_includes(&resolution, dest, &opts.nss)?;
    warnings.extend(default_includes.warnings);
    // Gate on the library policy over everything staged (resolved libs, the loader, and the
    // NSS modules), so a denied library cannot slip in via the default-includes.
    check_lib_policy(
        &resolution,
        &default_includes.staged,
        &opts.require,
        &opts.deny,
    )?;
    let sizes = stager::strip_and_measure(dest, &tree, &resolution, opts.strip, opts.upx)?;
    let interpreter = resolution.interpreter_path();
    Ok(StagedRootfs {
        tree,
        size: sizes,
        warnings,
        interpreter,
    })
}

// Sum the sizes of the staged rootfs's regular files — the uncompressed image content,
// including the NSS default-includes, the regenerated ld.so.cache, and the runtime extras
// (`--ca-certs`/`--tz`/`--init`), `--add-file` copies and `--locale` data that land after
// `build_rootfs`.
// Symlinks add ~0.
fn staged_size(dir: &Path) -> Result<u64> {
    let mut total = 0u64;
    for entry in walkdir::WalkDir::new(dir).follow_links(false) {
        let md = entry?.metadata()?;
        if md.is_file() {
            total += md.len();
        }
    }
    Ok(total)
}

// glibc reads LC_ALL first, then each per-category LC_*, then LANG, so any of the three
// selects a locale.
fn locale_selectors(env: &[String]) -> Vec<&str> {
    env.iter()
        .filter_map(|e| e.split_once('='))
        .filter(|(key, _)| *key == "LANG" || key.starts_with("LC_"))
        .map(|(_, value)| value)
        .filter(|value| !value.is_empty())
        .collect()
}

// glibc resolves these without any data on disk, so selecting one is never a mismatch.
const BUILTIN_LOCALES: &[&str] = &["C", "POSIX", "C.UTF-8"];

// `LANG=en_US.utf8` and `--locale en_US.UTF-8` name one locale to glibc. Compare names with
// the case folded and the codeset punctuation dropped, keeping any modifier.
fn normalize_locale(name: &str) -> String {
    let (base, modifier) = name.split_once('@').unwrap_or((name, ""));
    let (lang, codeset) = base.split_once('.').unwrap_or((base, ""));
    let codeset: String = codeset
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .collect();
    format!(
        "{}.{}@{}",
        lang.to_ascii_lowercase(),
        codeset.to_ascii_lowercase(),
        modifier.to_ascii_lowercase()
    )
}

// A staged locale that nothing selects is dead weight, and a selector naming a locale the
// pack did not stage is worse: glibc falls back to the C locale, and a program that ignores
// the setlocale return value never says so. The selection lives in the image environment,
// not in the locale data, so both cases are named rather than shipped silently.
fn locale_env_warning(locales: &[String], env: &[String]) -> Option<String> {
    let first = locales.first()?;
    let selectors = locale_selectors(env);
    if selectors.is_empty() {
        return Some(format!(
            "staged {} locale(s), but the image sets no LANG, LC_ALL or LC_* entry, so the \
             binary runs in the C locale. Add --env LANG={first}",
            locales.len()
        ));
    }
    let staged: Vec<String> = locales.iter().map(|l| normalize_locale(l)).collect();
    let missing: Vec<&str> = selectors
        .iter()
        .filter(|s| {
            let norm = normalize_locale(s);
            !staged.contains(&norm) && !BUILTIN_LOCALES.iter().any(|b| normalize_locale(b) == norm)
        })
        .copied()
        .collect();
    (!missing.is_empty()).then(|| {
        format!(
            "the image selects {}, which the pack did not stage, so glibc falls back to the C \
             locale there. Staged: {}",
            missing.join(", "),
            locales.join(", ")
        )
    })
}

// Enforce `--max-size` against the FULLY staged rootfs (after default-includes and
// runtime extras), so the budget reflects the whole image, not just the ELF payload.
fn enforce_max_size(dir: &Path, max_size: Option<u64>) -> Result<()> {
    let Some(max) = max_size else { return Ok(()) };
    let total = staged_size(dir)?;
    if total > max {
        bail!(
            "packed image is {}, over the --max-size limit of {}",
            crate::report::human_size(total),
            crate::report::human_size(max)
        );
    }
    Ok(())
}

/// Everything a pack needs beyond the binary itself. A struct (rather than a long
/// argument list) so new options — sbom, runtime extras, later push/upx — don't keep
/// widening every call site.
#[derive(Debug, Default, Clone)]
pub struct PackOptions {
    pub smoke: bool,
    pub strip: bool,
    /// Compress the packed binary with UPX (the executable only — not the loader/libs).
    pub upx: bool,
    pub sbom: Option<SbomRequest>,
    /// Vulnerability-scan the packed rootfs with grype; a `fail_on` gate aborts the pack.
    pub scan: Option<ScanRequest>,
    pub extras: RuntimeExtras,
    /// Host files to copy into the image (`--add-file SRC[:DST]`), beyond the fixed paths
    /// `--ca-certs` / `--tz` stage.
    pub add_files: Vec<AddFile>,
    /// What a symlink the user named becomes in the image: the packed binary's own path,
    /// and each `--add-file` source (`--symlinks`). Defaults to the historical flattening.
    pub symlinks: stager::SymlinkMode,
    /// Compiled glibc locales to stage under `/usr/lib/locale` (`--locale en_US.UTF-8`).
    pub locales: Vec<String>,
    /// Extra libraries (sonames or paths) to force-stage, e.g. dlopen'd plugins.
    pub includes: Vec<String>,
    /// Which name-service (NSS) modules to stage (`--nss`); default stages files + dns.
    pub nss: NssSelection,
    /// Fail the pack if any of these libraries (by soname) is staged (`--deny`).
    pub deny: Vec<String>,
    /// Fail the pack if any of these libraries (by soname) is absent (`--require`).
    pub require: Vec<String>,
    pub image: ImageConfig,
    /// Sign the pushed image with cosign (and attest the SBOM, if any). `--push` only.
    pub sign: bool,
    /// Fail the pack if the fully-staged rootfs exceeds this many bytes (`--max-size`).
    pub max_size: Option<u64>,
    /// Container engine for the docker-load sink and `--smoke` run (`--runtime`). Ignored by
    /// the daemonless sinks (`--oci-archive`, `--push`), which never invoke a runtime.
    pub runtime: crate::image::Runtime,
}

/// Where a pack delivers its result. Every sink shares the resolve → stage pipeline and
/// differs only in delivery, so adding one (the daemonless OCI archive / registry push
/// are the next two) is a new variant + a `pack` arm, not a new top-level entry point.
#[non_exhaustive] // new delivery sinks land in minors; not a stable exhaustive library API
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

/// What `finish_staging` produced. `extras` matters only to the image sinks (tini wrapping);
/// `stage_only` ignores it.
struct Finished {
    extras: stager::RuntimeResult,
    sbom: Option<String>,
    scan: Option<ScanSummary>,
}

// Everything BOTH sinks do after `build_rootfs`, in an order that matters: runtime extras,
// added files, locales, the locale warning, the max-size gate, then the SBOM and the scan --
// those two last because they read the staged tree, which is temporary for an image sink.
//
// Extracted because keeping two copies in step is a PROVEN hazard rather than a theoretical
// one: `--locale` and `--symlinks` each had to be added to both, and a third addition that
// reached only one would silently apply to one sink and not the other.
fn finish_staging(dest: &Path, opts: &PackOptions, warnings: &mut Vec<String>) -> Result<Finished> {
    let extras = stager::stage_runtime_extras(dest, &opts.extras)?;
    warnings.extend(stager::stage_added_files(
        dest,
        &opts.add_files,
        opts.symlinks,
    )?);
    stager::stage_locales(dest, &opts.locales)?;
    warnings.extend(locale_env_warning(&opts.locales, &opts.image.env));
    enforce_max_size(dest, opts.max_size)?;
    let sbom = maybe_sbom(dest, opts.sbom.as_ref())?;
    let scan = maybe_scan(dest, sbom.as_deref(), opts.scan.as_ref())?;
    Ok(Finished { extras, sbom, scan })
}

/// Stage `binary`'s rootfs into `out_dir` and stop — no image is built (`-n -o`).
pub fn stage_only(binary: &Path, out_dir: &Path, opts: &PackOptions) -> Result<PackReport> {
    // No image is built here, so there is nothing to smoke-run. The CLI blocks --smoke --no-build,
    // but `smoke` can also arrive from the config/profile — fail loud rather than silently drop it.
    if opts.smoke {
        bail!("--smoke needs a built image, so it isn't supported with --no-build; drop --smoke, or set `smoke = false` in the profile");
    }
    let StagedRootfs {
        tree,
        size,
        mut warnings,
        interpreter,
    } = build_rootfs(binary, out_dir, opts)?;
    // `extras` is unused here: no image is built, so there is no config to wrap with tini.
    let Finished { sbom, scan, .. } = finish_staging(out_dir, opts, &mut warnings)?;
    Ok(PackReport {
        tag: None,
        archive: None,
        pushed: None,
        staged_dir: Some(tree.root.display().to_string()),
        entrypoint: tree.entrypoint.display().to_string(),
        interpreter,
        size,
        warnings,
        smoke_ok: None,
        sbom,
        scan,
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
    scan: Option<ScanSummary>,
    /// The loader's image path, carried through to every image sink's report.
    interpreter: Option<String>,
}

fn stage_for_image(binary: &Path, opts: &PackOptions) -> Result<StagedImage> {
    let work = tempfile::tempdir()?;
    let dest = work.path().join("rootfs");
    let StagedRootfs {
        tree,
        size,
        mut warnings,
        interpreter,
    } = build_rootfs(binary, &dest, opts)?;
    // finish_staging generates the SBOM and scan while the staged rootfs still exists (dest is
    // temporary), which is why this call sits here rather than after the image config.
    let Finished { extras, sbom, scan } = finish_staging(&dest, opts, &mut warnings)?;

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
        scan,
        interpreter,
    })
}

/// Pack `binary` into a scratch image loaded in the local Docker daemon. With
/// `opts.smoke`, run the image once afterwards and fail if the dynamic loader could
/// not start it — the guard against a silently broken image.
pub fn run(binary: &Path, opts: &PackOptions) -> Result<PackReport> {
    let s = stage_for_image(binary, opts)?;
    image::load_into_docker(&s.tree, &s.tag, &s.cfg, opts.runtime)?;

    let mut smoke_ok = None;
    if opts.smoke {
        let outcome = image::smoke_run(opts.runtime, &s.tag, &[], SMOKE_TIMEOUT_SECS)?;
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
        scan: s.scan,
        interpreter: s.interpreter,
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
        scan: s.scan,
        interpreter: s.interpreter,
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
    // The push returns the pushed image's digest when the registry reports one; a plain push
    // never fails on a missing digest — only signing, which needs it, does.
    let digest_ref = crate::registry::push_to_registry(&s.tree, reference, &s.cfg)?;
    let signed = if opts.sign {
        let dref = digest_ref
            .context("cannot sign: the registry did not return a digest for the pushed image")?;
        Some(sign_pushed(&dref, opts)?)
    } else {
        None
    };
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
        scan: s.scan,
        interpreter: s.interpreter,
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

    fn resolution(sonames: &[&str]) -> resolver::Resolution {
        resolver::Resolution {
            interpreter: Some(resolver::ResolvedInterp {
                image_path: std::path::PathBuf::from("/lib64/ld-linux-x86-64.so.2"),
                source: std::path::PathBuf::from("/lib64/ld-linux-x86-64.so.2"),
            }),
            libs: sonames
                .iter()
                .map(|s| resolver::ResolvedLib {
                    soname: (*s).to_string(),
                    path: std::path::PathBuf::from(format!("/lib/{s}")),
                })
                .collect(),
            missing: vec![],
            edges: vec![],
        }
    }

    #[test]
    fn lib_policy_passes_when_satisfied_and_when_empty() {
        let res = resolution(&["libc.so.6", "libm.so.6"]);
        // No policy: always ok.
        assert!(check_lib_policy(&res, &[], &[], &[]).is_ok());
        // require present + deny absent: ok.
        assert!(
            check_lib_policy(&res, &[], &["libc.so.6".into()], &["libssl.so.3".into()]).is_ok()
        );
    }

    #[test]
    fn lib_policy_fails_on_denied_present_and_required_absent() {
        let res = resolution(&["libc.so.6", "libssl.so.3"]);
        let denied = check_lib_policy(&res, &[], &[], &["libssl.so.3".into()]).unwrap_err();
        assert!(denied
            .to_string()
            .contains("denied library present: libssl.so.3"));
        let missing = check_lib_policy(&res, &[], &["libseccomp.so.2".into()], &[]).unwrap_err();
        assert!(missing
            .to_string()
            .contains("required library missing: libseccomp.so.2"));
        // Both at once are reported together.
        let both =
            check_lib_policy(&res, &[], &["libx.so".into()], &["libssl.so.3".into()]).unwrap_err();
        let msg = both.to_string();
        assert!(msg.contains("denied library present") && msg.contains("required library missing"));
    }

    #[test]
    fn lib_policy_covers_loader_and_staged_nss_modules() {
        // The loader (interpreter) and NSS modules ship outside `resolution.libs`; the gate
        // must still see them. `staged_includes` mirrors what stage_default_includes reports.
        let res = resolution(&["libc.so.6"]);
        let staged = vec![
            std::path::PathBuf::from("/etc/nsswitch.conf"), // not a .so — ignored
            std::path::PathBuf::from("/usr/lib/x86_64-linux-gnu/libresolv.so.2"),
        ];
        // The loader is denyable by its file name.
        assert!(check_lib_policy(&res, &staged, &[], &["ld-linux-x86-64.so.2".into()]).is_err());
        // A staged NSS module is denyable even though it is not a resolved dependency.
        assert!(check_lib_policy(&res, &staged, &[], &["libresolv.so.2".into()]).is_err());
        // ...and requiring it is satisfied, since it does ship.
        assert!(check_lib_policy(&res, &staged, &["libresolv.so.2".into()], &[]).is_ok());
        // A non-`.so` staged file is not a library target.
        assert!(check_lib_policy(&res, &staged, &["nsswitch.conf".into()], &[]).is_err());
    }

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

    // Shorthand for the warning over one staged locale and one env entry.
    fn locale_warning(env: &[&str]) -> Option<String> {
        let locales = vec!["en_US.UTF-8".to_string()];
        let env: Vec<String> = env.iter().map(|e| (*e).to_string()).collect();
        locale_env_warning(&locales, &env)
    }

    #[test]
    fn staged_locale_without_any_selector_warns() {
        let warning = locale_warning(&[]).expect("a staged locale needs a selector");
        assert!(warning.contains("LANG=en_US.UTF-8"), "{warning}");
        // No locale staged means nothing to select, so there is nothing to say.
        assert!(locale_env_warning(&[], &[]).is_none());
    }

    #[test]
    fn a_selector_naming_the_staged_locale_is_quiet() {
        assert!(locale_warning(&["LANG=en_US.UTF-8"]).is_none());
        assert!(locale_warning(&["LC_ALL=en_US.UTF-8"]).is_none());
        // glibc reads each per-category LC_* as well, so one of those selects it too.
        assert!(locale_warning(&["LC_TIME=en_US.UTF-8"]).is_none());
        // glibc treats en_US.utf8 and en_US.UTF-8 as one locale, so the codeset punctuation
        // and the case must not decide this.
        assert!(locale_warning(&["LANG=en_us.utf8"]).is_none());
        // An empty value selects nothing, so it reads as no selector at all.
        assert!(locale_warning(&["LANG="]).is_some());
    }

    #[test]
    fn a_selector_naming_an_unstaged_locale_warns() {
        // The invisible failure this feature exists to prevent: the image selects a locale
        // whose data it does not carry, so glibc silently falls back to C.
        let warning = locale_warning(&["LANG=fr_FR.UTF-8"]).expect("mismatch must warn");
        assert!(warning.contains("fr_FR.UTF-8"), "{warning}");
        assert!(warning.contains("en_US.UTF-8"), "{warning}");
        // A per-category selector naming an unstaged locale fails for that category alone,
        // which is just as invisible.
        assert!(locale_warning(&["LANG=en_US.UTF-8", "LC_TIME=fr_FR.UTF-8"]).is_some());
        // C and POSIX need no data on disk, so selecting one is never a mismatch.
        assert!(locale_warning(&["LANG=C"]).is_none());
        assert!(locale_warning(&["LC_ALL=POSIX"]).is_none());
        assert!(locale_warning(&["LANG=C.UTF-8"]).is_none());
    }

    #[test]
    fn locale_names_normalize_down_to_what_glibc_sees() {
        assert_eq!(
            normalize_locale("en_US.UTF-8"),
            normalize_locale("en_us.utf8")
        );
        // A modifier is part of the identity, and a missing codeset is not the same locale.
        assert_ne!(normalize_locale("de_DE.UTF-8"), normalize_locale("de_DE"));
        assert_ne!(
            normalize_locale("de_DE.UTF-8@euro"),
            normalize_locale("de_DE.UTF-8")
        );
    }
}
