//! Orchestrate a pack: resolve → stage → default-includes → assemble → load.
//! This is the glue behind `scratchsmith pack`.

use crate::image::{self, ImageConfig};
use crate::packages::{self, Owners, Package, PackagesSelection};
use crate::report::{PackReport, Timings};
use crate::resolver::{self, Sysroot};
use crate::stager::{self, AddFile, NssSelection, RuntimeExtras, SizeReport, StagedTree};
use crate::supplychain::{self, SbomRequest, ScanRequest, ScanSource, ScanSummary};
use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use std::time::Instant;

/// How long to let a smoke-run's entrypoint run before treating it as "started".
const SMOKE_TIMEOUT_SECS: u32 = 15;

// Generate the SBOM of the staged rootfs if requested, returning its path.
fn maybe_sbom(rootfs: &Path, sbom: Option<&SbomRequest>) -> Result<Option<PathBuf>> {
    match sbom {
        Some(req) => {
            supplychain::generate_sbom(rootfs, req.format, &req.path)?;
            Ok(Some(req.path.clone()))
        }
        None => Ok(None),
    }
}

// Vulnerability-scan the staged rootfs with grype when requested, reusing the SBOM syft
// wrote if there is one (else scanning the rootfs directly). A `fail_on` gate turns a
// finding at or above that severity into a hard error, before anything is delivered.
fn maybe_scan(
    rootfs: &Path,
    sbom_path: Option<&Path>,
    scan: Option<&ScanRequest>,
) -> Result<Option<ScanSummary>> {
    let Some(req) = scan else { return Ok(None) };
    let source = match sbom_path {
        Some(p) => ScanSource::Sbom(p.to_path_buf()),
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
    /// The files staged so far that a package can own, as `(host path, image path)`.
    bundled: Vec<(PathBuf, PathBuf)>,
    clock: Clock,
}

/// The pack's stopwatch: when it began, and the time per phase so far. Every sink starts
/// with `build_rootfs`, so that is where the clock starts.
struct Clock {
    started: Instant,
    timings: Timings,
}

impl Clock {
    // Stamp the total and hand the timings to the report.
    fn finish(mut self) -> Timings {
        self.timings.total_ms = millis(self.started);
        self.timings
    }
}

fn millis(since: Instant) -> u64 {
    since.elapsed().as_millis() as u64
}

// Run one phase and return its result with how long it took. A failure returns early, so
// a failed phase has no timing -- there is no report to put it in.
fn timed<T>(phase: impl FnOnce() -> Result<T>) -> Result<(T, u64)> {
    let started = Instant::now();
    let out = phase()?;
    Ok((out, millis(started)))
}

// Resolve `binary` and build its complete rootfs (libs, loader, cache, NSS/passwd
// includes) under `dest`, optionally stripping. The shared core of every pack path.
// Returns the tree, the size report, the loader path and any include warnings (no printing).
fn build_rootfs(binary: &Path, dest: &Path, opts: &PackOptions) -> Result<StagedRootfs> {
    let mut clock = Clock {
        started: Instant::now(),
        timings: Timings::default(),
    };
    let info = resolver::read_elf_info(binary)?;
    // Reject musl up front rather than staging a subtly broken image.
    resolver::ensure_glibc(&info)?;

    let mut warnings = opts.notes.clone();
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
    resolution.print_notes();
    if !resolution.missing.is_empty() {
        resolution.print_hints();
        bail!(
            "cannot pack: unresolved dependencies: {}",
            resolver::missing_for_display(&resolution.missing)
        );
    }
    clock.timings.resolve_ms = millis(clock.started);
    let staging = Instant::now();
    let (tree, default_includes) =
        stager::stage_with_includes(binary, &resolution, dest, opts.symlinks, &opts.nss)?;
    warnings.extend(default_includes.warnings);
    // Gate on the library policy over everything staged (resolved libs, the loader, and the
    // NSS modules), so a denied library cannot slip in via the default-includes.
    check_lib_policy(
        &resolution,
        &default_includes.staged,
        &opts.require,
        &opts.deny,
    )?;
    let sizes = stager::strip_and_measure_with(
        dest,
        &tree,
        &resolution,
        &default_includes.staged,
        opts.strip,
        opts.upx,
    )?;
    let interpreter = resolution.interpreter_path();
    let bundled = bundled_files(binary, &tree, &resolution, &default_includes.staged);
    clock.timings.stage_ms = millis(staging);
    Ok(StagedRootfs {
        tree,
        size: sizes,
        warnings,
        interpreter,
        bundled,
        clock,
    })
}

// The files whose owner is worth asking for, as `(host path, image path)`: the binary, the
// resolved libraries, the loader and the NSS modules. The two paths are the same for all
// but two. The loader is read from its real file and staged at the path PT_INTERP names,
// and the binary is asked about by its real path and named by its entrypoint.
fn bundled_files(
    binary: &Path,
    tree: &StagedTree,
    resolution: &resolver::Resolution,
    staged_includes: &[PathBuf],
) -> Vec<(PathBuf, PathBuf)> {
    let host_binary = std::fs::canonicalize(binary).unwrap_or_else(|_| binary.to_path_buf());
    let mut files = vec![(host_binary, tree.entrypoint.clone())];
    files.extend(
        resolution
            .libs
            .iter()
            .map(|lib| (lib.path.clone(), lib.path.clone())),
    );
    files.extend(
        resolution
            .interpreter
            .iter()
            .map(|i| (i.source.clone(), i.image_path.clone())),
    );
    // The include report also lists nsswitch.conf, which scratchsmith writes itself.
    files.extend(
        staged_includes
            .iter()
            .filter(|p| p.to_string_lossy().contains(".so"))
            .map(|p| (p.clone(), p.clone())),
    );
    files
}

// Ask the host which package owns each bundled file. `None` means "not known": the lookup
// is off, the host has no package database, or the lookup failed.
//
// How a host that cannot answer is treated depends on what was asked:
// - the default selection stays quiet. It is on for every pack with a JSON report, `--sbom` or
//   `--scan`, so it must not turn a pack that worked into one that fails, or nag on a host with
//   neither dpkg nor rpm;
// - an explicit `report` gets a warning, and the report says `null`;
// - an explicit `sbom` or `image` FAILS. The user asked for an SBOM or an image that
//   carries the package data, and shipping one without it would look the same from outside;
// - a default `sbom` whose records fail (rpm 4.11 has no `rpmdb --exportdb`) is turned off,
//   and the lookup runs again without records, so the report still names the owners.
//   Records that then cannot be made (an `--add-file` on their path, no host os-release, an
//   rpm database rpm cannot build) are left out with a warning in `finish_staging`, for the
//   same reason. A write error in the output tree still fails the pack.
//
// `manager` is a parameter so each of those is testable on any host. It is a function, so
// `--packages none` probes nothing: "looks nothing up" includes the probe.
fn lookup_owners(
    files: &[(PathBuf, PathBuf)],
    conventions: &[(&str, PathBuf)],
    selection: &mut PackagesSelection,
    manager: impl FnOnce() -> Option<packages::Manager>,
    warnings: &mut Vec<String>,
) -> Result<Option<Owners>> {
    if !selection.any() {
        return Ok(None);
    }
    let asked: &str = if selection.sbom && selection.image {
        "sbom,image"
    } else if selection.image {
        "image"
    } else {
        "sbom"
    };
    let Some(manager) = manager() else {
        if selection.requires_records() {
            bail!(
                "--packages {asked} needs a dpkg or rpm database to name the packages, and \
                 this host has neither. Remove {asked} from --packages to pack without it"
            );
        }
        if selection.explicit {
            warnings.push(
                "--packages: this host has no dpkg or rpm database, so the report names no \
                 packages"
                    .to_string(),
            );
        }
        return Ok(None);
    };
    let mut found = packages::owners(manager, files, conventions, selection.needs_records());
    // Only an explicit selection has `image`, so this is the default `sbom`. Any failure
    // retries once without the records, also when the text report has no `report`: rpm 4.11
    // then succeeds and stays quiet, and every other failure fails again and warns below.
    if found.is_err() && selection.sbom && !selection.explicit {
        selection.sbom = false;
        found = packages::owners(manager, files, conventions, false);
    }
    match found {
        Ok(owners) => {
            // Not asked is not the same as not owned, and the two look alike in the list.
            if !owners.unasked.is_empty() {
                warnings.push(format!(
                    "--packages: dpkg reads `*`, `?`, `[` and `\\` in a path as a pattern, so \
                     these files were not looked up and name no package: {}",
                    // A path can hold a newline or a terminal escape, and the text
                    // report prints warnings as they are.
                    owners
                        .unasked
                        .iter()
                        .map(|p| p.escape_debug().to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
            Ok(Some(owners))
        }
        Err(err) if selection.requires_records() => {
            Err(err.context(format!("--packages {asked}: the package lookup failed")))
        }
        Err(err) => {
            // The package manager's own words can quote a path back, so they are escaped.
            let cause = format!("{err:#}");
            warnings.push(format!("package lookup failed: {}", cause.escape_debug()));
            Ok(None)
        }
    }
}

// `--packages sbom` has two readers, syft (`--sbom`) and grype (`--scan`). With neither on,
// nothing reads the records, so the output is turned off. An explicit `sbom` says so: asking
// for something and getting nothing must not be quiet. The default `sbom` was not asked for,
// so it goes quietly. With `sbom` alone that also skips the lookup, whose answer would go
// nowhere. Not an error: a configuration file can set the output once, for packs that pass
// `--sbom` only some of the time.
//
// Only `sbom` is ever cleared here. The report reads `report` alone, so `report_packages`
// gives the same answer for this selection and for `opts.packages`.
fn drop_unread_sbom(
    mut selection: PackagesSelection,
    reads_tree: bool,
    warnings: &mut Vec<String>,
) -> PackagesSelection {
    if selection.sbom && !reads_tree {
        if selection.explicit {
            warnings.push(
                "--packages sbom: neither --sbom nor --scan is on, so nothing reads the package \
                 records and this output does nothing. Add --sbom or --scan, or remove sbom \
                 from --packages"
                    .to_string(),
            );
        }
        selection.sbom = false;
    }
    selection
}

// The report's `packages` field. `None` (JSON `null`) is "not reported": the output is off,
// or the host could not answer. An empty list is a real answer: dpkg was asked, and no
// package owns any bundled file. A gate must be able to tell the two apart.
fn report_packages(selection: &PackagesSelection, owners: Option<Owners>) -> Option<Vec<Package>> {
    owners.filter(|_| selection.report).map(|o| o.packages)
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
    /// Where the owning-package data for the bundled files goes (`--packages`).
    pub packages: PackagesSelection,
    /// Warnings the caller found before the pack, such as a flag that has no effect. They lead
    /// the report's warnings.
    pub notes: Vec<String>,
}

/// Where a pack delivers its result. Every sink shares the resolve → stage pipeline and
/// differs only in delivery, so adding one (the daemonless OCI archive / registry push
/// are the next two) is a new variant + a `pack` arm, not a new top-level entry point.
#[derive(Clone)]
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

/// A pack option that the chosen sink, or `--watch`, cannot honour. [`Sink::conflict`] finds
/// it; the CLI words some of them itself, because only it knows where a config value was set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive] // a new sink or option rule may add one
pub enum Conflict {
    /// `smoke` with [`Sink::Rootfs`]: no image is built, so nothing can run.
    SmokeNoBuild,
    /// `smoke` with [`Sink::OciArchive`]: nothing loads the archive to run it.
    SmokeOciArchive,
    /// `smoke` with [`Sink::Push`]: the image goes to a registry, not to a local engine.
    SmokePush,
    /// `sign` without [`Sink::Push`]: cosign signs a pushed image by its digest.
    SignWithoutPush,
    /// `--watch` with [`Sink::Push`]: a registry is not the place for a pack on every save.
    WatchPush,
    /// `--watch` with `--format json`: one JSON document per pack is a stream shape nobody
    /// has chosen yet. Refusing it keeps that choice open; allowing it later is additive.
    WatchJson,
}

impl std::fmt::Display for Conflict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::SmokeNoBuild => "--smoke needs a built image, so it isn't supported with --no-build; drop --smoke, or remove `smoke = true` from the config and the selected profile",
            Self::SmokeOciArchive => "--smoke needs a running image, so it isn't supported with --oci-archive; load the archive (docker load / skopeo) and run it separately, or drop --smoke",
            Self::SmokePush => "--smoke needs a running image, so it isn't supported with --push; pull the pushed image and run it separately, or drop --smoke",
            Self::SignWithoutPush => "--sign needs a push target. Pass --push or set `push` in the config, or turn signing off",
            Self::WatchPush => "--watch cannot push: it packs again on every change. Pass --oci-archive, remove `push` from the config/profile, or drop --watch",
            Self::WatchJson => "--watch prints a text report for each pack; it cannot be used with --format json",
        })
    }
}

impl Sink {
    /// The first rule that `opts`, `--watch` and its JSON output break for this sink. Every
    /// sink-versus-option rule lives here, in the order the CLI has always reported them, so a
    /// caller that runs this before staging refuses every one of them before any work.
    pub fn conflict(&self, opts: &PackOptions, watch: bool, json: bool) -> Option<Conflict> {
        let push = matches!(self, Self::Push(_));
        if opts.smoke && matches!(self, Self::Rootfs(_)) {
            Some(Conflict::SmokeNoBuild)
        } else if opts.sign && !push {
            Some(Conflict::SignWithoutPush)
        } else if watch && push {
            Some(Conflict::WatchPush)
        } else if watch && json {
            Some(Conflict::WatchJson)
        } else if opts.smoke && matches!(self, Self::OciArchive(_)) {
            Some(Conflict::SmokeOciArchive)
        } else if opts.smoke && push {
            Some(Conflict::SmokePush)
        } else {
            None
        }
    }
}

/// Pack `binary` and deliver it via `sink` — the single entry point the CLI dispatches
/// to. `Rootfs` stops after staging; the image sinks build the scratch image and deliver.
pub fn pack(binary: &Path, opts: &PackOptions, sink: Sink) -> Result<PackReport> {
    // The CLI has refused these already, worded for where each option was set; this is the
    // check for any other caller, and it runs before any staging.
    if let Some(conflict) = sink.conflict(opts, false, false) {
        bail!(crate::cli::UsageError(conflict.to_string()));
    }
    let (delivered, common) = match sink {
        Sink::Rootfs(dir) => to_rootfs(binary, &dir, opts),
        Sink::DockerLoad => to_docker(binary, opts),
        Sink::OciArchive(out) => to_oci_archive(binary, opts, &out),
        Sink::Push(reference) => to_push(binary, opts, &reference),
    }?;
    Ok(report(delivered, common))
}

/// What a sink delivered, with only the fields that sink sets. The report's four delivery
/// fields hold exactly one value, and `signed` and `smoke_ok` only on the sink that can set
/// them, because no other shape of this enum exists.
enum Delivered {
    Rootfs {
        staged_dir: String,
    },
    /// `smoked` is true when the smoke-run started the binary. A failed smoke-run is an error,
    /// so the report's `smoke_ok` is never `Some(false)`.
    DockerLoad {
        tag: String,
        smoked: bool,
    },
    OciArchive {
        archive: String,
    },
    Push {
        pushed: String,
        signed: Option<String>,
    },
}

/// The report fields that every sink fills the same way.
struct Common {
    entrypoint: String,
    interpreter: Option<String>,
    size: SizeReport,
    warnings: Vec<String>,
    sbom: Option<String>,
    scan: Option<ScanSummary>,
    packages: Option<Vec<Package>>,
    clock: Clock,
}

// The one place a PackReport is built. The --format json shape is a v1.0 contract, so the
// fields keep their order and meaning: the JSON for every sink is unchanged.
fn report(delivered: Delivered, c: Common) -> PackReport {
    let (mut tag, mut archive, mut pushed, mut staged_dir) = (None, None, None, None);
    let (mut smoke_ok, mut signed) = (None, None);
    match delivered {
        Delivered::Rootfs { staged_dir: dir } => staged_dir = Some(dir),
        Delivered::DockerLoad { tag: t, smoked } => {
            tag = Some(t);
            smoke_ok = smoked.then_some(true);
        }
        Delivered::OciArchive { archive: a } => archive = Some(a),
        Delivered::Push {
            pushed: p,
            signed: s,
        } => {
            pushed = Some(p);
            signed = s;
        }
    }
    PackReport {
        tag,
        archive,
        pushed,
        staged_dir,
        entrypoint: c.entrypoint,
        interpreter: c.interpreter,
        size: c.size,
        warnings: c.warnings,
        smoke_ok,
        sbom: c.sbom,
        scan: c.scan,
        signed,
        timings: c.clock.finish(),
        packages: c.packages,
    }
}

/// What `finish_staging` produced. `extras` matters only to the image sinks (tini wrapping);
/// `to_rootfs` ignores it.
struct Finished {
    extras: stager::RuntimeResult,
    /// The packages that own the bundled files, when a lookup ran and the host could answer.
    owners: Option<Owners>,
    sbom: Option<String>,
    scan: Option<ScanSummary>,
}

// Everything BOTH sinks do after `build_rootfs`, in an order that matters: runtime extras,
// added files, locales, the locale warning, the package lookup, the `--packages image`
// records, the max-size gate, then the SBOM and the scan --
// those two last because they read the staged tree, which is temporary for an image sink.
//
// Extracted because keeping two copies in step is a PROVEN hazard rather than a theoretical
// one: `--locale` and `--symlinks` each had to be added to both, and a third addition that
// reached only one would silently apply to one sink and not the other.
fn finish_staging(
    dest: &Path,
    opts: &PackOptions,
    warnings: &mut Vec<String>,
    timings: &mut Timings,
    mut bundled: Vec<(PathBuf, PathBuf)>,
) -> Result<Finished> {
    let staging = Instant::now();
    let mut extras = stager::stage_runtime_extras(dest, &opts.extras)?;
    warnings.append(&mut extras.warnings);
    warnings.extend(stager::stage_added_files(
        dest,
        &opts.add_files,
        opts.symlinks,
    )?);
    stager::stage_locales(dest, &opts.locales)?;
    warnings.extend(locale_env_warning(&opts.locales, &opts.image.env));
    // Everything a package can own is in the tree now, so this is where the owners are
    // asked for: the files the flags above copied in, on top of the binary and its libraries.
    // Read inside the image: a link this pack staged (an `--add-file` link) must not answer
    // from the host.
    let staged_meta = |image: &Path| {
        stager::staged_path(dest, image, false)
            .ok()
            .and_then(|p| p.symlink_metadata().ok())
    };
    bundled.extend(extras.copied.iter().cloned());
    // An `--add-file` entry is credited only when its BYTES are in the image: a regular file
    // at the destination. A symlink mode can skip the entry, or stage a link in its place,
    // and a link carries none of the package's content, so naming the package for it would
    // put something in the SBOM that the image does not hold.
    bundled.extend(
        opts.add_files
            .iter()
            .filter(|f| staged_meta(&f.dst).is_some_and(|m| m.is_file()))
            .map(|f| {
                let host = std::fs::canonicalize(&f.src).unwrap_or_else(|_| f.src.clone());
                (host, f.dst.clone())
            }),
    );
    // Nothing is named that is not in the tree.
    bundled.retain(|(_, image)| staged_meta(image).is_some());
    // The CA bundle is generated on the host by `update-ca-certificates`, so no package owns
    // its path. It is built from the `ca-certificates` package, and that is the name a
    // reader of the SBOM needs, so it is credited by convention and the docs say so.
    let ca_bundle = PathBuf::from(stager::CA_BUNDLE);
    let conventions: Vec<(&str, PathBuf)> =
        if opts.extras.ca_certs && staged_meta(&ca_bundle).is_some_and(|m| m.is_file()) {
            vec![("ca-certificates", ca_bundle)]
        } else {
            Vec::new()
        };
    let reads_tree = opts.sbom.is_some() || opts.scan.is_some();
    let mut selection = drop_unread_sbom(opts.packages, reads_tree, warnings);
    let found = lookup_owners(
        &bundled,
        &conventions,
        &mut selection,
        packages::manager,
        warnings,
    )?;
    // A record must never land on a file the user added in this pack.
    let added: Vec<PathBuf> = opts.add_files.iter().map(|f| f.dst.clone()).collect();
    // `--packages image`: the records are image content, so they land before the size gate.
    let owners = found.as_ref().filter(|o| !o.packages.is_empty());
    if let (true, Some(owners)) = (selection.image, owners) {
        let asked = if selection.sbom {
            "sbom,image"
        } else {
            "image"
        };
        let records = packages::stage_records(dest, owners, &added)
            .map_err(|err| records_refused(err, asked))?;
        if records.berkeley_db() {
            warnings.push(
                "--packages image: this host's rpm database is a Berkeley DB, and rpm writes \
                 different bytes each time it builds one, so this image is not reproducible. \
                 Remove image from --packages to keep a stable digest"
                    .to_string(),
            );
        }
        records.keep();
    }
    enforce_max_size(dest, opts.max_size)?;
    timings.stage_ms += millis(staging);
    // `--packages sbom` without `image`: syft and grype must see the records and the image
    // must not carry them, so they are in the tree only while those two run. The guard
    // removes them on every path out of this function, a failed SBOM included.
    // `drop_unread_sbom` turned `sbom` off already when neither of the two runs.
    let _records = match owners {
        Some(owners) if selection.sbom && !selection.image => {
            match packages::stage_records(dest, owners, &added) {
                Ok(records) => Some(records),
                // 1.9 never staged records for the default, so records it cannot make do not
                // fail the pack. A file the user added wins over a record they did not ask
                // for. A write error in the tree still fails: the rest of the pack writes there.
                Err(err)
                    if !selection.explicit
                        && err.downcast_ref::<packages::RecordsSkipped>().is_some() =>
                {
                    let cause = format!("{err:#}");
                    warnings.push(format!(
                        "--packages: the SBOM and the scan see no package records. {}. Set \
                         --packages report to pack without them and without this warning",
                        cause.escape_debug()
                    ));
                    None
                }
                Err(err) => return Err(records_refused(err, "sbom")),
            }
        }
        _ => None,
    };
    let (sbom, ms) = timed(|| maybe_sbom(dest, opts.sbom.as_ref()))?;
    timings.sbom_ms = opts.sbom.is_some().then_some(ms);
    let (scan, ms) = timed(|| maybe_scan(dest, sbom.as_deref(), opts.scan.as_ref()))?;
    timings.scan_ms = opts.scan.is_some().then_some(ms);
    Ok(Finished {
        extras,
        owners: found,
        // The report's field is text, so only it is lossy. The tools got the path itself.
        sbom: sbom.map(|p| p.display().to_string()),
        scan,
    })
}

// An explicit `sbom` or `image` whose records cannot be made fails the pack. Name the way
// out, as the default's warning does. A write error in the tree is not that, and stays as is.
fn records_refused(err: anyhow::Error, asked: &str) -> anyhow::Error {
    if err.downcast_ref::<packages::RecordsSkipped>().is_none() {
        return err;
    }
    anyhow::anyhow!("{err:#}. Remove {asked} from --packages to pack without the records")
}

/// Refuse a `--no-build` output directory that is not new or empty, before anything is staged.
/// Staging merges into what is there, so a file from an earlier pack would stay in the tree.
/// A symlink is followed, as 1.x did, so a link to an empty directory packs. A path that
/// exists but is not a directory is refused too. An absent directory is created here, so
/// the pack owns it before any file is staged.
fn check_output_dir(out_dir: &Path) -> Result<()> {
    let shown = out_dir.display();
    let meta = match std::fs::metadata(out_dir) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return claim_output_dir(out_dir),
        Err(e) => bail!("cannot inspect the output directory {shown}: {e}"),
    };
    if !meta.is_dir() {
        bail!("the output path {shown} exists and is not a directory. Choose another path");
    }
    let mut entries = out_dir
        .read_dir()
        .map_err(|e| anyhow::anyhow!("cannot read the output directory {shown}: {e}"))?;
    if entries.next().is_some() {
        bail!("the output directory {shown} is not empty. Empty or remove it, or choose another directory");
    }
    Ok(())
}

/// Create the absent output directory. `create_dir` on the last name fails when something
/// made it after the check, or when it is a dangling link, so neither slips a used tree in.
fn claim_output_dir(out_dir: &Path) -> Result<()> {
    let shown = out_dir.display();
    if let Some(parent) = out_dir.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| anyhow::anyhow!("cannot create the parent of {shown}: {e}"))?;
    }
    match std::fs::create_dir(out_dir) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            bail!("the output path {shown} already exists. Choose another directory")
        }
        Err(e) => bail!("cannot create the output directory {shown}: {e}"),
    }
}

/// Stage `binary`'s rootfs into `out_dir` and stop — no image is built (`-n -o`).
pub fn stage_only(binary: &Path, out_dir: &Path, opts: &PackOptions) -> Result<PackReport> {
    pack(binary, opts, Sink::Rootfs(out_dir.to_path_buf()))
}

fn to_rootfs(binary: &Path, out_dir: &Path, opts: &PackOptions) -> Result<(Delivered, Common)> {
    check_output_dir(out_dir)?;
    let StagedRootfs {
        tree,
        size,
        mut warnings,
        interpreter,
        bundled,
        mut clock,
    } = build_rootfs(binary, out_dir, opts)?;
    // `extras` is unused here: no image is built, so there is no config to wrap with tini.
    let Finished {
        owners, sbom, scan, ..
    } = finish_staging(out_dir, opts, &mut warnings, &mut clock.timings, bundled)?;
    let delivered = Delivered::Rootfs {
        staged_dir: tree.root.display().to_string(),
    };
    let common = Common {
        entrypoint: tree.entrypoint.display().to_string(),
        interpreter,
        size,
        warnings,
        sbom,
        scan,
        packages: report_packages(&opts.packages, owners),
        clock,
    };
    Ok((delivered, common))
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
    /// The report's `packages` field, ready to move into it.
    packages: Option<Vec<Package>>,
    clock: Clock,
}

impl StagedImage {
    // The common report fields. The temp dir goes with it: delivery is done by now.
    fn into_common(self) -> Common {
        Common {
            entrypoint: self.tree.entrypoint.display().to_string(),
            interpreter: self.interpreter,
            size: self.size,
            warnings: self.warnings,
            sbom: self.sbom,
            scan: self.scan,
            packages: self.packages,
            clock: self.clock,
        }
    }
}

fn stage_for_image(binary: &Path, opts: &PackOptions) -> Result<StagedImage> {
    let work = tempfile::tempdir()?;
    let dest = work.path().join("rootfs");
    let StagedRootfs {
        tree,
        size,
        mut warnings,
        interpreter,
        bundled,
        mut clock,
    } = build_rootfs(binary, &dest, opts)?;
    // finish_staging generates the SBOM and scan while the staged rootfs still exists (dest is
    // temporary), which is why this call sits here rather than after the image config.
    let Finished {
        extras,
        owners,
        sbom,
        scan,
    } = finish_staging(&dest, opts, &mut warnings, &mut clock.timings, bundled)?;

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
            warnings.push(format!(
                "--user {user} runs the image as root; the default non-root user is recommended"
            ));
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
        packages: report_packages(&opts.packages, owners),
        clock,
    })
}

/// Pack `binary` into a scratch image loaded in the local Docker daemon. With
/// `opts.smoke`, run the image once afterwards and fail if the dynamic loader could
/// not start it — the guard against a silently broken image.
pub fn run(binary: &Path, opts: &PackOptions) -> Result<PackReport> {
    pack(binary, opts, Sink::DockerLoad)
}

fn to_docker(binary: &Path, opts: &PackOptions) -> Result<(Delivered, Common)> {
    let mut s = stage_for_image(binary, opts)?;
    let ((), ms) = timed(|| image::load_into_docker(&s.tree, &s.tag, &s.cfg, opts.runtime))?;
    s.clock.timings.deliver_ms = Some(ms);

    let mut smoked = false;
    if opts.smoke {
        let (outcome, ms) =
            timed(|| image::smoke_run(opts.runtime, &s.tag, &[], SMOKE_TIMEOUT_SECS))?;
        s.clock.timings.smoke_ms = Some(ms);
        if outcome.loader_failed() {
            bail!(
                "smoke-run failed: the image could not start the binary.\n{}",
                outcome.stderr.trim()
            );
        }
        smoked = true;
    }
    let tag = s.tag.clone();
    Ok((Delivered::DockerLoad { tag, smoked }, s.into_common()))
}

/// Pack `binary` into a daemonless OCI-archive tarball at `out`. No Docker daemon is
/// contacted; `docker load` / `skopeo copy oci-archive:<out>` accept the result.
fn to_oci_archive(binary: &Path, opts: &PackOptions, out: &Path) -> Result<(Delivered, Common)> {
    let mut s = stage_for_image(binary, opts)?;
    let ((), ms) = timed(|| image::write_oci_archive(&s.tree, &s.tag, &s.cfg, out))?;
    s.clock.timings.deliver_ms = Some(ms);
    let archive = out.display().to_string();
    Ok((Delivered::OciArchive { archive }, s.into_common()))
}

/// Pack `binary` and push it straight to a registry reference — no Docker daemon.
/// Credentials come from the local Docker config; every blob is uploaded (oci-client 0.18
/// makes no HEAD check first).
fn to_push(binary: &Path, opts: &PackOptions, reference: &str) -> Result<(Delivered, Common)> {
    let mut s = stage_for_image(binary, opts)?;
    // After staging, so a bad binary or option is reported first; before the push, which
    // would make the image public.
    if opts.sign {
        supplychain::check_cosign()?;
    }
    // The push returns the pushed image's digest when the registry reports one; a plain push
    // never fails on a missing or mismatched digest — only signing, which needs it, does.
    let (digest_ref, ms) = timed(|| crate::registry::push_to_registry(&s.tree, reference, &s.cfg))?;
    s.clock.timings.deliver_ms = Some(ms);
    let signed = if opts.sign {
        let (signed, ms) = timed(|| sign_pushed(reference, digest_ref, opts))?;
        s.clock.timings.sign_ms = Some(ms);
        Some(signed)
    } else {
        // Nothing reads the digest without --sign, but a registry that names a manifest other
        // than the one just pushed must not pass in silence.
        if let crate::registry::PushedDigest::Mismatch(e) = &digest_ref {
            s.warnings.push(format!("{e:#}"));
        }
        None
    };
    let pushed = reference.to_string();
    Ok((Delivered::Push { pushed, signed }, s.into_common()))
}

// cosign-sign the pushed image by digest, and — if an SBOM was generated — attach it as a
// signed attestation. Signing by digest (not tag) pins the exact image just pushed. Returns
// the signed digest reference for the report. The image is public by now, so each failure says
// how far signing got.
fn sign_pushed(
    reference: &str,
    digest: crate::registry::PushedDigest,
    opts: &PackOptions,
) -> Result<String> {
    let not_signed = || format!("{reference} was pushed, but it is not signed");
    let digest_ref = digest.for_signing().with_context(not_signed)?;
    supplychain::cosign_sign(&digest_ref).with_context(not_signed)?;
    if let Some(req) = &opts.sbom {
        supplychain::cosign_attest(&digest_ref, &req.path, req.format.cosign_predicate_type())
            .with_context(|| {
                format!("{reference} was pushed and signed, but its SBOM attestation failed")
            })?;
    }
    Ok(digest_ref)
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
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    format!("scratchsmith/{}:packed", path_component(&name))
}

// `name` as one reference path component, `[a-z0-9]+((\.|_|__|-+)[a-z0-9]+)*`. Each other
// character becomes `-`, a run of separators the grammar does not allow becomes one `-`, and a
// leading or trailing separator is dropped. A name that is already valid is kept as it is.
fn path_component(name: &str) -> String {
    let mapped: String = name
        .chars()
        .map(|c| match c {
            'a'..='z' | '0'..='9' | '.' | '_' | '-' => c,
            _ => '-',
        })
        .collect();
    let mut out = String::new();
    let mut sep = String::new();
    for c in mapped.chars() {
        if c.is_ascii_alphanumeric() {
            if !out.is_empty() && !sep.is_empty() {
                let allowed =
                    matches!(sep.as_str(), "." | "_" | "__") || sep.bytes().all(|b| b == b'-');
                out.push_str(if allowed { &sep } else { "-" });
            }
            sep.clear();
            out.push(c);
        } else {
            sep.push(c);
        }
    }
    if out.is_empty() {
        "image".into()
    } else {
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_delivery_fills_only_its_own_report_fields() {
        let common = || Common {
            entrypoint: "/app".into(),
            interpreter: None,
            size: SizeReport::default(),
            warnings: Vec::new(),
            sbom: None,
            scan: None,
            packages: None,
            clock: Clock {
                started: Instant::now(),
                timings: Timings::default(),
            },
        };
        // (tag, archive, pushed, staged_dir, smoke_ok, signed) for each delivery.
        let fields = |r: PackReport| {
            (
                r.tag,
                r.archive,
                r.pushed,
                r.staged_dir,
                r.smoke_ok,
                r.signed,
            )
        };
        let s = |v: &str| Some(v.to_string());
        let rootfs = Delivered::Rootfs {
            staged_dir: "out".into(),
        };
        assert_eq!(
            fields(report(rootfs, common())),
            (None, None, None, s("out"), None, None)
        );
        for (smoked, smoke_ok) in [(false, None), (true, Some(true))] {
            let docker = Delivered::DockerLoad {
                tag: "app:1".into(),
                smoked,
            };
            assert_eq!(
                fields(report(docker, common())),
                (s("app:1"), None, None, None, smoke_ok, None)
            );
        }
        let archive = Delivered::OciArchive {
            archive: "x.tar".into(),
        };
        assert_eq!(
            fields(report(archive, common())),
            (None, s("x.tar"), None, None, None, None)
        );
        let push = Delivered::Push {
            pushed: "r/x:1".into(),
            signed: s("r/x@sha256:0"),
        };
        assert_eq!(
            fields(report(push, common())),
            (None, None, s("r/x:1"), None, None, s("r/x@sha256:0"))
        );
    }

    #[test]
    fn each_sink_refuses_what_it_cannot_honour_in_the_cli_order() {
        let rootfs = Sink::Rootfs("out".into());
        let archive = Sink::OciArchive("x.tar".into());
        let push = Sink::Push("localhost:5000/x:1".into());
        let smoke = PackOptions {
            smoke: true,
            ..Default::default()
        };
        let sign = PackOptions {
            sign: true,
            ..Default::default()
        };
        let both = PackOptions {
            smoke: true,
            sign: true,
            ..Default::default()
        };
        let none = PackOptions::default();
        let cases = [
            (&rootfs, &smoke, false, false, Some(Conflict::SmokeNoBuild)),
            (
                &archive,
                &smoke,
                false,
                false,
                Some(Conflict::SmokeOciArchive),
            ),
            (&push, &smoke, false, false, Some(Conflict::SmokePush)),
            (&Sink::DockerLoad, &smoke, false, false, None),
            (
                &Sink::DockerLoad,
                &sign,
                false,
                false,
                Some(Conflict::SignWithoutPush),
            ),
            (&push, &sign, false, false, None),
            (&push, &none, true, false, Some(Conflict::WatchPush)),
            (&archive, &none, true, true, Some(Conflict::WatchJson)),
            (&archive, &none, false, true, None),
            // More than one rule broken: the first in the order the CLI always reported.
            (&rootfs, &both, true, true, Some(Conflict::SmokeNoBuild)),
            (&archive, &both, true, true, Some(Conflict::SignWithoutPush)),
            (&push, &smoke, true, true, Some(Conflict::WatchPush)),
            (&archive, &smoke, true, true, Some(Conflict::WatchJson)),
        ];
        for (sink, opts, watch, json, want) in cases {
            assert_eq!(sink.conflict(opts, watch, json), want);
        }
    }

    #[test]
    fn a_symlinked_output_dir_is_refused_only_when_its_target_is_not_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let real = tmp.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let with_slash = PathBuf::from(format!("{}/", link.display()));
        for out in [&link, &with_slash] {
            check_output_dir(out).unwrap();
        }
        std::fs::write(real.join("old"), b"x").unwrap();
        for out in [&link, &with_slash] {
            let err = check_output_dir(out).unwrap_err().to_string();
            assert!(err.contains("is not empty"), "{}: {err}", out.display());
        }
    }

    #[test]
    fn an_absent_output_dir_is_created_and_one_that_appears_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let out = tmp.path().join("a/b/rootfs");
        check_output_dir(&out).unwrap();
        assert!(out.is_dir(), "the check claims an absent directory");
        // What a racing writer leaves between the lookup and the claim.
        let err = claim_output_dir(&out).unwrap_err().to_string();
        assert!(err.contains("Choose another directory"), "{err}");
    }

    #[test]
    fn a_host_that_cannot_name_packages_fails_only_what_asked_for_records() {
        use crate::packages::PackagesOutput::{Image, None as Off, Report, Sbom};
        let select = |outputs: &[_]| PackagesSelection::from_outputs(outputs).unwrap();
        // No dpkg and no rpm on this "host", whatever the real one has.
        let lookup = |selection: &PackagesSelection| {
            let mut warnings = Vec::new();
            let result = lookup_owners(&[], &[], &mut selection.clone(), || None, &mut warnings);
            (result, warnings)
        };

        // The default is on for every pack with a JSON report, `--sbom` or `--scan`: it must
        // not fail one, or say anything. Its `sbom` output included, on either report.
        let default = PackagesSelection::default();
        assert!(default.sbom, "the default must include sbom");
        for selection in [default, default.for_text_report()] {
            let (result, warnings) = lookup(&selection);
            assert!(
                matches!(result, Ok(None)) && warnings.is_empty(),
                "{warnings:?}"
            );
        }
        // Off is off, down to the probe: `none` must not even ask whether dpkg is there.
        let mut warnings = Vec::new();
        let probe = || -> Option<packages::Manager> { panic!("--packages none probed the host") };
        let result = lookup_owners(&[], &[], &mut select(&[Off]), probe, &mut warnings);
        assert!(matches!(result, Ok(None)) && warnings.is_empty());
        // An explicit report cannot be filled, and says so, and the pack goes on.
        let (result, warnings) = lookup(&select(&[Report]));
        assert!(matches!(result, Ok(None)));
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        // An SBOM or an image that was asked to carry the data must not ship without it.
        for (outputs, named) in [
            (&[Sbom][..], "--packages sbom "),
            (&[Image][..], "--packages image "),
            (&[Report, Sbom, Image][..], "--packages sbom,image "),
        ] {
            let (result, _) = lookup(&select(outputs));
            let err = format!("{:#}", result.expect_err("records were asked for"));
            assert!(err.contains(named) && err.contains("dpkg or rpm"), "{err}");
        }

        // "Not known" and "known to be none" must stay apart in the report.
        let on = PackagesSelection::default();
        assert_eq!(report_packages(&on, None), None);
        assert_eq!(report_packages(&on, Some(Owners::default())), Some(vec![]));
        assert_eq!(
            report_packages(&select(&[Image]), Some(Owners::default())),
            None
        );
    }

    #[test]
    fn an_sbom_output_with_no_reader_is_dropped_with_a_warning() {
        use crate::packages::PackagesOutput::{Image, Report, Sbom};
        let select = |outputs: &[_]| PackagesSelection::from_outputs(outputs).unwrap();
        let drop = |selection, reads_tree| {
            let mut warnings = Vec::new();
            (
                drop_unread_sbom(selection, reads_tree, &mut warnings),
                warnings,
            )
        };

        // Neither syft nor grype runs: `sbom` goes, and with it the only reason to look up.
        let (kept, warnings) = drop(select(&[Sbom]), false);
        assert!(!kept.any() && !kept.needs_records());
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(warnings[0].contains("--packages sbom") && warnings[0].contains("--scan"));
        // The other outputs are kept as they were.
        let (kept, warnings) = drop(select(&[Report, Sbom, Image]), false);
        assert!(kept.report && kept.image && !kept.sbom);
        assert_eq!(warnings.len(), 1);

        // A reader is on, or `sbom` was not asked for: nothing changes and nothing is said.
        for (selection, reads_tree) in [
            (select(&[Report, Sbom]), true),
            (select(&[Report, Image]), false),
            (PackagesSelection::default(), true),
        ] {
            let (kept, warnings) = drop(selection, reads_tree);
            assert_eq!(kept, selection);
            assert!(warnings.is_empty(), "{warnings:?}");
        }

        // The default `sbom` with no reader goes too, but quietly: the user did not ask for it.
        let default = PackagesSelection::default();
        assert!(default.sbom, "the default must include sbom");
        let (kept, warnings) = drop(default, false);
        assert!(kept.report && !kept.sbom && !kept.explicit);
        assert!(warnings.is_empty(), "{warnings:?}");
        // With the text report too, so a default text pack looks nothing up.
        let (kept, warnings) = drop(default.for_text_report(), false);
        assert!(!kept.any() && warnings.is_empty(), "{warnings:?}");
    }

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
            hints: vec![],
            notes: vec![],
            arch_warnings: vec![],
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
    fn the_default_tag_is_a_valid_reference_for_any_name() {
        // TASK-210. Each of these gave an invalid reference before.
        for (name, want) in [
            ("c++filt", "c--filt"),
            ("my app", "my-app"),
            (".hidden", "hidden"),
            ("naïve", "na-ve"),
            ("Ünïcode-tool", "n-code-tool"),
            ("a._b", "a-b"),
            ("a___b", "a-b"),
            ("+++", "image"),
            ("x86_64-linux-gnu-g++", "x86_64-linux-gnu-g"),
        ] {
            let tag = image_tag(&Path::new("/usr/bin").join(name));
            assert_eq!(tag, format!("scratchsmith/{want}:packed"), "{name}");
            tag.parse::<oci_client::Reference>()
                .unwrap_or_else(|e| panic!("{name}: {tag}: {e}"));
        }
    }

    #[test]
    fn a_tag_that_is_valid_today_is_unchanged() {
        for name in [
            "myapp",
            "my-app",
            "my--app",
            "my_app",
            "my__app",
            "ld.so",
            "python3.12",
        ] {
            assert_eq!(
                image_tag(&Path::new("/usr/bin").join(name)),
                format!("scratchsmith/{name}:packed")
            );
        }
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
