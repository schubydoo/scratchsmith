//! Orchestrate a pack: resolve → stage → default-includes → assemble → load.
//! This is the glue behind `scratchsmith pack`.

use crate::image::{self, ImageConfig};
use crate::packages::{self, Owners, Package, PackagesSelection};
use crate::report::{PackReport, Timings};
use crate::resolver::{self, Libc, Sysroot};
use crate::stager::{self, AddFile, NssSelection, RuntimeExtras, SizeReport, StagedTree};
use crate::supplychain::{self, SbomRequest, ScanRequest, ScanSource, ScanSummary};
use anyhow::{bail, Context, Result};
use std::collections::HashMap;
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
    /// The C library behind `interpreter`.
    libc: Option<Libc>,
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
    if info.is_musl() {
        refuse_glibc_only_options(binary, opts)?;
    }

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
    let mut resolution =
        resolver::resolve_with_includes(binary, &Sysroot::new("/"), &opts.includes)?;
    add_binary_libs(binary, &info, &mut resolution, &opts.add_binaries)?;
    resolution.print_notes();
    if !resolution.missing.is_empty() {
        resolution.print_hints();
        bail!(
            "cannot pack: unresolved dependencies: {}",
            resolver::missing_for_display(&resolution.missing)
        );
    }
    // musl has no `GLIBC_` symbol versions, so there is nothing to compare.
    if resolution.musl.is_none() {
        warnings.extend(glibc_version_warnings(
            binary,
            &opts.add_binaries,
            &resolution,
        ));
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
    let libc = resolution.libc();
    let bundled = bundled_files(binary, &tree, &resolution, &default_includes.staged);
    clock.timings.stage_ms = millis(staging);
    Ok(StagedRootfs {
        tree,
        size: sizes,
        warnings,
        interpreter,
        libc,
        bundled,
        clock,
    })
}

// `--add-binary`: each added ELF is resolved on its own, by the same ld.so rules as the packed
// binary (`$ORIGIN` names the added file's own directory), and its libraries join the
// resolution. So a library both need stages once, and everything that reads the resolution
// covers the added ones too: ld.so.cache, `--deny`/`--require`, `--strip` and the package
// records. One image has one loader, so an ELF for another loader or machine is refused.
fn add_binary_libs(
    binary: &Path,
    main: &resolver::ElfInfo,
    resolution: &mut resolver::Resolution,
    added: &[AddFile],
) -> Result<()> {
    for add in added {
        let shown = add.src.display().to_string().escape_debug().to_string();
        let info = resolver::read_elf_info(&add.src).map_err(|e| {
            // The hint only fits a file that was read and is not an ELF at all: a missing
            // path or a damaged ELF has its own fix.
            if is_readable_non_elf(&add.src) {
                e.context(format!(
                    "--add-binary {shown} is not an ELF file: add it with --add-file"
                ))
            } else {
                e.context(format!("--add-binary {shown}"))
            }
        })?;
        added_binary_fits(binary, main, &info, &shown)?;
        origin_fits(&info, add, &shown)?;
        let theirs = resolver::resolve(&add.src, &Sysroot::new("/"))
            .with_context(|| format!("--add-binary {shown}"))?;
        added_libs_fit(binary, main, &theirs, &shown)?;
        merge_resolution(resolution, theirs);
        // A library names no loader, so `resolve` walks its dependencies by glibc's rules, in a
        // musl image too. On Alpine they usually find the same files, so this is a note, not a
        // refusal, until the walk can follow the packed binary's libc.
        if main.is_musl() && info.interpreter.is_none() && !info.needed.is_empty() {
            resolution.notes.push(format!(
                "--add-binary {shown} is a shared library, so the libraries it needs were \
                 resolved by glibc's search rules, not musl's. They usually find the same files \
                 on Alpine. Run the image with --smoke to check."
            ));
        }
    }
    Ok(())
}

// A library or static ELF names no loader, so `added_binary_fits` cannot see its libc. It
// shows in what the added file loads: a glibc `libc.so.6` beside a musl loader, or musl's libc
// in a glibc image, sits in the image and never loads (D9).
fn added_libs_fit(
    binary: &Path,
    main: &resolver::ElfInfo,
    theirs: &resolver::Resolution,
    shown: &str,
) -> Result<()> {
    let Some(ours) = main.uses_libc() else {
        return Ok(());
    };
    for lib in &theirs.libs {
        let Ok(info) = resolver::read_elf_info(&lib.path) else {
            continue;
        };
        if let Some(theirs) = info.libc.filter(|libc| *libc != ours) {
            bail!(
                "--add-binary {shown} loads {theirs} through {}, and {} uses {ours}. Pack \
                 programs and libraries of one libc in one image.",
                resolver::printable(&lib.path),
                resolver::printable(binary)
            );
        }
    }
    Ok(())
}

fn added_binary_fits(
    binary: &Path,
    main: &resolver::ElfInfo,
    added: &resolver::ElfInfo,
    shown: &str,
) -> Result<()> {
    // One libc for every program in one image (D9). A static ELF or a library has none.
    if let (Some(ours), Some(theirs)) = (main.uses_libc(), added.uses_libc()) {
        if ours != theirs {
            bail!(
                "--add-binary {shown} uses {theirs}, and {} uses {ours}. Pack programs of one \
                 libc in one image.",
                resolver::printable(binary)
            );
        }
    }
    if (added.machine, added.is_64) != (main.machine, main.is_64) {
        let arch = |i: &resolver::ElfInfo| {
            format!(
                "{} {}-bit",
                goblin::elf::header::machine_to_str(i.machine),
                if i.is_64 { 64 } else { 32 }
            )
        };
        bail!(
            "--add-binary {shown} is built for {}, and the packed binary for {}. One image \
             runs one architecture, so add a build of {shown} for {}",
            arch(added),
            arch(main),
            arch(main)
        );
    }
    // A static ELF, or a shared library, has no PT_INTERP and runs under any loader.
    if let Some(theirs) = &added.interpreter {
        if added.interpreter != main.interpreter {
            let ours = main.interpreter.as_deref().map_or_else(
                || "no interpreter (it is static)".to_string(),
                |i| format!("`{}`", i.escape_debug()),
            );
            bail!(
                "--add-binary {shown} loads through `{}`, and the packed binary through {ours}. \
                 The image stages one loader, so add a build of {shown} that uses the packed \
                 binary's loader",
                theirs.escape_debug()
            );
        }
    }
    Ok(())
}

fn is_readable_non_elf(path: &Path) -> bool {
    use std::io::Read;
    let mut magic = [0u8; 4];
    let Ok(mut file) = std::fs::File::open(path) else {
        return false;
    };
    let read = file.read(&mut magic).unwrap_or(0);
    path.is_file() && magic[..read] != *b"\x7fELF"
}

// The resolver expands `$ORIGIN` against the added file's real host directory, and its
// libraries stage at their host paths. ld.so expands it against the directory the program
// sits in inside the image. So an ELF that searches through `$ORIGIN` must land in its real
// directory, or the libraries found at pack time are not the ones ld.so looks for at run time.
fn origin_fits(info: &resolver::ElfInfo, add: &AddFile, shown: &str) -> Result<()> {
    let uses_origin = info
        .rpaths
        .iter()
        .chain(&info.runpaths)
        .chain(&info.needed)
        .any(|p| p.contains("$ORIGIN") || p.contains("${ORIGIN}"));
    if !uses_origin {
        return Ok(());
    }
    let real = std::fs::canonicalize(&add.src)
        .with_context(|| format!("--add-binary {shown}: resolving its real path"))?;
    if add.dst.parent() != real.parent() {
        bail!(
            "--add-binary {shown} finds libraries through `$ORIGIN`, which ld.so reads from \
             the program's own directory in the image. Stage it in its real directory, as \
             `--add-binary {shown}:{}`, so the libraries found for it are the ones it loads",
            real.display().to_string().escape_debug()
        );
    }
    Ok(())
}

// Fold an added ELF's resolution into the packed binary's. The libraries stage at their own
// host paths, so one real path is one file in the image: keep the first.
fn merge_resolution(into: &mut resolver::Resolution, theirs: resolver::Resolution) {
    for lib in theirs.libs {
        if !into.libs.iter().any(|l| l.path == lib.path) {
            into.libs.push(lib);
        }
    }
    for name in theirs.missing {
        if !into.missing.contains(&name) {
            into.missing.push(name);
        }
    }
    into.edges.extend(theirs.edges);
    into.hints.extend(theirs.hints);
    into.notes.extend(theirs.notes);
    into.arch_warnings.extend(theirs.arch_warnings);
    // One loader, so one path file: the added program's system dirs join the packed one's.
    // Its found-path links join too, or musl cannot open those libraries in the image.
    if let (Some(ours), Some(theirs)) = (&mut into.musl, theirs.musl) {
        for dir in theirs.system_dirs {
            if !ours.system_dirs.contains(&dir) {
                ours.system_dirs.push(dir);
            }
        }
        for link in theirs.links {
            if !ours.links.contains(&link) {
                ours.links.push(link);
            }
        }
    }
}

// musl has no NSS and reads no compiled glibc locale, so `--nss` and `--locale` would do
// nothing for a musl binary. Refuse an explicit value rather than drop it without a word. The
// set-in places come from the raw values, before `--nss` falls back to `files,dns`.
fn refuse_glibc_only_options(binary: &Path, opts: &PackOptions) -> Result<()> {
    let bin = resolver::printable(binary);
    let drop = |flag: &str, key: &str, set_in: &str| {
        if set_in == "the command line" {
            format!("Drop {flag}.")
        } else {
            format!("The `{key}` key is set in {set_in}: remove it there.")
        }
    };
    if let Some(set_in) = &opts.nss_set_in {
        bail!(crate::cli::UsageError(format!(
            "--nss selects glibc NSS modules, and {bin} uses musl, which has no NSS. {}",
            drop("--nss", "nss", set_in)
        )));
    }
    if let Some(set_in) = &opts.locale_set_in {
        bail!(crate::cli::UsageError(format!(
            "--locale compiles glibc locales, and {bin} uses musl, which does not read them. \
             musl has a built-in C.UTF-8. {}",
            drop("--locale", "locale", set_in)
        )));
    }
    Ok(())
}

// Resolution matches sonames, not symbol versions, so a binary built against a newer glibc
// than this host's resolves, stages and packs, and then ld.so refuses to start it ("version
// `GLIBC_2.38' not found"). Read the `GLIBC_` versions that the binary and each staged library
// need, and warn for each one the staged object it names does not define. A warning, not a
// failure: failing would change the exit code, which the v2 line keeps.
fn glibc_version_warnings(
    binary: &Path,
    added: &[AddFile],
    resolution: &resolver::Resolution,
) -> Vec<String> {
    // An object that cannot be read here was read by the resolver a moment ago, so this is
    // rare, and the pack does not depend on it: say nothing rather than fail.
    let read = |path: &Path| {
        std::fs::read(path)
            .ok()
            .and_then(|bytes| resolver::symbol_versions(&bytes).ok())
            .unwrap_or_default()
    };
    let mut objects = vec![(binary.to_path_buf(), read(binary))];
    objects.extend(added.iter().map(|a| (a.src.clone(), read(&a.src))));
    let mut provided = HashMap::new();
    for lib in &resolution.libs {
        let versions = read(&lib.path);
        provided.insert(lib.soname.clone(), versions.defined.clone());
        objects.push((lib.path.clone(), versions));
    }
    // The loader is a DT_NEEDED entry too (`__tls_get_addr` is in GLIBC_2.3 of
    // ld-linux-x86-64.so.2), named by the file name that PT_INTERP gives it.
    if let Some(interp) = &resolution.interpreter {
        if let Some(name) = interp.image_path.file_name() {
            let name = name.to_string_lossy().into_owned();
            provided.insert(name, read(&interp.source).defined);
        }
    }
    glibc_gaps(&objects, &provided)
}

// One warning for each object that needs a `GLIBC_` version its named object does not
// define, naming the highest such version. An object it names that is not staged is skipped:
// the resolver already failed the pack on it, or it is a loader this pack did not resolve. So
// is one that defines no versions (no DT_VERDEF, or not read again): ld.so accepts any version
// from it.
fn glibc_gaps(
    objects: &[(PathBuf, resolver::SymbolVersions)],
    provided: &HashMap<String, Vec<String>>,
) -> Vec<String> {
    let staged = provided.get("libc.so.6").and_then(|defined| {
        defined
            .iter()
            .filter_map(|v| resolver::glibc_release(v))
            .max()
    });
    let dotted = |release: &[u32]| {
        release
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(".")
    };
    let mut warnings = Vec::new();
    for (path, versions) in objects {
        let missing = versions.needed.iter().filter(|(file, version)| {
            version.starts_with("GLIBC_")
                && provided
                    .get(file)
                    .is_some_and(|defined| !defined.is_empty() && !defined.contains(version))
        });
        // The highest numbered version names the glibc to pack on. A name with no number
        // (`GLIBC_ABI_DT_RELR`) is reported only when it is the only one missing.
        let Some((file, version)) =
            missing.max_by_key(|(_, version)| resolver::glibc_release(version))
        else {
            continue;
        };
        let staged_note = staged
            .as_ref()
            .map(|r| {
                format!(
                    " (the newest version the staged libc.so.6 defines is GLIBC_{})",
                    dotted(r)
                )
            })
            .unwrap_or_default();
        let fix = match resolver::glibc_release(version) {
            Some(r) => format!("Pack on a host whose glibc is {} or newer", dotted(&r)),
            None => "Pack on a host with a newer glibc".to_string(),
        };
        warnings.push(format!(
            "{} needs {version} from {file}, which the staged {file} does not define{staged_note}, \
             so the image will not start. {fix}",
            path.display().to_string().escape_debug(),
            version = version.escape_debug(),
            file = file.escape_debug(),
        ));
    }
    warnings
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
//
// Returns the selection the rest of the pack goes by, beside the owners: the retry above can
// turn `sbom` off, and the records staged later must follow that.
// On an Alpine host the database is apk's, which `--packages` cannot read yet. Saying so
// beats "this host has neither", which reads as a host with no package manager.
fn no_records_error(asked: &str, apk: bool) -> String {
    if apk {
        format!(
            "--packages {asked} needs a dpkg or rpm database to name the packages, and this \
             host uses apk, which `--packages` does not read yet. Remove {asked} from \
             --packages to pack without it"
        )
    } else {
        format!(
            "--packages {asked} needs a dpkg or rpm database to name the packages, and this \
             host has neither. Remove {asked} from --packages to pack without it"
        )
    }
}

fn no_database_warning(apk: bool) -> String {
    if apk {
        "--packages: this host uses apk, which `--packages` does not read yet, so the report \
         names no packages"
            .to_string()
    } else {
        "--packages: this host has no dpkg or rpm database, so the report names no packages"
            .to_string()
    }
}

fn lookup_owners(
    files: &[(PathBuf, PathBuf)],
    conventions: &[(&str, PathBuf)],
    selection: PackagesSelection,
    manager: impl FnOnce() -> Option<packages::Manager>,
    warnings: &mut Vec<String>,
) -> Result<(PackagesSelection, Option<Owners>)> {
    if !selection.any() {
        return Ok((selection, None));
    }
    let asked = selection.records_label();
    let Some(manager) = manager() else {
        let apk = std::path::Path::new("/lib/apk/db/installed").exists();
        if selection.requires_records() {
            bail!("{}", no_records_error(asked, apk));
        }
        if selection.explicit {
            warnings.push(no_database_warning(apk));
        }
        return Ok((selection, None));
    };
    let found = packages::owners(manager, files, conventions, selection.needs_records());
    // Only an explicit selection has `image`, so this is the default `sbom`. Any failure
    // retries once without the records, also when the text report has no `report`: rpm 4.11
    // then succeeds and stays quiet, and every other failure fails again and warns below.
    let (selection, found) = if found.is_err() && selection.sbom && !selection.explicit {
        let without = PackagesSelection {
            sbom: false,
            ..selection
        };
        (
            without,
            packages::owners(manager, files, conventions, false),
        )
    } else {
        (selection, found)
    };
    let owners = match found {
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
            Some(owners)
        }
        Err(err) if selection.requires_records() => {
            return Err(err.context(format!("--packages {asked}: the package lookup failed")));
        }
        Err(err) => {
            // The package manager's own words can quote a path back, so they are escaped.
            let cause = format!("{err:#}");
            warnings.push(format!("package lookup failed: {}", cause.escape_debug()));
            None
        }
    };
    Ok((selection, owners))
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
    selection: PackagesSelection,
    reads_tree: bool,
    warnings: &mut Vec<String>,
) -> PackagesSelection {
    if !selection.sbom || reads_tree {
        return selection;
    }
    if selection.explicit {
        warnings.push(
            "--packages sbom: neither --sbom nor --scan is on, so nothing reads the package \
             records and this output does nothing. Add --sbom or --scan, or remove sbom from \
             --packages"
                .to_string(),
        );
    }
    PackagesSelection {
        sbom: false,
        ..selection
    }
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
    /// ELF files to copy into the image with their shared libraries (`--add-binary
    /// SRC[:DST]`). Each is resolved like the packed binary, and copied like an `--add-file`.
    pub add_binaries: Vec<AddFile>,
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
    /// Push the manifest by its digest only, creating or moving no tag. `--push` only.
    pub push_untagged: bool,
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
    /// Where an explicit `--nss` value is set (`the command line`, or the config file and
    /// profile), before the default applies. A musl pack refuses one.
    pub nss_set_in: Option<String>,
    /// Where an explicit `--locale` value is set, as for `nss_set_in`.
    pub locale_set_in: Option<String>,
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
    /// `push_untagged` without [`Sink::Push`]: only a push has a tag to leave alone.
    UntaggedWithoutPush,
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
            Self::UntaggedWithoutPush => "--push-untagged needs a push target. Pass --push or set `push` in the config, or remove `push-untagged = true`",
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
        } else if opts.push_untagged && !push {
            Some(Conflict::UntaggedWithoutPush)
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
    libc: Option<Libc>,
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
        libc: c.libc,
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
    // The program is always copied as a file, whatever `--symlinks` says: a link left in its
    // place could dangle or be skipped, and the libraries resolved for its target would then
    // ship without the program they serve.
    warnings.extend(stager::stage_added_files_as(
        dest,
        &opts.add_binaries,
        stager::SymlinkMode::CopyAll,
        "--add-binary",
    )?);
    if opts.extras.ca_certs {
        stager::stage_ca_bundle_link(dest)?;
    }
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
            .chain(&opts.add_binaries)
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
    let selection = drop_unread_sbom(opts.packages, reads_tree, warnings);
    let (selection, found) = lookup_owners(
        &bundled,
        &conventions,
        selection,
        packages::manager,
        warnings,
    )?;
    // A record must never land on a file the user added in this pack.
    let added: Vec<PathBuf> = opts
        .add_files
        .iter()
        .chain(&opts.add_binaries)
        .map(|f| f.dst.clone())
        .collect();
    // `--packages image`: the records are image content, so they land before the size gate.
    let owners = found.as_ref().filter(|o| !o.packages.is_empty());
    if let (true, Some(owners)) = (selection.image, owners) {
        let records = packages::stage_records(dest, owners, &added)
            .map_err(|err| records_refused(err, selection.records_label()))?;
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
                Err(err) => return Err(records_refused(err, selection.records_label())),
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
        libc,
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
        libc,
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
    libc: Option<Libc>,
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
            libc: self.libc,
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
        libc,
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
        libc,
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
    let (outcome, ms) = timed(|| {
        crate::registry::push_to_registry(&s.tree, reference, &s.cfg, opts.push_untagged)
    })?;
    let crate::registry::Pushed {
        digest: digest_ref,
        by_digest,
    } = outcome;
    s.clock.timings.deliver_ms = Some(ms);
    // An untagged push has no reference but its digest, so that is what the report names, and
    // what a signing failure names as the image to sign by hand.
    let pushed = if opts.push_untagged {
        by_digest
    } else {
        reference.to_string()
    };
    let signed = if opts.sign {
        let (signed, ms) = timed(|| sign_pushed(&pushed, digest_ref, opts))?;
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
    fn a_glibc_version_the_staged_object_lacks_warns_once_per_object() {
        let versions = |needed: &[(&str, &str)]| resolver::SymbolVersions {
            needed: needed
                .iter()
                .map(|(f, v)| (f.to_string(), v.to_string()))
                .collect(),
            defined: Vec::new(),
        };
        let defines = |names: &[&str]| names.iter().map(|n| n.to_string()).collect::<Vec<_>>();
        let provided = HashMap::from([
            (
                "libc.so.6".to_string(),
                defines(&["libc.so.6", "GLIBC_2.2.5", "GLIBC_2.34", "GLIBC_2.35"]),
            ),
            ("ld-linux-x86-64.so.2".to_string(), defines(&["GLIBC_2.3"])),
            ("libplain.so.1".to_string(), Vec::new()),
        ]);
        let objects = vec![
            // Needs two versions libc lacks: named once, by the higher one.
            (
                PathBuf::from("/app/new"),
                versions(&[
                    ("libc.so.6", "GLIBC_2.34"),
                    ("libc.so.6", "GLIBC_2.38"),
                    ("libc.so.6", "GLIBC_2.36"),
                ]),
            ),
            // Everything it needs is there, from libc and from the loader.
            (
                PathBuf::from("/app/old"),
                versions(&[
                    ("libc.so.6", "GLIBC_2.2.5"),
                    ("ld-linux-x86-64.so.2", "GLIBC_2.3"),
                ]),
            ),
            // Not glibc's, and from a file this pack did not stage: neither is checked here.
            (
                PathBuf::from("/app/cxx"),
                versions(&[
                    ("libstdc++.so.6", "GLIBCXX_3.4.30"),
                    ("libgone.so.1", "GLIBC_2.99"),
                ]),
            ),
            // ld.so accepts any version from an object that defines none.
            (
                PathBuf::from("/app/plain"),
                versions(&[("libplain.so.1", "GLIBC_2.99")]),
            ),
            // A version with no number still breaks the start.
            (
                PathBuf::from("/app/relr"),
                versions(&[("libc.so.6", "GLIBC_ABI_DT_RELR")]),
            ),
        ];
        let warnings = glibc_gaps(&objects, &provided);
        assert_eq!(
            warnings,
            [
                "/app/new needs GLIBC_2.38 from libc.so.6, which the staged libc.so.6 does not \
                 define (the newest version the staged libc.so.6 defines is GLIBC_2.35), so the \
                 image will not start. Pack on a host whose glibc is 2.38 or newer",
                "/app/relr needs GLIBC_ABI_DT_RELR from libc.so.6, which the staged libc.so.6 \
                 does not define (the newest version the staged libc.so.6 defines is \
                 GLIBC_2.35), so the image will not start. Pack on a host with a newer glibc",
            ]
        );
        // A path is escaped: the text report prints warnings as they are.
        let odd = vec![(
            PathBuf::from("/app/a\nb"),
            versions(&[("libc.so.6", "GLIBC_2.99")]),
        )];
        let warnings = glibc_gaps(&odd, &provided);
        assert!(warnings[0].starts_with("/app/a\\nb needs"), "{warnings:?}");
    }

    #[test]
    fn an_added_binary_must_match_the_packed_binarys_loader_and_machine() {
        let main = resolver::read_elf_info(Path::new("/usr/bin/id")).unwrap();
        let fits = |added: &resolver::ElfInfo| {
            added_binary_fits(Path::new("/usr/bin/id"), &main, added, "/x")
        };
        assert!(fits(&main).is_ok());
        // A static ELF, or a shared library, names no loader and fits any image.
        let static_elf = resolver::ElfInfo {
            interpreter: None,
            ..main.clone()
        };
        assert!(fits(&static_elf).is_ok());
        let other_loader = resolver::ElfInfo {
            interpreter: Some("/opt/glibc/ld.so".to_string()),
            ..main.clone()
        };
        let err = fits(&other_loader).unwrap_err().to_string();
        assert!(
            err.contains("loads through `/opt/glibc/ld.so`, and the packed binary through `"),
            "{err}"
        );
        let other_machine = resolver::ElfInfo {
            machine: if main.machine == goblin::elf::header::EM_AARCH64 {
                goblin::elf::header::EM_X86_64
            } else {
                goblin::elf::header::EM_AARCH64
            },
            ..main.clone()
        };
        let err = fits(&other_machine).unwrap_err().to_string();
        assert!(err.contains("One image runs one architecture"), "{err}");
        let other_class = resolver::ElfInfo {
            is_64: !main.is_64,
            ..main.clone()
        };
        assert!(fits(&other_class).is_err());
        // One libc for every program in one image (D9), in both directions.
        let musl = resolver::ElfInfo {
            interpreter: Some("/lib/ld-musl-x86_64.so.1".to_string()),
            ..main.clone()
        };
        assert_eq!(
            format!("{:#}", fits(&musl).unwrap_err()),
            "--add-binary /x uses musl, and /usr/bin/id uses glibc. Pack programs of one libc \
             in one image."
        );
        let err = added_binary_fits(Path::new("/app"), &musl, &main, "/x").unwrap_err();
        assert_eq!(
            format!("{err:#}"),
            "--add-binary /x uses glibc, and /app uses musl. Pack programs of one libc in one \
             image."
        );
        assert!(added_binary_fits(Path::new("/app"), &musl, &musl, "/x").is_ok());
    }

    #[test]
    fn an_added_binary_that_uses_origin_must_stay_in_its_real_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = std::fs::canonicalize(tmp.path())
            .unwrap()
            .join("opt/tool/bin");
        std::fs::create_dir_all(&dir).unwrap();
        let src = dir.join("tool");
        std::fs::write(&src, b"elf").unwrap();
        let add = |dst: &Path| AddFile {
            src: src.clone(),
            dst: dst.to_path_buf(),
        };
        let plain = resolver::read_elf_info(Path::new("/usr/bin/id")).unwrap();
        let moved = add(Path::new("/usr/local/bin/tool"));
        // No `$ORIGIN`: any destination works.
        assert!(origin_fits(&plain, &moved, "t").is_ok());
        for origin in ["$ORIGIN/../lib", "${ORIGIN}/../lib"] {
            let info = resolver::ElfInfo {
                runpaths: vec![origin.to_string()],
                ..plain.clone()
            };
            let err = origin_fits(&info, &moved, "t").unwrap_err().to_string();
            assert!(
                err.contains(&format!("`--add-binary t:{}`", src.display())),
                "{err}"
            );
            // Its real directory, under another name, is fine.
            assert!(origin_fits(&info, &add(&dir.join("tool2")), "t").is_ok());
        }
        let rpath = resolver::ElfInfo {
            rpaths: vec!["$ORIGIN".to_string()],
            ..plain.clone()
        };
        assert!(origin_fits(&rpath, &moved, "t").is_err());
    }

    #[test]
    fn the_add_file_hint_is_only_for_a_file_that_is_not_an_elf() {
        let tmp = tempfile::tempdir().unwrap();
        let script = tmp.path().join("run.sh");
        std::fs::write(&script, b"#!/bin/sh\n").unwrap();
        assert!(is_readable_non_elf(&script));
        let empty = tmp.path().join("empty");
        std::fs::write(&empty, b"").unwrap();
        assert!(is_readable_non_elf(&empty));
        assert!(!is_readable_non_elf(Path::new("/usr/bin/id")));
        assert!(!is_readable_non_elf(&tmp.path().join("missing")));
        assert!(!is_readable_non_elf(tmp.path()));
    }

    #[test]
    fn an_added_binarys_libraries_join_the_resolution_once() {
        let lib = |soname: &str, path: &str| resolver::ResolvedLib {
            soname: soname.to_string(),
            path: PathBuf::from(path),
        };
        let mut into = resolver::Resolution {
            libs: vec![lib("libc.so.6", "/lib/libc.so.6")],
            missing: vec!["libgone.so.1".to_string()],
            ..Default::default()
        };
        let theirs = resolver::Resolution {
            libs: vec![
                lib("libc.so.6", "/lib/libc.so.6"),
                lib("libtinfo.so.6", "/lib/libtinfo.so.6"),
            ],
            missing: vec!["libgone.so.1".to_string(), "libnew.so.2".to_string()],
            notes: vec!["a note".to_string()],
            ..Default::default()
        };
        merge_resolution(&mut into, theirs);
        assert_eq!(
            into.libs,
            [
                lib("libc.so.6", "/lib/libc.so.6"),
                lib("libtinfo.so.6", "/lib/libtinfo.so.6")
            ]
        );
        assert_eq!(into.missing, ["libgone.so.1", "libnew.so.2"]);
        assert_eq!(into.notes, ["a note"]);
    }

    #[test]
    fn an_added_musl_programs_system_dirs_and_links_join_once() {
        let link = |at: &str, to: &str| (PathBuf::from(at), PathBuf::from(to));
        let search = |dirs: &[&str], links: Vec<(PathBuf, PathBuf)>| resolver::MuslSearch {
            path_file: PathBuf::from("/etc/ld-musl-x86_64.path"),
            system_dirs: dirs.iter().map(PathBuf::from).collect(),
            links,
        };
        let shared = link("/usr/lib64/libz.so.1", "/usr/lib/libz.so.1");
        let mut into = resolver::Resolution {
            musl: Some(search(&["/usr/lib64"], vec![shared.clone()])),
            ..Default::default()
        };
        let theirs = resolver::Resolution {
            musl: Some(search(
                &["/usr/lib64", "/opt/sys"],
                vec![
                    shared.clone(),
                    link("/app/libs/libown.so.1", "/opt/other/libown.so.1.0"),
                ],
            )),
            ..Default::default()
        };
        merge_resolution(&mut into, theirs);
        let musl = into.musl.unwrap();
        assert_eq!(
            musl.system_dirs,
            [PathBuf::from("/usr/lib64"), PathBuf::from("/opt/sys")]
        );
        assert_eq!(
            musl.links,
            [
                shared,
                link("/app/libs/libown.so.1", "/opt/other/libown.so.1.0")
            ]
        );
    }

    #[test]
    fn a_binary_built_for_this_hosts_glibc_packs_with_no_version_warning() {
        let resolution = resolver::resolve(Path::new("/usr/bin/id"), &Sysroot::new("/")).unwrap();
        assert_eq!(
            glibc_version_warnings(Path::new("/usr/bin/id"), &[], &resolution),
            Vec::<String>::new()
        );
    }

    #[test]
    fn a_binary_that_needs_a_newer_glibc_than_the_staged_one_is_named() {
        // /usr/bin/id with one needed `GLIBC_2.x` name rewritten to `GLIBC_2.99`, in place
        // and at the same length, so only the version it needs changes.
        let mut bytes = std::fs::read("/usr/bin/id").unwrap();
        let at = bytes
            .windows(11)
            .position(|w| {
                w.starts_with(b"GLIBC_2.") && w[8..10].iter().all(u8::is_ascii_digit) && w[10] == 0
            })
            .expect("id needs a two-digit GLIBC_2.x version");
        bytes[at + 8..at + 10].copy_from_slice(b"99");
        let dir = tempfile::tempdir().unwrap();
        let binary = dir.path().join("id");
        std::fs::write(&binary, &bytes).unwrap();
        let resolution = resolver::resolve(Path::new("/usr/bin/id"), &Sysroot::new("/")).unwrap();
        let warnings = glibc_version_warnings(&binary, &[], &resolution);
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        // From libc.so.6 on most hosts, but the loader is the other glibc object it can name.
        let expected = format!("{} needs GLIBC_2.99 from ", binary.display());
        assert!(warnings[0].starts_with(&expected), "{warnings:?}");
        assert!(
            warnings[0].ends_with("glibc is 2.99 or newer"),
            "{warnings:?}"
        );
    }

    #[test]
    fn an_apk_host_is_named_when_packages_cannot_be_read() {
        let apk = no_records_error("sbom", true);
        assert!(
            apk.contains("this host uses apk, which `--packages` does not read yet"),
            "{apk}"
        );
        assert!(
            apk.ends_with("Remove sbom from --packages to pack without it"),
            "{apk}"
        );
        assert!(no_records_error("sbom", false).contains("this host has neither"));
        assert!(no_database_warning(true).contains("uses apk"));
        assert!(no_database_warning(false).contains("no dpkg or rpm database"));
    }

    #[test]
    fn each_delivery_fills_only_its_own_report_fields() {
        let common = || Common {
            entrypoint: "/app".into(),
            interpreter: None,
            libc: None,
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
        let untagged = PackOptions {
            push_untagged: true,
            ..Default::default()
        };
        let none = PackOptions::default();
        let cases = [
            (&push, &untagged, false, false, None),
            (
                &archive,
                &untagged,
                false,
                false,
                Some(Conflict::UntaggedWithoutPush),
            ),
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
            let result = lookup_owners(&[], &[], *selection, || None, &mut warnings);
            (result.map(|(_, owners)| owners), warnings)
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
        let result = lookup_owners(&[], &[], select(&[Off]), probe, &mut warnings);
        assert!(matches!(result, Ok((_, None))) && warnings.is_empty());
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
            musl: None,
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
