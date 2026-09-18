//! Stage a resolved binary into a rootfs: place the loader, libraries, and binary
//! at the paths the runtime expects, recreate soname symlinks, and regenerate the
//! loader cache. Consumes the [`Resolution`] produced by [`crate::resolver`].
//! See Tasks 1.4-1.5.

use crate::resolver::Resolution;
use anyhow::{bail, Context, Result};
use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;

/// A staged rootfs ready to become an image layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagedTree {
    /// The staging root on disk.
    pub root: PathBuf,
    /// The binary's path *inside* the image — the default entrypoint.
    pub entrypoint: PathBuf,
}

/// Optional runtime files a user can inject (Task 4.5). Unlike the always-on NSS
/// includes, these are opt-in, and an explicit request that can't be satisfied is an
/// error (the user asked for it), not a warning.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RuntimeExtras {
    /// TLS CA bundle at /etc/ssl/certs/ca-certificates.crt.
    pub ca_certs: bool,
    /// The resolved local timezone at /etc/localtime.
    pub tz: bool,
    /// A minimal init (`tini`) at /tini, to reap zombies / forward signals.
    pub init: bool,
}

/// Result of staging runtime extras — notably where `tini` landed, so the caller can
/// wrap the entrypoint with it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuntimeResult {
    pub tini_image_path: Option<String>,
}

const CA_BUNDLE: &str = "/etc/ssl/certs/ca-certificates.crt";

/// Inject the requested runtime extras into the staged rootfs.
pub fn stage_runtime_extras(dest: &Path, extras: &RuntimeExtras) -> Result<RuntimeResult> {
    let mut result = RuntimeResult::default();

    if extras.ca_certs {
        let src = Path::new(CA_BUNDLE);
        if !src.exists() {
            bail!("--ca-certs: CA bundle not found at {CA_BUNDLE}");
        }
        copy_into(src, dest, src)?;
    }

    if extras.tz {
        // /etc/localtime is usually a symlink into the zoneinfo DB; copy the resolved
        // zone file so the container's local time is correct without the whole DB.
        let localtime = Path::new("/etc/localtime");
        let real = std::fs::canonicalize(localtime).context("resolving /etc/localtime")?;
        copy_into(&real, dest, localtime)?;
    }

    if extras.init {
        let tini = find_tini().context("--init: tini not found; install tini")?;
        copy_into(&tini, dest, Path::new("/tini"))?;
        result.tini_image_path = Some("/tini".to_string());
    }

    Ok(result)
}

// Locate a tini binary in the usual places.
fn find_tini() -> Result<PathBuf> {
    for candidate in [
        "/usr/bin/tini",
        "/sbin/tini",
        "/usr/bin/tini-static",
        "/bin/tini",
    ] {
        let path = PathBuf::from(candidate);
        if path.exists() {
            return Ok(path);
        }
    }
    bail!("no tini binary found")
}

/// A host file to copy into the image (`--add-file SRC[:DST]`). `--ca-certs` and `--tz`
/// each stage one fixed path; this is the arbitrary-file escape hatch beside them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddFile {
    /// The host file to copy.
    pub src: PathBuf,
    /// Where it lands inside the image (absolute).
    pub dst: PathBuf,
}

impl AddFile {
    /// Parse a `SRC[:DST]` spec. Without `:DST` the file lands at its own path, so
    /// `--add-file /etc/motd` mirrors the host. The split is on the LAST colon, so a
    /// source path containing one still parses as long as the destination does not.
    pub fn parse(spec: &str) -> Result<AddFile> {
        let (src, dst) = spec.rsplit_once(':').unwrap_or((spec, spec));
        if src.is_empty() || dst.is_empty() {
            bail!("--add-file '{spec}': expected SRC or SRC:DST, both non-empty");
        }
        let dst_path = Path::new(dst);
        if !dst_path.is_absolute() {
            // Name both halves: a colon inside a bare SRC splits the spec in a way the user
            // never intended, and "the image path must be absolute" alone would not show it.
            bail!(
                "--add-file '{spec}': read '{src}' as the source and '{dst}' as the image path, \
                 but the image path must be absolute, e.g. ./app.conf:/etc/app.conf"
            );
        }
        // The image path is joined under the staging root, so a `..` would write outside it.
        if dst_path
            .components()
            .any(|c| c == std::path::Component::ParentDir)
        {
            bail!("--add-file '{spec}': the image path must not contain '..'");
        }
        Ok(AddFile {
            src: PathBuf::from(src),
            dst: dst_path.to_path_buf(),
        })
    }
}

/// Copy each `--add-file` source into the staged rootfs. A missing source, a non-regular
/// source, or an image path already staged is an error, not a warning: the user named this
/// file explicitly, so failing beats shipping an image that silently lacks it or silently
/// lost something else.
pub fn stage_added_files(dest: &Path, files: &[AddFile]) -> Result<()> {
    for file in files {
        // metadata() follows symlinks, so a symlinked source stages the file it names.
        let md = std::fs::metadata(&file.src)
            .with_context(|| format!("--add-file: cannot read {}", file.src.display()))?;
        if !md.is_file() {
            let kind = if md.is_dir() {
                "a directory"
            } else {
                "not a regular file"
            };
            bail!(
                "--add-file: {} is {kind}; --add-file takes regular files",
                file.src.display()
            );
        }
        // Refuse to land on anything already there. `std::fs::copy` would truncate it without
        // a word, and on a soname symlink it writes THROUGH the link and corrupts the real
        // library. symlink_metadata sees the link itself, so both cases are caught here.
        if under(dest, &file.dst).symlink_metadata().is_ok() {
            bail!(
                "--add-file: {} is already in the image; --add-file will not replace a staged \
                 file, and each image path can be given only once",
                file.dst.display()
            );
        }
        copy_into(&file.src, dest, &file.dst).with_context(|| {
            format!(
                "--add-file: staging {} at {}",
                file.src.display(),
                file.dst.display()
            )
        })?;
    }
    Ok(())
}

/// What the default-include step added, and what it could not find.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct IncludeReport {
    /// Image paths added (nsswitch, NSS modules, CA bundle).
    pub staged: Vec<PathBuf>,
    /// Best-effort items that were absent on the host — surfaced, never silently skipped.
    pub warnings: Vec<String>,
}

// A scratch image has no name-service config, so glibc name lookups fail before they
// even try. Ship a minimal one naming only the modules the selection stages — no
// systemd/mymachines NSS module to drag in. The glibc modules are dlopen'd, so the
// resolver never sees them; they must be pulled in explicitly, from the same directory
// as libc so the versions match exactly.

/// A name-service (NSS) module selectable with `--nss` / the `nss` config key. glibc
/// uses these for name lookups; staging fewer trims CVE surface.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive] // may gain modules in a minor; not a stable exhaustive library API
pub enum NssModule {
    /// Local-file lookups (/etc/passwd, /etc/hosts, ...): the libnss_files module.
    Files,
    /// DNS host lookups: the libnss_dns + libresolv modules.
    Dns,
    /// Stage no NSS modules and no nsswitch.conf. Must be the only value.
    None,
}

/// Which name-service modules to stage into the image. Built from `--nss`; the default
/// (both on) reproduces the historical local-files-plus-DNS behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NssSelection {
    pub files: bool,
    pub dns: bool,
}

impl Default for NssSelection {
    fn default() -> Self {
        Self {
            files: true,
            dns: true,
        }
    }
}

impl NssSelection {
    /// Stage nothing — no NSS modules and no nsswitch.conf.
    pub const NONE: Self = Self {
        files: false,
        dns: false,
    };

    /// Build a selection from the `--nss` values. Empty means the default set. A `none`
    /// value must stand alone; combining it with a module is a usage error.
    pub fn from_modules(modules: &[NssModule]) -> Result<Self> {
        if modules.is_empty() {
            return Ok(Self::default());
        }
        if modules.contains(&NssModule::None) {
            if modules.len() > 1 {
                bail!("--nss none cannot be combined with other modules");
            }
            return Ok(Self::NONE);
        }
        Ok(Self {
            files: modules.contains(&NssModule::Files),
            dns: modules.contains(&NssModule::Dns),
        })
    }

    fn is_none(self) -> bool {
        !self.files && !self.dns
    }

    // The glibc modules this selection needs, version-matched beside libc.
    fn modules(self) -> Vec<&'static str> {
        let mut m = Vec::new();
        if self.files {
            m.push("libnss_files.so.2");
        }
        if self.dns {
            m.push("libnss_dns.so.2");
            m.push("libresolv.so.2");
        }
        m
    }

    // A minimal nsswitch.conf naming only the selected sources, or None when nothing is
    // staged (a static image doing no name lookups). The file never names a source whose
    // module is absent: the file-only databases appear only when `files` is staged.
    fn nsswitch(self) -> Option<String> {
        if self.is_none() {
            return None;
        }
        let hosts = match (self.files, self.dns) {
            (true, true) => "files dns",
            (true, false) => "files",
            (false, true) => "dns",
            (false, false) => unreachable!("is_none returned early"),
        };
        let files_dbs = if self.files {
            "\
passwd:         files
group:          files
shadow:         files
networks:       files
protocols:      files
services:       files
"
        } else {
            ""
        };
        Some(format!("{files_dbs}hosts:          {hosts}\n"))
    }
}

// A `passwd: files` nsswitch is a lie without a passwd database, and binaries that
// call getpwuid() at startup (to find $HOME) get a null and may misbehave. Ship a
// minimal one, matching dockerize2's template. The non-root default user (Task 2.3)
// will extend this later.
const MINIMAL_PASSWD: &str = "\
root:x:0:0:root:/root:/sbin/nologin
nonroot:x:65532:65532:nonroot:/home/nonroot:/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/sbin/nologin
";

const MINIMAL_GROUP: &str = "\
root:x:0:
nonroot:x:65532:
nobody:x:65534:
";

/// Stage `binary` and its resolved dependencies under `dest`, then build the cache.
pub fn stage(binary: &Path, resolution: &Resolution, dest: &Path) -> Result<StagedTree> {
    let tree = stage_files(binary, resolution, dest)?;
    generate_ld_cache(dest, resolution)?;
    Ok(tree)
}

/// Add the runtime files glibc loads outside the dependency graph so that DNS and
/// user lookups work: a minimal nsswitch.conf, the NSS modules (version-matched to
/// the staged libc), and — when `files` is staged — a minimal passwd/group. `nss`
/// selects which modules and nsswitch sources are staged (`--nss`). Missing NSS modules
/// become warnings, not errors. TLS CA certs are a separate opt-in (`--ca-certs`, Task 4.5).
pub fn stage_default_includes(
    resolution: &Resolution,
    dest: &Path,
    nss: &NssSelection,
) -> Result<IncludeReport> {
    let mut report = IncludeReport::default();

    if let Some(body) = nss.nsswitch() {
        let nsswitch = under(dest, Path::new("/etc/nsswitch.conf"));
        std::fs::create_dir_all(nsswitch.parent().unwrap())?;
        std::fs::write(&nsswitch, body)?;
        report.staged.push(PathBuf::from("/etc/nsswitch.conf"));
    }

    // NSS modules live beside libc; without libc (a static binary) there is nothing
    // to match against, so there is nothing to do here.
    let modules = nss.modules();
    if !modules.is_empty() {
        match libc_dir(resolution) {
            Some(dir) => {
                for name in modules {
                    let src = dir.join(name);
                    if src.exists() {
                        copy_into(&src, dest, &src)?;
                        report.staged.push(src);
                    } else {
                        report
                            .warnings
                            .push(format!("NSS module not found: {name}"));
                    }
                }
            }
            None => report
                .warnings
                .push("no libc in resolution; skipped NSS modules".into()),
        }
    }

    // passwd/group are read through the `files` NSS module. Without it (a `dns`-only or
    // `none` selection) glibc cannot read them, so shipping them would be dead weight and
    // a lie — an image with /etc/passwd whose getpwuid() still returns null. Stage them
    // only when `files` is staged.
    if nss.files {
        for (path, body) in [
            ("/etc/passwd", MINIMAL_PASSWD),
            ("/etc/group", MINIMAL_GROUP),
        ] {
            let target = under(dest, Path::new(path));
            std::fs::create_dir_all(target.parent().unwrap())?;
            std::fs::write(&target, body)?;
            report.staged.push(PathBuf::from(path));
        }
    }

    Ok(report)
}

/// One staged ELF file's size, before and after an optional strip.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct SizeEntry {
    pub path: String,
    pub before: u64,
    pub after: u64,
}

/// Sizes of the staged ELF payload (binary + loader + libraries), with totals.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct SizeReport {
    pub entries: Vec<SizeEntry>,
    pub total_before: u64,
    pub total_after: u64,
    pub stripped: bool,
    /// The executable was UPX-compressed (its `after` reflects the compressed size).
    pub upx: bool,
}

impl std::fmt::Display for SizeReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Show before -> after columns whenever a size reduction was applied (strip or UPX).
        let reduced = self.stripped || self.upx;
        for e in &self.entries {
            if reduced {
                writeln!(f, "  {:>10} -> {:>10}  {}", e.before, e.after, e.path)?;
            } else {
                writeln!(f, "  {:>10}  {}", e.after, e.path)?;
            }
        }
        if reduced {
            let saved = self.total_before.saturating_sub(self.total_after);
            write!(
                f,
                "  total {} -> {} bytes (saved {})",
                self.total_before, self.total_after, saved
            )
        } else {
            write!(f, "  total {} bytes", self.total_after)
        }
    }
}

/// Measure the staged ELF payload, optionally stripping each file first. Strip uses
/// `strip --strip-unneeded`, which is safe for both executables and shared objects
/// (it keeps the dynamic symbols the loader needs).
pub fn strip_and_measure(
    dest: &Path,
    tree: &StagedTree,
    resolution: &Resolution,
    strip: bool,
    upx: bool,
) -> Result<SizeReport> {
    // The ELF files we placed: the binary, the loader, and every resolved library. UPX
    // compresses the executable ONLY — compressing the loader or a shared library would
    // break startup — so it is applied to the binary (the first target) alone.
    let binary = under(dest, &tree.entrypoint);
    let mut targets: Vec<PathBuf> = vec![binary.clone()];
    if let Some(interp) = &resolution.interpreter {
        targets.push(under(dest, &interp.image_path));
    }
    targets.extend(resolution.libs.iter().map(|l| under(dest, &l.path)));

    let mut report = SizeReport {
        stripped: strip,
        upx,
        ..Default::default()
    };
    for path in targets {
        let before = std::fs::metadata(&path)?.len();
        if strip {
            run_strip(&path)?;
        }
        // Strip first (a smaller input compresses better), then UPX the executable.
        if upx && path == binary {
            run_upx(&path)?;
        }
        let after = std::fs::metadata(&path)?.len();
        report.total_before += before;
        report.total_after += after;
        report.entries.push(SizeEntry {
            path: display_image_path(dest, &path),
            before,
            after,
        });
    }
    Ok(report)
}

fn run_strip(path: &Path) -> Result<()> {
    let out = Command::new("strip")
        .arg("--strip-unneeded")
        .arg(path)
        .output()
        .context("running strip (install binutils?)")?;
    if !out.status.success() {
        bail!(
            "strip failed on {}: {}",
            path.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

// Compress an executable in place with UPX (`--best` for ratio). UPX is absent on many
// hosts, so a spawn failure is surfaced as a clear, actionable error, not a panic.
fn run_upx(path: &Path) -> Result<()> {
    let out = Command::new("upx")
        .arg("--best")
        .arg(path)
        .output()
        .context("running upx (install upx?)")?;
    if !out.status.success() {
        bail!(
            "upx failed on {}: {}",
            path.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

// Show a staged file by its image-absolute path, not the temp staging prefix.
fn display_image_path(dest: &Path, staged: &Path) -> String {
    staged
        .strip_prefix(dest)
        .map(|rel| format!("/{}", rel.display()))
        .unwrap_or_else(|_| staged.display().to_string())
}

// The directory libc resolved from — the version-matched source for NSS modules.
fn libc_dir(resolution: &Resolution) -> Option<PathBuf> {
    resolution
        .libs
        .iter()
        .find(|l| l.soname.starts_with("libc.so"))
        .and_then(|l| l.path.parent().map(Path::to_path_buf))
}

// File placement only — no ld.so.cache — so the copy and symlink logic is testable
// without the external ldconfig tool.
fn stage_files(binary: &Path, resolution: &Resolution, dest: &Path) -> Result<StagedTree> {
    // Never build an image known to be broken; the caller must fix the deps first.
    if !resolution.missing.is_empty() {
        bail!(
            "refusing to stage: unresolved dependencies: {}",
            resolution.missing.join(", ")
        );
    }

    // Mirror the binary at its real path so any $ORIGIN-relative RPATH still resolves;
    // that same absolute path is the default entrypoint.
    let binary_real =
        std::fs::canonicalize(binary).with_context(|| format!("locating {}", binary.display()))?;
    copy_into(&binary_real, dest, &binary_real)?;

    // The kernel execs PT_INTERP verbatim, so the loader must live at that exact path.
    if let Some(interp) = &resolution.interpreter {
        copy_into(&interp.source, dest, &interp.image_path)?;
    }

    // Each library: place the real file, then recreate the soname symlink the loader
    // looks up when the real file name differs (the versioned-soname case).
    for lib in &resolution.libs {
        copy_into(&lib.path, dest, &lib.path)?;
        if lib.path.file_name() != Some(OsStr::new(&lib.soname)) {
            symlink_soname(dest, &lib.path, &lib.soname)?;
        }
    }

    Ok(StagedTree {
        root: dest.to_path_buf(),
        entrypoint: binary_real,
    })
}

// Regenerate /etc/ld.so.cache inside the staged root. A fresh root has no
// ld.so.conf, so write one listing every dir we staged into, then let ldconfig
// (which knows the glibc cache format) build the cache against that root.
fn generate_ld_cache(dest: &Path, resolution: &Resolution) -> Result<()> {
    let mut dirs = BTreeSet::new();
    for lib in &resolution.libs {
        if let Some(dir) = lib.path.parent() {
            dirs.insert(dir.to_path_buf());
        }
    }
    if let Some(interp) = &resolution.interpreter {
        if let Some(dir) = interp.image_path.parent() {
            dirs.insert(dir.to_path_buf());
        }
    }

    let conf = under(dest, Path::new("/etc/ld.so.conf"));
    std::fs::create_dir_all(conf.parent().unwrap())?;
    let body: String = dirs.iter().map(|d| format!("{}\n", d.display())).collect();
    std::fs::write(&conf, body).with_context(|| format!("writing {}", conf.display()))?;

    run_ldconfig(dest)?;

    let cache = under(dest, Path::new("/etc/ld.so.cache"));
    if !cache.exists() {
        bail!("ldconfig produced no cache at {}", cache.display());
    }
    Ok(())
}

// Map an absolute image path to its location under the staging root.
fn under(root: &Path, abs: &Path) -> PathBuf {
    root.join(abs.strip_prefix("/").unwrap_or(abs))
}

fn copy_into(src: &Path, root: &Path, abs_target: &Path) -> Result<()> {
    let target = under(root, abs_target);
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::copy(src, &target)
        .with_context(|| format!("copying {} -> {}", src.display(), target.display()))?;
    Ok(())
}

// Recreate the soname symlink beside the real file, pointing at its basename (a
// relative link, so it stays valid once the tree becomes the image root).
fn symlink_soname(root: &Path, real_abs: &Path, soname: &str) -> Result<()> {
    let dir = real_abs.parent().context("library has no parent dir")?;
    let link = under(root, &dir.join(soname));
    let target = real_abs.file_name().context("library has no file name")?;
    if link.symlink_metadata().is_ok() {
        return Ok(()); // idempotent
    }
    std::os::unix::fs::symlink(target, &link)
        .with_context(|| format!("linking {} -> {:?}", link.display(), target))?;
    Ok(())
}

// Run ldconfig against `root`. ldconfig lives in a system sbin that is not always
// on PATH, so try the usual locations; a genuine failure is reported, not skipped.
fn run_ldconfig(root: &Path) -> Result<()> {
    for prog in ["ldconfig", "/usr/sbin/ldconfig", "/sbin/ldconfig"] {
        match Command::new(prog).arg("-r").arg(root).output() {
            Ok(out) if out.status.success() => return Ok(()),
            Ok(out) => bail!(
                "ldconfig failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e).context("running ldconfig"),
        }
    }
    bail!("ldconfig not found; install glibc tools (libc-bin) to build the loader cache")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resolver::{ResolvedInterp, ResolvedLib};
    use std::fs;

    // Build a fake source file with known bytes and return its canonical path.
    fn make_file(path: &Path, bytes: &[u8]) -> PathBuf {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
        fs::canonicalize(path).unwrap()
    }

    #[test]
    fn loader_lands_at_its_pt_interp_path() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        let dest = tmp.path().join("dest");
        let binary = make_file(&src.join("app"), b"binary");
        let loader = make_file(&src.join("real-ld.so"), b"LOADER");

        let res = Resolution {
            interpreter: Some(ResolvedInterp {
                image_path: PathBuf::from("/lib64/ld-linux-x86-64.so.2"),
                source: loader,
            }),
            libs: vec![],
            missing: vec![],
            edges: vec![],
        };
        stage_files(&binary, &res, &dest).unwrap();

        let staged_loader = dest.join("lib64/ld-linux-x86-64.so.2");
        assert!(
            staged_loader.exists(),
            "loader must be at its PT_INTERP path"
        );
        assert_eq!(fs::read(&staged_loader).unwrap(), b"LOADER");
    }

    #[test]
    fn versioned_soname_gets_real_file_plus_symlink() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("usr/lib/x86_64-linux-gnu");
        let dest = tmp.path().join("dest");
        let binary = make_file(&tmp.path().join("bin/app"), b"binary");
        // Real file is libfoo.so.1.2.3; the loader looks up soname libfoo.so.1.
        let real = make_file(&src.join("libfoo.so.1.2.3"), b"FOO");

        let res = Resolution {
            interpreter: None,
            libs: vec![ResolvedLib {
                soname: "libfoo.so.1".into(),
                path: real.clone(),
            }],
            missing: vec![],
            edges: vec![],
        };
        stage_files(&binary, &res, &dest).unwrap();

        let staged_dir = under(&dest, real.parent().unwrap());
        let real_file = staged_dir.join("libfoo.so.1.2.3");
        let soname_link = staged_dir.join("libfoo.so.1");
        assert!(real_file.exists(), "real versioned file must be staged");
        assert_eq!(
            fs::read_link(&soname_link).unwrap(),
            PathBuf::from("libfoo.so.1.2.3"),
            "soname symlink must point at the real file's basename"
        );
    }

    #[test]
    fn binary_is_staged_as_the_entrypoint() {
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("dest");
        let binary = make_file(&tmp.path().join("opt/tool/run"), b"binary");

        let res = Resolution::default();
        let tree = stage_files(&binary, &res, &dest).unwrap();

        assert_eq!(tree.entrypoint, binary);
        assert!(under(&dest, &binary).exists(), "binary must be staged");
    }

    #[test]
    fn unresolved_dependencies_refuse_to_stage() {
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("dest");
        let binary = make_file(&tmp.path().join("app"), b"binary");

        let res = Resolution {
            interpreter: None,
            libs: vec![],
            missing: vec!["libmissing.so".into()],
            edges: vec![],
        };
        let err = stage_files(&binary, &res, &dest).unwrap_err();
        assert!(err.to_string().contains("libmissing.so"));
    }

    #[test]
    fn default_includes_stage_nsswitch_nss_and_passwd() {
        let tmp = tempfile::tempdir().unwrap();
        let libdir = tmp.path().join("usr/lib/x86_64-linux-gnu");
        let dest = tmp.path().join("dest");
        // libc and its version-matched NSS modules share a directory.
        let libc = make_file(&libdir.join("libc.so.6"), b"LIBC");
        for m in ["libnss_files.so.2", "libnss_dns.so.2", "libresolv.so.2"] {
            make_file(&libdir.join(m), b"NSS");
        }

        let res = Resolution {
            interpreter: None,
            libs: vec![ResolvedLib {
                soname: "libc.so.6".into(),
                path: libc,
            }],
            missing: vec![],
            edges: vec![],
        };
        let report = stage_default_includes(&res, &dest, &NssSelection::default()).unwrap();

        // Minimal nsswitch avoids systemd NSS modules: files + dns only.
        let nsswitch = std::fs::read_to_string(dest.join("etc/nsswitch.conf")).unwrap();
        assert!(nsswitch.contains("files dns"), "want files+dns: {nsswitch}");
        assert!(
            !nsswitch.contains("mymachines"),
            "must avoid systemd NSS: {nsswitch}"
        );
        // NSS modules mirror their real (temp) source dir, so compute from that.
        let dir = res.libs[0].path.parent().unwrap();
        assert!(under(&dest, &dir.join("libnss_dns.so.2")).exists());
        assert!(under(&dest, &dir.join("libresolv.so.2")).exists());
        // passwd: files needs a passwd database, or startup getpwuid() gets null.
        let passwd = std::fs::read_to_string(dest.join("etc/passwd")).unwrap();
        assert!(passwd.contains("root:x:0:0"), "{passwd}");
        assert!(dest.join("etc/group").exists());
        assert!(report.warnings.is_empty(), "{:?}", report.warnings);
    }

    #[test]
    fn missing_nss_modules_warn_but_do_not_fail() {
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("dest");
        // libc with no NSS modules beside it.
        let libc = make_file(&tmp.path().join("usr/lib/libc.so.6"), b"LIBC");

        let res = Resolution {
            interpreter: None,
            libs: vec![ResolvedLib {
                soname: "libc.so.6".into(),
                path: libc,
            }],
            missing: vec![],
            edges: vec![],
        };
        let report = stage_default_includes(&res, &dest, &NssSelection::default()).unwrap();

        // nsswitch/passwd are always written; absent NSS modules become warnings.
        assert!(dest.join("etc/nsswitch.conf").exists());
        assert!(dest.join("etc/passwd").exists());
        assert!(report.warnings.iter().any(|w| w.contains("libnss_files")));
    }

    // Build a resolution whose libc sits beside the three NSS modules, staged under a
    // fresh temp dir. Returns (tempdir, resolution, dest) for a `--nss` staging test.
    fn nss_fixture() -> (tempfile::TempDir, Resolution, PathBuf) {
        let tmp = tempfile::tempdir().unwrap();
        let libdir = tmp.path().join("usr/lib/x86_64-linux-gnu");
        let dest = tmp.path().join("dest");
        let libc = make_file(&libdir.join("libc.so.6"), b"LIBC");
        for m in ["libnss_files.so.2", "libnss_dns.so.2", "libresolv.so.2"] {
            make_file(&libdir.join(m), b"NSS");
        }
        let res = Resolution {
            interpreter: None,
            libs: vec![ResolvedLib {
                soname: "libc.so.6".into(),
                path: libc,
            }],
            missing: vec![],
            edges: vec![],
        };
        (tmp, res, dest)
    }

    #[test]
    fn nss_files_only_drops_dns_module_and_resolv() {
        let (_tmp, res, dest) = nss_fixture();
        let sel = NssSelection {
            files: true,
            dns: false,
        };
        stage_default_includes(&res, &dest, &sel).unwrap();

        let nsswitch = std::fs::read_to_string(dest.join("etc/nsswitch.conf")).unwrap();
        assert!(nsswitch.contains("hosts:          files\n"), "{nsswitch}");
        assert!(!nsswitch.contains("dns"), "dns must be gone: {nsswitch}");
        let dir = res.libs[0].path.parent().unwrap();
        assert!(under(&dest, &dir.join("libnss_files.so.2")).exists());
        assert!(!under(&dest, &dir.join("libnss_dns.so.2")).exists());
        assert!(!under(&dest, &dir.join("libresolv.so.2")).exists());
    }

    #[test]
    fn nss_none_writes_no_nsswitch_and_no_modules() {
        let (_tmp, res, dest) = nss_fixture();
        stage_default_includes(&res, &dest, &NssSelection::NONE).unwrap();

        assert!(!dest.join("etc/nsswitch.conf").exists());
        let dir = res.libs[0].path.parent().unwrap();
        assert!(!under(&dest, &dir.join("libnss_files.so.2")).exists());
        // Without libnss_files, glibc cannot read passwd/group, so they are not shipped.
        assert!(!dest.join("etc/passwd").exists());
        assert!(!dest.join("etc/group").exists());
    }

    #[test]
    fn nss_dns_only_omits_file_databases() {
        let (_tmp, res, dest) = nss_fixture();
        let sel = NssSelection {
            files: false,
            dns: true,
        };
        stage_default_includes(&res, &dest, &sel).unwrap();

        let nsswitch = std::fs::read_to_string(dest.join("etc/nsswitch.conf")).unwrap();
        assert!(nsswitch.contains("hosts:          dns\n"), "{nsswitch}");
        assert!(!nsswitch.contains("passwd:"), "file dbs gone: {nsswitch}");
        let dir = res.libs[0].path.parent().unwrap();
        assert!(under(&dest, &dir.join("libnss_dns.so.2")).exists());
        assert!(under(&dest, &dir.join("libresolv.so.2")).exists());
        assert!(!under(&dest, &dir.join("libnss_files.so.2")).exists());
        // dns-only drops the file databases, so the unreadable passwd/group are not shipped.
        assert!(!dest.join("etc/passwd").exists());
    }

    #[test]
    fn nss_from_modules_maps_values_and_rejects_none_mix() {
        assert_eq!(
            NssSelection::from_modules(&[]).unwrap(),
            NssSelection::default()
        );
        assert_eq!(
            NssSelection::from_modules(&[NssModule::None]).unwrap(),
            NssSelection::NONE
        );
        assert_eq!(
            NssSelection::from_modules(&[NssModule::Files]).unwrap(),
            NssSelection {
                files: true,
                dns: false
            }
        );
        let err = NssSelection::from_modules(&[NssModule::None, NssModule::Files]).unwrap_err();
        assert!(err.to_string().contains("cannot be combined"), "{err}");
    }

    #[test]
    fn size_report_renders_entries_stripped_and_plain() {
        let stripped = SizeReport {
            entries: vec![SizeEntry {
                path: "/lib/x.so".into(),
                before: 100,
                after: 40,
            }],
            total_before: 100,
            total_after: 40,
            stripped: true,
            upx: false,
        };
        let text = stripped.to_string();
        assert!(text.contains("100"), "before size missing: {text}");
        assert!(text.contains("/lib/x.so"), "path missing: {text}");
        assert!(text.contains("saved"), "savings summary missing: {text}");

        let plain = SizeReport {
            entries: vec![SizeEntry {
                path: "/lib/x.so".into(),
                before: 40,
                after: 40,
            }],
            total_before: 40,
            total_after: 40,
            stripped: false,
            upx: false,
        };
        assert!(plain.to_string().contains("/lib/x.so"));

        // UPX (even without strip) shows the before -> after delta and a savings total.
        let compressed = SizeReport {
            entries: vec![SizeEntry {
                path: "/app".into(),
                before: 200,
                after: 80,
            }],
            total_before: 200,
            total_after: 80,
            stripped: false,
            upx: true,
        };
        let text = compressed.to_string();
        assert!(text.contains("200"), "before size missing: {text}");
        assert!(
            text.contains("saved"),
            "upx savings summary missing: {text}"
        );
    }

    #[test]
    fn add_file_spec_parses_both_forms() {
        let relocated = AddFile::parse("./app.conf:/etc/app.conf").unwrap();
        assert_eq!(relocated.src, PathBuf::from("./app.conf"));
        assert_eq!(relocated.dst, PathBuf::from("/etc/app.conf"));

        // Bare SRC mirrors the host path, so /etc/motd lands at /etc/motd.
        let mirrored = AddFile::parse("/etc/motd").unwrap();
        assert_eq!(mirrored.src, PathBuf::from("/etc/motd"));
        assert_eq!(mirrored.dst, PathBuf::from("/etc/motd"));

        // The split is on the LAST colon, so a colon in the source survives.
        let odd = AddFile::parse("./od:d.conf:/etc/app.conf").unwrap();
        assert_eq!(odd.src, PathBuf::from("./od:d.conf"));
        assert_eq!(odd.dst, PathBuf::from("/etc/app.conf"));
    }

    #[test]
    fn add_file_spec_rejects_bad_destinations() {
        // A relative image path would land somewhere the caller never named.
        let err = AddFile::parse("./app.conf:etc/app.conf")
            .unwrap_err()
            .to_string();
        assert!(err.contains("must be absolute"), "{err}");

        // A bare relative SRC is the same mistake: it is its own destination.
        assert!(AddFile::parse("./app.conf").is_err());

        // A colon inside a BARE src splits the spec in a way the user never meant, so the
        // error names both halves rather than only complaining about the image path.
        let err = AddFile::parse("/etc/my:file").unwrap_err().to_string();
        assert!(err.contains("read '/etc/my' as the source"), "{err}");
        assert!(err.contains("'file' as the image path"), "{err}");

        // `..` would escape the staging root once joined under it.
        let err = AddFile::parse("./app.conf:/etc/../../outside")
            .unwrap_err()
            .to_string();
        assert!(err.contains(".."), "{err}");

        assert!(AddFile::parse(":/etc/app.conf").is_err());
        assert!(AddFile::parse("./app.conf:").is_err());
    }

    #[test]
    fn add_file_copies_sources_and_creates_parents() {
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("dest");
        let src = make_file(&tmp.path().join("src/app.conf"), b"tuning");

        let files = vec![AddFile {
            src: src.clone(),
            dst: PathBuf::from("/etc/app/deep/app.conf"),
        }];
        stage_added_files(&dest, &files).unwrap();

        let landed = dest.join("etc/app/deep/app.conf");
        assert_eq!(fs::read(&landed).unwrap(), b"tuning");
    }

    #[test]
    fn add_file_refuses_to_replace_something_already_staged() {
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("dest");
        let a = make_file(&tmp.path().join("src/a.conf"), b"first");
        let b = make_file(&tmp.path().join("src/b.conf"), b"second");

        // Two entries for one image path: without the check the first would vanish silently.
        let err = stage_added_files(
            &dest,
            &[
                AddFile {
                    src: a,
                    dst: PathBuf::from("/etc/app.conf"),
                },
                AddFile {
                    src: b.clone(),
                    dst: PathBuf::from("/etc/app.conf"),
                },
            ],
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("already in the image"), "{err}");
        // The first write stands; the pack aborts rather than truncating it.
        assert_eq!(fs::read(dest.join("etc/app.conf")).unwrap(), b"first");

        // A soname symlink is the dangerous case: fs::copy follows it and overwrites the real
        // library. symlink_metadata sees the link, so this is refused too.
        let libdir = dest.join("lib");
        fs::create_dir_all(&libdir).unwrap();
        fs::write(libdir.join("libc.so.6.real"), b"REAL").unwrap();
        std::os::unix::fs::symlink("libc.so.6.real", libdir.join("libc.so.6")).unwrap();
        let err = stage_added_files(
            &dest,
            &[AddFile {
                src: b,
                dst: PathBuf::from("/lib/libc.so.6"),
            }],
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("already in the image"), "{err}");
        assert_eq!(fs::read(libdir.join("libc.so.6.real")).unwrap(), b"REAL");
    }

    #[test]
    fn add_file_fails_loud_on_a_directory_or_a_missing_source() {
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("dest");

        let dir = tmp.path().join("src/etc");
        fs::create_dir_all(&dir).unwrap();
        let err = stage_added_files(
            &dest,
            &[AddFile {
                src: dir,
                dst: PathBuf::from("/etc"),
            }],
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("is a directory"), "{err}");

        // An explicitly named file that is not there is an error, never a warning: the
        // image would otherwise ship silently without it.
        let err = stage_added_files(
            &dest,
            &[AddFile {
                src: tmp.path().join("nope.conf"),
                dst: PathBuf::from("/etc/nope.conf"),
            }],
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("cannot read"), "{err}");
    }
}
