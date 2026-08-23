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

/// What the default-include step added, and what it could not find.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct IncludeReport {
    /// Image paths added (nsswitch, NSS modules, CA bundle).
    pub staged: Vec<PathBuf>,
    /// Best-effort items that were absent on the host — surfaced, never silently skipped.
    pub warnings: Vec<String>,
}

// A scratch image has no name-service config, so glibc name lookups fail before
// they even try. Ship a minimal one: local files plus DNS, which needs only the
// libnss_files/libnss_dns modules — no systemd/mymachines NSS module to drag in.
const MINIMAL_NSSWITCH: &str = "\
passwd:         files
group:          files
shadow:         files
hosts:          files dns
networks:       files
protocols:      files
services:       files
";

// The glibc NSS/resolver modules that `hosts: files dns` needs. They are dlopen'd,
// so the resolver never sees them; they must be pulled in explicitly, and from the
// same directory as libc so the versions match exactly.
const NSS_MODULES: &[&str] = &["libnss_files.so.2", "libnss_dns.so.2", "libresolv.so.2"];

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
/// the staged libc), and a minimal passwd/group. Missing NSS modules become
/// warnings, not errors. TLS CA certs are a separate opt-in (`--ca-certs`, Task 4.5).
pub fn stage_default_includes(resolution: &Resolution, dest: &Path) -> Result<IncludeReport> {
    let mut report = IncludeReport::default();

    let nsswitch = under(dest, Path::new("/etc/nsswitch.conf"));
    std::fs::create_dir_all(nsswitch.parent().unwrap())?;
    std::fs::write(&nsswitch, MINIMAL_NSSWITCH)?;
    report.staged.push(PathBuf::from("/etc/nsswitch.conf"));

    // NSS modules live beside libc; without libc (a static binary) there is nothing
    // to match against, so there is nothing to do here.
    match libc_dir(resolution) {
        Some(dir) => {
            for name in NSS_MODULES {
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

    for (path, body) in [
        ("/etc/passwd", MINIMAL_PASSWD),
        ("/etc/group", MINIMAL_GROUP),
    ] {
        let target = under(dest, Path::new(path));
        std::fs::create_dir_all(target.parent().unwrap())?;
        std::fs::write(&target, body)?;
        report.staged.push(PathBuf::from(path));
    }

    Ok(report)
}

/// One staged ELF file's size, before and after an optional strip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SizeEntry {
    pub path: String,
    pub before: u64,
    pub after: u64,
}

/// Sizes of the staged ELF payload (binary + loader + libraries), with totals.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SizeReport {
    pub entries: Vec<SizeEntry>,
    pub total_before: u64,
    pub total_after: u64,
    pub stripped: bool,
}

impl std::fmt::Display for SizeReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for e in &self.entries {
            if self.stripped {
                writeln!(f, "  {:>10} -> {:>10}  {}", e.before, e.after, e.path)?;
            } else {
                writeln!(f, "  {:>10}  {}", e.after, e.path)?;
            }
        }
        if self.stripped {
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
) -> Result<SizeReport> {
    // The ELF files we placed: the binary, the loader, and every resolved library.
    let mut targets: Vec<PathBuf> = vec![under(dest, &tree.entrypoint)];
    if let Some(interp) = &resolution.interpreter {
        targets.push(under(dest, &interp.image_path));
    }
    targets.extend(resolution.libs.iter().map(|l| under(dest, &l.path)));

    let mut report = SizeReport {
        stripped: strip,
        ..Default::default()
    };
    for path in targets {
        let before = std::fs::metadata(&path)?.len();
        if strip {
            run_strip(&path)?;
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
        };
        let report = stage_default_includes(&res, &dest).unwrap();

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
        };
        let report = stage_default_includes(&res, &dest).unwrap();

        // nsswitch/passwd are always written; absent NSS modules become warnings.
        assert!(dest.join("etc/nsswitch.conf").exists());
        assert!(dest.join("etc/passwd").exists());
        assert!(report.warnings.iter().any(|w| w.contains("libnss_files")));
    }
}
