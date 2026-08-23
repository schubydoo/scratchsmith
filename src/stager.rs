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

/// Stage `binary` and its resolved dependencies under `dest`, then build the cache.
pub fn stage(binary: &Path, resolution: &Resolution, dest: &Path) -> Result<StagedTree> {
    let tree = stage_files(binary, resolution, dest)?;
    generate_ld_cache(dest, resolution)?;
    Ok(tree)
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
}
