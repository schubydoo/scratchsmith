//! Compare two staged rootfs directories (`diff` subcommand): the files added, removed,
//! and changed between them, plus the total size delta. An image-drift regression gate.
//! Pairs with `unpack` — an OCI image extracted to a directory is diffed the same way.

use crate::report::{DiffFile, DiffReport};
use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::Path;

// One file's identity for comparison: its size and a content fingerprint (sha256 for a
// regular file, the link target for a symlink). Directories carry no content of their own.
struct Entry {
    size: u64,
    fingerprint: String,
}

// Walk `root` and fingerprint every regular file and symlink, keyed by path relative to
// `root`. Symlinks are compared by target, never followed.
fn scan(root: &Path) -> Result<BTreeMap<String, Entry>> {
    let mut map = BTreeMap::new();
    for entry in walkdir::WalkDir::new(root).follow_links(false) {
        let entry = entry.with_context(|| format!("walking {}", root.display()))?;
        let rel = entry
            .path()
            .strip_prefix(root)
            .unwrap_or_else(|_| entry.path())
            .to_string_lossy()
            .into_owned();
        if rel.is_empty() {
            continue; // the root itself
        }
        let meta = entry.metadata()?;
        if meta.file_type().is_symlink() {
            let target = std::fs::read_link(entry.path())?;
            map.insert(
                rel,
                Entry {
                    size: 0,
                    fingerprint: format!("symlink:{}", target.display()),
                },
            );
        } else if meta.is_file() {
            let bytes = std::fs::read(entry.path())
                .with_context(|| format!("reading {}", entry.path().display()))?;
            map.insert(
                rel,
                Entry {
                    size: meta.len(),
                    fingerprint: hex(Sha256::digest(&bytes)),
                },
            );
        }
    }
    Ok(map)
}

/// Compare two staged rootfs directories, reporting the files added in `b`, removed from
/// `a`, and changed between them, plus each side's total file size.
pub fn build(a: &Path, b: &Path) -> Result<DiffReport> {
    let old = scan(a)?;
    let new = scan(b)?;

    let mut added = Vec::new();
    let mut changed = Vec::new();
    for (path, entry) in &new {
        match old.get(path) {
            None => added.push(DiffFile {
                path: path.clone(),
                size: entry.size,
            }),
            Some(prev) if prev.fingerprint != entry.fingerprint => changed.push(path.clone()),
            Some(_) => {}
        }
    }
    let removed: Vec<DiffFile> = old
        .iter()
        .filter(|(path, _)| !new.contains_key(*path))
        .map(|(path, entry)| DiffFile {
            path: path.clone(),
            size: entry.size,
        })
        .collect();

    Ok(DiffReport {
        added,
        removed,
        changed,
        size_before: old.values().map(|e| e.size).sum(),
        size_after: new.values().map(|e| e.size).sum(),
    })
}

fn hex(digest: impl AsRef<[u8]>) -> String {
    use std::fmt::Write as _;
    digest.as_ref().iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn write(dir: &Path, rel: &str, body: &[u8]) {
        let p = dir.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, body).unwrap();
    }

    #[test]
    fn build_reports_added_removed_and_changed() {
        let tmp = tempfile::tempdir().unwrap();
        let (a, b) = (tmp.path().join("a"), tmp.path().join("b"));
        // same/unchanged, changed (content), removed (only in a), added (only in b).
        write(&a, "bin/app", b"same");
        write(&b, "bin/app", b"same");
        write(&a, "lib/libc.so.6", b"old-libc");
        write(&b, "lib/libc.so.6", b"new-libc-longer");
        write(&a, "lib/libgone.so.1", b"gone");
        write(&b, "lib/libnew.so.1", b"brand new");

        let report = build(&a, &b).unwrap();
        assert_eq!(
            report
                .added
                .iter()
                .map(|f| f.path.as_str())
                .collect::<Vec<_>>(),
            vec!["lib/libnew.so.1"]
        );
        assert_eq!(
            report
                .removed
                .iter()
                .map(|f| f.path.as_str())
                .collect::<Vec<_>>(),
            vec!["lib/libgone.so.1"]
        );
        assert_eq!(report.changed, vec!["lib/libc.so.6".to_string()]);
        assert!(report.has_changes());
        // size delta reflects the changed + added - removed bytes.
        assert_eq!(
            report.size_after,
            ("same".len() + "new-libc-longer".len() + "brand new".len()) as u64
        );
    }

    #[test]
    fn identical_trees_have_no_changes() {
        let tmp = tempfile::tempdir().unwrap();
        let (a, b) = (tmp.path().join("a"), tmp.path().join("b"));
        write(&a, "bin/app", b"x");
        write(&b, "bin/app", b"x");
        let report = build(&a, &b).unwrap();
        assert!(!report.has_changes());
        assert_eq!(report.size_before, report.size_after);
    }
}
