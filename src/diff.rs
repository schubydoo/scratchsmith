//! Compare two staged rootfs directories (`diff` subcommand): the files added, removed,
//! and changed between them, plus the total size delta. An image-drift regression gate.
//! Pairs with `unpack` — an OCI image extracted to a directory is diffed the same way.

use crate::image::hex;
use crate::report::{DiffFile, DiffMode, DiffReport};
use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::io::Read;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

// One file's identity for comparison: its size and a content fingerprint (sha256 for a
// regular file, the link target's raw bytes for a symlink), and its permission bits. A
// symlink has no mode of its own on Linux, so it carries none.
struct Entry {
    size: u64,
    fingerprint: Vec<u8>,
    mode: Option<u32>,
}

// One tree: its regular files and symlinks, and its directories with their permission bits.
// `unpack` strips setuid and setgid, so a mode is the only permission signal left to compare.
#[derive(Default)]
struct Tree {
    files: BTreeMap<OsString, Entry>,
    dirs: BTreeMap<OsString, u32>,
}

impl Tree {
    // A directory with nothing under it. Keys sort by byte, so the first key at or after
    // `dir/` is under it if any is.
    fn is_empty_dir(&self, dir: &OsStr) -> bool {
        let prefix = OsString::from_vec([dir.as_bytes(), b"/"].concat());
        let under = |map_key: Option<&OsString>| {
            map_key.is_some_and(|k| k.as_bytes().starts_with(prefix.as_bytes()))
        };
        !under(self.files.range(prefix.clone()..).next().map(|(k, _)| k))
            && !under(self.dirs.range(prefix.clone()..).next().map(|(k, _)| k))
    }
}

// Walk `root` and fingerprint every regular file and symlink, keyed by path relative to
// `root`. Symlinks are compared by target, never followed. Keys and targets stay raw bytes:
// a lossy conversion would merge two names that differ only in non-UTF-8 bytes. An `OsString`
// key sorts by bytes, as the old `String` key did; a `PathBuf` would sort by component.
fn scan(root: &Path) -> Result<Tree> {
    let mut tree = Tree::default();
    for entry in walkdir::WalkDir::new(root).follow_links(false) {
        // walkdir's error, and every path below, can carry a file name out of an image
        // someone else built, so each is escaped before it reaches the terminal.
        let shown = |p: &Path| crate::resolver::escape_for_display(&p.to_string_lossy());
        let entry = entry.map_err(|e| {
            anyhow::anyhow!(
                "walking {}: {}",
                shown(root),
                crate::resolver::escape_for_display(&e.to_string())
            )
        })?;
        let rel = entry
            .path()
            .strip_prefix(root)
            .with_context(|| format!("{} is not under {}", shown(entry.path()), shown(root)))?
            .as_os_str()
            .to_owned();
        if rel.is_empty() {
            continue; // the root itself
        }
        let meta = entry.metadata().map_err(|e| {
            anyhow::anyhow!("{}", crate::resolver::escape_for_display(&e.to_string()))
        })?;
        if meta.file_type().is_symlink() {
            let target = std::fs::read_link(entry.path())?;
            tree.files.insert(
                rel,
                Entry {
                    size: 0,
                    fingerprint: [b"symlink:", target.as_os_str().as_bytes()].concat(),
                    mode: None,
                },
            );
        } else if meta.is_file() {
            let fingerprint = sha256_file(entry.path())
                .with_context(|| format!("reading {}", shown(entry.path())))?;
            tree.files.insert(
                rel,
                Entry {
                    size: meta.len(),
                    fingerprint: fingerprint.into_bytes(),
                    mode: Some(meta.permissions().mode() & 0o7777),
                },
            );
        } else if meta.is_dir() {
            tree.dirs.insert(rel, meta.permissions().mode() & 0o7777);
        }
    }
    Ok(tree)
}

// Hash a file without holding it in memory: a sparse file from an unpacked hostile layer can
// claim far more bytes than there is RAM.
fn sha256_file(path: &Path) -> std::io::Result<String> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        match file.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => hasher.update(&buf[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(hex(hasher.finalize()))
}

// A path for the report, which holds text. A UTF-8 name is kept as it is. A non-UTF-8 name is
// escaped whole, its invalid bytes as `\xNN`, so two names that differ only in those bytes
// still read differently.
fn report_path(path: &OsStr) -> String {
    let bytes = path.as_bytes();
    if let Ok(text) = std::str::from_utf8(bytes) {
        return text.to_owned();
    }
    let mut out = String::new();
    for chunk in bytes.utf8_chunks() {
        out.push_str(&crate::resolver::escape_for_display(chunk.valid()));
        for b in chunk.invalid() {
            out.push_str(&format!("\\x{b:02x}"));
        }
    }
    out
}

/// Compare two staged rootfs directories, reporting the files added in `b`, removed from
/// `a`, and changed between them, the files and directories whose mode changed, the empty
/// directories in only one tree, plus each side's total file size.
pub fn build(a: &Path, b: &Path) -> Result<DiffReport> {
    let old_tree = scan(a)?;
    let new_tree = scan(b)?;
    let (old, new) = (&old_tree.files, &new_tree.files);

    let mut added = Vec::new();
    let mut changed = Vec::new();
    for (path, entry) in new {
        match old.get(path) {
            None => added.push(DiffFile {
                path: report_path(path),
                size: entry.size,
            }),
            Some(prev) if prev.fingerprint != entry.fingerprint => changed.push(report_path(path)),
            Some(_) => {}
        }
    }
    let removed: Vec<DiffFile> = old
        .iter()
        .filter(|(path, _)| !new.contains_key(*path))
        .map(|(path, entry)| DiffFile {
            path: report_path(path),
            size: entry.size,
        })
        .collect();

    let mode = |m: u32| format!("{m:04o}");
    let file_modes = new.iter().filter_map(|(path, entry)| {
        let (before, after) = (old.get(path)?.mode?, entry.mode?);
        Some((path, before, after))
    });
    let dir_modes = new_tree
        .dirs
        .iter()
        .filter_map(|(path, &after)| Some((path, *old_tree.dirs.get(path)?, after)));
    // Byte order across files and directories, as the other lists are.
    let mut mode_changed: Vec<_> = file_modes
        .chain(dir_modes)
        .filter(|(_, before, after)| before != after)
        .collect();
    mode_changed.sort_by(|x, y| x.0.cmp(y.0));
    let mode_changed = mode_changed
        .into_iter()
        .map(|(path, before, after)| DiffMode {
            path: report_path(path),
            before: mode(before),
            after: mode(after),
        })
        .collect();
    // An empty directory in only one tree. A directory that holds anything shows through what
    // it holds.
    let lone_empty_dirs = |tree: &Tree, other: &Tree| -> Vec<String> {
        tree.dirs
            .keys()
            .filter(|path| !other.dirs.contains_key(*path) && tree.is_empty_dir(path))
            .map(|path| report_path(path))
            .collect()
    };

    Ok(DiffReport {
        added,
        removed,
        changed,
        mode_changed,
        dirs_added: lone_empty_dirs(&new_tree, &old_tree),
        dirs_removed: lone_empty_dirs(&old_tree, &new_tree),
        size_before: old.values().map(|e| e.size).sum(),
        size_after: new.values().map(|e| e.size).sum(),
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

    fn chmod(path: &Path, mode: u32) {
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn a_lost_exec_bit_is_a_mode_change() {
        let tmp = tempfile::tempdir().unwrap();
        let (a, b) = (tmp.path().join("a"), tmp.path().join("b"));
        write(&a, "bin/app", b"same");
        write(&b, "bin/app", b"same");
        chmod(&a.join("bin/app"), 0o755);
        chmod(&b.join("bin/app"), 0o644);
        let report = build(&a, &b).unwrap();
        assert!(report.changed.is_empty(), "{:?}", report.changed);
        assert_eq!(report.mode_changed.len(), 1);
        let m = &report.mode_changed[0];
        assert_eq!(
            (m.path.as_str(), m.before.as_str(), m.after.as_str()),
            ("bin/app", "0755", "0644")
        );
        assert!(report.has_changes());
    }

    #[test]
    fn a_world_writable_directory_is_a_mode_change() {
        let tmp = tempfile::tempdir().unwrap();
        let (a, b) = (tmp.path().join("a"), tmp.path().join("b"));
        write(&a, "srv/data", b"x");
        write(&b, "srv/data", b"x");
        chmod(&a.join("srv"), 0o755);
        chmod(&b.join("srv"), 0o777);
        let report = build(&a, &b).unwrap();
        let modes: Vec<_> = report
            .mode_changed
            .iter()
            .map(|m| (m.path.as_str(), m.before.as_str(), m.after.as_str()))
            .collect();
        assert_eq!(modes, [("srv", "0755", "0777")]);
    }

    #[test]
    fn a_symlink_has_no_mode_to_compare() {
        let tmp = tempfile::tempdir().unwrap();
        let (a, b) = (tmp.path().join("a"), tmp.path().join("b"));
        for root in [&a, &b] {
            fs::create_dir_all(root).unwrap();
            std::os::unix::fs::symlink("target", root.join("link")).unwrap();
        }
        assert!(!build(&a, &b).unwrap().has_changes());
    }

    #[test]
    fn an_empty_directory_in_one_tree_is_reported() {
        let tmp = tempfile::tempdir().unwrap();
        let (a, b) = (tmp.path().join("a"), tmp.path().join("b"));
        write(&a, "bin/app", b"x");
        write(&b, "bin/app", b"x");
        fs::create_dir_all(a.join("var/old")).unwrap();
        fs::create_dir_all(b.join("tmp")).unwrap();
        // Nested: only the empty leaf is listed, since it implies its parents.
        fs::create_dir_all(b.join("run/lock")).unwrap();
        let report = build(&a, &b).unwrap();
        assert_eq!(report.dirs_added, ["run/lock", "tmp"]);
        assert_eq!(report.dirs_removed, ["var/old"]);
        assert!(report.added.is_empty() && report.removed.is_empty());
        assert!(report.has_changes());
    }

    #[test]
    fn a_new_directory_with_files_shows_through_its_files() {
        let tmp = tempfile::tempdir().unwrap();
        let (a, b) = (tmp.path().join("a"), tmp.path().join("b"));
        fs::create_dir_all(&a).unwrap();
        write(&b, "etc/app.conf", b"x");
        // `x-1` sorts between `x` and `x/` by byte, and must not count as under `x`.
        fs::create_dir_all(b.join("x")).unwrap();
        write(&b, "x-1/file", b"y");
        let report = build(&a, &b).unwrap();
        assert_eq!(report.dirs_added, ["x"]);
        let added: Vec<_> = report.added.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(added, ["etc/app.conf", "x-1/file"]);
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

    #[test]
    fn a_symlink_compares_by_its_target() {
        let tmp = tempfile::tempdir().unwrap();
        let (a, b) = (tmp.path().join("a"), tmp.path().join("b"));
        for (root, target) in [(&a, "libx.so.1.0"), (&b, "libx.so.1.1")] {
            fs::create_dir_all(root.join("lib")).unwrap();
            std::os::unix::fs::symlink(target, root.join("lib/libx.so.1")).unwrap();
        }
        let report = build(&a, &b).unwrap();
        assert_eq!(report.changed, vec!["lib/libx.so.1".to_string()]);
        assert_eq!((report.size_before, report.size_after), (0, 0));
    }

    #[test]
    fn names_that_differ_only_in_non_utf8_bytes_stay_separate() {
        let tmp = tempfile::tempdir().unwrap();
        let (a, b) = (tmp.path().join("a"), tmp.path().join("b"));
        let (ff, fe) = (OsStr::from_bytes(b"x\xff"), OsStr::from_bytes(b"x\xfe"));
        for root in [&a, &b] {
            fs::create_dir_all(root).unwrap();
            fs::write(root.join(ff), b"same").unwrap();
        }
        fs::write(b.join(fe), b"payload").unwrap();

        let report = build(&a, &b).unwrap();
        assert_eq!(
            report
                .added
                .iter()
                .map(|f| f.path.as_str())
                .collect::<Vec<_>>(),
            vec![r"x\xfe"]
        );
        assert!(report.removed.is_empty() && report.changed.is_empty());
        assert!(report.has_changes());
        assert_eq!(report.size_after, ("same".len() + "payload".len()) as u64);
    }

    #[test]
    fn the_report_lists_paths_in_byte_order() {
        let tmp = tempfile::tempdir().unwrap();
        let (a, b) = (tmp.path().join("a"), tmp.path().join("b"));
        fs::create_dir_all(&a).unwrap();
        // `.` sorts before `/` by byte, though `lib` sorts before `lib.d` by component.
        write(&b, "usr/lib/a.so", b"a");
        write(&b, "usr/lib.d/b", b"b");
        let report = build(&a, &b).unwrap();
        assert_eq!(
            report
                .added
                .iter()
                .map(|f| f.path.as_str())
                .collect::<Vec<_>>(),
            vec!["usr/lib.d/b", "usr/lib/a.so"]
        );
    }

    #[test]
    fn a_symlink_target_that_differs_only_in_non_utf8_bytes_is_changed() {
        let tmp = tempfile::tempdir().unwrap();
        let (a, b) = (tmp.path().join("a"), tmp.path().join("b"));
        for (root, target) in [(&a, b"t\xff"), (&b, b"t\xfe")] {
            fs::create_dir_all(root).unwrap();
            std::os::unix::fs::symlink(OsStr::from_bytes(target), root.join("link")).unwrap();
        }
        assert_eq!(build(&a, &b).unwrap().changed, vec!["link".to_string()]);
    }

    #[test]
    fn a_report_path_keeps_utf8_and_escapes_a_non_utf8_name_whole() {
        let shown = |b: &[u8]| report_path(OsStr::from_bytes(b));
        assert_eq!(
            shown("lib/caf\u{e9}\\x.so".as_bytes()),
            "lib/caf\u{e9}\\x.so"
        );
        assert_eq!(shown(b"x\xfe"), r"x\xfe");
        assert_ne!(shown(b"x\xfe"), shown(b"x\xff"));
        // Once a name is escaped, its own backslash and controls are escaped with it.
        assert_eq!(shown(b"a\\\n\xc3"), r"a\\\n\xc3");
    }

    #[test]
    fn a_walk_error_escapes_the_file_name() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        // An unreadable directory whose name, from an image someone else built, holds a
        // line break and a terminal escape. walkdir's error quotes the path.
        let dir = tmp.path().join("d\nerror: forged\x1b[2J");
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o000)).unwrap();
        let readable = fs::read_dir(&dir).is_ok();
        let result = scan(tmp.path());
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        if readable {
            return; // root reads it anyway, so there is no error to inspect
        }
        let Err(err) = result else {
            panic!("an unreadable directory must fail the walk");
        };
        let err = format!("{err:#}");
        assert!(!err.contains('\n') && !err.contains('\x1b'), "{err:?}");
        assert!(err.contains("\\nerror: forged"), "{err}");
    }

    #[test]
    fn a_sparse_file_hashes_like_its_full_content() {
        use std::io::{Seek, SeekFrom, Write};
        // Small on purpose: this pins the digest of a holey file, not the streaming, which no
        // unit test can tell apart from a whole-file read without a file larger than memory.
        const SIZE: u64 = 1 << 20;
        let tmp = tempfile::tempdir().unwrap();
        // Mostly hole, as `unpack` writes a sparse layer entry: it hashes as its zero-filled
        // content.
        let mut f = fs::File::create(tmp.path().join("big")).unwrap();
        f.write_all(b"head").unwrap();
        f.seek(SeekFrom::Start(SIZE - 4)).unwrap();
        f.write_all(b"tail").unwrap();
        drop(f);
        let mut full = vec![0u8; SIZE as usize];
        full[..4].copy_from_slice(b"head");
        full[SIZE as usize - 4..].copy_from_slice(b"tail");

        let entry = &scan(tmp.path()).unwrap().files[OsStr::new("big")];
        assert_eq!(entry.size, SIZE);
        assert_eq!(entry.fingerprint, hex(Sha256::digest(&full)).into_bytes());
    }
}
