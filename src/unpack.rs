//! Extract an OCI image archive back to a directory (`unpack` subcommand): read the
//! OCI-layout tarball (`pack --oci-archive`, or any skopeo/buildah OCI archive), apply its
//! layers in order into a directory, and report what landed. Pairs with `diff` — unpack two
//! images, then compare the directories. Audits an image you did not build, so every step
//! treats the archive as hostile: blobs are digest-verified, decompression is capped, both
//! extraction and whiteout deletion refuse any path that escapes the target, and setuid and
//! setgid bits are never applied.

use crate::image::hex;
use crate::report::UnpackReport;
use crate::resolver::escape_for_display;
use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::ffi::{OsStr, OsString};
use std::fmt::Write as _;
use std::io::Read;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStringExt;
use std::path::{Component, Path, PathBuf};

// Refuse a layer that decompresses beyond this, so a tiny hostile archive with a highly
// compressible layer cannot exhaust memory (a "decompression bomb").
const MAX_LAYER_BYTES: u64 = 2 * 1024 * 1024 * 1024;

// The most one archive entry may hold. A gzip layer can be a little larger than the layer it
// decompresses to (stored deflate blocks add 5 bytes per 64 KiB), so leave 2 MiB of room.
const MAX_ENTRY_BYTES: u64 = MAX_LAYER_BYTES + (MAX_LAYER_BYTES >> 10);

// The most a pipe may yield in all. A pipe reports no length to bound the entries by, and every
// blob is held in memory.
const MAX_PIPE_BYTES: u64 = 16 * 1024 * 1024 * 1024;

// The most archive text one error quotes. An honest path is at most PATH_MAX (4096) bytes,
// so only a hostile string (a tar long name, or a JSON string, can run to the layer cap) is
// ever cut. tar's own error chain can quote three paths (entry, `--output`, link target).
const SHOWN_MAX: usize = 8 * 1024;
const TAR_ERR_MAX: usize = 64 * 1024;

/// Extract the OCI archive at `archive` into `dest`, applying every layer in order.
pub fn run(archive: &Path, dest: &Path) -> Result<UnpackReport> {
    let (blobs, index) = read_archive(archive)?;

    let manifest_digest = strip_sha256(
        index["manifests"][0]["digest"]
            .as_str()
            .context("index.json has no manifest descriptor")?,
    )?;
    let manifest: serde_json::Value =
        serde_json::from_slice(blob(&blobs, manifest_digest)?).context("parsing image manifest")?;
    // A multi-arch index (what `scratchsmith index` composes) has `manifests`, not `layers`.
    let Some(layers) = manifest["layers"].as_array() else {
        if manifest.get("manifests").is_some() {
            bail!("archive holds a multi-arch image index; unpack a single-arch manifest instead");
        }
        bail!("image manifest has no layers");
    };

    std::fs::create_dir_all(dest).with_context(|| format!("creating {}", dest.display()))?;
    let mut files = 0usize;
    let mut setid = std::collections::BTreeSet::new();
    for layer in layers {
        let digest = strip_sha256(
            layer["digest"]
                .as_str()
                .context("layer descriptor has no digest")?,
        )?;
        let media = layer["mediaType"].as_str().unwrap_or_default();
        let bytes = blob(&blobs, digest)?;
        if media.ends_with("gzip") {
            files += apply_layer(&gunzip(bytes)?, dest, &mut setid)?;
        } else if media.ends_with("tar") {
            // Uncompressed: hand the blob straight through, no second copy.
            files += apply_layer(bytes, dest, &mut setid)?;
        } else {
            bail!("unsupported layer media type: {}", shown(media, SHOWN_MAX));
        }
    }

    Ok(UnpackReport {
        source: archive.display().to_string(),
        dir: dest.display().to_string(),
        layers: layers.len(),
        files,
        stripped_setid: setid
            .iter()
            .map(|p: &PathBuf| p.display().to_string())
            .collect(),
    })
}

// Read every blob and index.json out of the OCI-layout tarball, verifying each blob's bytes
// hash to the digest in its name — a tampered archive fails loudly rather than extracting.
fn read_archive(archive: &Path) -> Result<(HashMap<String, Vec<u8>>, serde_json::Value)> {
    let file =
        std::fs::File::open(archive).with_context(|| format!("opening {}", archive.display()))?;
    let meta = file
        .metadata()
        .with_context(|| format!("reading {}", archive.display()))?;
    let mut budget = archive_budget(&meta);
    let pipe = !meta.is_file();
    let mut ar = tar::Archive::new(file);
    let mut blobs = HashMap::new();
    let mut index_bytes = None;
    for entry in ar.entries().context("reading OCI archive")? {
        let mut e = entry.map_err(escape_tar_err)?;
        let stored = e.path()?.to_string_lossy().into_owned();
        // `tar -cf img.tar .` inside a layout directory stores `./index.json`; the name is the
        // same file, so match it without the prefix. Errors still quote the stored name.
        let path = stored.strip_prefix("./").unwrap_or(&stored);
        // The `blobs/` and `blobs/sha256/` directory entries carry a trailing slash and
        // an empty body (a skopeo/buildah export tars the layout directory), so only
        // digest-verify real blob files — not the directory entry itself.
        let digest = path
            .strip_prefix("blobs/sha256/")
            .filter(|d| !d.is_empty() && e.header().entry_type().is_file());
        if digest.is_none() && path != "index.json" {
            continue; // unused, so never read
        }
        // tar fills a GNU sparse entry's holes with zeros on read, so a few header bytes can
        // claim any size. No OCI layout writer emits one.
        if e.header().entry_type().is_gnu_sparse() {
            bail!(
                "refusing GNU sparse entry {} in the OCI archive",
                crate::resolver::escape_for_display(&stored)
            );
        }
        let buf = read_bounded(&mut e, &mut budget, MAX_ENTRY_BYTES, pipe, &stored)?;
        if let Some(digest) = digest {
            let actual = hex(Sha256::digest(&buf));
            if actual != digest {
                bail!("blob sha256:{} does not match its content (got sha256:{actual}) — tampered archive", shown(digest, SHOWN_MAX));
            }
            blobs.insert(digest.to_string(), buf);
        } else {
            index_bytes = Some(buf);
        }
    }
    let index = serde_json::from_slice(
        &index_bytes.context("archive has no index.json — not an OCI image layout")?,
    )
    .context("parsing index.json")?;
    Ok((blobs, index))
}

// The entries read can never hold more bytes than the archive file itself. A pipe reports no
// length, so it gets a fixed budget.
fn archive_budget(meta: &std::fs::Metadata) -> u64 {
    if meta.is_file() {
        meta.len()
    } else {
        MAX_PIPE_BYTES
    }
}

// Read one archive entry of at most `cap` bytes, charging it to `budget` (what the archive can
// still hold). Bytes past the budget were never stored in the file, only synthesized by the
// reader. The cap holds for a large or a sparse file on disk, whose budget is its length.
// `pipe` says the budget is `MAX_PIPE_BYTES`, so the error names the limit that was hit.
fn read_bounded(
    entry: impl Read,
    budget: &mut u64,
    cap: u64,
    pipe: bool,
    name: &str,
) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    entry
        .take((*budget).min(cap).saturating_add(1))
        .read_to_end(&mut buf)?;
    let len = buf.len() as u64;
    if len > cap {
        bail!(
            "OCI archive entry {} is larger than {cap} bytes; refusing",
            crate::resolver::escape_for_display(name)
        );
    }
    if len > *budget && pipe {
        bail!(
            "OCI archive entry {} takes the piped archive past {MAX_PIPE_BYTES} bytes (16 GiB); \
             refusing",
            crate::resolver::escape_for_display(name)
        );
    }
    if len > *budget {
        bail!(
            "OCI archive entry {} holds more bytes than the archive itself; refusing",
            crate::resolver::escape_for_display(name)
        );
    }
    *budget -= len;
    Ok(buf)
}

// Apply one layer's tar into `dest`: first honor its whiteouts (deletions of lower layers),
// then extract its real files. Both paths refuse anything that escapes `dest`.
// An entry path as the image path it names: `./usr/bin/x` and `usr/bin/x` are both `/usr/bin/x`.
// `..` pops, as the extractor resolves it, so `usr/../etc/su` is `/etc/su`.
fn image_path(entry: &Path) -> PathBuf {
    let mut out = PathBuf::from("/");
    for c in entry.components() {
        match c {
            std::path::Component::Normal(n) => out.push(n),
            std::path::Component::ParentDir => {
                out.pop();
            }
            _ => {}
        }
    }
    out
}

/// Archive text for a line `unpack`'s caller prints: escaped, bounded and quoted, as this
/// module's own errors show it.
pub(crate) fn shown_archive_text(text: &str) -> String {
    shown(text, SHOWN_MAX)
}

// Drop everything under `path` from the setuid/setgid record, and `path` itself unless
// `keep_self`: a whiteout removed them. `Path` orders by component, so the descendants sit
// right after `path` in the set, and a range walk touches only them. A `retain` over the
// whole set per whiteout would let a hostile layer make this quadratic.
fn forget_under(setid: &mut std::collections::BTreeSet<PathBuf>, path: &Path, keep_self: bool) {
    let gone: Vec<PathBuf> = setid
        .range(path.to_path_buf()..)
        .take_while(|p| p.starts_with(path))
        .filter(|p| !(keep_self && p.as_path() == path))
        .cloned()
        .collect();
    for p in gone {
        setid.remove(&p);
    }
}

// `setid` collects the image paths whose setuid or setgid bit this extraction cleared, as the
// final image has them: a later layer that rewrites a path without the bit, or a whiteout that
// deletes it, takes it off again.
fn apply_layer(
    tar_bytes: &[u8],
    dest: &Path,
    setid: &mut std::collections::BTreeSet<PathBuf>,
) -> Result<usize> {
    let dest_canon =
        std::fs::canonicalize(dest).with_context(|| format!("resolving {}", dest.display()))?;

    // Pass 1: whiteouts. `.wh.<name>` deletes `<name>`; `.wh..wh..opq` clears the directory.
    for entry in tar::Archive::new(tar_bytes).entries()? {
        let path = entry.map_err(escape_tar_err)?.path()?.into_owned();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if let Some(stripped) = name.strip_prefix(".wh.") {
            apply_whiteout(
                &dest_canon,
                dest,
                path.parent().unwrap_or(Path::new("")),
                stripped,
                setid,
            )?;
        }
    }

    // Pass 2: real files (skip the whiteout markers themselves).
    let mut count = 0usize;
    let mut ar = tar::Archive::new(tar_bytes);
    ar.set_preserve_permissions(true);
    // Never apply setuid/setgid from the archive: extracted files belong to whoever runs
    // unpack, so a kept bit plants a setuid binary owned by that user (root, run as root).
    // The mask is applied after preserve, so the sticky bit and 0o777 stay as authored.
    ar.set_mask(0o6000);
    ar.set_overwrite(true);
    for entry in ar.entries()? {
        let mut e = entry.map_err(escape_tar_err)?;
        let path = e.path()?.into_owned();
        if path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with(".wh."))
        {
            continue;
        }
        // `unpack_in` returns Ok(false) when it refuses a path that escapes `dest`. Fail
        // loudly: a silently-dropped entry ships a rootfs that does not match the image.
        // The mask clears the bits on disk; remember where, so the report can say so.
        let image = image_path(&path);
        if e.header().mode().is_ok_and(|m| m & 0o6000 != 0) {
            setid.insert(image);
        } else {
            setid.remove(&image);
        }
        if !e.unpack_in(dest).map_err(escape_tar_err)? {
            bail!(
                "refusing to extract an entry that escapes the target: {}",
                shown(path.display(), SHOWN_MAX)
            );
        }
        count += 1;
    }
    Ok(count)
}

// Honor one whiteout marker. `stripped` is the marker name minus the `.wh.` prefix, so an
// opaque marker (`.wh..wh..opq`) arrives as `.wh..opq`. The parent is opened one directory at
// a time with `dest` as the root, and the deletion runs relative to that open directory. A
// path is never resolved twice, so a symlink swapped in after the walk (a local user with
// write access inside `dest`) cannot carry the deletion outside.
// The setuid/setgid record is updated only where something is deleted, after every early
// return, so a marker the extractor refuses (`.wh.` alone names the root) cannot erase it.
fn apply_whiteout(
    dest_canon: &Path,
    dest: &Path,
    parent: &Path,
    stripped: &str,
    setid: &mut std::collections::BTreeSet<PathBuf>,
) -> Result<()> {
    // `.wh.` alone, or a marker naming `.`/`..`/a path, is not a single-file deletion.
    if stripped.is_empty() || stripped == "." || stripped == ".." || stripped.contains('/') {
        return Ok(());
    }
    // The joined path is for messages only; `None` is a `..` or an absolute entry path.
    let Some(shown_dir) = safe_join(dest, parent) else {
        return Ok(());
    };
    // `image` is where the walk landed, so a marker under `lib -> usr/lib` clears the record
    // of the file it deleted, under `/usr/lib`.
    let Some((dir, image)) = open_dir_in_root(dest_canon, parent)? else {
        return Ok(()); // absent, or not a directory — nothing to delete
    };
    if stripped == ".wh..opq" {
        // An opaque marker clears the directory's contents, not the directory.
        clear_dir(&dir, &shown_dir)?;
        forget_under(setid, &image, true);
    } else {
        remove_at(&dir, OsStr::new(stripped), &shown_dir)?;
        forget_under(setid, &image.join(stripped), false);
    }
    Ok(())
}

// Join `rel` under `dest`, refusing any component that could escape it (`..`, absolute).
fn safe_join(dest: &Path, rel: &Path) -> Option<PathBuf> {
    let mut out = dest.to_path_buf();
    for comp in rel.components() {
        match comp {
            Component::Normal(c) => out.push(c),
            Component::CurDir => {}
            _ => return None, // ParentDir / RootDir / Prefix would escape dest
        }
    }
    Some(out)
}

// Open `rel` under `root` as if `root` were `/`, one component at a time. A symlink is followed
// by its text (an absolute one restarts at `root`, and `..` stops there), as the image sees it.
// Every step opens relative to the directory before it, with O_NOFOLLOW. O_PATH needs only
// search permission, as `canonicalize` did. Returns the directory and its path in the image;
// `None` means absent, not a directory, or a symlink loop.
fn open_dir_in_root(root: &Path, rel: &Path) -> Result<Option<(OwnedFd, PathBuf)>> {
    use rustix::fs::{FileType, Mode, OFlags};
    use rustix::io::Errno;
    // The loader's limit on symlinks in one path (MAXSYMLINKS).
    const MAX_LINKS: usize = 40;
    let opening = || format!("opening {}", shown(root.join(rel).display(), SHOWN_MAX));
    let open_path = |at: BorrowedFd<'_>, name: &OsStr| {
        rustix::fs::openat(
            at,
            name,
            OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
    };
    let root_fd = open_path(rustix::fs::CWD, root.as_os_str()).with_context(opening)?;
    // The directories opened below the root, so `..` steps back without a path.
    let mut chain: Vec<(OwnedFd, OsString)> = Vec::new();
    // `rel` is read one part at a time, so a hostile entry name costs nothing past the first
    // part that is absent. Only the parts a symlink's text adds are queued.
    let mut rest = rel.iter();
    let mut pending: VecDeque<OsString> = VecDeque::new();
    let mut links = 0;
    while let Some(name) = pending
        .pop_front()
        .or_else(|| rest.next().map(OsStr::to_os_string))
    {
        if name == "." || name == "/" {
            continue;
        }
        if name == ".." {
            chain.pop();
            continue;
        }
        let last = pending.is_empty() && rest.as_path().as_os_str().is_empty();
        let cur = chain.last().map_or(root_fd.as_fd(), |(fd, _)| fd.as_fd());
        let fd = match open_path(cur, &name) {
            Ok(fd) => fd,
            Err(Errno::NOENT) => return Ok(None),
            Err(e) => return Err(e).with_context(opening),
        };
        let stat = rustix::fs::fstat(&fd).with_context(opening)?;
        match FileType::from_raw_mode(stat.st_mode) {
            FileType::Directory => chain.push((fd, name)),
            FileType::Symlink => {
                links += 1;
                if links > MAX_LINKS {
                    return Ok(None);
                }
                // Read through the link's own handle, so its text is the one just opened.
                let target = rustix::fs::readlinkat(&fd, "", Vec::new()).with_context(opening)?;
                let target = PathBuf::from(OsString::from_vec(target.into_bytes()));
                if target.is_absolute() {
                    chain.clear();
                }
                for part in target.iter().rev() {
                    pending.push_front(part.to_os_string());
                }
            }
            // A marker beneath a regular file is a broken layer, so say so, as before.
            _ if last => return Err(Errno::NOTDIR).with_context(opening),
            _ => return Ok(None),
        }
    }
    let image = std::iter::once(OsStr::new("/"))
        .chain(chain.iter().map(|(_, name)| name.as_os_str()))
        .collect();
    let dir = chain.pop().map_or(root_fd, |(fd, _)| fd);
    Ok(Some((dir, image)))
}

fn open_dir(at: impl AsFd, name: &OsStr) -> rustix::io::Result<OwnedFd> {
    use rustix::fs::{Mode, OFlags};
    rustix::fs::openat(
        at,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
}

// Remove `name` in `dir`: a file, a symlink (never followed), or a directory tree. A missing
// target is not an error. `shown_dir` names `dir` in messages.
fn remove_at(dir: &OwnedFd, name: &OsStr, shown_dir: &Path) -> Result<()> {
    use rustix::fs::{AtFlags, FileType};
    let shown_path = shown_dir.join(name);
    let removing = || format!("removing {}", shown(shown_path.display(), SHOWN_MAX));
    let stat = match rustix::fs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => stat,
        Err(rustix::io::Errno::NOENT) => return Ok(()),
        Err(e) => {
            return Err(e)
                .with_context(|| format!("stat {}", shown(shown_path.display(), SHOWN_MAX)))
        }
    };
    if FileType::from_raw_mode(stat.st_mode) == FileType::Directory {
        // O_NOFOLLOW: a directory swapped for a symlink since the stat fails here.
        let sub = open_dir(dir, name).with_context(removing)?;
        clear_dir(&sub, &shown_path)?;
        rustix::fs::unlinkat(dir, name, AtFlags::REMOVEDIR).with_context(removing)
    } else {
        rustix::fs::unlinkat(dir, name, AtFlags::empty()).with_context(removing)
    }
}

// Remove everything inside `dir`, but not `dir` itself. `dir` may be an O_PATH handle, so the
// listing reopens it for reading, relative to the handle.
fn clear_dir(dir: &OwnedFd, shown_dir: &Path) -> Result<()> {
    let reading = || format!("reading {}", shown(shown_dir.display(), SHOWN_MAX));
    let mut names = Vec::new();
    let readable = open_dir(dir, OsStr::new(".")).with_context(reading)?;
    for entry in rustix::fs::Dir::new(readable).with_context(reading)? {
        let entry = entry.with_context(reading)?;
        let name = entry.file_name().to_bytes();
        if name != b"." && name != b".." {
            names.push(OsString::from_vec(name.to_vec()));
        }
    }
    for name in names {
        remove_at(dir, &name, shown_dir)?;
    }
    Ok(())
}

fn blob<'a>(blobs: &'a HashMap<String, Vec<u8>>, digest: &str) -> Result<&'a Vec<u8>> {
    blobs.get(digest).with_context(|| {
        format!(
            "archive is missing blob sha256:{}",
            shown(digest, SHOWN_MAX)
        )
    })
}

fn strip_sha256(digest: &str) -> Result<&str> {
    digest
        .strip_prefix("sha256:")
        .with_context(|| format!("digest is not sha256: {}", shown(digest, SHOWN_MAX)))
}

// tar quotes archive bytes (entry paths, link names, raw header fields) in its own errors, so
// escape the whole cause chain before it joins ours. It is a whole message, so no quotes.
fn escape_tar_err(err: std::io::Error) -> anyhow::Error {
    let err = anyhow::Error::from(err);
    let (text, cut) = bounded(format_args!("{err:#}"), TAR_ERR_MAX);
    anyhow::Error::msg(text + &cut)
}

// Archive text for an error line: escaped, bounded, and quoted. Escaping stops a forged line;
// the quotes show where the archive's words end, so a name cannot forge words of ours inside
// the line, nor fake the cut marker, which stays outside them.
fn shown(text: impl std::fmt::Display, max: usize) -> String {
    let (text, cut) = bounded(text, max);
    format!("\"{text}\"{cut}")
}

// Escaped by `escape_for_display`, plus the marker for what was cut. Escaping grows a control
// byte sixfold, so only the first `max` bytes are kept and escaped, and the rest is counted.
fn bounded(text: impl std::fmt::Display, max: usize) -> (String, String) {
    let mut head = Head {
        kept: String::new(),
        max,
        cut: 0,
    };
    let _ = write!(head, "{text}");
    let cut = match head.cut {
        0 => String::new(),
        n => format!("…(+{n} bytes)"),
    };
    (escape_for_display(&head.kept), cut)
}

// Keeps the first `max` bytes written (cut on a char boundary) and counts the rest, so a
// huge `Display` is never copied whole.
struct Head {
    kept: String,
    max: usize,
    cut: usize,
}

impl std::fmt::Write for Head {
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        let mut room = if self.cut == 0 {
            s.len().min(self.max - self.kept.len())
        } else {
            0
        };
        while !s.is_char_boundary(room) {
            room -= 1;
        }
        self.kept.push_str(&s[..room]);
        self.cut += s.len() - room;
        Ok(())
    }
}

// Decompress a gzip layer, refusing one that expands past the cap (decompression bomb).
fn gunzip(data: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(data)
        .take(MAX_LAYER_BYTES + 1)
        .read_to_end(&mut out)
        .context("decompressing layer")?;
    if out.len() as u64 > MAX_LAYER_BYTES {
        bail!("layer decompresses past {MAX_LAYER_BYTES} bytes; refusing (possible decompression bomb)");
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Build a small uncompressed tar in memory from (path, bytes) entries.
    fn tar_of(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut ar = tar::Builder::new(Vec::new());
        for (name, body) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(body.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            ar.append_data(&mut header, name, &body[..]).unwrap();
        }
        ar.into_inner().unwrap()
    }

    // Build a small uncompressed tar of empty (path, entry type, mode) entries.
    fn tar_with_modes(entries: &[(&str, tar::EntryType, u32)]) -> Vec<u8> {
        let mut ar = tar::Builder::new(Vec::new());
        for (name, kind, mode) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(*kind);
            header.set_size(0);
            header.set_mode(*mode);
            header.set_cksum();
            ar.append_data(&mut header, name, &b""[..]).unwrap();
        }
        ar.into_inner().unwrap()
    }

    fn mode_of(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::symlink_metadata(path)
            .unwrap()
            .permissions()
            .mode()
            & 0o7777
    }

    #[test]
    fn apply_layer_strips_setuid_and_setgid() {
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("out");
        std::fs::create_dir_all(&dest).unwrap();
        let layer = tar_with_modes(&[
            ("bin/suid", tar::EntryType::Regular, 0o4755),
            ("bin/sgid", tar::EntryType::Regular, 0o2755),
            ("shared/", tar::EntryType::Directory, 0o6755),
        ]);
        apply_layer(&layer, &dest, &mut Default::default()).unwrap();
        assert_eq!(mode_of(&dest.join("bin/suid")), 0o755);
        assert_eq!(mode_of(&dest.join("bin/sgid")), 0o755);
        assert_eq!(mode_of(&dest.join("shared")), 0o755);
    }

    #[test]
    fn the_report_names_each_cleared_bit_as_the_final_image_has_it() {
        use std::collections::BTreeSet;
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("out");
        std::fs::create_dir_all(&dest).unwrap();
        let mut setid = BTreeSet::new();
        apply_layer(
            &tar_with_modes(&[
                ("./usr/bin/su", tar::EntryType::Regular, 0o4755),
                ("usr/bin/wall", tar::EntryType::Regular, 0o2755),
                ("usr/bin/ls", tar::EntryType::Regular, 0o755),
                ("var/mail/", tar::EntryType::Directory, 0o2775),
                ("opt/a/sgid", tar::EntryType::Regular, 0o2755),
                // Sorts between `/opt/a/…` entries as a string, but after them by component.
                ("opt/a-b/sgid", tar::EntryType::Regular, 0o2755),
            ]),
            &dest,
            &mut setid,
        )
        .unwrap();
        let names = |s: &BTreeSet<PathBuf>| {
            s.iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
        };
        assert_eq!(
            names(&setid),
            [
                "/opt/a/sgid",
                "/opt/a-b/sgid",
                "/usr/bin/su",
                "/usr/bin/wall",
                "/var/mail"
            ]
        );

        // A later layer rewrites `su` without the bit, deletes `wall`, and clears `/opt/a`.
        apply_layer(
            &tar_with_modes(&[
                ("usr/bin/su", tar::EntryType::Regular, 0o755),
                ("usr/bin/.wh.wall", tar::EntryType::Regular, 0o644),
                ("opt/a/.wh..wh..opq", tar::EntryType::Regular, 0o644),
            ]),
            &dest,
            &mut setid,
        )
        .unwrap();
        assert_eq!(names(&setid), ["/opt/a-b/sgid", "/var/mail"]);
    }

    #[test]
    fn a_whiteout_that_deletes_nothing_keeps_the_setid_record() {
        use std::collections::BTreeSet;
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("out");
        std::fs::create_dir_all(&dest).unwrap();
        let mut setid = BTreeSet::new();
        apply_layer(
            &tar_with_modes(&[
                ("etc/su", tar::EntryType::Regular, 0o4755),
                ("bin/ping", tar::EntryType::Regular, 0o4755),
            ]),
            &dest,
            &mut setid,
        )
        .unwrap();
        // `..` is folded the way the extractor resolves it (tar's builder refuses to write one).
        assert_eq!(image_path(Path::new("usr/../etc/su")), Path::new("/etc/su"));
        assert_eq!(image_path(Path::new("./a/../../b")), Path::new("/b"));

        // A bare marker names the root, and an opaque marker on a missing directory has
        // nothing to clear: the extractor deletes nothing, so the record keeps both paths.
        apply_layer(
            &tar_with_modes(&[
                (".wh.", tar::EntryType::Regular, 0o644),
                ("gone/.wh..wh..opq", tar::EntryType::Regular, 0o644),
            ]),
            &dest,
            &mut setid,
        )
        .unwrap();
        let names: Vec<_> = setid.iter().map(|p| p.display().to_string()).collect();
        assert_eq!(names, ["/bin/ping", "/etc/su"]);
    }

    #[test]
    fn apply_layer_keeps_sticky_and_plain_modes() {
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("out");
        std::fs::create_dir_all(&dest).unwrap();
        let layer = tar_with_modes(&[
            ("tmp/", tar::EntryType::Directory, 0o1777),
            ("etc/conf", tar::EntryType::Regular, 0o644),
        ]);
        apply_layer(&layer, &dest, &mut Default::default()).unwrap();
        assert_eq!(mode_of(&dest.join("tmp")), 0o1777);
        assert_eq!(mode_of(&dest.join("etc/conf")), 0o644);
    }

    #[test]
    fn apply_layer_extracts_files() {
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("out");
        std::fs::create_dir_all(&dest).unwrap();
        let layer = tar_of(&[("bin/app", b"hi"), ("etc/conf", b"x")]);
        let n = apply_layer(&layer, &dest, &mut Default::default()).unwrap();
        assert!(dest.join("bin/app").exists());
        assert_eq!(std::fs::read(dest.join("bin/app")).unwrap(), b"hi");
        assert!(dest.join("etc/conf").exists());
        assert_eq!(n, 2);
    }

    #[test]
    fn apply_layer_honors_whiteouts() {
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("out");
        std::fs::create_dir_all(dest.join("etc")).unwrap();
        std::fs::write(dest.join("etc/keep"), b"k").unwrap();
        std::fs::write(dest.join("etc/gone"), b"g").unwrap();
        let layer = tar_of(&[("etc/.wh.gone", b"")]);
        apply_layer(&layer, &dest, &mut Default::default()).unwrap();
        assert!(dest.join("etc/keep").exists(), "unrelated file kept");
        assert!(!dest.join("etc/gone").exists(), "whiteout should delete");
        assert!(!dest.join("etc/.wh.gone").exists(), "marker not written");
    }

    #[test]
    fn bare_wh_marker_does_not_delete_its_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("out");
        std::fs::create_dir_all(dest.join("usr/lib")).unwrap();
        std::fs::write(dest.join("usr/lib/keep"), b"k").unwrap();
        // `.wh.` with an empty name must not wipe `usr/lib`.
        apply_layer(
            &tar_of(&[("usr/lib/.wh.", b"")]),
            &dest,
            &mut Default::default(),
        )
        .unwrap();
        assert!(dest.join("usr/lib/keep").exists());
    }

    #[test]
    fn whiteout_refuses_to_delete_through_a_symlink_out_of_dest() {
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("out");
        std::fs::create_dir_all(&dest).unwrap();
        // A "victim" tree outside dest, with a file the whiteout must not reach.
        let outside = tmp.path().join("victim");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("secret"), b"s").unwrap();
        // A lower layer left `etc` as a symlink pointing outside dest.
        std::os::unix::fs::symlink(&outside, dest.join("etc")).unwrap();

        // A later layer whites out `etc/secret`, then clears `etc` opaquely.
        apply_layer(
            &tar_of(&[("etc/.wh.secret", b"")]),
            &dest,
            &mut Default::default(),
        )
        .unwrap();
        apply_layer(
            &tar_of(&[("etc/.wh..wh..opq", b"")]),
            &dest,
            &mut Default::default(),
        )
        .unwrap();

        assert!(
            outside.join("secret").exists(),
            "deletion escaped dest through the symlink"
        );
    }

    #[test]
    fn a_whiteout_deletes_in_the_directory_it_opened_not_by_path() {
        // The race: the walk has opened `a`, and then someone swaps `a` for a symlink to a
        // directory outside. The deletion must still land in the directory that was opened.
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("out");
        std::fs::create_dir_all(dest.join("a")).unwrap();
        std::fs::write(dest.join("a/secret"), b"in").unwrap();
        let outside = tmp.path().join("victim");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("secret"), b"out").unwrap();

        let (dir, _) = open_dir_in_root(&dest, Path::new("a")).unwrap().unwrap();
        std::fs::rename(dest.join("a"), dest.join("b")).unwrap();
        std::os::unix::fs::symlink(&outside, dest.join("a")).unwrap();
        remove_at(&dir, OsStr::new("secret"), &dest.join("a")).unwrap();

        assert!(
            outside.join("secret").exists(),
            "the deletion followed the swap"
        );
        assert!(
            !dest.join("b/secret").exists(),
            "the opened directory lost the file"
        );
    }

    #[test]
    fn a_whiteout_removes_a_tree_without_following_its_symlinks() {
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("out");
        std::fs::create_dir_all(dest.join("d/e")).unwrap();
        std::fs::write(dest.join("d/e/f"), b"f").unwrap();
        let outside = tmp.path().join("victim");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("secret"), b"s").unwrap();
        std::os::unix::fs::symlink(&outside, dest.join("d/e/link")).unwrap();

        apply_layer(&tar_of(&[(".wh.d", b"")]), &dest, &mut Default::default()).unwrap();
        assert!(!dest.join("d").exists());
        assert!(outside.join("secret").exists());
    }

    #[test]
    fn a_whiteout_follows_an_image_symlink_with_dest_as_root() {
        // A usrmerge image: `lib` points at `usr/lib`, written absolute or relative. `..`
        // past the top stays at the top, as it does inside the image.
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("out");
        std::fs::create_dir_all(dest.join("usr/lib")).unwrap();
        std::os::unix::fs::symlink("/usr/lib", dest.join("lib")).unwrap();
        std::os::unix::fs::symlink("../../../usr/lib", dest.join("lib32")).unwrap();
        for (marker, file) in [
            ("lib/.wh.liba.so", "liba.so"),
            ("lib32/.wh.libb.so", "libb.so"),
        ] {
            std::fs::write(dest.join("usr/lib").join(file), b"x").unwrap();
            apply_layer(&tar_of(&[(marker, b"")]), &dest, &mut Default::default()).unwrap();
            assert!(!dest.join("usr/lib").join(file).exists(), "{marker}");
        }
    }

    #[test]
    fn a_whiteout_through_a_link_clears_the_record_where_it_deleted() {
        use std::collections::BTreeSet;
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("out");
        std::fs::create_dir_all(&dest).unwrap();
        let mut setid = BTreeSet::new();
        apply_layer(
            &tar_with_modes(&[("usr/lib/su", tar::EntryType::Regular, 0o4755)]),
            &dest,
            &mut setid,
        )
        .unwrap();
        std::os::unix::fs::symlink("/usr/lib", dest.join("lib")).unwrap();
        apply_layer(&tar_of(&[("lib/.wh.su", b"")]), &dest, &mut setid).unwrap();
        assert!(!dest.join("usr/lib/su").exists());
        assert!(setid.is_empty(), "{setid:?}");
    }

    #[test]
    fn a_whiteout_needs_only_search_permission_on_the_way_down() {
        // An earlier layer can leave a directory without owner-read; deleting a name inside
        // it needs only search (x), as it did before the walk used handles.
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("out");
        std::fs::create_dir_all(dest.join("a/b")).unwrap();
        std::fs::write(dest.join("a/b/f"), b"f").unwrap();
        std::fs::set_permissions(dest.join("a"), std::fs::Permissions::from_mode(0o311)).unwrap();
        let got = apply_layer(
            &tar_of(&[("a/b/.wh.f", b"")]),
            &dest,
            &mut Default::default(),
        );
        std::fs::set_permissions(dest.join("a"), std::fs::Permissions::from_mode(0o755)).unwrap();
        got.unwrap();
        assert!(!dest.join("a/b/f").exists());
    }

    #[test]
    fn a_symlink_loop_in_a_whiteout_path_deletes_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("out");
        std::fs::create_dir_all(&dest).unwrap();
        std::os::unix::fs::symlink("loop", dest.join("loop")).unwrap();
        apply_layer(
            &tar_of(&[("loop/.wh.x", b"")]),
            &dest,
            &mut Default::default(),
        )
        .unwrap();
        assert!(dest.join("loop").symlink_metadata().is_ok());
    }

    #[test]
    fn read_archive_rejects_a_tampered_blob() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("bad.tar");
        // A blob whose bytes do not hash to the digest in its name.
        std::fs::write(
            &path,
            tar_of(&[("blobs/sha256/deadbeef", b"not-that-hash")]),
        )
        .unwrap();
        let err = read_archive(&path).unwrap_err();
        assert!(
            err.to_string().contains("does not match its content"),
            "{err}"
        );
    }

    #[test]
    fn read_archive_skips_the_blobs_directory_entry() {
        // A real skopeo/buildah export tars the layout dir, emitting a `blobs/sha256/`
        // directory entry (trailing slash, empty body). It must not be hashed as a blob.
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("ok.tar");
        let body = b"layerbytes";
        let digest = hex(Sha256::digest(body));

        let mut ar = tar::Builder::new(Vec::new());
        let mut dir = tar::Header::new_gnu();
        dir.set_entry_type(tar::EntryType::Directory);
        dir.set_size(0);
        dir.set_mode(0o755);
        dir.set_cksum();
        ar.append_data(&mut dir, "blobs/sha256/", &b""[..]).unwrap();
        let mut bh = tar::Header::new_gnu();
        bh.set_size(body.len() as u64);
        bh.set_mode(0o644);
        bh.set_cksum();
        ar.append_data(&mut bh, format!("blobs/sha256/{digest}"), &body[..])
            .unwrap();
        let mut ih = tar::Header::new_gnu();
        ih.set_size(2);
        ih.set_mode(0o644);
        ih.set_cksum();
        ar.append_data(&mut ih, "index.json", &b"{}"[..]).unwrap();
        std::fs::write(&path, ar.into_inner().unwrap()).unwrap();

        let (blobs, _index) =
            read_archive(&path).expect("a directory entry must not fail the archive");
        assert!(blobs.contains_key(&digest), "the real blob is still read");
    }

    // A GNU sparse entry with no stored data: one hole of `real_size` bytes, which tar
    // expands into zeros on read. `append_data` cannot build one, so set the fields by hand.
    fn append_sparse(ar: &mut tar::Builder<Vec<u8>>, name: &str, real_size: u64) {
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::GNUSparse);
        h.set_path(name).unwrap();
        h.set_size(0);
        h.set_mode(0o644);
        let gnu = h.as_gnu_mut().unwrap();
        gnu.set_real_size(real_size);
        gnu.sparse[0].set_offset(real_size);
        gnu.sparse[0].set_length(0);
        h.set_cksum();
        ar.append(&h, &b""[..]).unwrap();
    }

    #[test]
    fn read_archive_accepts_dot_slash_entry_names() {
        // What `tar -cf img.tar .` writes inside an OCI layout directory.
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("dot.tar");
        let body = b"layerbytes";
        let digest = hex(Sha256::digest(body));
        let blob = format!("./blobs/sha256/{digest}");
        // Raw header names: tar's builder normalizes `./` away, so set the bytes by hand.
        let mut ar = tar::Builder::new(Vec::new());
        for (name, data) in [(blob.as_str(), &body[..]), ("./index.json", &b"{}"[..])] {
            let mut h = tar::Header::new_gnu();
            h.as_gnu_mut().unwrap().name[..name.len()].copy_from_slice(name.as_bytes());
            h.set_size(data.len() as u64);
            h.set_mode(0o644);
            h.set_entry_type(tar::EntryType::Regular);
            h.set_cksum();
            ar.append(&h, data).unwrap();
        }
        std::fs::write(&path, ar.into_inner().unwrap()).unwrap();
        let (blobs, index) = read_archive(&path).expect("a ./ prefix names the same file");
        assert!(blobs.contains_key(&digest));
        assert_eq!(index, serde_json::json!({}));
    }

    #[test]
    fn read_archive_refuses_a_sparse_index_json_without_reading_it() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("sparse.tar");
        let mut ar = tar::Builder::new(Vec::new());
        append_sparse(&mut ar, "index.json", 64 << 30);
        std::fs::write(&path, ar.into_inner().unwrap()).unwrap();
        let err = read_archive(&path).unwrap_err();
        assert!(err.to_string().contains("GNU sparse entry"), "{err}");
    }

    #[test]
    fn read_archive_skips_unused_sparse_entries_unread() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("sparse.tar");
        let body = b"layerbytes";
        let digest = hex(Sha256::digest(body));
        let sparse_blob = "0".repeat(64);
        let mut ar = tar::Builder::new(Vec::new());
        append_sparse(&mut ar, "oci-layout", 64 << 30);
        // Not a regular file, so it was never taken as a blob; reading it expands 64 GiB.
        append_sparse(&mut ar, &format!("blobs/sha256/{sparse_blob}"), 64 << 30);
        let mut rest = tar_of(&[
            (&format!("blobs/sha256/{digest}"), &body[..]),
            ("index.json", b"{}"),
        ]);
        ar.get_mut().append(&mut rest);
        std::fs::write(&path, ar.into_inner().unwrap()).unwrap();

        let (blobs, _index) = read_archive(&path).expect("unused entries are skipped");
        assert!(blobs.contains_key(&digest));
        assert!(!blobs.contains_key(&sparse_blob));
    }

    #[test]
    fn an_entry_reading_past_the_archive_size_fails() {
        let mut budget = 16;
        let buf = read_bounded(
            &b"0123456789abcdef"[..],
            &mut budget,
            16,
            false,
            "index.json",
        )
        .unwrap();
        assert_eq!(
            (buf.len(), budget),
            (16, 0),
            "exactly the archive size is fine"
        );

        let mut budget = 16;
        let err = read_bounded(
            std::io::repeat(0),
            &mut budget,
            64,
            false,
            "index.json\u{1b}[2J",
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("more bytes than the archive itself"), "{msg}");
        assert!(!msg.contains("pipe"), "a file on disk is not a pipe: {msg}");
        assert!(
            !msg.contains('\u{1b}'),
            "the entry name must be escaped: {msg}"
        );

        let mut budget = 16;
        let err = read_bounded(std::io::repeat(0), &mut budget, 64, true, "index.json")
            .unwrap_err()
            .to_string();
        assert!(err.contains("takes the piped archive past"), "{err}");
    }

    #[test]
    fn an_entry_past_its_own_cap_fails_whatever_the_budget() {
        // A sparse or huge file on disk reports a huge length, and a pipe gets a 16 GiB budget,
        // so the budget alone lets one entry fill memory.
        let mut budget = u64::MAX;
        let buf = read_bounded(&b"01234567"[..], &mut budget, 8, true, "index.json").unwrap();
        assert_eq!(buf.len(), 8, "exactly the cap is fine");

        let mut budget = u64::MAX;
        let err = read_bounded(
            std::io::repeat(0),
            &mut budget,
            8,
            true,
            "blobs/sha256/x\u{1b}[2J",
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("is larger than 8 bytes"), "{err}");
        assert!(
            !err.contains('\u{1b}'),
            "the entry name must be escaped: {err}"
        );
    }

    #[test]
    fn a_pipe_archive_has_a_total_budget() {
        // A pipe reports no length, and it used to get an unlimited budget.
        let tmp = tempfile::tempdir().unwrap();
        let fifo = tmp.path().join("img.tar");
        rustix::fs::mknodat(
            rustix::fs::CWD,
            &fifo,
            rustix::fs::FileType::Fifo,
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
            0,
        )
        .unwrap();
        let body = b"layerbytes";
        let digest = hex(Sha256::digest(body));
        let data = tar_of(&[
            (&format!("blobs/sha256/{digest}"), &body[..]),
            ("index.json", b"{}"),
        ]);
        let writer = fifo.clone();
        std::thread::spawn(move || {
            use std::io::Write;
            let _ = std::fs::OpenOptions::new()
                .write(true)
                .open(&writer)
                .and_then(|mut w| w.write_all(&data));
        });
        // `metadata` does not open the FIFO, so the writer still meets the read below.
        let meta = std::fs::metadata(&fifo).unwrap();
        assert_eq!(archive_budget(&meta), MAX_PIPE_BYTES);
        let (blobs, _) = read_archive(&fifo).expect("an honest pipe still unpacks");
        assert!(blobs.contains_key(&digest));
    }

    #[test]
    fn an_archive_from_write_oci_archive_still_unpacks() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("root");
        std::fs::create_dir_all(root.join("usr/lib")).unwrap();
        std::fs::write(root.join("usr/lib/libx.so.1.2"), b"x").unwrap();
        std::os::unix::fs::symlink("libx.so.1.2", root.join("usr/lib/libx.so.1")).unwrap();
        let archive = tmp.path().join("img.tar");
        let staged = crate::stager::StagedTree {
            root,
            entrypoint: "/app".into(),
            loader: None,
        };
        crate::image::write_oci_archive(&staged, "t:1", &Default::default(), &archive).unwrap();

        let dest = tmp.path().join("out");
        let report = run(&archive, &dest).unwrap();
        assert_eq!((report.layers, report.files), (1, 4));
        assert_eq!(
            std::fs::read(dest.join("usr/lib/libx.so.1.2")).unwrap(),
            b"x"
        );
        assert_eq!(
            std::fs::read_link(dest.join("usr/lib/libx.so.1")).unwrap(),
            Path::new("libx.so.1.2")
        );
    }

    // Archive text in an error still shows, escaped, but never as a raw line break or escape.
    const EVIL: &str = "evil\nerror: forged\x1b[2J";
    fn assert_escaped(err: &anyhow::Error) {
        let shown = format!("{err:#}");
        assert!(!shown.chars().any(char::is_control), "{shown:?}");
        assert!(shown.contains("\\u{1b}[2J"), "{shown:?}");
    }

    // An OCI-layout tarball holding `index` and each blob under its own digest.
    fn oci_archive(dir: &Path, index: &serde_json::Value, blobs: &[&[u8]]) -> PathBuf {
        let index = serde_json::to_vec(index).unwrap();
        let names: Vec<String> = blobs
            .iter()
            .map(|b| format!("blobs/sha256/{}", hex(Sha256::digest(b))))
            .collect();
        let mut entries: Vec<(&str, &[u8])> = vec![("index.json", &index)];
        entries.extend(names.iter().map(String::as_str).zip(blobs.iter().copied()));
        let path = dir.join("img.tar");
        std::fs::write(&path, tar_of(&entries)).unwrap();
        path
    }

    #[test]
    fn run_errors_escape_media_types_and_digests() {
        let tmp = tempfile::tempdir().unwrap();
        let layer = tar_of(&[("a", b"x")]);
        let manifest = serde_json::to_vec(&serde_json::json!({
            "layers": [{
                "mediaType": EVIL,
                "digest": format!("sha256:{}", hex(Sha256::digest(&layer))),
            }],
        }))
        .unwrap();
        let manifest_digest = format!("sha256:{}", hex(Sha256::digest(&manifest)));
        // An unsupported media type, a digest naming no blob, a digest that is not sha256.
        for digest in [manifest_digest, format!("sha256:{EVIL}"), EVIL.to_string()] {
            let index = serde_json::json!({ "manifests": [{ "digest": digest }] });
            let archive = oci_archive(tmp.path(), &index, &[&manifest, &layer]);
            assert_escaped(&run(&archive, &tmp.path().join("out")).unwrap_err());
        }
    }

    // An archive whose index names `manifest`, stored as a blob beside `blobs`.
    fn archive_of(dir: &Path, manifest: &serde_json::Value, blobs: &[&[u8]]) -> PathBuf {
        let manifest = serde_json::to_vec(manifest).unwrap();
        let digest = format!("sha256:{}", hex(Sha256::digest(&manifest)));
        let index = serde_json::json!({ "manifests": [{ "digest": digest }] });
        let mut all = vec![manifest.as_slice()];
        all.extend_from_slice(blobs);
        oci_archive(dir, &index, &all)
    }

    #[test]
    fn run_refuses_an_index_and_a_manifest_without_layers() {
        // One directory each: `oci_archive` always writes `img.tar`.
        let (a, b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let index = archive_of(a.path(), &serde_json::json!({ "manifests": [] }), &[]);
        let bare = archive_of(b.path(), &serde_json::json!({ "config": {} }), &[]);
        assert_ne!(
            std::fs::read(&index).unwrap(),
            std::fs::read(&bare).unwrap()
        );

        let err = run(&index, &a.path().join("out")).unwrap_err();
        assert!(
            format!("{err:#}").contains("multi-arch image index"),
            "{err:#}"
        );
        let err = run(&bare, &b.path().join("out")).unwrap_err();
        assert!(format!("{err:#}").contains("has no layers"), "{err:#}");
    }

    #[test]
    fn run_applies_an_uncompressed_layer() {
        let tmp = tempfile::tempdir().unwrap();
        let layer = tar_of(&[("a", b"x")]);
        let manifest = serde_json::json!({
            "layers": [{
                "mediaType": "application/vnd.oci.image.layer.v1.tar",
                "digest": format!("sha256:{}", hex(Sha256::digest(&layer))),
            }],
        });
        let archive = archive_of(tmp.path(), &manifest, &[&layer]);
        let dest = tmp.path().join("out");
        let report = run(&archive, &dest).unwrap();
        assert_eq!((report.layers, report.files), (1, 1));
        assert_eq!(std::fs::read(dest.join("a")).unwrap(), b"x");
    }

    #[test]
    fn read_archive_escapes_a_blob_name_and_tar_header_text() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("bad.tar");
        std::fs::write(&path, tar_of(&[(&format!("blobs/sha256/{EVIL}"), b"x")])).unwrap();
        assert_escaped(&read_archive(&path).unwrap_err());

        // tar itself quotes a malformed header field, and the entry path, in its error.
        let mut h = tar::Header::new_gnu();
        h.set_path(EVIL).unwrap();
        h.as_gnu_mut().unwrap().cksum = *b"\x1b[2J\n\0\0\0";
        let mut bytes = h.as_bytes().to_vec();
        bytes.resize(bytes.len() + 1024, 0);
        std::fs::write(&path, bytes).unwrap();
        assert_escaped(&read_archive(&path).unwrap_err());
    }

    #[test]
    fn apply_layer_errors_escape_entry_paths() {
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("out");
        std::fs::create_dir_all(&dest).unwrap();
        std::fs::write(dest.join("f\x1b[2J"), b"x").unwrap();

        // Our refusal of a `..` entry (raw header: tar's builder rejects `..` itself).
        let mut h = tar::Header::new_gnu();
        let name = format!("../{EVIL}");
        h.as_gnu_mut().unwrap().name[..name.len()].copy_from_slice(name.as_bytes());
        h.set_size(0);
        h.set_mode(0o644);
        h.set_cksum();
        let mut ar = tar::Builder::new(Vec::new());
        ar.append(&h, &b""[..]).unwrap();
        let escaping = ar.into_inner().unwrap();
        // tar's own extraction error, and a whiteout's failed stat, beneath a regular file.
        let blocked = tar_of(&[("f\x1b[2J/g\nforged", b"y")]);
        let whiteout = tar_of(&[("f\x1b[2J/.wh.g\nforged", b"")]);

        for layer in [escaping, blocked, whiteout] {
            assert_escaped(&apply_layer(&layer, &dest, &mut Default::default()).unwrap_err());
        }
    }

    #[test]
    fn shown_quotes_archive_text_and_keeps_the_cut_marker_outside() {
        // A name that reads as our own words, and one that fakes the cut marker.
        let forged = "a — tampered archive. All blobs verified. blob sha256:b";
        assert_eq!(shown(forged, SHOWN_MAX), format!("\"{forged}\""));
        assert_eq!(shown("x…(+9 bytes)", SHOWN_MAX), "\"x…(+9 bytes)\"");
        assert_eq!(shown("x".repeat(10), 4), "\"xxxx\"…(+6 bytes)");
    }

    #[test]
    fn a_huge_archive_string_yields_a_short_error() {
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("out");
        std::fs::create_dir_all(&dest).unwrap();
        let huge = "\x1f".repeat(1 << 20);

        // A symlink whose GNU long link name tar quotes in its symlink() failure.
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::Symlink);
        h.set_size(0);
        let mut ar = tar::Builder::new(Vec::new());
        ar.append_link(&mut h, "k", &huge).unwrap();
        let symlink = ar.into_inner().unwrap();

        // A GNU long name escaping through `..`, which our own refusal quotes.
        let name = format!("../{huge}\0");
        let mut long = tar::Header::new_gnu();
        long.as_gnu_mut().unwrap().name[..13].copy_from_slice(b"././@LongLink");
        long.set_entry_type(tar::EntryType::GNULongName);
        long.set_size(name.len() as u64);
        long.set_cksum();
        let mut h = tar::Header::new_gnu();
        h.set_path("x").unwrap();
        h.set_size(0);
        h.set_cksum();
        let mut ar = tar::Builder::new(Vec::new());
        ar.append(&long, name.as_bytes()).unwrap();
        ar.append(&h, &b""[..]).unwrap();
        let escaping = ar.into_inner().unwrap();

        for layer in [symlink, escaping] {
            let shown = format!(
                "{:#}",
                apply_layer(&layer, &dest, &mut Default::default()).unwrap_err()
            );
            assert!(shown.len() < 6 * TAR_ERR_MAX + 256, "{} bytes", shown.len());
            assert!(shown.contains(" bytes)"), "{shown}");
            assert!(!shown.chars().any(char::is_control));
        }
    }

    #[test]
    fn safe_join_refuses_escapes() {
        let dest = Path::new("/tmp/dest");
        assert!(safe_join(dest, Path::new("a/b")).is_some());
        assert!(safe_join(dest, Path::new("../x")).is_none());
        assert!(safe_join(dest, Path::new("/etc/passwd")).is_none());
    }
}
