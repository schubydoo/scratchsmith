//! Extract an OCI image archive back to a directory (`unpack` subcommand): read the
//! OCI-layout tarball (`pack --oci-archive`, or any skopeo/buildah OCI archive), apply its
//! layers in order into a directory, and report what landed. Pairs with `diff` — unpack two
//! images, then compare the directories. Audits an image you did not build.

use crate::report::UnpackReport;
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::io::Read;
use std::path::{Component, Path, PathBuf};

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
    let layers = manifest["layers"]
        .as_array()
        .context("manifest has no layers")?;

    std::fs::create_dir_all(dest).with_context(|| format!("creating {}", dest.display()))?;
    let mut files = 0usize;
    for layer in layers {
        let digest = strip_sha256(
            layer["digest"]
                .as_str()
                .context("layer descriptor has no digest")?,
        )?;
        let media = layer["mediaType"].as_str().unwrap_or_default();
        let bytes = blob(&blobs, digest)?;
        let tar_bytes = if media.ends_with("gzip") {
            gunzip(bytes)?
        } else {
            bytes.clone()
        };
        files += apply_layer(&tar_bytes, dest)?;
    }

    Ok(UnpackReport {
        source: archive.display().to_string(),
        dir: dest.display().to_string(),
        layers: layers.len(),
        files,
    })
}

// Read every blob (keyed by its sha256 hex) and index.json out of the OCI-layout tarball.
fn read_archive(archive: &Path) -> Result<(HashMap<String, Vec<u8>>, serde_json::Value)> {
    let file =
        std::fs::File::open(archive).with_context(|| format!("opening {}", archive.display()))?;
    let mut ar = tar::Archive::new(file);
    let mut blobs = HashMap::new();
    let mut index_bytes = None;
    for entry in ar.entries().context("reading OCI archive")? {
        let mut e = entry?;
        let path = e.path()?.to_string_lossy().into_owned();
        let mut buf = Vec::new();
        e.read_to_end(&mut buf)?;
        if path == "index.json" {
            index_bytes = Some(buf);
        } else if let Some(digest) = path.strip_prefix("blobs/sha256/") {
            blobs.insert(digest.to_string(), buf);
        }
    }
    let index = serde_json::from_slice(
        &index_bytes.context("archive has no index.json — not an OCI image layout")?,
    )
    .context("parsing index.json")?;
    Ok((blobs, index))
}

// Apply one layer's tar into `dest`: first honor its whiteouts (deletions of lower layers),
// then extract its real files. `tar::Entry::unpack_in` refuses paths that escape `dest`.
fn apply_layer(tar_bytes: &[u8], dest: &Path) -> Result<usize> {
    // Pass 1: whiteouts. `.wh.<name>` deletes `<name>`; `.wh..wh..opq` clears the directory.
    for entry in tar::Archive::new(tar_bytes).entries()? {
        let path = entry?.path()?.into_owned();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if let Some(stripped) = name.strip_prefix(".wh.") {
            apply_whiteout(dest, path.parent().unwrap_or(Path::new("")), stripped)?;
        }
    }
    // Pass 2: real files (skip the whiteout markers themselves).
    let mut count = 0usize;
    let mut ar = tar::Archive::new(tar_bytes);
    ar.set_preserve_permissions(true);
    ar.set_overwrite(true);
    for entry in ar.entries()? {
        let mut e = entry?;
        let is_wh = e
            .path()?
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with(".wh."));
        if is_wh {
            continue;
        }
        if e.unpack_in(dest)? {
            count += 1;
        }
    }
    Ok(count)
}

// Honor one whiteout marker. `stripped` is the marker name minus the `.wh.` prefix, so an
// opaque marker (`.wh..wh..opq`) arrives as `.wh..opq`.
fn apply_whiteout(dest: &Path, parent: &Path, stripped: &str) -> Result<()> {
    if stripped == ".wh..opq" {
        // Opaque: everything the lower layers put in this directory is hidden.
        if let Some(dir) = safe_join(dest, parent) {
            if dir.is_dir() {
                for entry in std::fs::read_dir(&dir)? {
                    remove_any(&entry?.path())?;
                }
            }
        }
    } else if let Some(target) = safe_join(dest, &parent.join(stripped)) {
        remove_any(&target)?;
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

// Remove a file, symlink, or directory tree; a missing target is not an error.
fn remove_any(path: &Path) -> Result<()> {
    let meta = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e).with_context(|| format!("stat {}", path.display())),
    };
    if meta.is_dir() {
        std::fs::remove_dir_all(path)
    } else {
        std::fs::remove_file(path)
    }
    .with_context(|| format!("removing {}", path.display()))
}

fn blob<'a>(blobs: &'a HashMap<String, Vec<u8>>, digest: &str) -> Result<&'a Vec<u8>> {
    blobs
        .get(digest)
        .with_context(|| format!("archive is missing blob sha256:{digest}"))
}

fn strip_sha256(digest: &str) -> Result<&str> {
    digest
        .strip_prefix("sha256:")
        .with_context(|| format!("digest is not sha256: {digest}"))
}

fn gunzip(data: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(data)
        .read_to_end(&mut out)
        .context("decompressing layer")?;
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

    #[test]
    fn apply_layer_extracts_files() {
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("out");
        std::fs::create_dir_all(&dest).unwrap();
        let layer = tar_of(&[("bin/app", b"hi"), ("etc/conf", b"x")]);
        let n = apply_layer(&layer, &dest).unwrap();
        assert!(dest.join("bin/app").exists());
        assert_eq!(std::fs::read(dest.join("bin/app")).unwrap(), b"hi");
        assert!(dest.join("etc/conf").exists());
        assert_eq!(n, 2);
    }

    #[test]
    fn apply_layer_honors_whiteouts() {
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("out");
        // A lower layer left a file; the next layer whites it out.
        std::fs::create_dir_all(dest.join("etc")).unwrap();
        std::fs::write(dest.join("etc/keep"), b"k").unwrap();
        std::fs::write(dest.join("etc/gone"), b"g").unwrap();
        let layer = tar_of(&[("etc/.wh.gone", b"")]);
        apply_layer(&layer, &dest).unwrap();
        assert!(dest.join("etc/keep").exists(), "unrelated file kept");
        assert!(!dest.join("etc/gone").exists(), "whiteout should delete");
        // The marker file itself is not written.
        assert!(!dest.join("etc/.wh.gone").exists());
    }

    #[test]
    fn safe_join_refuses_escapes() {
        let dest = Path::new("/tmp/dest");
        assert!(safe_join(dest, Path::new("a/b")).is_some());
        assert!(safe_join(dest, Path::new("../x")).is_none());
        assert!(safe_join(dest, Path::new("/etc/passwd")).is_none());
    }
}
