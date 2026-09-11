//! Extract an OCI image archive back to a directory (`unpack` subcommand): read the
//! OCI-layout tarball (`pack --oci-archive`, or any skopeo/buildah OCI archive), apply its
//! layers in order into a directory, and report what landed. Pairs with `diff` — unpack two
//! images, then compare the directories. Audits an image you did not build, so every step
//! treats the archive as hostile: blobs are digest-verified, decompression is capped, and
//! both extraction and whiteout deletion refuse any path that escapes the target.

use crate::report::UnpackReport;
use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::Read;
use std::path::{Component, Path, PathBuf};

// Refuse a layer that decompresses beyond this, so a tiny hostile archive with a highly
// compressible layer cannot exhaust memory (a "decompression bomb").
const MAX_LAYER_BYTES: u64 = 2 * 1024 * 1024 * 1024;

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
    for layer in layers {
        let digest = strip_sha256(
            layer["digest"]
                .as_str()
                .context("layer descriptor has no digest")?,
        )?;
        let media = layer["mediaType"].as_str().unwrap_or_default();
        let bytes = blob(&blobs, digest)?;
        if media.ends_with("gzip") {
            files += apply_layer(&gunzip(bytes)?, dest)?;
        } else if media.ends_with("tar") {
            // Uncompressed: hand the blob straight through, no second copy.
            files += apply_layer(bytes, dest)?;
        } else {
            bail!("unsupported layer media type: {media}");
        }
    }

    Ok(UnpackReport {
        source: archive.display().to_string(),
        dir: dest.display().to_string(),
        layers: layers.len(),
        files,
    })
}

// Read every blob and index.json out of the OCI-layout tarball, verifying each blob's bytes
// hash to the digest in its name — a tampered archive fails loudly rather than extracting.
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
            let actual = hex(Sha256::digest(&buf));
            if actual != digest {
                bail!("blob sha256:{digest} does not match its content (got sha256:{actual}) — tampered archive");
            }
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
// then extract its real files. Both paths refuse anything that escapes `dest`.
fn apply_layer(tar_bytes: &[u8], dest: &Path) -> Result<usize> {
    let dest_canon =
        std::fs::canonicalize(dest).with_context(|| format!("resolving {}", dest.display()))?;

    // Pass 1: whiteouts. `.wh.<name>` deletes `<name>`; `.wh..wh..opq` clears the directory.
    for entry in tar::Archive::new(tar_bytes).entries()? {
        let path = entry?.path()?.into_owned();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if let Some(stripped) = name.strip_prefix(".wh.") {
            apply_whiteout(
                &dest_canon,
                dest,
                path.parent().unwrap_or(Path::new("")),
                stripped,
            )?;
        }
    }

    // Pass 2: real files (skip the whiteout markers themselves).
    let mut count = 0usize;
    let mut ar = tar::Archive::new(tar_bytes);
    ar.set_preserve_permissions(true);
    ar.set_overwrite(true);
    for entry in ar.entries()? {
        let mut e = entry?;
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
        if !e.unpack_in(dest)? {
            bail!(
                "refusing to extract an entry that escapes the target: {}",
                path.display()
            );
        }
        count += 1;
    }
    Ok(count)
}

// Honor one whiteout marker. `stripped` is the marker name minus the `.wh.` prefix, so an
// opaque marker (`.wh..wh..opq`) arrives as `.wh..opq`. Containment is a filesystem check,
// not a string one: the parent directory is resolved (following symlinks) and must stay
// inside `dest`, so a symlink planted by a lower layer cannot redirect a deletion outside.
fn apply_whiteout(dest_canon: &Path, dest: &Path, parent: &Path, stripped: &str) -> Result<()> {
    // `.wh.` alone, or a marker naming `.`/`..`/a path, is not a single-file deletion.
    if stripped.is_empty() || stripped == "." || stripped == ".." || stripped.contains('/') {
        return Ok(());
    }
    let Some(dir) = resolved_dir_within(dest_canon, dest, parent) else {
        return Ok(()); // absent, or resolves outside dest — nothing safe to delete
    };
    if stripped == ".wh..opq" {
        if dir.is_dir() {
            for entry in std::fs::read_dir(&dir)? {
                remove_any(&entry?.path())?;
            }
        }
    } else {
        remove_any(&dir.join(stripped))?;
    }
    Ok(())
}

// Resolve `dest/parent` and return it only when it exists and stays inside `dest` after
// following every symlink in the chain. `None` means "absent or escapes" — do nothing.
fn resolved_dir_within(dest_canon: &Path, dest: &Path, parent: &Path) -> Option<PathBuf> {
    let joined = safe_join(dest, parent)?;
    let real = std::fs::canonicalize(&joined).ok()?;
    real.starts_with(dest_canon).then_some(real)
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
        std::fs::create_dir_all(dest.join("etc")).unwrap();
        std::fs::write(dest.join("etc/keep"), b"k").unwrap();
        std::fs::write(dest.join("etc/gone"), b"g").unwrap();
        let layer = tar_of(&[("etc/.wh.gone", b"")]);
        apply_layer(&layer, &dest).unwrap();
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
        apply_layer(&tar_of(&[("usr/lib/.wh.", b"")]), &dest).unwrap();
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
        apply_layer(&tar_of(&[("etc/.wh.secret", b"")]), &dest).unwrap();
        apply_layer(&tar_of(&[("etc/.wh..wh..opq", b"")]), &dest).unwrap();

        assert!(
            outside.join("secret").exists(),
            "deletion escaped dest through the symlink"
        );
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
    fn safe_join_refuses_escapes() {
        let dest = Path::new("/tmp/dest");
        assert!(safe_join(dest, Path::new("a/b")).is_some());
        assert!(safe_join(dest, Path::new("../x")).is_none());
        assert!(safe_join(dest, Path::new("/etc/passwd")).is_none());
    }
}
