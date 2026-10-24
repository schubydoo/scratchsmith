#![no_main]
//! Fuzz the OCI-archive unpacker (`unpack::run`) with STRUCTURED input. The raw-bytes
//! `unpack` target rarely forms a valid archive, so it only exercises the outer tar/gzip/JSON
//! parse. This harness assembles a real OCI-layout archive from arbitrary layers — regular
//! files, directories, symlinks (whose targets may escape), whiteouts (`.wh.` and opaque),
//! GNU sparse entries (in a layer, and rarely a sparse `index.json` in the archive), chosen
//! media types, an optional digest tamper, and an optional image-index manifest — so
//! the fuzzer reaches the layer application, whiteout deletion, path-containment, digest
//! verification, and media dispatch that the raw target cannot. It asserts no panic, and
//! that no error it returns can break a line of output.

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use sha2::{Digest, Sha256};
use std::io::Write as _;

#[derive(Arbitrary, Debug)]
struct Spec {
    layers: Vec<LayerSpec>,
    // Rare on purpose: a tampered blob makes `read_archive` bail before any layer runs, so
    // keep it to ~1 in 32 inputs and let the rest reach the layer/whiteout code.
    tamper: u8,
    include_dir_entry: bool,
    // Make the top manifest an image index (no `layers`) — exercises the index-detect branch.
    manifest_is_index: bool,
    // Rare on purpose (like `tamper`): drop the first layer's `digest` field so unpack's
    // "layer descriptor has no digest" error path runs, without starving the happy path.
    drop_first_digest: u8,
    // Rare on purpose (like `tamper`): a second, GNU sparse `index.json`, which `read_archive`
    // must refuse before reading, because tar fills its hole with zeros of any claimed size.
    // A sparse blob name would not reach that refusal: a non-regular blob entry is skipped.
    sparse_index: u8,
}

#[derive(Arbitrary, Debug)]
struct LayerSpec {
    entries: Vec<EntrySpec>,
    media: Media,
}

#[derive(Arbitrary, Debug)]
struct EntrySpec {
    path: String,
    kind: Kind,
}

#[derive(Arbitrary, Debug)]
enum Kind {
    File(Vec<u8>),
    Dir,
    Symlink(String),
    Whiteout,
    Opaque,
    // GNU sparse: `data` stored at `offset`, then a hole of `tail` bytes, which the layer's
    // extraction expands.
    Sparse {
        data: Vec<u8>,
        offset: u16,
        tail: u16,
    },
}

#[derive(Arbitrary, Debug)]
enum Media {
    Gzip,
    Tar,
    Unsupported, // a valid tar blob but a media type unpack must reject
}

// One safe relative path component set: alphanumerics plus `.-_`, at most six short
// components, never empty / `.` / `..`, so `tar` accepts it (it refuses `..`) and paths
// collide across layers (small alphabet) to make whiteouts hit real files.
fn rel(raw: &str) -> String {
    let parts: Vec<String> = raw
        .split('/')
        .filter_map(|c| {
            let c: String = c
                .chars()
                .filter(|ch| ch.is_ascii_alphanumeric() || *ch == '.' || *ch == '-' || *ch == '_')
                .take(8)
                .collect();
            if c.is_empty() || c == "." || c == ".." {
                None
            } else {
                Some(c)
            }
        })
        .take(6)
        .collect();
    if parts.is_empty() {
        "x".into()
    } else {
        parts.join("/")
    }
}

// Split a relative path into (dir, last) so a whiteout marker can be built beside its target.
fn dir_and_base(path: &str) -> (String, String) {
    match path.rsplit_once('/') {
        Some((d, b)) => (format!("{d}/"), b.to_string()),
        None => (String::new(), path.to_string()),
    }
}

fn hex(d: impl AsRef<[u8]>) -> String {
    use std::fmt::Write as _;
    d.as_ref().iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

fn header(size: u64, kind: tar::EntryType) -> tar::Header {
    let mut h = tar::Header::new_gnu();
    h.set_size(size);
    // A directory needs the execute bit or a non-root run cannot descend into it, and the
    // layer aborts before the interesting entries.
    h.set_mode(if kind == tar::EntryType::Directory {
        0o755
    } else {
        0o644
    });
    h.set_entry_type(kind);
    h
}

fn put_file(ar: &mut tar::Builder<Vec<u8>>, name: &str, data: &[u8]) {
    let mut h = header(data.len() as u64, tar::EntryType::Regular);
    h.set_cksum();
    let _ = ar.append_data(&mut h, name, data);
}

// Build one layer's uncompressed tar from its entries. Best-effort: a rejected entry is
// skipped, never fatal.
fn layer_tar(spec: &LayerSpec) -> Vec<u8> {
    let mut ar = tar::Builder::new(Vec::new());
    for e in spec.entries.iter().take(12) {
        let base = rel(&e.path);
        let _ = match &e.kind {
            Kind::File(body) => {
                let body = &body[..body.len().min(256)];
                let mut h = header(body.len() as u64, tar::EntryType::Regular);
                h.set_cksum();
                ar.append_data(&mut h, &base, body)
            }
            Kind::Dir => {
                let mut h = header(0, tar::EntryType::Directory);
                h.set_cksum();
                ar.append_data(&mut h, format!("{base}/"), &b""[..])
            }
            Kind::Symlink(target) => {
                // The link target may escape (`../..`, `/etc`) — that is the case the
                // whiteout containment check must survive.
                let t: String = target
                    .chars()
                    .filter(|c| !c.is_control())
                    .take(48)
                    .collect();
                let mut h = header(0, tar::EntryType::Symlink);
                let r = h.set_link_name(if t.is_empty() { "/tmp" } else { &t });
                h.set_cksum();
                r.and_then(|_| ar.append_data(&mut h, &base, &b""[..]))
            }
            Kind::Whiteout => {
                let (dir, b) = dir_and_base(&base);
                let mut h = header(0, tar::EntryType::Regular);
                h.set_cksum();
                ar.append_data(&mut h, format!("{dir}.wh.{b}"), &b""[..])
            }
            Kind::Opaque => {
                let (dir, _) = dir_and_base(&base);
                let mut h = header(0, tar::EntryType::Regular);
                h.set_cksum();
                ar.append_data(&mut h, format!("{dir}.wh..wh..opq"), &b""[..])
            }
            Kind::Sparse { data, offset, tail } => {
                let data = &data[..data.len().min(256)];
                let real = u64::from(*offset) + data.len() as u64 + u64::from(*tail);
                append_sparse(&mut ar, &base, data, (*offset).into(), real)
            }
        };
    }
    ar.into_inner().unwrap_or_default()
}

// A GNU sparse entry: `data` at `offset`, and a hole up to `real` bytes. The map ends with a
// zero-length block at `real`, as GNU tar writes it. `append_data` cannot build one, so set the
// header fields by hand.
fn append_sparse(
    ar: &mut tar::Builder<Vec<u8>>,
    name: &str,
    data: &[u8],
    offset: u64,
    real: u64,
) -> std::io::Result<()> {
    let mut h = header(data.len() as u64, tar::EntryType::GNUSparse);
    h.set_path(name)?;
    if let Some(gnu) = h.as_gnu_mut() {
        gnu.set_real_size(real);
        let mut blocks = gnu.sparse.iter_mut();
        if !data.is_empty() {
            if let Some(b) = blocks.next() {
                b.set_offset(offset);
                b.set_length(data.len() as u64);
            }
        }
        if let Some(b) = blocks.next() {
            b.set_offset(real);
            b.set_length(0);
        }
    }
    h.set_cksum();
    ar.append(&h, data)
}

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    let _ = e.write_all(data);
    e.finish().unwrap_or_default()
}

// Assemble the OCI-layout tarball (oci-layout + index.json + blobs) into `out`.
fn build_archive(spec: &Spec) -> Vec<u8> {
    // Each layer: (blob bytes, media type string).
    let mut blobs: Vec<(String, Vec<u8>)> = Vec::new(); // (digest_name, bytes) to write
    let mut layer_descs: Vec<serde_json::Value> = Vec::new();

    for (i, layer) in spec.layers.iter().take(4).enumerate() {
        let tar = layer_tar(layer);
        let (bytes, media) = match layer.media {
            Media::Gzip => (gzip(&tar), "application/vnd.oci.image.layer.v1.tar+gzip"),
            Media::Tar => (tar, "application/vnd.oci.image.layer.v1.tar"),
            Media::Unsupported => (tar, "application/vnd.oci.image.layer.v1.tar+zstd"),
        };
        let digest = hex(Sha256::digest(&bytes));
        let mut desc = serde_json::Map::new();
        desc.insert("mediaType".into(), media.into());
        desc.insert("size".into(), bytes.len().into());
        // Omit the digest on the first layer ~1 in 16 inputs so the "no digest" bail runs. Use
        // a non-zero residue: Arbitrary zero-fills a short input's tail, so `== 0` would fire in
        // lockstep with `tamper == 0`, whose earlier digest-mismatch bail preempts this path.
        if !(i == 0 && spec.drop_first_digest % 16 == 7) {
            desc.insert("digest".into(), format!("sha256:{digest}").into());
        }
        layer_descs.push(serde_json::Value::Object(desc));
        blobs.push((digest, bytes));
    }

    // A dummy config blob.
    let config_bytes = b"{}".to_vec();
    let config_digest = hex(Sha256::digest(&config_bytes));
    blobs.push((config_digest.clone(), config_bytes.clone()));

    let manifest = if spec.manifest_is_index {
        serde_json::json!({ "manifests": [] })
    } else {
        serde_json::json!({
            "config": { "digest": format!("sha256:{config_digest}"), "size": config_bytes.len() },
            "layers": layer_descs,
        })
    };
    let manifest_bytes = serde_json::to_vec(&manifest).unwrap_or_default();
    let manifest_digest = hex(Sha256::digest(&manifest_bytes));
    blobs.push((manifest_digest.clone(), manifest_bytes));

    let index = serde_json::json!({
        "manifests": [{ "digest": format!("sha256:{manifest_digest}") }],
    });

    // Optionally corrupt one blob's stored name so its content no longer matches — this must
    // trip the digest-verification failure, not a panic.
    if spec.tamper % 32 == 0 {
        if let Some(first) = blobs.first_mut() {
            first.0 = "deadbeef".into();
        }
    }

    let mut ar = tar::Builder::new(Vec::new());
    put_file(&mut ar, "oci-layout", br#"{"imageLayoutVersion":"1.0.0"}"#);
    put_file(
        &mut ar,
        "index.json",
        &serde_json::to_vec(&index).unwrap_or_default(),
    );
    if spec.include_dir_entry {
        let mut h = header(0, tar::EntryType::Directory);
        h.set_cksum();
        let _ = ar.append_data(&mut h, "blobs/sha256/", &b""[..]);
    }
    // After the real `index.json`, so the loop reaches this one. A non-zero residue, for the
    // reason `drop_first_digest` gives. The claimed size is 64 GiB.
    if spec.sparse_index % 32 == 5 {
        let _ = append_sparse(&mut ar, "index.json", &[], 0, 64 << 30);
    }
    for (name, data) in &blobs {
        put_file(&mut ar, &format!("blobs/sha256/{name}"), data);
    }
    ar.into_inner().unwrap_or_default()
}

fuzz_target!(|spec: Spec| {
    let bytes = build_archive(&spec);
    let Ok(tmp) = tempfile::tempdir() else {
        return;
    };
    let archive = tmp.path().join("img.tar");
    if std::fs::write(&archive, &bytes).is_err() {
        return;
    }
    // An error quotes text out of the archive (digests, media types, entry paths, tar's own
    // header text) and `main` prints it to the terminal. None may carry a character that
    // breaks or reorders a line, or the archive could forge a line of scratchsmith's output.
    // `breaks_a_line` is the set the escape uses: Cc, the separators, and the bidi controls.
    // Entry paths here pass `rel`, so what this mainly reaches is a symlink target that
    // tar quotes in its own errors.
    use scratchsmith::resolver::breaks_a_line;
    if let Err(err) = scratchsmith::unpack::run(&archive, &tmp.path().join("out")) {
        let shown = format!("{err:#}");
        assert!(
            !shown.chars().any(breaks_a_line),
            "an unpack error carries a character that breaks a line: {shown:?}"
        );
    }
});
