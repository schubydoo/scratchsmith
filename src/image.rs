//! Assemble the staged rootfs into a container image. Sinks: the local Docker daemon
//! via a docker-archive tarball (Task 1.6), and a daemonless **OCI archive** (Task 5.1).
//! Registry push (5.2) is next. Layers are reproducible (2.9).

use crate::stager::StagedTree;
use anyhow::{bail, Context, Result};
use oci_client::client::{ClientConfig, ClientProtocol, Config as OciConfig, ImageLayer};
use oci_client::secrets::RegistryAuth;
use oci_client::{Client, Reference};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::Path;
use std::process::Command;

/// User-configurable image metadata (Task 2.2). Empty fields fall back to defaults:
/// the entrypoint defaults to the packed binary, and PATH is always present.
#[derive(Debug, Clone, Default)]
pub struct ImageConfig {
    /// Overrides the default entrypoint (the packed binary) when non-empty.
    pub entrypoint: Vec<String>,
    /// Default arguments (`Cmd`) appended to the entrypoint.
    pub cmd: Vec<String>,
    /// Extra environment entries (`KEY=VALUE`); override PATH by key if given.
    pub env: Vec<String>,
    /// Working directory inside the image.
    pub workdir: Option<String>,
    /// Image user; defaults to the non-root `nonroot` uid when unset.
    pub user: Option<String>,
}

/// Assemble `staged` into an image and load it into the local Docker daemon as `tag`.
pub fn load_into_docker(staged: &StagedTree, tag: &str, cfg: &ImageConfig) -> Result<()> {
    let built = build_image(staged, cfg)?;
    let work = tempfile::tempdir().context("temp dir for image archive")?;
    let archive = work.path().join("image.tar");
    write_docker_archive(&built, tag, &archive)?;
    docker_load(&archive)?;
    Ok(())
}

/// Write an **OCI image-layout** tarball (`oci-layout` + `index.json` + `blobs/sha256/*`)
/// with no Docker daemon — Task 5.1. `skopeo`, `buildah`, and OCI-aware tooling read this
/// shape (as does `docker load` where the containerd image store is enabled). The config
/// and layer blobs are the exact same bytes the docker sink uses — so the image ID is
/// identical across sinks; the OCI manifest/index here are new artifacts this path adds.
pub fn write_oci_archive(
    staged: &StagedTree,
    tag: &str,
    cfg: &ImageConfig,
    out: &Path,
) -> Result<()> {
    let built = build_image(staged, cfg)?;

    let manifest = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": OCI_MANIFEST,
        "config": descriptor(OCI_CONFIG, &built.config_digest, built.config_bytes.len()),
        "layers": [descriptor(OCI_LAYER_GZIP, &built.layer.digest, built.layer.gzip.len())],
    });
    let manifest_bytes = serde_json::to_vec(&manifest)?;
    let manifest_digest = hex(Sha256::digest(&manifest_bytes));

    let mut manifest_desc = descriptor(OCI_MANIFEST, &manifest_digest, manifest_bytes.len());
    // The ref name lets `docker load` / `skopeo` tag the imported image.
    manifest_desc["annotations"] = serde_json::json!({ "org.opencontainers.image.ref.name": tag });
    let index = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": OCI_INDEX,
        "manifests": [manifest_desc],
    });

    let mut ar = tar::Builder::new(std::fs::File::create(out)?);
    append_bytes(&mut ar, "oci-layout", br#"{"imageLayoutVersion":"1.0.0"}"#)?;
    append_bytes(&mut ar, "index.json", &serde_json::to_vec(&index)?)?;
    append_bytes(
        &mut ar,
        &blob_path(&built.config_digest),
        &built.config_bytes,
    )?;
    append_bytes(&mut ar, &blob_path(&built.layer.digest), &built.layer.gzip)?;
    append_bytes(&mut ar, &blob_path(&manifest_digest), &manifest_bytes)?;
    ar.finish().context("finishing OCI archive")?;
    Ok(())
}

/// Push the assembled image straight to a registry (Task 5.2) — **no Docker daemon**.
/// The config + layer blobs and the manifest go up over HTTPS; oci-client HEAD-skips any
/// blob the registry already has. Credentials come from the local Docker config
/// (`~/.docker/config.json`, incl. credential helpers); a localhost registry is treated as
/// plain-HTTP (matching Docker's insecure-localhost default), which also lets CI test
/// against a local `registry:2`.
pub fn push_to_registry(staged: &StagedTree, reference: &str, cfg: &ImageConfig) -> Result<()> {
    let built = build_image(staged, cfg)?;
    let reference: Reference = reference
        .parse()
        .with_context(|| format!("invalid image reference {reference:?}"))?;

    let registry = reference.registry();
    let auth = auth_from_credential(docker_credential::get_credential(registry).ok(), registry);
    let client = Client::new(ClientConfig {
        protocol: registry_protocol(registry),
        ..Default::default()
    });

    let layers = vec![ImageLayer::oci_v1_gzip(built.layer.gzip, None)];
    let config = OciConfig::oci_v1(built.config_bytes, None);

    // oci-client is async; run one scoped current-thread runtime for the push rather than
    // making the whole CLI async.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("tokio runtime for registry push")?;
    // The pack report is the single user-facing line (like the other sinks); don't
    // print here too.
    rt.block_on(client.push(&reference, &layers, config, &auth, None))
        .with_context(|| format!("pushing to {reference}"))?;
    Ok(())
}

// Map a Docker-config credential to a registry auth. UsernamePassword covers the common
// case — token-auth registries (GHCR, Docker Hub) do the OAuth exchange from these Basic
// creds. An identity-token credential isn't wired yet (auth hardening), so warn rather than
// silently look anonymous; no credential is genuinely anonymous. Split out as a pure
// function (credential in → auth out) so every arm is unit-testable without real creds.
fn auth_from_credential(
    cred: Option<docker_credential::DockerCredential>,
    registry: &str,
) -> RegistryAuth {
    match cred {
        Some(docker_credential::DockerCredential::UsernamePassword(user, pass)) => {
            RegistryAuth::Basic(user, pass)
        }
        Some(docker_credential::DockerCredential::IdentityToken(_)) => {
            eprintln!(
                "warning: found an identity-token credential for {registry}, which scratchsmith \
                 doesn't use yet — trying anonymous. If the push needs auth, log in with a \
                 username/password (docker login --password-stdin)."
            );
            RegistryAuth::Anonymous
        }
        None => RegistryAuth::Anonymous,
    }
}

// Plain-HTTP for a localhost registry (matching Docker's insecure-localhost default),
// HTTPS otherwise.
fn registry_protocol(registry: &str) -> ClientProtocol {
    if is_local_registry(registry) {
        ClientProtocol::HttpsExcept(vec![registry.to_string()])
    } else {
        ClientProtocol::Https
    }
}

// Is this registry a localhost one? Handles `host[:port]` and bracketed IPv6
// (`[::1]:5000`); the colons inside a bare IPv6 address mean we can't just split on ':'.
fn is_local_registry(registry: &str) -> bool {
    let host = registry
        .strip_prefix('[')
        .and_then(|rest| rest.split(']').next()) // [::1]:5000 -> ::1
        .or_else(|| registry.rsplit_once(':').map(|(h, _)| h)) // host:port -> host
        .unwrap_or(registry);
    matches!(host, "localhost" | "127.0.0.1" | "::1")
}

const OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
const OCI_INDEX: &str = "application/vnd.oci.image.index.v1+json";
const OCI_CONFIG: &str = "application/vnd.oci.image.config.v1+json";
const OCI_LAYER_GZIP: &str = "application/vnd.oci.image.layer.v1.tar+gzip";

// An OCI content descriptor: mediaType + sha256 digest + size, referencing a blob.
fn descriptor(media_type: &str, digest_hex: &str, size: usize) -> serde_json::Value {
    serde_json::json!({
        "mediaType": media_type,
        "digest": format!("sha256:{digest_hex}"),
        "size": size,
    })
}

fn blob_path(digest_hex: &str) -> String {
    format!("blobs/sha256/{digest_hex}")
}

/// The reusable pieces of a built image — the layer plus the config blob — shared by
/// every sink (docker-archive, OCI archive, later registry push). Building it once keeps
/// the digests byte-identical across sinks.
struct BuiltImage {
    layer: Layer,
    config_bytes: Vec<u8>,
    config_digest: String,
}

fn build_image(staged: &StagedTree, cfg: &ImageConfig) -> Result<BuiltImage> {
    let layer = build_layer(&staged.root)?;
    let config = image_config(&staged.entrypoint, &layer.diff_id, cfg);
    let config_bytes = serde_json::to_vec(&config)?;
    let config_digest = hex(Sha256::digest(&config_bytes));
    Ok(BuiltImage {
        layer,
        config_bytes,
        config_digest,
    })
}

// A docker-archive is a tar of: the image config, the single rootfs layer, and a
// manifest.json tying them together. `docker load` reads exactly this shape.
fn write_docker_archive(built: &BuiltImage, tag: &str, out: &Path) -> Result<()> {
    let config_name = format!("{}.json", built.config_digest);
    // The layer file is referenced by its gzip digest; the config records the
    // uncompressed diff_id. docker sniffs the gzip so the .tar name is fine.
    let layer_name = format!("{}/layer.tar", built.layer.digest);
    let manifest = serde_json::json!([{
        "Config": config_name,
        "RepoTags": [tag],
        "Layers": [layer_name],
    }]);
    let manifest_bytes = serde_json::to_vec(&manifest)?;

    let mut ar = tar::Builder::new(std::fs::File::create(out)?);
    append_bytes(&mut ar, &config_name, &built.config_bytes)?;
    append_bytes(&mut ar, &layer_name, &built.layer.gzip)?;
    append_bytes(&mut ar, "manifest.json", &manifest_bytes)?;
    ar.finish().context("finishing image archive")?;
    Ok(())
}

/// A built image layer: the gzip bytes, plus the two hashes that must stay distinct.
pub struct Layer {
    /// gzip-compressed layer tar (what goes in the archive / is pushed).
    pub gzip: Vec<u8>,
    /// sha256 of the UNCOMPRESSED tar — the config's `rootfs.diff_ids` entry.
    pub diff_id: String,
    /// sha256 of the GZIP blob — the manifest's `layers[].digest`.
    pub digest: String,
}

/// Build a reproducible, gzipped layer from the staged rootfs. The diff_id (from the
/// uncompressed tar) and the digest (from the gzip) are computed separately —
/// conflating them is the classic bug that yields unpullable images.
pub fn build_layer(root: &Path) -> Result<Layer> {
    let tar_bytes = deterministic_tar(root)?;
    let diff_id = hex(Sha256::digest(&tar_bytes));
    let gzip = gzip(&tar_bytes)?;
    let digest = hex(Sha256::digest(&gzip));
    Ok(Layer {
        gzip,
        diff_id,
        digest,
    })
}

// Tar the staged tree reproducibly: entries sorted by path, mtime zeroed, uid/gid 0,
// canonical modes, symlinks preserved. The same rootfs yields a byte-identical tar.
fn deterministic_tar(root: &Path) -> Result<Vec<u8>> {
    use std::os::unix::fs::PermissionsExt;

    let mut paths: Vec<std::path::PathBuf> = walkdir::WalkDir::new(root)
        .into_iter()
        .filter_map(|e| e.ok())
        .map(|e| e.into_path())
        .filter(|p| p != root)
        .collect();
    paths.sort();

    let mut ar = tar::Builder::new(Vec::new());
    for path in paths {
        let rel = path.strip_prefix(root)?;
        let meta = std::fs::symlink_metadata(&path)?;
        let mut header = tar::Header::new_gnu();
        header.set_mtime(0);
        header.set_uid(0);
        header.set_gid(0);

        if meta.file_type().is_symlink() {
            let target = std::fs::read_link(&path)?;
            header.set_entry_type(tar::EntryType::Symlink);
            header.set_size(0);
            header.set_mode(0o777);
            ar.append_link(&mut header, rel, &target)?;
        } else if meta.is_dir() {
            header.set_entry_type(tar::EntryType::Directory);
            header.set_size(0);
            header.set_mode(0o755);
            ar.append_data(&mut header, rel, std::io::empty())?;
        } else {
            let data = std::fs::read(&path)?;
            let exec = meta.permissions().mode() & 0o111 != 0;
            header.set_entry_type(tar::EntryType::Regular);
            header.set_size(data.len() as u64);
            header.set_mode(if exec { 0o755 } else { 0o644 });
            ar.append_data(&mut header, rel, &data[..])?;
        }
    }
    Ok(ar.into_inner()?)
}

// Deterministic gzip: fixed mtime and OS byte in the header so equal input -> equal output.
fn gzip(data: &[u8]) -> Result<Vec<u8>> {
    let mut enc = flate2::GzBuilder::new()
        .mtime(0)
        .operating_system(255)
        .write(Vec::new(), flate2::Compression::default());
    enc.write_all(data)?;
    Ok(enc.finish()?)
}

const DEFAULT_PATH: &str = "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
/// Distroless-style non-root uid:gid; the default so images never run as root.
const DEFAULT_USER: &str = "65532:65532";

fn image_config(default_entrypoint: &Path, diff_id: &str, cfg: &ImageConfig) -> serde_json::Value {
    let entrypoint = if cfg.entrypoint.is_empty() {
        vec![default_entrypoint.to_string_lossy().into_owned()]
    } else {
        cfg.entrypoint.clone()
    };

    let user = cfg.user.clone().unwrap_or_else(|| DEFAULT_USER.to_string());
    let mut config = serde_json::json!({
        "Entrypoint": entrypoint,
        "Env": merged_env(&cfg.env),
        "User": user,
    });
    if !cfg.cmd.is_empty() {
        config["Cmd"] = serde_json::json!(cfg.cmd);
    }
    if let Some(wd) = &cfg.workdir {
        config["WorkingDir"] = serde_json::json!(wd);
    }

    serde_json::json!({
        // Host-arch only at v1; multi-arch is Task 5.4.
        "architecture": "amd64",
        "os": "linux",
        "config": config,
        "rootfs": { "type": "layers", "diff_ids": [format!("sha256:{diff_id}")] },
        "history": [{ "created": "1970-01-01T00:00:00Z", "created_by": "scratchsmith" }],
    })
}

/// True when an image user string denotes root (uid 0 or `root`), so the caller can
/// warn. Accepts the `uid`, `uid:gid`, and name forms.
pub fn is_root_user(user: &str) -> bool {
    let uid = user.split(':').next().unwrap_or(user);
    uid == "0" || uid == "root"
}

// Start from the default PATH, then apply user env entries, overriding by key so a
// user-supplied PATH replaces the default rather than duplicating it.
fn merged_env(user: &[String]) -> Vec<String> {
    let key_of = |e: &str| e.split('=').next().unwrap_or(e).to_string();
    let mut env = vec![DEFAULT_PATH.to_string()];
    for entry in user {
        let key = key_of(entry);
        match env.iter_mut().find(|e| key_of(e) == key) {
            Some(slot) => *slot = entry.clone(),
            None => env.push(entry.clone()),
        }
    }
    env
}

/// The result of running a packed image once.
#[derive(Debug, Clone)]
pub struct SmokeOutcome {
    /// Process exit code, or `None` if the container was killed (e.g. timeout).
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

impl SmokeOutcome {
    /// True when the dynamic loader failed to start the binary — a missing library,
    /// missing interpreter, or bad exec. This is the staging failure a smoke-run
    /// exists to catch, distinct from the app's own non-zero exit.
    pub fn loader_failed(&self) -> bool {
        matches!(self.code, Some(126) | Some(127))
            || self.stderr.contains("error while loading shared libraries")
            || self.stderr.contains("cannot open shared object file")
            || self.stderr.contains("no such file or directory")
    }
}

/// Run the packed image once (`docker run --rm <tag> <args>`) under a timeout, so a
/// missing-library or missing-loader failure is caught before the image is trusted.
/// A timeout is treated as "started" — a long-running entrypoint is not a failure.
pub fn smoke_run(tag: &str, args: &[&str], timeout_secs: u32) -> Result<SmokeOutcome> {
    let out = Command::new("timeout")
        .arg(timeout_secs.to_string())
        .args(["docker", "run", "--rm", tag])
        .args(args)
        .output()
        .context("running docker run for the smoke test")?;
    Ok(SmokeOutcome {
        code: out.status.code().filter(|&c| c != 124), // 124 = timeout killed it
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    })
}

fn docker_load(archive: &Path) -> Result<()> {
    let out = Command::new("docker")
        .arg("load")
        .arg("-i")
        .arg(archive)
        .output()
        .context("running docker load (is the Docker daemon running?)")?;
    if !out.status.success() {
        bail!(
            "docker load failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

fn append_bytes<W: Write>(ar: &mut tar::Builder<W>, name: &str, data: &[u8]) -> Result<()> {
    let mut header = tar::Header::new_gnu();
    header.set_size(data.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    ar.append_data(&mut header, name, data)?;
    Ok(())
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

    fn tiny_rootfs() -> tempfile::TempDir {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("root");
        std::fs::create_dir_all(root.join("usr/lib")).unwrap();
        std::fs::write(root.join("usr/lib/libx.so.1.2"), b"x").unwrap();
        std::os::unix::fs::symlink("libx.so.1.2", root.join("usr/lib/libx.so.1")).unwrap();
        tmp
    }

    #[test]
    fn diff_id_and_layer_digest_are_distinct() {
        let tmp = tiny_rootfs();
        let layer = build_layer(&tmp.path().join("root")).unwrap();
        assert_eq!(layer.diff_id.len(), 64);
        assert_eq!(layer.digest.len(), 64);
        // diff_id is the uncompressed hash, digest the gzip hash — never equal.
        assert_ne!(layer.diff_id, layer.digest);
        assert!(!layer.gzip.is_empty());
    }

    #[test]
    fn layer_build_is_reproducible() {
        // Two builds of the same rootfs must yield identical hashes (sorted entries,
        // zeroed mtime/uid/gid, deterministic gzip).
        let tmp = tiny_rootfs();
        let root = tmp.path().join("root");
        let a = build_layer(&root).unwrap();
        let b = build_layer(&root).unwrap();
        assert_eq!(a.diff_id, b.diff_id, "diff_id must be stable");
        assert_eq!(a.digest, b.digest, "layer digest must be stable");
        assert_eq!(a.gzip, b.gzip, "gzip bytes must be identical");
    }

    #[test]
    fn oci_archive_is_a_well_formed_layout() {
        use std::collections::HashMap;
        use std::io::Read;

        let tmp = tiny_rootfs();
        let staged = StagedTree {
            root: tmp.path().join("root"),
            entrypoint: "/app".into(),
        };
        let out = tmp.path().join("img.tar");
        write_oci_archive(
            &staged,
            "scratchsmith/app:packed",
            &ImageConfig::default(),
            &out,
        )
        .unwrap();

        // Read the archive back: collect the blobs (asserting each is content-addressed)
        // plus the layout + index.
        let mut blobs: HashMap<String, Vec<u8>> = HashMap::new();
        let mut has_layout = false;
        let mut index_bytes = Vec::new();
        let mut ar = tar::Archive::new(std::fs::File::open(&out).unwrap());
        for entry in ar.entries().unwrap() {
            let mut e = entry.unwrap();
            let path = e.path().unwrap().to_string_lossy().into_owned();
            let mut buf = Vec::new();
            e.read_to_end(&mut buf).unwrap();
            if path == "oci-layout" {
                has_layout = true;
            } else if path == "index.json" {
                index_bytes = buf;
            } else if let Some(digest) = path.strip_prefix("blobs/sha256/") {
                assert_eq!(
                    hex(Sha256::digest(&buf)),
                    digest,
                    "blob {path} is not content-addressed"
                );
                blobs.insert(digest.to_string(), buf);
            } else {
                panic!("unexpected archive entry: {path}");
            }
        }
        assert!(has_layout, "missing oci-layout");

        let index: serde_json::Value = serde_json::from_slice(&index_bytes).unwrap();
        assert_eq!(index["mediaType"], OCI_INDEX);
        let mdesc = &index["manifests"][0];
        assert_eq!(mdesc["mediaType"], OCI_MANIFEST);
        assert_eq!(
            mdesc["annotations"]["org.opencontainers.image.ref.name"],
            "scratchsmith/app:packed"
        );

        // The index points to a manifest blob that exists and references a present
        // config + layer, with descriptor sizes matching the actual blob lengths.
        let strip = |d: &serde_json::Value| {
            d.as_str()
                .unwrap()
                .strip_prefix("sha256:")
                .unwrap()
                .to_string()
        };
        let manifest: serde_json::Value =
            serde_json::from_slice(blobs.get(&strip(&mdesc["digest"])).expect("manifest blob"))
                .unwrap();
        let cdig = strip(&manifest["config"]["digest"]);
        let ldig = strip(&manifest["layers"][0]["digest"]);
        assert_eq!(manifest["config"]["mediaType"], OCI_CONFIG);
        assert_eq!(manifest["layers"][0]["mediaType"], OCI_LAYER_GZIP);
        assert_eq!(
            manifest["config"]["size"].as_u64().unwrap() as usize,
            blobs.get(&cdig).expect("config blob").len()
        );
        assert_eq!(
            manifest["layers"][0]["size"].as_u64().unwrap() as usize,
            blobs.get(&ldig).expect("layer blob").len()
        );
    }

    #[test]
    fn local_registry_detection() {
        assert!(is_local_registry("localhost:5000"));
        assert!(is_local_registry("127.0.0.1:5099"));
        assert!(is_local_registry("127.0.0.1"));
        assert!(is_local_registry("localhost"));
        assert!(is_local_registry("[::1]:5000"), "bracketed IPv6 localhost");
        assert!(!is_local_registry("ghcr.io"));
        assert!(!is_local_registry("registry.example.com:5000"));
    }

    #[test]
    fn registry_protocol_is_http_only_for_localhost() {
        assert!(matches!(
            registry_protocol("ghcr.io"),
            ClientProtocol::Https
        ));
        assert!(matches!(
            registry_protocol("localhost:5000"),
            ClientProtocol::HttpsExcept(_)
        ));
    }

    #[test]
    fn auth_from_credential_maps_each_variant() {
        use docker_credential::DockerCredential::{IdentityToken, UsernamePassword};
        assert!(matches!(
            auth_from_credential(Some(UsernamePassword("u".into(), "p".into())), "ghcr.io"),
            RegistryAuth::Basic(_, _)
        ));
        // Identity-token creds aren't wired yet → anonymous (with a warning).
        assert!(matches!(
            auth_from_credential(Some(IdentityToken("t".into())), "ghcr.io"),
            RegistryAuth::Anonymous
        ));
        assert!(matches!(
            auth_from_credential(None, "ghcr.io"),
            RegistryAuth::Anonymous
        ));
    }

    #[test]
    fn config_defaults_to_the_packed_binary_entrypoint() {
        let cfg = image_config(Path::new("/opt/app"), "abc123", &ImageConfig::default());
        assert_eq!(cfg["config"]["Entrypoint"][0], "/opt/app");
        assert_eq!(cfg["rootfs"]["diff_ids"][0], "sha256:abc123");
        // PATH is always present; no Cmd/WorkingDir unless set.
        assert!(cfg["config"]["Env"][0]
            .as_str()
            .unwrap()
            .starts_with("PATH="));
        assert!(cfg["config"]["Cmd"].is_null());
        // Non-root by default.
        assert_eq!(cfg["config"]["User"], "65532:65532");
    }

    #[test]
    fn root_user_is_recognized_in_every_form() {
        assert!(is_root_user("0"));
        assert!(is_root_user("0:0"));
        assert!(is_root_user("root"));
        assert!(!is_root_user("65532"));
        assert!(!is_root_user("nonroot"));
    }

    #[test]
    fn config_applies_entrypoint_cmd_env_and_workdir() {
        let opts = ImageConfig {
            entrypoint: vec!["/bin/tool".into()],
            cmd: vec!["--serve".into()],
            env: vec!["FOO=bar".into()],
            workdir: Some("/work".into()),
            user: None,
        };
        let cfg = image_config(Path::new("/opt/app"), "d", &opts);
        assert_eq!(cfg["config"]["Entrypoint"][0], "/bin/tool");
        assert_eq!(cfg["config"]["Cmd"][0], "--serve");
        assert_eq!(cfg["config"]["WorkingDir"], "/work");
        let env: Vec<&str> = cfg["config"]["Env"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert!(env.contains(&"FOO=bar"));
    }

    #[test]
    fn user_path_overrides_the_default_instead_of_duplicating() {
        let env = merged_env(&["PATH=/only".to_string()]);
        assert_eq!(env, vec!["PATH=/only".to_string()]);
    }

    fn outcome(code: Option<i32>, stderr: &str) -> SmokeOutcome {
        SmokeOutcome {
            code,
            stdout: String::new(),
            stderr: stderr.into(),
        }
    }

    #[test]
    fn loader_failure_is_detected_by_exit_code_or_message() {
        // A missing library shows up as exit 127 and/or the loader's message.
        assert!(outcome(Some(127), "").loader_failed());
        assert!(
            outcome(Some(1), "error while loading shared libraries: libz.so.1").loader_failed()
        );
        assert!(outcome(Some(126), "").loader_failed());
    }

    #[test]
    fn an_app_nonzero_exit_is_not_a_loader_failure() {
        // The binary started fine and chose to exit non-zero (e.g. bad args).
        assert!(!outcome(Some(2), "error: missing subcommand").loader_failed());
        // A timeout (code None) means it started and kept running.
        assert!(!outcome(None, "").loader_failed());
    }
}
