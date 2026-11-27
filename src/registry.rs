//! Daemonless registry push via oci-client: blobs before manifest, auth from the Docker
//! config. Username/password creds ride oci-client's own token exchange; an identity-token
//! credential is exchanged here for a bearer access token (oci-client can't do that grant).

use crate::image::{self, ImageConfig};
use crate::stager::StagedTree;
use anyhow::{bail, Context, Result};
use oci_client::client::{ClientConfig, ClientProtocol, Config as OciConfig, ImageLayer};
use oci_client::manifest::{OciImageIndex, OciImageManifest, OciManifest};
use oci_client::secrets::RegistryAuth;
use oci_client::{Client, Reference};
use sha2::{Digest, Sha256};
use std::time::Duration;

/// Push the assembled image straight to a registry — **no Docker daemon**. The config and
/// layer blobs and the manifest go up over HTTPS; oci-client 0.18 uploads every blob, with
/// no HEAD check for one the registry already has. Credentials come from the local Docker config
/// (`~/.docker/config.json`, incl. credential helpers); a localhost registry is treated as
/// plain-HTTP (matching Docker's insecure-localhost default), which also lets CI test
/// against a local `registry:2`. Returns what the registry said about the pushed manifest's
/// digest; a plain push succeeds whatever it said, and only `--sign` needs a confirmed one.
pub fn push_to_registry(
    staged: &StagedTree,
    reference: &str,
    cfg: &ImageConfig,
    untagged: bool,
) -> Result<Pushed> {
    // Everything cheap first. Building the image stages and gzips the whole rootfs, so a bad
    // reference, a broken credential helper or a missing trust store used to surface only
    // after all of that work — where `index` reports the same failures instantly.
    let reference: Reference = if untagged {
        untagged_reference(reference)?
    } else {
        reference
            .parse()
            .with_context(|| format!("invalid image reference {reference:?}"))?
    };
    if let Some(digest) = reference.digest() {
        eprintln!("warning: {}", digest_push_deprecation(digest));
    }

    // `registry()` is the Docker-config key (e.g. `docker.io`); `resolve_registry()` is the
    // real endpoint we talk HTTP to (e.g. `registry-1.docker.io`). Look creds up by the
    // former, exchange/probe against the latter.
    let plan = plan_credential(lookup_credential(reference.registry())?);
    let endpoint = reference.resolve_registry().to_string();
    let repository = reference.repository().to_string();
    let Clients {
        registry: client,
        http,
    } = registry_clients(&endpoint)?;

    let built = image::build_image(staged, cfg)?;
    let layers = vec![ImageLayer::oci_v1_gzip(built.layer.gzip, None)];
    let config = OciConfig::oci_v1(built.config_bytes, None);
    // The manifest `push` builds itself when given `None`, built here so its digest is known.
    let manifest = OciImageManifest::build(&layers, &config, None);
    let pushed_digest = manifest_digest(&OciManifest::Image(manifest.clone()))?;
    // An untagged push PUTs the manifest under its own digest, which names no tag. The digest
    // goes where the tag would, as `manifest_target` does for a digest reference.
    let target = if untagged {
        Reference::with_tag(
            reference.registry().to_string(),
            reference.repository().to_string(),
            pushed_digest.clone(),
        )
    } else {
        manifest_target(&reference)
    };
    let by_digest = format!(
        "{}/{}@{}",
        reference.registry(),
        reference.repository(),
        pushed_digest
    );

    // oci-client is async; run one scoped current-thread runtime for the identity-token
    // exchange (if any) and the push, rather than making the whole CLI async.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("tokio runtime for registry push")?;
    let digest_ref = rt.block_on(async {
        let auth = resolve_auth(plan, &endpoint, &repository, &http).await?;
        // The pack report is the single user-facing line (like the other sinks); don't
        // print here too.
        let pushed = client
            .push(&target, &layers, config, &auth, Some(manifest))
            .await
            .with_context(|| format!("pushing to {reference}"))?;
        Ok::<_, anyhow::Error>(digest_ref_from(
            &reference,
            &pushed.manifest_url,
            &pushed_digest,
        ))
    })?;
    Ok(Pushed {
        digest: digest_ref,
        by_digest,
    })
}

/// What [`push_to_registry`] pushed.
#[derive(Debug)]
pub struct Pushed {
    /// What the registry said about the pushed manifest's digest.
    pub digest: PushedDigest,
    /// `registry/repo@sha256:…` for the manifest scratchsmith PUT.
    pub by_digest: String,
}

/// Parse a `--push-untagged` reference, which names a repository and nothing else. oci-client
/// reads a bare `app` as `app:latest`, so a tag the user wrote is found in the text: it is a
/// `:` after the last `/` (a registry port comes before the first one).
pub fn untagged_reference(raw: &str) -> Result<Reference> {
    let reference: Reference = raw
        .parse()
        .with_context(|| format!("invalid image reference {raw:?}"))?;
    let shown = crate::resolver::escape_for_display(raw);
    if reference.digest().is_some() {
        bail!(
            "--push-untagged pushes by the image's own digest, so the --push reference names a \
             repository with no digest: {shown}"
        );
    }
    if raw
        .rsplit('/')
        .next()
        .is_some_and(|last| last.contains(':'))
    {
        bail!(
            "--push-untagged pushes no tag, so the --push reference names a repository with no \
             tag: drop `:{}` from {shown}, or drop --push-untagged (or `push-untagged` in the config) \
             to push to that tag",
            crate::resolver::escape_for_display(reference.tag().unwrap_or_default())
        );
    }
    Ok(reference)
}

/// A per-arch image that went into an index, for the report.
#[derive(Debug)]
pub struct IndexEntry {
    /// The source reference the user supplied.
    pub source: String,
    /// The detected platform, e.g. `linux/amd64`.
    pub platform: String,
    /// The child manifest's digest (`sha256:…`).
    pub digest: String,
}

/// The result of assembling and pushing a multi-arch index.
#[derive(Debug)]
pub struct IndexOutcome {
    /// The per-arch children that were assembled, in input order.
    pub entries: Vec<IndexEntry>,
    /// What the registry said about the pushed index's digest.
    pub digest_ref: PushedDigest,
}

/// What a push response says about the digest of the manifest just pushed. cosign signs by
/// digest, so `--sign` refuses only `Mismatch`; a plain push succeeds with any of the three.
#[derive(Debug)]
#[must_use = "a `Mismatch` must reach the user, as a refusal or a warning"]
pub enum PushedDigest {
    /// The by-digest reference (`registry/repo@sha256:…`) of the manifest pushed.
    Confirmed(String),
    /// The response named no digest. Holds the by-digest reference of the manifest that
    /// scratchsmith PUT, which is what gets signed.
    Unreported(String),
    /// The response named a digest other than the manifest pushed. Holds the two digests.
    Mismatch(anyhow::Error),
}

impl PushedDigest {
    /// The reference to sign, or why there is none.
    pub fn for_signing(self) -> Result<String> {
        match self {
            Self::Confirmed(reference) => Ok(reference),
            // The registry named no digest (a tag-based `Location`), so it chose nothing:
            // sign the digest of the bytes we sent. cosign looks it up, so a registry that
            // stored other bytes fails the signing instead of passing it.
            Self::Unreported(reference) => Ok(reference),
            // The same refusal text as before the enum: the facts, framed as a refusal.
            Self::Mismatch(err) => {
                bail!("cannot sign: {err:#}; refusing to sign a digest the registry chose")
            }
        }
    }
}

/// Whether a manifest is a single image or an image index (a multi-arch list). The value
/// names are a `verify --format json` contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ManifestKind {
    Image,
    Index,
}

/// An image reference resolved to the digest it named when it was read.
#[derive(Debug)]
pub struct Resolved {
    /// The by-digest reference, `registry/repo@sha256:…`.
    pub digest_ref: String,
    /// The digest alone, `sha256:…`.
    pub digest: String,
    /// What the manifest at that digest is.
    pub kind: ManifestKind,
    /// Whether the reference named a tag and no digest, so the digest came from the registry.
    pub by_tag: bool,
}

/// Parse an image reference given on the command line. A bad one is a usage error.
pub fn parse_image_reference(image: &str) -> Result<Reference> {
    image
        .parse()
        .with_context(|| format!("invalid image reference {image:?}"))
        .map_err(crate::cli::usage)
}

/// Read `reference` from its registry, once, and return its digest and manifest kind. A tag
/// is resolved to the digest it points to now, so a caller that checks the digest checks what
/// it reports, even if the tag moves later.
pub fn resolve(reference: &Reference) -> Result<Resolved> {
    let image = reference.whole();
    let plan = plan_credential(lookup_credential(reference.registry())?);
    let endpoint = reference.resolve_registry().to_string();
    let repository = reference.repository().to_string();
    let Clients {
        registry: client,
        http,
    } = registry_clients(&endpoint)?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("tokio runtime for the registry read")?;
    let (raw, served) = rt.block_on(async {
        let auth = resolve_auth(plan, &endpoint, &repository, &http).await?;
        client
            .pull_manifest_raw(reference, &auth, CHILD_MANIFEST_TYPES)
            .await
            .with_context(|| format!("pulling the manifest for {image}"))
    })?;
    // oci-client checked the bytes against both the digest asked for and the one served. A
    // digest the user gave stays the one reported, in the algorithm they wrote.
    let digest = reference.digest().map_or(served, str::to_string);
    let kind = manifest_kind(&raw).with_context(|| format!("reading the manifest for {image}"))?;
    Ok(Resolved {
        digest_ref: Reference::with_digest(
            reference.registry().to_string(),
            repository,
            digest.clone(),
        )
        .whole(),
        by_tag: reference.digest().is_none(),
        digest,
        kind,
    })
}

/// Read whether registry-served manifest bytes are an image or an index. The OCI spec makes
/// `mediaType` optional, so with none a `manifests` array marks an index. A byte-level entry
/// point for fuzzing, since the bytes are untrusted.
pub fn manifest_kind(raw: &[u8]) -> Result<ManifestKind> {
    let manifest: serde_json::Value =
        serde_json::from_slice(raw).context("parsing the manifest")?;
    let Some(fields) = manifest.as_object() else {
        bail!("the manifest is not a JSON object");
    };
    let is_index = match fields.get("mediaType").and_then(|v| v.as_str()) {
        Some(media_type) => is_multi_arch_media_type(media_type),
        None => fields.get("manifests").is_some_and(|v| v.is_array()),
    };
    Ok(if is_index {
        ManifestKind::Index
    } else {
        ManifestKind::Image
    })
}

// Manifest media types accepted when pulling a child. Both OCI and Docker single-image
// manifests are valid children; the two list types are accepted only so a mistakenly
// passed index is fetched and rejected with a clear message rather than an opaque error.
const CHILD_MANIFEST_TYPES: &[&str] = &[
    crate::image::OCI_MANIFEST,
    "application/vnd.docker.distribution.manifest.v2+json",
    crate::image::OCI_INDEX,
    "application/vnd.docker.distribution.manifest.list.v2+json",
];

/// Assemble a multi-arch OCI image index from per-arch images **already pushed** to the
/// registry (a native-arch CI matrix) and push it to `target` — the daemonless equivalent
/// of `docker manifest create`. Each source is pulled to read its manifest digest and size
/// and its platform (architecture/os, from the image config); no image is built and no
/// cross-arch resolution happens. Children must live in the target's registry (a manifest
/// list references them by digest, within the same repository). Returns the assembled
/// entries and the pushed index's by-digest reference.
pub fn push_index(target: &str, sources: &[String]) -> Result<IndexOutcome> {
    if sources.is_empty() {
        bail!("no source images given to assemble into an index");
    }
    let target_ref: Reference = target
        .parse()
        .with_context(|| format!("invalid target reference {target:?}"))
        .map_err(crate::cli::usage)?;
    let source_refs = sources
        .iter()
        .map(|s| {
            let r: Reference = s
                .parse()
                .with_context(|| format!("invalid source reference {s:?}"))
                .map_err(crate::cli::usage)?;
            // An image index references its children by digest, resolved within the
            // repository it was pulled from — so every source must be in the target's
            // repository (this push publishes only the list, never copies child blobs).
            // The usual shape is the same repo, a different tag: app:1.0-amd64 -> app:1.0.
            if r.registry() != target_ref.registry() || r.repository() != target_ref.repository() {
                bail!(crate::cli::UsageError(format!(
                    "source {s} is {}/{} but the target index is {}/{}; an image index \
                     references its children by digest within one repository, so every \
                     source must be in the target's repository (typically the same repo, a \
                     different tag)",
                    r.registry(),
                    r.repository(),
                    target_ref.registry(),
                    target_ref.repository()
                )));
            }
            Ok((s.clone(), r))
        })
        .collect::<Result<Vec<_>>>()?;

    let plan = plan_credential(lookup_credential(target_ref.registry())?);
    let endpoint = target_ref.resolve_registry().to_string();
    let repository = target_ref.repository().to_string();
    let Clients {
        registry: client,
        http,
    } = registry_clients(&endpoint)?;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("tokio runtime for the index push")?;
    rt.block_on(async {
        let auth = resolve_auth(plan, &endpoint, &repository, &http).await?;
        let mut children = Vec::with_capacity(source_refs.len());
        for (source, r) in &source_refs {
            children.push(fetch_child(&client, r, &auth, source).await?);
        }
        let index = build_index(&children)?;
        let pushed_digest = manifest_digest(&OciManifest::ImageIndex(index.clone()))?;
        let url = client
            .push_manifest_list(&manifest_target(&target_ref), &auth, index)
            .await
            .with_context(|| format!("pushing the image index to {target}"))?;
        let entries = children
            .into_iter()
            .map(|c| IndexEntry {
                platform: platform_label(&c),
                source: c.source,
                digest: c.digest,
            })
            .collect();
        Ok(IndexOutcome {
            entries,
            digest_ref: digest_ref_from(&target_ref, &url, &pushed_digest),
        })
    })
}

// A child manifest gathered from the registry — everything an index entry needs.
struct Child {
    source: String,
    media_type: String,
    digest: String,
    size: i64,
    architecture: String,
    os: String,
    // CPU variant (e.g. `v7` for arm), when the config declares one. Part of a platform's
    // identity: without it, arm/v7 and arm/v6 collide and runtime matching can miss.
    variant: Option<String>,
}

// Pull one source: its raw manifest (for the exact stored size, digest, and media type) and
// its config (for the platform). Size and digest must be the registry's own bytes, so they
// come from the raw manifest — never a re-serialization, which may not be byte-identical.
async fn fetch_child(
    client: &Client,
    reference: &Reference,
    auth: &RegistryAuth,
    source: &str,
) -> Result<Child> {
    let (raw, digest) = client
        .pull_manifest_raw(reference, auth, CHILD_MANIFEST_TYPES)
        .await
        .with_context(|| format!("pulling the manifest for {source}"))?;
    let (media_type, config_digest) = parse_child_manifest(&raw, source)?;
    // We already have the manifest bytes, so pull only the config blob it names — one GET
    // instead of re-fetching the manifest. Addressing it by digest (from the manifest we
    // just verified) keeps it immutable, so a tag re-pushed mid-run can't swap the platform
    // under the size/digest recorded above. Auth was primed by the pull_manifest_raw above.
    let mut config_bytes = Vec::new();
    client
        .pull_blob(reference, config_digest.as_str(), &mut config_bytes)
        .await
        .with_context(|| format!("pulling the config for {source}"))?;
    let (architecture, os, variant) = parse_child_config(&config_bytes, source)?;
    Ok(Child {
        source: source.to_string(),
        media_type,
        digest,
        size: raw.len() as i64,
        architecture,
        os,
        variant,
    })
}

/// Parse a child image's manifest bytes into `(media_type, config_digest)`. A byte-level entry
/// point for fuzzing — the manifest is whatever a registry chose to serve, so it is untrusted.
pub fn parse_child_manifest(raw: &[u8], source: &str) -> Result<(String, String)> {
    let manifest: serde_json::Value = serde_json::from_slice(raw)
        .with_context(|| format!("parsing the manifest for {source}"))?;
    let media_type = manifest
        .get("mediaType")
        .and_then(|v| v.as_str())
        .unwrap_or(crate::image::OCI_MANIFEST)
        .to_string();
    if is_multi_arch_media_type(&media_type) {
        bail!(
            "source {source} is itself a multi-arch index ({}); pass the single-arch images, \
             not an index",
            // A registry-served string, matched only by a substring test above.
            crate::resolver::escape_for_display(&media_type)
        );
    }
    let config_digest = manifest
        .get("config")
        .and_then(|c| c.get("digest"))
        .and_then(|v| v.as_str())
        .with_context(|| format!("the manifest for {source} has no config.digest"))?
        .to_string();
    Ok((media_type, config_digest))
}

/// Parse a child image's config bytes into `(architecture, os, variant)`. A byte-level entry
/// point for fuzzing — the config blob is registry-served, so it is untrusted.
pub fn parse_child_config(bytes: &[u8], source: &str) -> Result<(String, String, Option<String>)> {
    let config: serde_json::Value = serde_json::from_slice(bytes)
        .with_context(|| format!("parsing the config for {source}"))?;
    let architecture = config
        .get("architecture")
        .and_then(|v| v.as_str())
        .with_context(|| format!("the config for {source} has no architecture"))?
        .to_string();
    // Fail loud on a missing `os`, like a missing architecture — never silently stamp
    // `linux` on a foreign image and ship a quietly-wrong platform in the index.
    let os = config
        .get("os")
        .and_then(|v| v.as_str())
        .with_context(|| format!("the config for {source} has no os"))?
        .to_string();
    let variant = config
        .get("variant")
        .and_then(|v| v.as_str())
        .map(str::to_string);
    Ok((architecture, os, variant))
}

// An OCI image index or a Docker manifest list — a multi-arch manifest, not a single image.
// Passing one as an index child is a mistake we reject with a clear message.
fn is_multi_arch_media_type(media_type: &str) -> bool {
    media_type.contains("index") || media_type.contains("manifest.list")
}

// Human platform label `os/arch` (or `os/arch/variant`), for the report and error messages.
fn platform_label(c: &Child) -> String {
    match &c.variant {
        Some(v) => format!("{}/{}/{}", c.os, c.architecture, v),
        None => format!("{}/{}", c.os, c.architecture),
    }
}

// Assemble the gathered children into an OCI image index. Built as JSON and deserialized
// into oci-client's typed index so an unknown architecture degrades to `Arch::Other`
// rather than failing. Rejects duplicate platforms: two children claiming the same os/arch
// make an ambiguous index and usually mean a mislabeled or wrong source.
fn build_index(children: &[Child]) -> Result<OciImageIndex> {
    let mut seen = std::collections::HashSet::new();
    for c in children {
        // Variant is part of the platform's identity, so arm/v7 and arm/v6 are distinct.
        if !seen.insert((c.os.as_str(), c.architecture.as_str(), c.variant.as_deref())) {
            bail!(
                "two source images resolve to the same platform {}; each platform must be \
                 unique in an index",
                // The os/arch/variant strings come from a registry-served config blob.
                crate::resolver::escape_for_display(&platform_label(c))
            );
        }
    }
    let manifests: Vec<serde_json::Value> = children
        .iter()
        .map(|c| {
            let mut platform = serde_json::json!({
                "architecture": c.architecture,
                "os": c.os,
            });
            if let Some(variant) = &c.variant {
                platform["variant"] = serde_json::json!(variant);
            }
            serde_json::json!({
                "mediaType": c.media_type,
                "digest": c.digest,
                "size": c.size,
                "platform": platform,
            })
        })
        .collect();
    let index = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": crate::image::OCI_INDEX,
        "manifests": manifests,
    });
    serde_json::from_value(index).context("assembling the OCI image index")
}

// The deprecation line for a `--push` reference that names a digest. A registry stores a
// manifest under its own digest, so a push to any other digest fails there, and one to the
// right digest needs a digest nobody knows before the build. 3.0 refuses it (TASK-254).
fn digest_push_deprecation(digest: &str) -> String {
    format!(
        "a digest in the --push reference ({}) is deprecated, and 3.0 will refuse it. Push to \
         a tag instead",
        crate::resolver::escape_for_display(digest)
    )
}

// The reference to hand oci-client for the manifest PUT. When a push to a digest gets no
// `Location` back, oci-client 0.18.0 panics (src/client.rs:1873, "The manifest URL always ends
// with the image tag suffix"): its fallback strips the tag, not the digest, off the URL. With
// the digest as the tag, the URL is the same (`/v2/<repo>/manifests/<digest>`) and the
// fallback strips what the URL ends with.
fn manifest_target(reference: &Reference) -> Reference {
    match reference.digest() {
        Some(digest) => Reference::with_tag(
            reference.registry().to_string(),
            reference.repository().to_string(),
            digest.to_string(),
        ),
        None => reference.clone(),
    }
}

// Build a by-digest reference (`registry/repo@sha256:…`) for `pushed`, the digest of the
// manifest we uploaded. cosign signs by digest, so this is what `--sign` targets — precise and
// immune to a tag being moved after the push. When the push response's manifest URL (the
// registry's `Location` header) names a digest, it must be that same one: signing the one it
// names would let the registry pick the image our identity signs. Only `--sign` consults the
// result, so no answer fails a plain push.
fn digest_ref_from(reference: &Reference, manifest_url: &str, pushed: &str) -> PushedDigest {
    let ours = format!(
        "{}/{}@{}",
        reference.registry(),
        reference.repository(),
        pushed
    );
    let Some(reported) = manifest_url
        .rsplit("/manifests/")
        .next()
        .and_then(|tail| tail.split(['?', '#']).next())
        .filter(|d| d.starts_with("sha256:"))
    else {
        return PushedDigest::Unreported(ours);
    };
    // Exact equality with our own `sha256:` + 64 lowercase hex also refuses a malformed digest.
    if reported != pushed {
        // The facts only: without `--sign` this is a warning, and nothing was asked to sign.
        return PushedDigest::Mismatch(anyhow::anyhow!(
            "the registry reported digest {} for the manifest just pushed, but that \
             manifest's digest is {pushed}",
            crate::resolver::escape_for_display(reported)
        ));
    }
    PushedDigest::Confirmed(ours)
}

// The digest of the manifest bytes oci-client PUTs: `push_manifest` serializes the
// `OciManifest` with olpc-cjson's canonical formatter (oci-client 0.18 client.rs:1811-1823),
// so the same value through the same formatter is the same bytes.
fn manifest_digest(manifest: &OciManifest) -> Result<String> {
    let mut body = Vec::new();
    let mut ser =
        serde_json::Serializer::with_formatter(&mut body, olpc_cjson::CanonicalFormatter::new());
    serde::Serialize::serialize(manifest, &mut ser).context("serializing the manifest")?;
    Ok(format!("sha256:{}", image::hex(Sha256::digest(&body))))
}

/// What to do with a Docker-config credential. UsernamePassword and "no credential" resolve
/// to a `RegistryAuth` directly; an identity token needs a network exchange first, so it's
/// kept distinct. Split from the exchange as a pure function so every arm is unit-testable
/// without real creds or a network.
enum CredentialPlan {
    Ready(RegistryAuth),
    IdentityToken(String),
}

// Split "no credential is configured" from "the credential lookup FAILED".
//
// Both used to collapse to `None` via `.ok()` and push ANONYMOUSLY. Against a registry that
// requires auth the user then got an opaque 401 instead of "your credential helper failed";
// against one that accepts anonymous writes, the push SUCCEEDED under an identity they did not
// choose.
//
// The split is by "is there a credential here at all", NOT by how the variant name reads -- two
// of them read as failures and are not. Each arm below says which it is and why.
//
// Pure and takes the Result directly, so every variant is unit-testable without a Docker config
// on the machine.
fn credential_or_anonymous(
    got: std::result::Result<
        docker_credential::DockerCredential,
        docker_credential::CredentialRetrievalError,
    >,
    registry: &str,
) -> Result<Option<docker_credential::DockerCredential>> {
    use docker_credential::CredentialRetrievalError as E;

    // A credential helper reports "I have no entry for this server" by EXITING NON-ZERO with
    // this exact message, not by printing nothing. That is the docker-credential-helpers
    // protocol; the native stores print it on stdout.
    const CREDENTIALS_NOT_FOUND: &str = "credentials not found in native keychain";

    match got {
        Ok(cred) => Ok(Some(cred)),
        // A helper saying "nothing here" -- NOT a broken helper, despite the variant name.
        // `creds_store` is consulted for EVERY registry (docker_credential lib.rs:143-145),
        // so without this arm no machine carrying a `credsStore` could push anonymously --
        // Docker Desktop writes one, and so does `docker login` with pass or secretservice.
        // Docker's own CLI carves out the same case by name, in
        // cli/config/credentials/native_store.go. A helper reporting not-found with a
        // NON-standard message (ecr-login, gcloud) still lands in the fatal arm below, which
        // is the safe side to err on.
        Err(E::HelperFailure { stdout, stderr, .. })
            if stdout.trim() == CREDENTIALS_NOT_FOUND || stderr.trim() == CREDENTIALS_NOT_FOUND =>
        {
            Ok(None)
        }
        // Nothing to find. `ConfigReadError` belongs here and it is NOT obvious: the crate
        // returns it both when the config cannot be OPENED (`File::open`, lib.rs:232 -- the
        // ordinary "this machine has no Docker config" case) and when it cannot be PARSED
        // (config.rs:89). So an unreadable or corrupt config also pushes anonymously in
        // silence. The missing-file case dominates by far, and classifying the variant as a
        // failure broke every anonymous push to a local registry, which is how this was
        // caught. `ConfigNotFound` is narrower: the config PATH could not be resolved.
        Err(E::NoCredentialConfigured | E::ConfigNotFound | E::ConfigReadError) => Ok(None),
        // A credential for this registry EXISTS and something about using it broke. This is
        // the set the user must hear about: it used to become an anonymous push.
        Err(
            e @ (E::HelperCommunicationError
            | E::MalformedHelperResponse
            | E::HelperFailure { .. }
            | E::CredentialDecodingError
            | E::CredentialMismatchError),
        ) => Err(anyhow::Error::new(e)).with_context(|| {
            format!(
                "looking up the credential for {registry}; fix the credential helper or the \
                 stored login, or remove the entry to push anonymously"
            )
        }),
    }
}

/// The key `docker login` stores a Docker Hub login under.
const DOCKER_HUB_LOGIN_KEY: &str = "https://index.docker.io/v1/";

// The registry names a Docker Hub reference can carry (oci-client reports `docker.io`).
fn is_docker_hub(registry: &str) -> bool {
    matches!(
        registry,
        "docker.io" | "index.docker.io" | "registry-1.docker.io"
    )
}

// The stored credential for `registry`, or `None` to go anonymous.
fn lookup_credential(registry: &str) -> Result<Option<docker_credential::DockerCredential>> {
    lookup_credential_with(registry, docker_credential::get_credential)
}

// Docker CLI keeps the Hub login under `https://index.docker.io/v1/`, and the pass,
// secretservice, osxkeychain and wincred helpers match that string or its host exactly, so a
// helper asked for `docker.io` misses it (TASK-202). Ask for the CLI's key first. `docker.io`
// stays as the fallback, which still finds an `auths` or `credHelpers` entry keyed that way.
// A broken helper on the first ask is fatal, as on any other.
fn lookup_credential_with(
    registry: &str,
    get: impl Fn(
        &str,
    ) -> std::result::Result<
        docker_credential::DockerCredential,
        docker_credential::CredentialRetrievalError,
    >,
) -> Result<Option<docker_credential::DockerCredential>> {
    if is_docker_hub(registry) {
        if let Some(cred) = credential_or_anonymous(get(DOCKER_HUB_LOGIN_KEY), registry)? {
            return Ok(Some(cred));
        }
    }
    credential_or_anonymous(get(registry), registry)
}

fn plan_credential(cred: Option<docker_credential::DockerCredential>) -> CredentialPlan {
    use docker_credential::DockerCredential::{IdentityToken, UsernamePassword};
    match cred {
        // Token-auth registries (GHCR, Docker Hub) do the OAuth exchange from these Basic
        // creds inside oci-client, so pass them straight through.
        Some(UsernamePassword(user, pass)) => {
            CredentialPlan::Ready(RegistryAuth::Basic(user, pass))
        }
        Some(IdentityToken(token)) => CredentialPlan::IdentityToken(token),
        // No credential is genuinely anonymous (public pull-through / local registry).
        None => CredentialPlan::Ready(RegistryAuth::Anonymous),
    }
}

async fn resolve_auth(
    plan: CredentialPlan,
    endpoint: &str,
    repository: &str,
    http: &reqwest::Client,
) -> Result<RegistryAuth> {
    match plan {
        CredentialPlan::Ready(auth) => Ok(auth),
        CredentialPlan::IdentityToken(token) => {
            let access = exchange_identity_token(http, endpoint, repository, &token).await?;
            Ok(RegistryAuth::Bearer(access))
        }
    }
}

/// Exchange a Docker identity token (an OAuth2 refresh token) for a short-lived bearer
/// access token, per the Docker token-auth spec. oci-client only knows how to obtain a token
/// from Basic creds, so we run the `grant_type=refresh_token` POST ourselves and hand the
/// result back as `RegistryAuth::Bearer`. Two calls: read the `WWW-Authenticate` challenge
/// from `/v2/` to find the realm, then POST the grant.
async fn exchange_identity_token(
    http: &reqwest::Client,
    endpoint: &str,
    repository: &str,
    refresh_token: &str,
) -> Result<String> {
    let scheme = registry_scheme(endpoint);

    // 1. Discover the token realm from the registry's Bearer challenge.
    let v2 = format!("{scheme}://{endpoint}/v2/");
    let probe = http
        .get(&v2)
        .send()
        .await
        .with_context(|| format!("probing {v2} for an auth challenge"))?;
    let challenge = probe
        .headers()
        .get(reqwest::header::WWW_AUTHENTICATE)
        .and_then(|h| h.to_str().ok())
        .map(str::to_owned)
        .with_context(|| {
            format!("{endpoint} presented no Bearer challenge; cannot exchange the identity token")
        })?;
    let shown = crate::resolver::escape_for_display;
    let realm = extract_challenge_param(&challenge, "realm").with_context(|| {
        format!(
            "no realm in the auth challenge from {endpoint}: \"{}\"",
            shown(&challenge)
        )
    })?;
    let realm = token_realm(&realm, endpoint)?;
    let service =
        extract_challenge_param(&challenge, "service").unwrap_or_else(|| endpoint.to_string());

    // 2. Run the refresh-token grant and pull the access token out of the response.
    let scope = format!("repository:{repository}:pull,push");
    let params = [
        ("grant_type", "refresh_token"),
        ("service", service.as_str()),
        ("scope", scope.as_str()),
        ("client_id", "scratchsmith"),
        ("refresh_token", refresh_token),
    ];
    let res = http
        .post(realm.clone())
        .form(&params)
        .send()
        .await
        .with_context(|| format!("exchanging the identity token at {realm}"))?;
    let status = res.status();
    // The token client follows no redirect, so the refresh token is never sent on to a host
    // the challenge did not name. A redirect is refused, not followed by hand. A client that
    // did follow one has already resent the body, and its answer is not used either.
    if status.is_redirection() || res.url() != &realm {
        anyhow::bail!(
            "the token endpoint {realm} answered with a redirect ({status}); scratchsmith does \
             not send the identity token on to another address"
        );
    }
    // A body that cannot be READ is not an empty body. `unwrap_or_default()` turned a
    // connection reset mid-response into "", which then surfaced as a token-decoding error
    // that named the wrong cause. The status rides along in the context, so a non-success
    // exchange still reports it even when the body is unreadable.
    if !status.is_success() {
        let (head, cut) = read_capped(res, TOKEN_ERROR_SHOWN).await.with_context(|| {
            format!("reading the identity-token response from {realm} ({status})")
        })?;
        let more = if cut { "..." } else { "" };
        anyhow::bail!(
            "identity-token exchange at {realm} failed ({status}): {}{more}",
            shown(&String::from_utf8_lossy(&head))
        );
    }
    let (body, cut) = read_capped(res, TOKEN_BODY_LIMIT)
        .await
        .with_context(|| format!("reading the identity-token response from {realm} ({status})"))?;
    if cut {
        anyhow::bail!("the token response from {realm} is larger than {TOKEN_BODY_LIMIT} bytes");
    }
    select_token(&body, realm.as_str())
}

// The most of a token response that is read. A token is a few KiB; this only stops a host
// that streams without end from filling memory.
const TOKEN_BODY_LIMIT: usize = 1 << 20;
// How much of a failed exchange's body the error shows.
const TOKEN_ERROR_SHOWN: usize = 1024;

// Read at most `limit` bytes of the body, and whether there was more.
async fn read_capped(mut res: reqwest::Response, limit: usize) -> Result<(Vec<u8>, bool)> {
    let mut body = Vec::new();
    while let Some(chunk) = res.chunk().await? {
        let room = limit - body.len();
        if chunk.len() > room {
            body.extend_from_slice(&chunk[..room]);
            return Ok((body, true));
        }
        body.extend_from_slice(&chunk);
    }
    Ok((body, false))
}

// The realm the refresh token may be sent to. The registry names it in its challenge, so it
// is untrusted: only https, so the token never crosses the network in the clear. Plain http
// only for a loopback realm of a local registry, which already speaks http (`registry_scheme`)
// and never leaves the host.
fn token_realm(realm: &str, endpoint: &str) -> Result<reqwest::Url> {
    let shown = crate::resolver::escape_for_display;
    let url = reqwest::Url::parse(realm).with_context(|| {
        format!(
            "the auth challenge from {endpoint} names a realm that is not a URL: \"{}\"",
            shown(realm)
        )
    })?;
    let loopback = url.host_str().is_some_and(|h| {
        h.eq_ignore_ascii_case("localhost")
            || h.trim_start_matches('[')
                .trim_end_matches(']')
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    });
    match url.scheme() {
        "https" => Ok(url),
        "http" if loopback && registry_scheme(endpoint) == "http" => Ok(url),
        _ => anyhow::bail!(
            "the auth challenge from {endpoint} names the realm \"{}\", which is not https; \
             scratchsmith sends the identity token only over https",
            shown(realm)
        ),
    }
}

/// Pick the usable token from a token-endpoint response body. A byte-level entry point for
/// fuzzing — the body comes from a third-party token host, so it is untrusted.
pub fn select_token(body: &[u8], realm: &str) -> Result<String> {
    let parsed: TokenResponse = serde_json::from_slice(body)
        .with_context(|| format!("decoding the token response from {realm}"))?;
    // Prefer a non-empty `access_token`, else a non-empty `token` — filter each candidate
    // before the fallback so an empty `access_token` can't mask a usable `token`.
    let non_empty = |t: String| Some(t).filter(|t| !t.is_empty());
    parsed
        .access_token
        .and_then(non_empty)
        .or_else(|| parsed.token.and_then(non_empty))
        .with_context(|| format!("token endpoint {realm} returned no access_token"))
}

// The registry token endpoint answers with `token` and/or the OAuth2-standard `access_token`;
// accept either (Docker Hub uses `token`, most others `access_token`).
#[derive(serde::Deserialize)]
struct TokenResponse {
    #[serde(default)]
    token: Option<String>,
    #[serde(default)]
    access_token: Option<String>,
}

// Pull a quoted parameter out of a `WWW-Authenticate: Bearer realm="…",service="…"` header.
// Substring-scoped so a comma inside a later value (e.g. `scope="…:pull,push"`) can't confuse
// it — we read only up to the closing quote of the requested key.
fn extract_challenge_param(challenge: &str, key: &str) -> Option<String> {
    let needle = format!("{key}=\"");
    let start = challenge.find(&needle)? + needle.len();
    let rest = &challenge[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

// `http` for a localhost registry (matching Docker's insecure-localhost default), `https`
// otherwise — the string form of `registry_protocol`, for the URLs we build by hand.
fn registry_scheme(registry: &str) -> &'static str {
    if is_local_registry(registry) {
        "http"
    } else {
        "https"
    }
}

// How long a connect to a registry or token host may take. oci-client and reqwest set none by
// default, so a host that never answers blocked `--push` and `index` with no output.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

// How long the token host may go quiet while it answers. Only the token exchange gets a read
// timeout: reqwest counts upload time against it, and oci-client can send a whole layer in one
// request, so on the registry client it would cut off a slow upload.
const TOKEN_READ_TIMEOUT: Duration = Duration::from_secs(60);

// The plain client for the identity-token exchange, with its limits.
// It follows no redirect: one would resend the refresh token to whatever address it names.
fn token_client(connect: Duration, read: Duration) -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .connect_timeout(connect)
        .read_timeout(read)
        .redirect(reqwest::redirect::Policy::none())
}

/// The two HTTP clients a registry command uses: oci-client for the registry protocol, and a
/// plain one for the identity-token exchange that oci-client cannot do.
struct Clients {
    registry: Client,
    http: reqwest::Client,
}

/// Build both clients for `endpoint`, reporting a failure instead of dying on it.
///
/// NOT `Client::new`. That swallows the builder error, logs it through `log` (which this CLI
/// installs no subscriber for, so it goes nowhere), and falls back to `Client::default()` —
/// whose `reqwest::Client::default()` PANICS on the very failure it just caught. On a host with
/// no CA certificate store, which is most minimal containers and every `FROM scratch` image,
/// `scratchsmith index` died with SIGSEGV and no message. `try_from` is the same construction
/// with the error handed back.
///
/// The system trust store comes first, so a corporate CA and `SSL_CERT_FILE` keep working and
/// a host that has a store sees no change. Only when that store cannot be used do the clients
/// fall back to the Mozilla roots compiled into the binary.
///
/// Call this BEFORE the tokio runtime starts: the fallback changes the process environment,
/// which is only sound while this is the one thread.
fn registry_clients(endpoint: &str) -> Result<Clients> {
    let build = || -> Result<Clients> {
        Ok(Clients {
            registry: Client::try_from(ClientConfig {
                protocol: registry_protocol(endpoint),
                connect_timeout: Some(CONNECT_TIMEOUT),
                ..Default::default()
            })?,
            http: token_client(CONNECT_TIMEOUT, TOKEN_READ_TIMEOUT).build()?,
        })
    };
    let system = match build() {
        Ok(clients) => return Ok(clients),
        Err(e) => e,
    };

    // Fail closed when the user chose the store. SSL_CERT_FILE or SSL_CERT_DIR is an explicit
    // trust decision, often a narrower one (a single corporate CA). Widening it to Mozilla's
    // whole set because the path is wrong or the file is empty would be the opposite of what
    // they asked for, so the bundled roots are only for a host that configured nothing.
    if let Some(var) = explicit_trust_store(|v| std::env::var_os(v).is_some()) {
        return Err(system).with_context(|| {
            format!(
                "building the registry client for {endpoint}; {var} is set, so scratchsmith \
                 does not fall back to its bundled CA roots. Fix what it points at, or unset it"
            )
        });
    }

    // WORKAROUND for oci-client 0.18.0, to drop once upstream is fixed (no issue is filed
    // yet). The direct route is `ClientConfig::tls_certs_only`, and it cannot work: after
    // `TryFrom<ClientConfig>` builds that client, its `..Default::default()` builds a second,
    // throwaway `reqwest::Client::default()`, which panics on an empty system store. The one
    // input that default client obeys is `SSL_CERT_FILE`, so the bundled roots go to a PEM
    // file and the variable points at it while both clients are built. The roots are read
    // at build time, so the variable is restored and the file closed right after.
    //
    // The file is a memfd, reached through /proc: the host this path exists for is a FROM
    // scratch container, which has no /tmp and may be read-only.
    let memfd = rustix::fs::memfd_create("scratchsmith-ca-roots", rustix::fs::MemfdFlags::CLOEXEC)
        .context("creating an in-memory file for the bundled CA roots")?;
    let mut pem = std::fs::File::from(memfd);
    std::io::Write::write_all(&mut pem, bundled_roots_pem().as_bytes())
        .context("writing the bundled CA roots")?;
    let pem_path = std::path::PathBuf::from(format!(
        "/proc/self/fd/{}",
        std::os::fd::AsRawFd::as_raw_fd(&pem)
    ));
    let clients = {
        let _restore = EnvOverride::set("SSL_CERT_FILE", &pem_path);
        build()
    }
    .with_context(|| {
        format!(
            "building the registry client for {endpoint} with the bundled CA roots, after the \
             system trust store failed ({system:#}). The bundled roots are read through /proc, \
             so they need it mounted; otherwise install ca-certificates or set SSL_CERT_FILE"
        )
    })?;
    // A supply-chain tool must not change whom it trusts in silence.
    eprintln!(
        "warning: the system CA trust store could not be used ({system:#}), so TLS uses the \
         Mozilla root certificates bundled with scratchsmith. Set SSL_CERT_FILE to use your own."
    );
    Ok(clients)
}

// The variable that names the user's own trust store, if one is set. `is_set` is a parameter
// so the rule is testable without touching the process environment.
fn explicit_trust_store(is_set: impl Fn(&str) -> bool) -> Option<&'static str> {
    ["SSL_CERT_FILE", "SSL_CERT_DIR"]
        .into_iter()
        .find(|var| is_set(var))
}

// Mozilla's root set as one PEM bundle, the format `SSL_CERT_FILE` takes.
fn bundled_roots_pem() -> String {
    use base64::Engine;
    let mut pem = String::new();
    for der in webpki_root_certs::TLS_SERVER_ROOT_CERTS {
        pem.push_str("-----BEGIN CERTIFICATE-----\n");
        let b64 = base64::engine::general_purpose::STANDARD.encode(der);
        for line in b64.as_bytes().chunks(64) {
            // Base64 output is ASCII, so each 64-byte chunk is valid UTF-8.
            pem.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
            pem.push('\n');
        }
        pem.push_str("-----END CERTIFICATE-----\n");
    }
    pem
}

// Sets one environment variable and puts the old state back on drop, whether that was a
// value or no variable at all.
struct EnvOverride {
    key: &'static str,
    old: Option<std::ffi::OsString>,
}

impl EnvOverride {
    fn set(key: &'static str, value: &std::path::Path) -> Self {
        let old = std::env::var_os(key);
        std::env::set_var(key, value);
        EnvOverride { key, old }
    }
}

impl Drop for EnvOverride {
    fn drop(&mut self) {
        match &self.old {
            Some(value) => std::env::set_var(self.key, value),
            None => std::env::remove_var(self.key),
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

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
    fn registry_scheme_and_protocol_track_localhost() {
        assert_eq!(registry_scheme("ghcr.io"), "https");
        assert_eq!(registry_scheme("localhost:5000"), "http");
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
    fn a_missing_credential_is_anonymous_but_a_broken_helper_is_an_error() {
        use docker_credential::CredentialRetrievalError as E;
        use docker_credential::DockerCredential::UsernamePassword;

        // Found: passed through.
        assert!(matches!(
            credential_or_anonymous(Ok(UsernamePassword("u".into(), "p".into())), "ghcr.io"),
            Ok(Some(UsernamePassword(_, _)))
        ));

        // Nothing to find: genuinely anonymous, which is a supported way to push to a public
        // or local registry. ConfigReadError is in this set deliberately -- the crate returns
        // it when the config file cannot be OPENED, i.e. the common "no Docker config here"
        // case. Treating it as a failure broke `index_assembles_a_pushed_image_into_an_index`
        // against a local registry, which is the regression this row now pins.
        for nothing in [
            E::NoCredentialConfigured,
            E::ConfigNotFound,
            E::ConfigReadError,
        ] {
            assert!(
                matches!(credential_or_anonymous(Err(nothing), "ghcr.io"), Ok(None)),
                "an absent credential must stay anonymous"
            );
        }

        // A helper reporting "no entry for this server" does so by EXITING NON-ZERO with the
        // standard message, so this HelperFailure is the anonymous case. Without it, no
        // machine carrying a `credsStore` could push anonymously, because `creds_store` is
        // consulted for every registry. Both streams, since third-party helpers differ.
        for stream in ["stdout", "stderr"] {
            let (stdout, stderr) = match stream {
                "stdout" => (
                    "credentials not found in native keychain\n".to_string(),
                    String::new(),
                ),
                _ => (
                    String::new(),
                    "  credentials not found in native keychain  ".to_string(),
                ),
            };
            assert!(
                matches!(
                    credential_or_anonymous(
                        Err(E::HelperFailure {
                            helper: "docker-credential-desktop".into(),
                            stdout,
                            stderr,
                        }),
                        "localhost:5000",
                    ),
                    Ok(None)
                ),
                "a helper reporting not-found on {stream} must stay anonymous"
            );
        }

        // Everything else is a FAILURE, and used to be swallowed into an anonymous push.
        // Named individually rather than with a catch-all, so a new variant added upstream
        // has to be classified here by hand instead of defaulting into silence.
        for broken in [
            E::HelperCommunicationError,
            E::MalformedHelperResponse,
            E::HelperFailure {
                helper: "docker-credential-x".into(),
                stdout: String::new(),
                stderr: "boom".into(),
            },
            E::CredentialDecodingError,
            E::CredentialMismatchError,
        ] {
            let err = credential_or_anonymous(Err(broken), "ghcr.io")
                .expect_err("a failed credential lookup must not become an anonymous push");
            let msg = format!("{err:#}");
            assert!(
                msg.contains("ghcr.io"),
                "the error must name the registry, got: {msg}"
            );
        }
    }

    #[test]
    fn a_docker_hub_lookup_asks_for_the_docker_login_key_first() {
        use docker_credential::CredentialRetrievalError as E;
        use docker_credential::DockerCredential::UsernamePassword;
        use std::cell::RefCell;
        let not_found = || E::HelperFailure {
            helper: "docker-credential-pass".into(),
            stdout: "credentials not found in native keychain".into(),
            stderr: String::new(),
        };
        // A fake store that holds one login, under `stored`.
        let run = |registry: &str, stored: &str| {
            let asked = RefCell::new(Vec::new());
            let got = lookup_credential_with(registry, |server| {
                asked.borrow_mut().push(server.to_string());
                if server == stored {
                    Ok(UsernamePassword("u".into(), "p".into()))
                } else {
                    Err(not_found())
                }
            });
            (
                got.map(|c| c.is_some()).map_err(|e| format!("{e:#}")),
                asked.into_inner(),
            )
        };

        // The login `docker login` wrote is found, and docker.io is never asked.
        for hub in ["docker.io", "index.docker.io", "registry-1.docker.io"] {
            assert_eq!(
                run(hub, DOCKER_HUB_LOGIN_KEY),
                (Ok(true), vec![DOCKER_HUB_LOGIN_KEY.to_string()]),
                "{hub}"
            );
        }
        // A login kept under docker.io is still found, on the second ask.
        assert_eq!(
            run("docker.io", "docker.io"),
            (
                Ok(true),
                vec![DOCKER_HUB_LOGIN_KEY.to_string(), "docker.io".to_string()]
            )
        );
        // No login anywhere stays anonymous.
        assert_eq!(run("docker.io", "nowhere").0, Ok(false));
        // Any other registry is asked by its own name, once.
        assert_eq!(
            run("ghcr.io", "ghcr.io"),
            (Ok(true), vec!["ghcr.io".to_string()])
        );

        // A broken helper on the first ask fails the lookup; docker.io is not tried after it.
        let asked = RefCell::new(Vec::new());
        let err = lookup_credential_with("docker.io", |server| {
            asked.borrow_mut().push(server.to_string());
            Err(E::HelperCommunicationError)
        })
        .unwrap_err();
        assert!(format!("{err:#}").contains("docker.io"), "{err:#}");
        assert_eq!(asked.into_inner(), vec![DOCKER_HUB_LOGIN_KEY.to_string()]);
    }

    #[test]
    fn a_docker_hub_lookup_still_reads_auths_under_either_key() {
        // No helper: the `auths` map answers. Docker CLI writes the URL key, other tools write
        // docker.io; both must be found for a Hub reference.
        for key in [DOCKER_HUB_LOGIN_KEY, "docker.io", "index.docker.io"] {
            let config = format!(r#"{{"auths":{{"{key}":{{"auth":"dTpw"}}}}}}"#);
            let got = lookup_credential_with("docker.io", |server| {
                docker_credential::get_credential_from_reader(config.as_bytes(), server)
            })
            .unwrap();
            assert!(
                matches!(got, Some(docker_credential::DockerCredential::UsernamePassword(ref u, ref p)) if u == "u" && p == "p"),
                "{key}: {got:?}"
            );
        }
    }

    #[test]
    fn plan_credential_maps_each_variant() {
        use docker_credential::DockerCredential::{IdentityToken, UsernamePassword};
        assert!(matches!(
            plan_credential(Some(UsernamePassword("u".into(), "p".into()))),
            CredentialPlan::Ready(RegistryAuth::Basic(_, _))
        ));
        assert!(matches!(
            plan_credential(Some(IdentityToken("t".into()))),
            CredentialPlan::IdentityToken(t) if t == "t"
        ));
        assert!(matches!(
            plan_credential(None),
            CredentialPlan::Ready(RegistryAuth::Anonymous)
        ));
    }

    // A digest as `manifest_digest` writes it, and another one a registry might name instead.
    const PUSHED: &str = "sha256:2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae";
    const EVIL: &str = "sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";

    #[test]
    fn digest_ref_from_builds_a_by_digest_reference() {
        let r: Reference = "ghcr.io/you/app:latest".parse().unwrap();
        let at = |url: &str| match digest_ref_from(&r, url, PUSHED) {
            PushedDigest::Confirmed(reference) => Some(reference),
            PushedDigest::Unreported(reference) => {
                assert_eq!(reference, format!("ghcr.io/you/app@{PUSHED}"));
                None
            }
            PushedDigest::Mismatch(err) => panic!("{err:#}"),
        };
        let want = Some(format!("ghcr.io/you/app@{PUSHED}"));
        assert_eq!(
            at(&format!("https://ghcr.io/v2/you/app/manifests/{PUSHED}")),
            want
        );
        // A namespace/query suffix on the URL is trimmed.
        assert_eq!(
            at(&format!(
                "https://ghcr.io/v2/you/app/manifests/{PUSHED}?ns=ghcr.io"
            )),
            want
        );
        // A URL without a sha256 digest is unreported (a plain push must not fail on it).
        assert_eq!(at("https://ghcr.io/v2/you/app/manifests/latest"), None);
        assert_eq!(at("https://ghcr.io/v2/you/app/manifests/sha512:abc"), None);
    }

    #[test]
    fn digest_ref_from_refuses_a_digest_other_than_the_one_pushed() {
        let r: Reference = "ghcr.io/you/app:latest".parse().unwrap();
        let upper = PUSHED.to_uppercase().replace("SHA256", "sha256");
        let truncated = &PUSHED[..PUSHED.len() - 1];
        let extra_path = format!("{PUSHED}/x");
        for tail in [EVIL, &upper, truncated, &extra_path, "sha256:"] {
            let err = digest_ref_from(
                &r,
                &format!("https://ghcr.io/v2/you/app/manifests/{tail}"),
                PUSHED,
            )
            .for_signing()
            .expect_err("only the pushed digest may be signed");
            let msg = format!("{err:#}");
            assert!(
                msg.contains("cannot sign") && msg.contains(tail) && msg.contains(PUSHED),
                "got: {msg}"
            );
        }
        // The registry's text is escaped, so it cannot forge a line of output.
        let PushedDigest::Mismatch(err) = digest_ref_from(
            &r,
            "https://ghcr.io/v2/you/app/manifests/sha256:\nforged",
            PUSHED,
        ) else {
            panic!("a forged digest is a mismatch, not an absent one");
        };
        assert!(!format!("{err:#}").contains('\n'), "got: {err:#}");
    }

    #[test]
    fn an_unreported_digest_signs_the_manifest_that_was_put() {
        let ours = format!("ghcr.io/you/app@{PUSHED}");
        let got = PushedDigest::Unreported(ours.clone()).for_signing();
        assert_eq!(got.unwrap(), ours);
    }

    // How the mock registry answers a manifest PUT.
    #[derive(Clone, Copy)]
    enum ManifestAnswer {
        // `Location` names the digest of the bytes it received.
        Honest,
        // `Location` names another digest: the registry picks what would be signed.
        Names(&'static str),
        // No `Location` (ECR); oci-client then derives the URL from its own hash of the body.
        NoLocation,
        // `Location` names the tag, not a digest.
        Tag,
    }

    fn sha256_of(bytes: &[u8]) -> String {
        format!("sha256:{}", image::hex(Sha256::digest(bytes)))
    }

    // A mock registry for repository `app`: blob uploads succeed, `extra` mocks are mounted,
    // and a manifest PUT is answered per `answer`.
    fn mock_registry(answer: ManifestAnswer, extra: Vec<Mock>) -> MockServer {
        block_on(async {
            let server = MockServer::start().await;
            let upload =
                |status| ResponseTemplate::new(status).insert_header("Location", "/upload");
            Mock::given(method("POST"))
                .and(path("/v2/app/blobs/uploads/"))
                .respond_with(upload(202))
                .mount(&server)
                .await;
            Mock::given(method("PATCH"))
                .and(path("/upload"))
                .respond_with(upload(202))
                .mount(&server)
                .await;
            Mock::given(method("PUT"))
                .and(path("/upload"))
                .respond_with(upload(201))
                .mount(&server)
                .await;
            Mock::given(method("PUT"))
                .and(wiremock::matchers::path_regex("^/v2/app/manifests/"))
                .respond_with(move |req: &wiremock::Request| {
                    let res = ResponseTemplate::new(201);
                    let digest = match answer {
                        ManifestAnswer::Honest => sha256_of(&req.body),
                        ManifestAnswer::Names(d) => d.to_string(),
                        ManifestAnswer::NoLocation => return res,
                        ManifestAnswer::Tag => {
                            let tag = req.url.path().rsplit('/').next().unwrap_or_default();
                            tag.to_string()
                        }
                    };
                    res.insert_header("Location", format!("/v2/app/manifests/{digest}").as_str())
                })
                .mount(&server)
                .await;
            for m in extra {
                m.mount(&server).await;
            }
            server
        })
    }

    // The digest of the one manifest the mock registry received: the image actually pushed.
    fn received_manifest_digest(server: &MockServer) -> String {
        let requests = block_on(server.received_requests()).expect("recording is on");
        let puts: Vec<_> = requests
            .iter()
            .filter(|r| {
                r.method.as_str() == "PUT" && r.url.path().starts_with("/v2/app/manifests/")
            })
            .collect();
        assert_eq!(puts.len(), 1, "one manifest PUT");
        sha256_of(&puts[0].body)
    }

    #[test]
    fn a_push_signs_the_manifest_it_put_never_a_digest_the_registry_names() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("root");
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("app"), b"app").unwrap();
        let staged = StagedTree {
            root,
            entrypoint: "/app".into(),
            loader: None,
        };
        let push = |answer| {
            let server = mock_registry(answer, Vec::new());
            let host = server.address().to_string();
            let got = push_to_registry(
                &staged,
                &format!("{host}/app:1"),
                &ImageConfig::default(),
                false,
            )
            .expect("the push itself succeeds whatever digest the registry reports")
            .digest;
            (got, host, received_manifest_digest(&server))
        };
        // A tag-based `Location` names no digest, so the bytes put are signed (TASK-232).
        for answer in [
            ManifestAnswer::Honest,
            ManifestAnswer::NoLocation,
            ManifestAnswer::Tag,
        ] {
            let (got, host, put) = push(answer);
            if matches!(answer, ManifestAnswer::Tag) {
                assert!(matches!(got, PushedDigest::Unreported(_)), "{got:?}");
            }
            assert_eq!(got.for_signing().unwrap(), format!("{host}/app@{put}"));
        }
        let (got, _, put) = push(ManifestAnswer::Names(EVIL));
        let msg = format!(
            "{:#}",
            got.for_signing()
                .expect_err("a digest the registry chose is not signed")
        );
        assert!(msg.contains(EVIL) && msg.contains(&put), "got: {msg}");
    }

    #[test]
    fn an_index_push_signs_the_index_it_put_never_a_digest_the_registry_names() {
        let config = br#"{"architecture":"amd64","os":"linux"}"#;
        let config_digest = sha256_of(config);
        let child = serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 2,
            "mediaType": crate::image::OCI_MANIFEST,
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": config_digest,
                "size": config.len(),
            },
            "layers": [],
        }))
        .unwrap();
        let push = |answer| {
            let server = mock_registry(
                answer,
                vec![
                    Mock::given(method("GET"))
                        .and(path("/v2/app/manifests/amd64"))
                        .respond_with(
                            ResponseTemplate::new(200)
                                .set_body_raw(child.clone(), crate::image::OCI_MANIFEST),
                        ),
                    Mock::given(method("GET"))
                        .and(path(format!("/v2/app/blobs/{config_digest}")))
                        .respond_with(ResponseTemplate::new(200).set_body_bytes(config.to_vec())),
                ],
            );
            let host = server.address().to_string();
            let outcome = push_index(&format!("{host}/app:multi"), &[format!("{host}/app:amd64")])
                .expect("the index push itself succeeds whatever digest the registry reports");
            (outcome.digest_ref, host, received_manifest_digest(&server))
        };
        // A tag-based `Location` names no digest, so the bytes put are signed (TASK-232).
        for answer in [
            ManifestAnswer::Honest,
            ManifestAnswer::NoLocation,
            ManifestAnswer::Tag,
        ] {
            let (got, host, put) = push(answer);
            if matches!(answer, ManifestAnswer::Tag) {
                assert!(matches!(got, PushedDigest::Unreported(_)), "{got:?}");
            }
            assert_eq!(got.for_signing().unwrap(), format!("{host}/app@{put}"));
        }
        let (got, _, put) = push(ManifestAnswer::Names(EVIL));
        let msg = format!(
            "{:#}",
            got.for_signing()
                .expect_err("a digest the registry chose is not signed")
        );
        assert!(msg.contains(EVIL) && msg.contains(&put), "got: {msg}");
    }

    #[test]
    fn extract_challenge_param_reads_realm_and_service_past_commas() {
        let c = r#"Bearer realm="https://ghcr.io/token",service="ghcr.io",scope="repository:o/i:pull,push""#;
        assert_eq!(
            extract_challenge_param(c, "realm").as_deref(),
            Some("https://ghcr.io/token")
        );
        assert_eq!(
            extract_challenge_param(c, "service").as_deref(),
            Some("ghcr.io")
        );
        // scope's embedded comma must not truncate the value.
        assert_eq!(
            extract_challenge_param(c, "scope").as_deref(),
            Some("repository:o/i:pull,push")
        );
        assert_eq!(extract_challenge_param(c, "missing"), None);
    }

    fn block_on<F: std::future::Future>(fut: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(fut)
    }

    fn bearer(auth: RegistryAuth) -> String {
        match auth {
            RegistryAuth::Bearer(t) => t,
            _ => panic!("expected a Bearer token"),
        }
    }

    // Drive the full identity-token path (`resolve_auth` -> `exchange_identity_token`) against a
    // mock registry: `/v2/` hands back the given Bearer challenge (realm pointed at the same
    // server), and the realm answers with `token_response`. `challenge` is `None` to omit the
    // `WWW-Authenticate` header entirely.
    fn resolve_via_mock(
        challenge: Option<&str>,
        token_response: ResponseTemplate,
        repository: &str,
    ) -> Result<RegistryAuth> {
        block_on(async {
            let server = MockServer::start().await;
            let realm = format!("{}/token", server.uri());
            let mut v2 = ResponseTemplate::new(401);
            if let Some(c) = challenge {
                v2 = v2.insert_header("WWW-Authenticate", c.replace("{realm}", &realm).as_str());
            }
            Mock::given(method("GET"))
                .and(path("/v2/"))
                .respond_with(v2)
                .mount(&server)
                .await;
            Mock::given(method("POST"))
                .and(path("/token"))
                .respond_with(token_response)
                .mount(&server)
                .await;

            let endpoint = server.uri().strip_prefix("http://").unwrap().to_string();
            resolve_auth(
                CredentialPlan::IdentityToken("refresh-xyz".into()),
                &endpoint,
                repository,
                &test_token_client(),
            )
            .await
        })
    }

    // The client the commands build, with short limits.
    fn test_token_client() -> reqwest::Client {
        token_client(Duration::from_secs(5), Duration::from_secs(5))
            .build()
            .unwrap()
    }

    #[test]
    fn the_token_realm_must_be_https_except_on_loopback_for_a_local_registry() {
        for ok in [
            ("https://auth.docker.io/token", "registry-1.docker.io"),
            ("https://ghcr.io/token", "ghcr.io"),
            ("https://127.0.0.1/token", "localhost:5000"),
            ("http://127.0.0.1:5001/token", "localhost:5000"),
            ("http://localhost:5001/token", "127.0.0.1:5000"),
            ("http://[::1]:5001/token", "[::1]:5000"),
        ] {
            assert!(token_realm(ok.0, ok.1).is_ok(), "{ok:?}");
        }
        for (realm, endpoint) in [
            // Plain http to a real host, from a remote or a local registry.
            ("http://auth.example.com/token", "registry.example.com"),
            ("http://auth.example.com/token", "localhost:5000"),
            // Loopback http is only for a registry that is itself local.
            ("http://127.0.0.1:5001/token", "ghcr.io"),
            ("ftp://ghcr.io/token", "ghcr.io"),
            ("not a url", "ghcr.io"),
            ("/token", "ghcr.io"),
        ] {
            let err = token_realm(realm, endpoint).expect_err(realm);
            assert!(format!("{err:#}").contains(endpoint), "{err:#}");
        }
        // The realm is the registry's text: escaped in the error.
        let err = format!(
            "{:#}",
            token_realm("http://a.example/\n\x1b[2J", "ghcr.io").unwrap_err()
        );
        assert!(!err.contains('\n') && !err.contains('\x1b'), "{err:?}");
    }

    #[test]
    fn an_http_realm_never_receives_the_refresh_token() {
        let err = block_on(async {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/v2/"))
                .respond_with(ResponseTemplate::new(401).insert_header(
                    "WWW-Authenticate",
                    r#"Bearer realm="http://auth.example.com/token",service="mock""#,
                ))
                .mount(&server)
                .await;
            let endpoint = server.uri().strip_prefix("http://").unwrap().to_string();
            resolve_auth(
                CredentialPlan::IdentityToken("refresh-xyz".into()),
                &endpoint,
                "owner/img",
                &test_token_client(),
            )
            .await
        })
        .expect_err("an http realm must be refused");
        assert!(format!("{err:#}").contains("not https"), "{err:#}");
    }

    // A mock whose token endpoint redirects to `/elsewhere`, which counts its hits.
    fn exchange_against_a_redirect(http: reqwest::Client) -> (Result<RegistryAuth>, usize) {
        block_on(async {
            let server = MockServer::start().await;
            let realm = format!("{}/token", server.uri());
            Mock::given(method("GET"))
                .and(path("/v2/"))
                .respond_with(ResponseTemplate::new(401).insert_header(
                    "WWW-Authenticate",
                    format!(r#"Bearer realm="{realm}",service="mock""#).as_str(),
                ))
                .mount(&server)
                .await;
            Mock::given(method("POST"))
                .and(path("/token"))
                .respond_with(
                    ResponseTemplate::new(307)
                        .insert_header("Location", format!("{}/elsewhere", server.uri()).as_str()),
                )
                .mount(&server)
                .await;
            Mock::given(method("POST"))
                .and(path("/elsewhere"))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_body_json(serde_json::json!({ "access_token": "stolen" })),
                )
                .mount(&server)
                .await;
            let endpoint = server.uri().strip_prefix("http://").unwrap().to_string();
            let got = resolve_auth(
                CredentialPlan::IdentityToken("refresh-xyz".into()),
                &endpoint,
                "owner/img",
                &http,
            )
            .await;
            let hits = server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .filter(|r| r.url.path() == "/elsewhere")
                .count();
            (got, hits)
        })
    }

    #[test]
    fn a_redirected_token_exchange_is_refused_and_not_followed() {
        let (got, hits) = exchange_against_a_redirect(test_token_client());
        let err = got.expect_err("a redirect must be refused");
        assert!(format!("{err:#}").contains("redirect"), "{err:#}");
        assert_eq!(hits, 0, "the refresh token went to the redirect target");
        // A client that follows redirects has resent the body by then; its answer is still
        // not used.
        let (got, _) = exchange_against_a_redirect(reqwest::Client::new());
        assert!(format!("{:#}", got.expect_err("followed")).contains("redirect"));
    }

    #[test]
    fn a_failed_exchange_shows_a_short_escaped_part_of_the_body() {
        let body = format!("bad\n\x1b[2Jforged line{}", "x".repeat(10_000));
        let err = resolve_via_mock(
            Some(r#"Bearer realm="{realm}",service="mock""#),
            ResponseTemplate::new(500).set_body_string(body),
            "owner/img",
        )
        .expect_err("a 500 is a failure");
        let msg = format!("{err:#}");
        assert!(!msg.contains('\n') && !msg.contains('\x1b'), "{msg:?}");
        assert!(msg.contains("bad\\n\\u{1b}[2Jforged line"), "{msg}");
        assert!(msg.ends_with("..."), "{msg}");
        assert!(msg.len() < 2 * TOKEN_ERROR_SHOWN, "{}", msg.len());
    }

    #[test]
    fn an_endless_token_response_is_cut_off() {
        let err = resolve_via_mock(
            Some(r#"Bearer realm="{realm}",service="mock""#),
            ResponseTemplate::new(200).set_body_string("x".repeat(TOKEN_BODY_LIMIT + 1)),
            "owner/img",
        )
        .expect_err("an oversized body is refused");
        assert!(format!("{err:#}").contains("larger than"), "{err:#}");
    }

    #[test]
    fn the_bundled_roots_round_trip_through_pem() {
        // The PEM is what the platform verifier reads back through SSL_CERT_FILE, so every
        // root must survive the encoding, byte for byte.
        let pem = bundled_roots_pem();
        let roots = webpki_root_certs::TLS_SERVER_ROOT_CERTS;
        assert!(
            roots.len() > 50,
            "a real root set, not a stub: {}",
            roots.len()
        );
        assert_eq!(
            pem.matches("-----BEGIN CERTIFICATE-----").count(),
            roots.len()
        );

        use base64::Engine;
        let decoded: Vec<Vec<u8>> = pem
            .split("-----END CERTIFICATE-----\n")
            .filter(|block| !block.is_empty())
            .map(|block| {
                let body: String = block.lines().filter(|l| !l.starts_with("-----")).collect();
                assert!(
                    block.lines().all(|l| l.len() <= 64),
                    "PEM lines are 64 wide"
                );
                base64::engine::general_purpose::STANDARD
                    .decode(body)
                    .unwrap()
            })
            .collect();
        let original: Vec<Vec<u8>> = roots.iter().map(|der| der.to_vec()).collect();
        assert_eq!(decoded, original);
    }

    #[test]
    fn an_explicit_trust_store_is_either_variable() {
        assert_eq!(explicit_trust_store(|_| false), None);
        assert_eq!(
            explicit_trust_store(|v| v == "SSL_CERT_FILE"),
            Some("SSL_CERT_FILE")
        );
        assert_eq!(
            explicit_trust_store(|v| v == "SSL_CERT_DIR"),
            Some("SSL_CERT_DIR")
        );
        assert_eq!(explicit_trust_store(|_| true), Some("SSL_CERT_FILE"));
    }

    #[test]
    fn env_override_puts_back_a_value_and_an_absence() {
        // Names no other test or library reads, so parallel tests cannot collide.
        let set = "SCRATCHSMITH_TEST_ENV_OVERRIDE_SET";
        std::env::set_var(set, "before");
        {
            let _o = EnvOverride::set(set, std::path::Path::new("/during"));
            assert_eq!(std::env::var_os(set).unwrap(), "/during");
        }
        assert_eq!(std::env::var_os(set).unwrap(), "before");
        std::env::remove_var(set);

        let unset = "SCRATCHSMITH_TEST_ENV_OVERRIDE_UNSET";
        {
            let _o = EnvOverride::set(unset, std::path::Path::new("/during"));
            assert!(std::env::var_os(unset).is_some());
        }
        assert!(
            std::env::var_os(unset).is_none(),
            "an absent variable stays absent"
        );
    }

    #[test]
    fn resolve_auth_passes_ready_credentials_through() {
        let auth = block_on(resolve_auth(
            CredentialPlan::Ready(RegistryAuth::Anonymous),
            "ghcr.io",
            "owner/img",
            &reqwest::Client::new(),
        ))
        .expect("a ready credential needs no network");
        assert!(matches!(auth, RegistryAuth::Anonymous));
    }

    #[test]
    fn identity_token_exchange_returns_a_bearer_access_token() {
        let auth = resolve_via_mock(
            Some(r#"Bearer realm="{realm}",service="mock""#),
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({ "access_token": "abc123" })),
            "owner/img",
        )
        .expect("exchange should succeed");
        assert_eq!(bearer(auth), "abc123");
    }

    #[test]
    fn identity_token_exchange_accepts_the_docker_hub_token_field() {
        let auth = resolve_via_mock(
            Some(r#"Bearer realm="{realm}",service="mock""#),
            ResponseTemplate::new(200).set_body_json(serde_json::json!({ "token": "hub-token" })),
            "owner/img",
        )
        .expect("exchange should accept a `token` field");
        assert_eq!(bearer(auth), "hub-token");
    }

    #[test]
    fn identity_token_exchange_prefers_a_nonempty_token_over_an_empty_access_token() {
        let auth = resolve_via_mock(
            Some(r#"Bearer realm="{realm}",service="mock""#),
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({ "access_token": "", "token": "real" })),
            "owner/img",
        )
        .expect("an empty access_token must fall through to a usable token");
        assert_eq!(bearer(auth), "real");
    }

    #[test]
    fn identity_token_exchange_surfaces_a_denied_grant() {
        let err = resolve_via_mock(
            Some(r#"Bearer realm="{realm}",service="mock""#),
            ResponseTemplate::new(403).set_body_json(serde_json::json!({ "details": "denied" })),
            "owner/img",
        )
        .expect_err("a 403 grant must be an error");
        assert!(
            format!("{err:#}").contains("403"),
            "error should name the status"
        );
    }

    #[test]
    fn identity_token_exchange_needs_a_bearer_challenge() {
        let err = resolve_via_mock(
            None, // /v2/ returns 401 with no WWW-Authenticate header
            ResponseTemplate::new(200),
            "owner/img",
        )
        .expect_err("no challenge means we can't find the token realm");
        assert!(format!("{err:#}").contains("no Bearer challenge"));
    }

    #[test]
    fn identity_token_exchange_needs_a_realm_in_the_challenge() {
        let err = resolve_via_mock(
            Some(r#"Bearer service="mock""#), // service but no realm
            ResponseTemplate::new(200),
            "owner/img",
        )
        .expect_err("a challenge without a realm can't be exchanged");
        assert!(format!("{err:#}").contains("no realm"));
    }

    #[test]
    fn identity_token_exchange_rejects_a_response_without_a_token() {
        let err = resolve_via_mock(
            Some(r#"Bearer realm="{realm}",service="mock""#),
            ResponseTemplate::new(200).set_body_json(serde_json::json!({ "expires_in": 300 })),
            "owner/img",
        )
        .expect_err("no access_token means the exchange failed");
        assert!(format!("{err:#}").contains("no access_token"));
    }

    #[test]
    fn identity_token_exchange_reports_an_undecodable_response() {
        let err = resolve_via_mock(
            Some(r#"Bearer realm="{realm}",service="mock""#),
            ResponseTemplate::new(200).set_body_string("this is not json"),
            "owner/img",
        )
        .expect_err("a non-JSON token response is an error");
        assert!(format!("{err:#}").contains("decoding the token response"));
    }

    #[test]
    fn identity_token_exchange_errors_when_the_registry_is_unreachable() {
        // Nothing listens on port 1 -> the /v2/ probe fails before any challenge.
        let err = block_on(resolve_auth(
            CredentialPlan::IdentityToken("refresh-xyz".into()),
            "127.0.0.1:1",
            "owner/img",
            &reqwest::Client::new(),
        ))
        .expect_err("an unreachable registry must error");
        assert!(format!("{err:#}").contains("probing"));
    }

    // TASK-200. A listener whose accept queue is full: the kernel drops the next SYN, so a
    // connect to it never completes. It never accepts, so a connect that did would get no
    // answer either. The returned streams hold the queue full.
    fn stalled_listener() -> (std::net::TcpListener, Vec<std::net::TcpStream>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let mut held = Vec::new();
        for _ in 0..4096 {
            match std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(300)) {
                Ok(stream) => held.push(stream),
                Err(_) => return (listener, held),
            }
        }
        panic!(
            "the accept queue never filled after {} connects",
            held.len()
        );
    }

    #[test]
    fn a_connect_that_never_completes_fails_and_names_the_endpoint() {
        let (listener, _held) = stalled_listener();
        let endpoint = listener.local_addr().unwrap().to_string();
        // A read limit far past the connect limit, so only the connect limit can end it fast.
        let http = token_client(Duration::from_secs(1), Duration::from_secs(120))
            .build()
            .unwrap();
        let started = std::time::Instant::now();
        let err = block_on(exchange_identity_token(&http, &endpoint, "owner/img", "t"))
            .expect_err("a stalled connect must error");
        assert!(
            started.elapsed() < Duration::from_secs(20),
            "{:?}",
            started.elapsed()
        );
        assert!(
            format!("{err:#}").contains(&format!("probing http://{endpoint}/v2/")),
            "{err:#}"
        );
    }

    #[test]
    fn a_token_host_that_stalls_after_connect_fails_within_the_limit() {
        // Accepts, then says nothing.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = listener.local_addr().unwrap().to_string();
        let quiet = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            std::thread::sleep(Duration::from_secs(5));
            drop(stream);
        });
        let http = token_client(Duration::from_secs(30), Duration::from_secs(1))
            .build()
            .unwrap();
        let started = std::time::Instant::now();
        let err = block_on(exchange_identity_token(&http, &endpoint, "owner/img", "t"))
            .expect_err("a stalled token host must error");
        assert!(
            started.elapsed() < Duration::from_secs(4),
            "{:?}",
            started.elapsed()
        );
        assert!(format!("{err:#}").contains("probing"), "{err:#}");
        quiet.join().unwrap();
    }

    // TASK-241: a digest becomes the tag, so oci-client builds the same manifest URL and its
    // no-`Location` fallback cannot panic. Registry and repository stay as written.
    #[test]
    fn a_digest_reference_pushes_its_manifest_under_the_digest_as_the_tag() {
        let digest = format!("sha256:{}", "a".repeat(64));
        for written in [
            format!("ghcr.io/owner/app@{digest}"),
            format!("ghcr.io/owner/app:1.0@{digest}"),
        ] {
            let r: Reference = written.parse().unwrap();
            let target = manifest_target(&r);
            assert_eq!(target.registry(), "ghcr.io", "{written}");
            assert_eq!(target.repository(), "owner/app", "{written}");
            assert_eq!(target.tag(), Some(digest.as_str()), "{written}");
            assert_eq!(target.digest(), None, "{written}");
        }
        let tagged: Reference = "ghcr.io/owner/app:1.0".parse().unwrap();
        assert_eq!(manifest_target(&tagged), tagged);
    }

    #[test]
    fn an_untagged_reference_names_a_repository_and_nothing_else() {
        for ok in ["ghcr.io/owner/app", "localhost:5000/app", "app"] {
            let r = untagged_reference(ok).unwrap_or_else(|e| panic!("{ok}: {e:#}"));
            assert_eq!(r.digest(), None, "{ok}");
        }
        // `:latest` written out is a tag the user asked for, though a bare name parses the same.
        for (tagged, tag) in [
            ("ghcr.io/owner/app:1.0", "1.0"),
            ("app:latest", "latest"),
            ("localhost:5000/app:1", "1"),
        ] {
            let err = format!("{:#}", untagged_reference(tagged).unwrap_err());
            assert!(err.contains(&format!("drop `:{tag}`")), "{tagged}: {err}");
        }
        let digest = format!("ghcr.io/owner/app@sha256:{}", "a".repeat(64));
        let err = format!("{:#}", untagged_reference(&digest).unwrap_err());
        assert!(err.contains("with no digest"), "{err}");
        assert!(untagged_reference("Bad/Ref").is_err());
    }

    #[test]
    fn an_untagged_push_puts_the_manifest_under_its_digest_and_no_tag() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("root");
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("app"), b"app").unwrap();
        let staged = StagedTree {
            root,
            entrypoint: "/app".into(),
            loader: None,
        };
        for answer in [ManifestAnswer::Honest, ManifestAnswer::NoLocation] {
            let server = mock_registry(answer, Vec::new());
            let host = server.address().to_string();
            let got = push_to_registry(
                &staged,
                &format!("{host}/app"),
                &ImageConfig::default(),
                true,
            )
            .expect("an untagged push succeeds");
            let put = received_manifest_digest(&server);
            let requests = block_on(server.received_requests()).unwrap();
            let paths: Vec<_> = requests
                .iter()
                .filter(|r| r.method.as_str() == "PUT" && r.url.path().contains("/manifests/"))
                .map(|r| r.url.path().to_string())
                .collect();
            assert_eq!(paths, [format!("/v2/app/manifests/{put}")]);
            assert_eq!(got.by_digest, format!("{host}/app@{put}"));
            assert_eq!(got.digest.for_signing().unwrap(), got.by_digest);
        }
    }

    #[test]
    fn the_digest_deprecation_names_the_digest_and_the_way_out() {
        let line = digest_push_deprecation("sha256:abc");
        assert!(line.contains("(sha256:abc) is deprecated"), "{line}");
        assert!(line.contains("3.0 will refuse it"), "{line}");
        assert!(line.contains("Push to a tag instead"), "{line}");
    }

    #[test]
    fn the_registry_limits_are_the_ones_the_task_set() {
        assert_eq!(CONNECT_TIMEOUT, Duration::from_secs(30));
        assert_eq!(TOKEN_READ_TIMEOUT, Duration::from_secs(60));
    }

    fn child(arch: &str, os: &str, digest: &str) -> Child {
        child_v(arch, os, None, digest)
    }

    fn child_v(arch: &str, os: &str, variant: Option<&str>, digest: &str) -> Child {
        Child {
            source: format!("reg/app:{arch}"),
            media_type: "application/vnd.oci.image.manifest.v1+json".into(),
            digest: digest.into(),
            size: 100,
            architecture: arch.into(),
            os: os.into(),
            variant: variant.map(str::to_string),
        }
    }

    #[test]
    fn build_index_assembles_children_with_their_platforms() {
        let children = vec![
            child("amd64", "linux", "sha256:aaa"),
            child("arm64", "linux", "sha256:bbb"),
        ];
        let index = build_index(&children).expect("assemble");
        // Round-trip through JSON to pin the wire shape the registry will receive.
        let json = serde_json::to_value(&index).unwrap();
        assert_eq!(json["schemaVersion"], 2);
        assert_eq!(json["mediaType"], "application/vnd.oci.image.index.v1+json");
        let manifests = json["manifests"].as_array().unwrap();
        assert_eq!(manifests.len(), 2);
        assert_eq!(manifests[0]["digest"], "sha256:aaa");
        assert_eq!(manifests[0]["size"], 100);
        assert_eq!(manifests[0]["platform"]["architecture"], "amd64");
        assert_eq!(manifests[0]["platform"]["os"], "linux");
        assert_eq!(manifests[1]["platform"]["architecture"], "arm64");
    }

    #[test]
    fn build_index_rejects_duplicate_platforms() {
        let children = vec![
            child("amd64", "linux", "sha256:aaa"),
            child("amd64", "linux", "sha256:ccc"),
        ];
        let err = build_index(&children).expect_err("duplicate platform must be rejected");
        assert!(
            format!("{err:#}").contains("same platform linux/amd64"),
            "got: {err}"
        );
    }

    #[test]
    fn a_duplicate_platform_error_escapes_the_registry_label() {
        // os/arch come from a config blob the registry serves.
        let evil = "linux\nsigned evil\x1b[2J";
        let children = vec![
            child("amd64", evil, "sha256:aaa"),
            child("amd64", evil, "sha256:ccc"),
        ];
        let err = format!(
            "{:#}",
            build_index(&children).expect_err("duplicate platform")
        );
        assert!(!err.contains('\n') && !err.contains('\x1b'), "{err:?}");
        assert!(err.contains("linux\\nsigned evil"), "{err}");
    }

    #[test]
    fn build_index_keeps_an_unknown_architecture() {
        // An unmapped arch must survive as-is (oci-client stores it as Arch::Other), not
        // be dropped or rejected — the whole point of stamping the real host arch upstream.
        let index = build_index(&[child("riscv64", "linux", "sha256:ddd")]).expect("assemble");
        let json = serde_json::to_value(&index).unwrap();
        assert_eq!(json["manifests"][0]["platform"]["architecture"], "riscv64");
    }

    #[test]
    fn build_index_carries_the_variant_and_treats_variants_as_distinct_platforms() {
        // arm/v7 and arm/v6 are different platforms — both must be kept, each with its
        // variant in the descriptor, not collapsed as a duplicate.
        let children = vec![
            child_v("arm", "linux", Some("v7"), "sha256:a7"),
            child_v("arm", "linux", Some("v6"), "sha256:a6"),
        ];
        let index = build_index(&children).expect("distinct variants must both be kept");
        let json = serde_json::to_value(&index).unwrap();
        assert_eq!(json["manifests"].as_array().unwrap().len(), 2);
        assert_eq!(json["manifests"][0]["platform"]["variant"], "v7");
        assert_eq!(json["manifests"][1]["platform"]["variant"], "v6");
        // No variant key when the config declares none (amd64), rather than a null.
        let amd = build_index(&[child("amd64", "linux", "sha256:aaa")]).unwrap();
        let amd = serde_json::to_value(&amd).unwrap();
        assert!(amd["manifests"][0]["platform"].get("variant").is_none());
    }

    #[test]
    fn build_index_rejects_a_duplicate_variant_and_names_it() {
        // Same os/arch/variant is a duplicate; the message renders the variant via
        // platform_label's Some(variant) arm (os/arch/variant).
        let children = vec![
            child_v("arm", "linux", Some("v7"), "sha256:a"),
            child_v("arm", "linux", Some("v7"), "sha256:b"),
        ];
        let err = build_index(&children).expect_err("same os/arch/variant must be rejected");
        assert!(
            format!("{err:#}").contains("same platform linux/arm/v7"),
            "got: {err}"
        );
    }

    #[test]
    fn push_index_rejects_a_cross_repository_source() {
        // A child in a sibling repo can't be referenced by an index in another repo. This
        // is caught synchronously, before any network call — so no registry is contacted.
        let err = push_index(
            "reg.example.com/you/app:1.0",
            &["reg.example.com/you/other:1.0-amd64".into()],
        )
        .expect_err("a cross-repository source must be rejected");
        assert!(
            format!("{err:#}").contains("target's repository"),
            "got: {err}"
        );
    }

    #[test]
    fn push_index_rejects_an_empty_source_list() {
        let err = push_index("reg.example.com/you/app:1.0", &[])
            .expect_err("an empty source list must be rejected");
        assert!(
            format!("{err:#}").contains("no source images"),
            "got: {err}"
        );
    }

    #[test]
    fn multi_arch_media_types_are_recognized() {
        assert!(is_multi_arch_media_type(
            "application/vnd.oci.image.index.v1+json"
        ));
        assert!(is_multi_arch_media_type(
            "application/vnd.docker.distribution.manifest.list.v2+json"
        ));
        assert!(!is_multi_arch_media_type(
            "application/vnd.oci.image.manifest.v1+json"
        ));
        assert!(!is_multi_arch_media_type(
            "application/vnd.docker.distribution.manifest.v2+json"
        ));
    }

    #[test]
    fn manifest_kind_reads_each_accepted_media_type() {
        for (media_type, kind) in [
            (crate::image::OCI_MANIFEST, ManifestKind::Image),
            (
                "application/vnd.docker.distribution.manifest.v2+json",
                ManifestKind::Image,
            ),
            (crate::image::OCI_INDEX, ManifestKind::Index),
            (
                "application/vnd.docker.distribution.manifest.list.v2+json",
                ManifestKind::Index,
            ),
        ] {
            assert!(CHILD_MANIFEST_TYPES.contains(&media_type));
            let raw = format!(r#"{{"schemaVersion":2,"mediaType":"{media_type}"}}"#);
            assert_eq!(manifest_kind(raw.as_bytes()).unwrap(), kind, "{media_type}");
        }
    }

    #[test]
    fn manifest_kind_without_a_media_type_looks_for_a_manifests_array() {
        // The OCI spec makes `mediaType` optional, so an index may carry none.
        let index = br#"{"schemaVersion":2,"manifests":[]}"#;
        assert_eq!(manifest_kind(index).unwrap(), ManifestKind::Index);
        let image = br#"{"schemaVersion":2,"config":{"digest":"sha256:a"},"layers":[]}"#;
        assert_eq!(manifest_kind(image).unwrap(), ManifestKind::Image);
        // `manifests` that is not an array does not make an index.
        let odd = br#"{"schemaVersion":2,"manifests":{}}"#;
        assert_eq!(manifest_kind(odd).unwrap(), ManifestKind::Image);
    }

    #[test]
    fn manifest_kind_errors_on_bytes_that_are_not_a_json_object() {
        assert!(manifest_kind(b"not json").is_err());
        assert!(manifest_kind(b"[1,2]").is_err());
    }

    #[test]
    fn parse_child_manifest_reads_media_type_and_config_digest() {
        let raw = br#"{"mediaType":"application/vnd.oci.image.manifest.v1+json",
            "config":{"digest":"sha256:abc"}}"#;
        let (media_type, digest) = parse_child_manifest(raw, "src").unwrap();
        assert_eq!(media_type, "application/vnd.oci.image.manifest.v1+json");
        assert_eq!(digest, "sha256:abc");
    }

    #[test]
    fn parse_child_manifest_defaults_the_media_type_when_absent() {
        // No mediaType: fall back to the OCI manifest type rather than fail.
        let (media_type, digest) =
            parse_child_manifest(br#"{"config":{"digest":"sha256:d"}}"#, "src").unwrap();
        assert_eq!(media_type, "application/vnd.oci.image.manifest.v1+json");
        assert_eq!(digest, "sha256:d");
    }

    #[test]
    fn parse_child_manifest_rejects_a_multi_arch_index() {
        let raw = br#"{"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[]}"#;
        let err = parse_child_manifest(raw, "src").unwrap_err().to_string();
        assert!(err.contains("multi-arch index"), "{err}");
    }

    #[test]
    fn the_multi_arch_rejection_escapes_the_media_type() {
        let raw = br#"{"mediaType":"application/vnd.oci.image.index.v1+json\nerror: forged\u001b[2J","manifests":[]}"#;
        let err = parse_child_manifest(raw, "src").unwrap_err().to_string();
        assert!(!err.contains('\n') && !err.contains('\x1b'), "{err:?}");
        assert!(err.contains("json\\nerror: forged"), "{err}");
    }

    #[test]
    fn parse_child_manifest_errors_without_a_config_digest() {
        let err = parse_child_manifest(br#"{"config":{}}"#, "src")
            .unwrap_err()
            .to_string();
        assert!(err.contains("no config.digest"), "{err}");
    }

    #[test]
    fn parse_child_manifest_errors_on_non_json() {
        assert!(parse_child_manifest(b"not json", "src").is_err());
    }

    #[test]
    fn parse_child_config_reads_architecture_os_and_variant() {
        let raw = br#"{"architecture":"arm64","os":"linux","variant":"v8"}"#;
        let (arch, os, variant) = parse_child_config(raw, "src").unwrap();
        assert_eq!(arch, "arm64");
        assert_eq!(os, "linux");
        assert_eq!(variant.as_deref(), Some("v8"));
    }

    #[test]
    fn parse_child_config_leaves_variant_none_when_absent() {
        let (arch, os, variant) =
            parse_child_config(br#"{"architecture":"amd64","os":"linux"}"#, "src").unwrap();
        assert_eq!(arch, "amd64");
        assert_eq!(os, "linux");
        assert_eq!(variant, None);
    }

    #[test]
    fn parse_child_config_errors_without_architecture() {
        let err = parse_child_config(br#"{"os":"linux"}"#, "src")
            .unwrap_err()
            .to_string();
        assert!(err.contains("no architecture"), "{err}");
    }

    #[test]
    fn parse_child_config_errors_without_os() {
        // A missing os must fail loud, never silently stamp linux on a foreign image.
        let err = parse_child_config(br#"{"architecture":"amd64"}"#, "src")
            .unwrap_err()
            .to_string();
        assert!(err.contains("no os"), "{err}");
    }
}
