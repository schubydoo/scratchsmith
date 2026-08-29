//! Daemonless registry push via oci-client: blobs before manifest, auth from the Docker
//! config. Username/password creds ride oci-client's own token exchange; an identity-token
//! credential is exchanged here for a bearer access token (oci-client can't do that grant).
//! See Task 5.2.

use crate::image::{self, ImageConfig};
use crate::stager::StagedTree;
use anyhow::{bail, Context, Result};
use oci_client::client::{ClientConfig, ClientProtocol, Config as OciConfig, ImageLayer};
use oci_client::manifest::OciImageIndex;
use oci_client::secrets::RegistryAuth;
use oci_client::{Client, Reference};

/// Push the assembled image straight to a registry (Task 5.2) — **no Docker daemon**.
/// The config + layer blobs and the manifest go up over HTTPS; oci-client HEAD-skips any
/// blob the registry already has. Credentials come from the local Docker config
/// (`~/.docker/config.json`, incl. credential helpers); a localhost registry is treated as
/// plain-HTTP (matching Docker's insecure-localhost default), which also lets CI test
/// against a local `registry:2`. Returns the pushed image's by-digest reference
/// (`registry/repo@sha256:…`) when the registry reports a digest — `Some` for `--sign` to
/// sign, `None` when the response carries no digest (a plain push still succeeds).
pub fn push_to_registry(
    staged: &StagedTree,
    reference: &str,
    cfg: &ImageConfig,
) -> Result<Option<String>> {
    let built = image::build_image(staged, cfg)?;
    let reference: Reference = reference
        .parse()
        .with_context(|| format!("invalid image reference {reference:?}"))?;

    // `registry()` is the Docker-config key (e.g. `docker.io`); `resolve_registry()` is the
    // real endpoint we talk HTTP to (e.g. `registry-1.docker.io`). Look creds up by the
    // former, exchange/probe against the latter.
    let plan = plan_credential(docker_credential::get_credential(reference.registry()).ok());
    let endpoint = reference.resolve_registry().to_string();
    let repository = reference.repository().to_string();

    let layers = vec![ImageLayer::oci_v1_gzip(built.layer.gzip, None)];
    let config = OciConfig::oci_v1(built.config_bytes, None);
    let client = Client::new(ClientConfig {
        protocol: registry_protocol(&endpoint),
        ..Default::default()
    });

    // oci-client is async; run one scoped current-thread runtime for the identity-token
    // exchange (if any) and the push, rather than making the whole CLI async.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("tokio runtime for registry push")?;
    let digest_ref = rt.block_on(async {
        let auth = resolve_auth(plan, &endpoint, &repository).await?;
        // The pack report is the single user-facing line (like the other sinks); don't
        // print here too.
        let pushed = client
            .push(&reference, &layers, config, &auth, None)
            .await
            .with_context(|| format!("pushing to {reference}"))?;
        Ok::<_, anyhow::Error>(digest_ref_from(&reference, &pushed.manifest_url))
    })?;
    Ok(digest_ref)
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
    /// The pushed index's by-digest reference (`registry/repo@sha256:…`) when the registry
    /// reports a digest — `Some` for `--sign`, `None` when the response carries none.
    pub digest_ref: Option<String>,
}

// Manifest media types accepted when pulling a child. Both OCI and Docker single-image
// manifests are valid children; the two list types are accepted only so a mistakenly
// passed index is fetched and rejected with a clear message rather than an opaque error.
const CHILD_MANIFEST_TYPES: &[&str] = &[
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
    "application/vnd.oci.image.index.v1+json",
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
        .with_context(|| format!("invalid target reference {target:?}"))?;
    let source_refs = sources
        .iter()
        .map(|s| {
            let r: Reference = s
                .parse()
                .with_context(|| format!("invalid source reference {s:?}"))?;
            // An image index references its children by digest, resolved within the
            // repository it was pulled from — so every source must be in the target's
            // repository (this push publishes only the list, never copies child blobs).
            // The usual shape is the same repo, a different tag: app:1.0-amd64 -> app:1.0.
            if r.registry() != target_ref.registry() || r.repository() != target_ref.repository() {
                bail!(
                    "source {s} is {}/{} but the target index is {}/{}; an image index \
                     references its children by digest within one repository, so every \
                     source must be in the target's repository (typically the same repo, a \
                     different tag)",
                    r.registry(),
                    r.repository(),
                    target_ref.registry(),
                    target_ref.repository()
                );
            }
            Ok((s.clone(), r))
        })
        .collect::<Result<Vec<_>>>()?;

    let plan = plan_credential(docker_credential::get_credential(target_ref.registry()).ok());
    let endpoint = target_ref.resolve_registry().to_string();
    let repository = target_ref.repository().to_string();
    let client = Client::new(ClientConfig {
        protocol: registry_protocol(&endpoint),
        ..Default::default()
    });

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("tokio runtime for the index push")?;
    rt.block_on(async {
        let auth = resolve_auth(plan, &endpoint, &repository).await?;
        let mut children = Vec::with_capacity(source_refs.len());
        for (source, r) in &source_refs {
            children.push(fetch_child(&client, r, &auth, source).await?);
        }
        let index = build_index(&children)?;
        let url = client
            .push_manifest_list(&target_ref, &auth, index)
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
            digest_ref: digest_ref_from(&target_ref, &url),
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
    let manifest: serde_json::Value = serde_json::from_slice(&raw)
        .with_context(|| format!("parsing the manifest for {source}"))?;
    let media_type = manifest
        .get("mediaType")
        .and_then(|v| v.as_str())
        .unwrap_or("application/vnd.oci.image.manifest.v1+json")
        .to_string();
    if is_multi_arch_media_type(&media_type) {
        bail!(
            "source {source} is itself a multi-arch index ({media_type}); pass the \
             single-arch images, not an index"
        );
    }
    // Pull the config pinned to the digest we just resolved, not the (possibly moving) tag,
    // so this manifest's size/digest and its platform always come from the same image even
    // if the tag is re-pushed mid-run.
    let by_digest: Reference = format!(
        "{}/{}@{}",
        reference.registry(),
        reference.repository(),
        digest
    )
    .parse()
    .with_context(|| format!("building a by-digest reference for {source}"))?;
    let (_m, _d, config_json) = client
        .pull_manifest_and_config(&by_digest, auth)
        .await
        .with_context(|| format!("pulling the config for {source}"))?;
    let config: serde_json::Value = serde_json::from_str(&config_json)
        .with_context(|| format!("parsing the config for {source}"))?;
    let architecture = config
        .get("architecture")
        .and_then(|v| v.as_str())
        .with_context(|| format!("the config for {source} has no architecture"))?
        .to_string();
    let os = config
        .get("os")
        .and_then(|v| v.as_str())
        .unwrap_or("linux")
        .to_string();
    let variant = config
        .get("variant")
        .and_then(|v| v.as_str())
        .map(str::to_string);
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
                platform_label(c)
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
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": manifests,
    });
    serde_json::from_value(index).context("assembling the OCI image index")
}

// Build a by-digest reference (`registry/repo@sha256:…`) from the push response's manifest
// URL, which ends in the pushed manifest's digest. cosign signs by digest, so this is what
// `--sign` targets — precise and immune to a tag being moved after the push. `None` when the
// URL carries no digest: the push still succeeded, so this must not fail a plain push (only
// `--sign`, which needs the digest, errors — in the caller).
fn digest_ref_from(reference: &Reference, manifest_url: &str) -> Option<String> {
    let digest = manifest_url
        .rsplit("/manifests/")
        .next()
        .and_then(|tail| tail.split(['?', '#']).next())
        .filter(|d| d.starts_with("sha256:"))?;
    Some(format!(
        "{}/{}@{}",
        reference.registry(),
        reference.repository(),
        digest
    ))
}

/// What to do with a Docker-config credential. UsernamePassword and "no credential" resolve
/// to a `RegistryAuth` directly; an identity token needs a network exchange first, so it's
/// kept distinct. Split from the exchange as a pure function so every arm is unit-testable
/// without real creds or a network.
enum CredentialPlan {
    Ready(RegistryAuth),
    IdentityToken(String),
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
) -> Result<RegistryAuth> {
    match plan {
        CredentialPlan::Ready(auth) => Ok(auth),
        CredentialPlan::IdentityToken(token) => {
            let http = reqwest::Client::builder()
                .build()
                .context("building the HTTP client for the identity-token exchange")?;
            let access = exchange_identity_token(&http, endpoint, repository, &token).await?;
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
    let realm = extract_challenge_param(&challenge, "realm").with_context(|| {
        format!("no realm in the auth challenge from {endpoint}: {challenge:?}")
    })?;
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
        .post(&realm)
        .form(&params)
        .send()
        .await
        .with_context(|| format!("exchanging the identity token at {realm}"))?;
    let status = res.status();
    let body = res.text().await.unwrap_or_default();
    if !status.is_success() {
        anyhow::bail!("identity-token exchange at {realm} failed ({status}): {body}");
    }
    let parsed: TokenResponse = serde_json::from_str(&body)
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

    #[test]
    fn digest_ref_from_builds_a_by_digest_reference() {
        let r: Reference = "ghcr.io/you/app:latest".parse().unwrap();
        assert_eq!(
            digest_ref_from(&r, "https://ghcr.io/v2/you/app/manifests/sha256:abc123").as_deref(),
            Some("ghcr.io/you/app@sha256:abc123")
        );
        // A namespace/query suffix on the URL is trimmed.
        assert_eq!(
            digest_ref_from(
                &r,
                "https://ghcr.io/v2/you/app/manifests/sha256:def?ns=ghcr.io"
            )
            .as_deref(),
            Some("ghcr.io/you/app@sha256:def")
        );
        // A URL without a digest yields None (a plain push must not fail on it).
        assert_eq!(
            digest_ref_from(&r, "https://ghcr.io/v2/you/app/manifests/latest"),
            None
        );
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
            )
            .await
        })
    }

    #[test]
    fn resolve_auth_passes_ready_credentials_through() {
        let auth = block_on(resolve_auth(
            CredentialPlan::Ready(RegistryAuth::Anonymous),
            "ghcr.io",
            "owner/img",
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
        ))
        .expect_err("an unreachable registry must error");
        assert!(format!("{err:#}").contains("probing"));
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
}
