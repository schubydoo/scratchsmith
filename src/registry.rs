//! Daemonless registry push via oci-client: blobs before manifest, auth from the Docker
//! config. Username/password creds ride oci-client's own token exchange; an identity-token
//! credential is exchanged here for a bearer access token (oci-client can't do that grant).
//! See Task 5.2.

use crate::image::{self, ImageConfig};
use crate::stager::StagedTree;
use anyhow::{Context, Result};
use oci_client::client::{ClientConfig, ClientProtocol, Config as OciConfig, ImageLayer};
use oci_client::secrets::RegistryAuth;
use oci_client::{Client, Reference};

/// Push the assembled image straight to a registry (Task 5.2) — **no Docker daemon**.
/// The config + layer blobs and the manifest go up over HTTPS; oci-client HEAD-skips any
/// blob the registry already has. Credentials come from the local Docker config
/// (`~/.docker/config.json`, incl. credential helpers); a localhost registry is treated as
/// plain-HTTP (matching Docker's insecure-localhost default), which also lets CI test
/// against a local `registry:2`.
pub fn push_to_registry(staged: &StagedTree, reference: &str, cfg: &ImageConfig) -> Result<()> {
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
    rt.block_on(async {
        let auth = resolve_auth(plan, &endpoint, &repository).await?;
        // The pack report is the single user-facing line (like the other sinks); don't
        // print here too.
        client
            .push(&reference, &layers, config, &auth, None)
            .await
            .with_context(|| format!("pushing to {reference}"))?;
        Ok::<_, anyhow::Error>(())
    })?;
    Ok(())
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
    parsed
        .access_token
        .or(parsed.token)
        .filter(|t| !t.is_empty())
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
}
