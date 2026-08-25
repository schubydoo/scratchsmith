//! Daemonless registry push via oci-client: blobs before manifest, bearer auth from
//! the Docker config. See Task 5.2.

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

#[cfg(test)]
mod tests {
    use super::*;

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
}
