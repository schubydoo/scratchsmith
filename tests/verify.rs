//! `verify` end to end, against a mock registry and a fake cosign that logs its arguments.
//! A real cosign check needs a keyless signature from a live identity, so it runs in
//! `push-auth-smoke.yml` instead.

use sha2::Digest;
use std::path::Path;
use std::process::{Command, Output};

mod common;
use common::fake_tools;

const IMAGE_MANIFEST: &str = r#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":2},"layers":[]}"#;
const INDEX_MANIFEST: &str = r#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","size":2,"platform":{"architecture":"amd64","os":"linux"}}]}"#;

const ISSUER: &str = "https://token.actions.githubusercontent.com";
const PATTERN: &str = r"^https://github\.com/you/app/\.github/workflows/release\.yml@";

fn digest_of(body: &str) -> String {
    let hex: String = sha2::Sha256::digest(body.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    format!("sha256:{hex}")
}

// A registry for repository `app` that serves the image manifest at tag `1` and the index at
// tag `multi`, each also by its digest.
fn mock_registry() -> (tokio::runtime::Runtime, wiremock::MockServer) {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, ResponseTemplate};
    // wiremock serves from a thread of its own, so the CLI child process reaches it while
    // this runtime sits idle.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let server = rt.block_on(async {
        let server = wiremock::MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v2/"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        for (tag, body, media_type) in [
            (
                "1",
                IMAGE_MANIFEST,
                "application/vnd.oci.image.manifest.v1+json",
            ),
            (
                "multi",
                INDEX_MANIFEST,
                "application/vnd.oci.image.index.v1+json",
            ),
        ] {
            let digest = digest_of(body);
            for at in [tag, digest.as_str()] {
                Mock::given(method("GET"))
                    .and(path(format!("/v2/app/manifests/{at}")))
                    .respond_with(
                        ResponseTemplate::new(200)
                            .insert_header("Content-Type", media_type)
                            .insert_header("Docker-Content-Digest", digest.as_str())
                            .set_body_raw(body.as_bytes().to_vec(), media_type),
                    )
                    .mount(&server)
                    .await;
            }
        }
        server
    });
    (rt, server)
}

// A cosign that logs each call to `$ASKED` and exits with `$VERIFY_EXIT` for `verify` and
// `$ATTEST_EXIT` for `verify-attestation`, as cosign does on a mismatch.
const FAKE_COSIGN: &str = r#"echo "$*" >> "$ASKED"
case "$1" in
verify) [ "${VERIFY_EXIT:-0}" = 0 ] || { echo 'Error: no matching signatures' >&2; exit "$VERIFY_EXIT"; } ;;
verify-attestation) [ "${ATTEST_EXIT:-0}" = 0 ] || { echo 'Error: none of the attestations matched' >&2; exit "$ATTEST_EXIT"; } ;;
esac"#;

fn verify(dir: &Path, args: &[&str], env: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_scratchsmith"));
    cmd.arg("verify")
        .args(args)
        .env("PATH", fake_tools(dir, &[("cosign", FAKE_COSIGN)]))
        .env("ASKED", dir.join("asked"))
        // No Docker config, so the registry read is anonymous.
        .env("HOME", dir);
    for (key, value) in env {
        cmd.env(key, value);
    }
    cmd.output().unwrap()
}

fn asked(dir: &Path) -> String {
    std::fs::read_to_string(dir.join("asked")).unwrap_or_default()
}

fn text(out: &Output) -> (String, String) {
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn a_tag_is_checked_by_the_digest_it_points_to() {
    let (_rt, server) = mock_registry();
    let host = server.address().to_string();
    let tag = format!("{host}/app:1");
    let by_digest = format!("{host}/app@{}", digest_of(IMAGE_MANIFEST));
    let tmp = tempfile::tempdir().unwrap();
    let out = verify(
        tmp.path(),
        &[
            &tag,
            "--certificate-identity-regexp",
            PATTERN,
            "--certificate-oidc-issuer",
            ISSUER,
        ],
        &[],
    );
    let (stdout, stderr) = text(&out);
    assert_eq!(out.status.code(), Some(0), "{stderr}");
    assert_eq!(
        asked(tmp.path()),
        format!(
            "version\nverify {by_digest} --certificate-identity-regexp {PATTERN} \
             --certificate-oidc-issuer {ISSUER}\n"
        ),
        "cosign gets the digest, never the tag"
    );
    assert_eq!(
        stdout.trim_end(),
        format!(
            "verified signature: {by_digest}\n  signed by an identity that matches {PATTERN}\n  \
             issued by {ISSUER}\nnote: this proves who signed this image digest. It does not \
             prove that the image is safe, or that the SBOM is complete.\nnote: {tag} is a tag. \
             It pointed to {} when verify ran. A tag can move, so pin the digest.",
            digest_of(IMAGE_MANIFEST)
        )
    );

    // JSON: `requested` keeps the tag, `image` is the digest reference, and no note is printed.
    let tmp = tempfile::tempdir().unwrap();
    let out = verify(
        tmp.path(),
        &[
            &tag,
            "--certificate-identity",
            "me@example.com",
            "--certificate-oidc-issuer",
            "https://accounts.example.com",
            "--format",
            "json",
        ],
        &[],
    );
    let (stdout, stderr) = text(&out);
    assert_eq!(out.status.code(), Some(0), "{stderr}");
    let report: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(
        report,
        serde_json::json!({
            "requested": tag,
            "image": by_digest,
            "kind": "image",
            "identity": "me@example.com",
            "identity_is_regexp": false,
            "issuer": "https://accounts.example.com",
            "signature": true,
            "attestation": null,
        })
    );
}

#[test]
fn sbom_checks_the_attestation_of_the_chosen_type() {
    let (_rt, server) = mock_registry();
    let host = server.address().to_string();
    let by_digest = format!("{host}/app@{}", digest_of(IMAGE_MANIFEST));
    for (extra, kind) in [
        (&[][..], "cyclonedx"),
        (&["--sbom-format", "spdx-json"][..], "spdxjson"),
    ] {
        let tmp = tempfile::tempdir().unwrap();
        let mut args = vec![
            by_digest.as_str(),
            "--certificate-identity-regexp",
            PATTERN,
            "--certificate-oidc-issuer",
            ISSUER,
            "--sbom",
        ];
        args.extend(extra);
        let out = verify(tmp.path(), &args, &[]);
        let (stdout, stderr) = text(&out);
        assert_eq!(out.status.code(), Some(0), "{stderr}");
        let ids =
            format!("--certificate-identity-regexp {PATTERN} --certificate-oidc-issuer {ISSUER}");
        assert_eq!(
            asked(tmp.path()),
            format!(
                "version\nverify {by_digest} {ids}\nverify-attestation {by_digest} --type {kind} \
                 {ids}\n"
            )
        );
        assert!(
            stdout.contains(&format!(
                "verified attestation: {kind} SBOM, same identity and issuer\n"
            )),
            "{stdout}"
        );
        // A digest was given, so there is no tag note.
        assert!(!stdout.contains("is a tag"), "{stdout}");
    }
}

#[test]
fn an_index_is_checked_by_its_own_digest_and_refuses_sbom() {
    let (_rt, server) = mock_registry();
    let host = server.address().to_string();
    let index = format!("{host}/app:multi");
    let by_digest = format!("{host}/app@{}", digest_of(INDEX_MANIFEST));
    let base = [
        index.as_str(),
        "--certificate-identity-regexp",
        PATTERN,
        "--certificate-oidc-issuer",
        ISSUER,
    ];
    let tmp = tempfile::tempdir().unwrap();
    let out = verify(
        tmp.path(),
        &[&base[..], &["--format", "json"]].concat(),
        &[],
    );
    let (stdout, stderr) = text(&out);
    assert_eq!(out.status.code(), Some(0), "{stderr}");
    assert!(
        asked(tmp.path()).contains(&format!("\nverify {by_digest} ")),
        "{}",
        asked(tmp.path())
    );
    let report: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(report["kind"], "index", "{report}");

    let tmp = tempfile::tempdir().unwrap();
    let out = verify(tmp.path(), &base, &[]);
    let (stdout, _) = text(&out);
    assert!(
        stdout.ends_with(
            "note: this checked the signature on the index. It did not check the images that \
             the index lists.\n"
        ),
        "{stdout}"
    );

    let tmp = tempfile::tempdir().unwrap();
    let out = verify(tmp.path(), &[&base[..], &["--sbom"]].concat(), &[]);
    let (_, stderr) = text(&out);
    assert_eq!(out.status.code(), Some(2), "{stderr}");
    assert!(
        stderr.contains(&format!(
            "error: {index} is an image index. index --sign attaches no SBOM attestation, so \
             --sbom does not apply. Drop --sbom."
        )),
        "{stderr}"
    );
    assert_eq!(asked(tmp.path()), "version\n", "no check ran");
}

#[test]
fn a_failed_check_exits_1_and_names_the_check() {
    let (_rt, server) = mock_registry();
    let host = server.address().to_string();
    let by_digest = format!("{host}/app@{}", digest_of(IMAGE_MANIFEST));
    let args = [
        by_digest.as_str(),
        "--certificate-identity-regexp",
        PATTERN,
        "--certificate-oidc-issuer",
        ISSUER,
        "--sbom",
        "--format",
        "json",
    ];
    for (env, check, cosign_said) in [
        (("VERIFY_EXIT", "1"), "signature", "no matching signatures"),
        (
            ("ATTEST_EXIT", "1"),
            "attestation",
            "none of the attestations matched",
        ),
    ] {
        let tmp = tempfile::tempdir().unwrap();
        let out = verify(tmp.path(), &args, &[env]);
        let (stdout, stderr) = text(&out);
        assert_eq!(out.status.code(), Some(1), "{stderr}");
        assert!(
            stderr.starts_with(&format!("error: {check} check failed for {by_digest}"))
                && stderr.contains(cosign_said),
            "{stderr}"
        );
        assert_eq!(stdout, "", "a failure prints no report");
    }
}

#[test]
fn a_usage_refusal_exits_2_before_cosign_runs() {
    let id = ["--certificate-identity", "me@example.com"];
    let issuer = ["--certificate-oidc-issuer", ISSUER];
    let cases: [Vec<&str>; 6] = [
        // No identity flag.
        [&["reg.example/app:1"][..], &issuer].concat(),
        // Both identity flags.
        [
            &[
                "reg.example/app:1",
                "--certificate-identity-regexp",
                PATTERN,
            ][..],
            &id,
            &issuer,
        ]
        .concat(),
        // No issuer.
        [&["reg.example/app:1"][..], &id].concat(),
        // A pattern with no leading `^`.
        [
            &[
                "reg.example/app:1",
                "--certificate-identity-regexp",
                "github\\.com/you/",
            ][..],
            &issuer,
        ]
        .concat(),
        // --sbom-format without --sbom.
        [
            &["reg.example/app:1", "--sbom-format", "spdx-json"][..],
            &id,
            &issuer,
        ]
        .concat(),
        // A bad image reference.
        [&["Not A Ref!"][..], &id, &issuer].concat(),
    ];
    for args in cases {
        let tmp = tempfile::tempdir().unwrap();
        let out = verify(tmp.path(), &args, &[]);
        let (_, stderr) = text(&out);
        assert_eq!(out.status.code(), Some(2), "{args:?}: {stderr}");
        assert_eq!(asked(tmp.path()), "", "{args:?}: cosign was called");
    }
}

#[test]
fn no_cosign_exits_1_with_the_install_hint() {
    let tmp = tempfile::tempdir().unwrap();
    let empty = tmp.path().join("empty");
    std::fs::create_dir(&empty).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_scratchsmith"))
        .args([
            "verify",
            "reg.example/app:1",
            "--certificate-identity",
            "me@example.com",
            "--certificate-oidc-issuer",
            ISSUER,
        ])
        .env("PATH", &empty)
        .env("HOME", tmp.path())
        .output()
        .unwrap();
    let (_, stderr) = text(&out);
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    assert!(
        stderr.contains("verify needs cosign")
            && stderr.contains("install cosign: https://github.com/sigstore/cosign"),
        "{stderr}"
    );
}
