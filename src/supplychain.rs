//! SBOM (syft) and image signing/attestation (cosign), shelled out and feature-gated
//! so their absence never breaks a core pack. See Tasks 4.3-4.4.
//!
//! Signing/attestation act on a registry image reference (cosign works by digest in a
//! registry), so `pack --push --sign` runs them against the digest the push returns.
//! SBOM runs against the staged rootfs and is usable on its own.

use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;

/// SBOM output format. CycloneDX is the default (better security-tool support);
/// SPDX is offered for license/compliance consumers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum, serde::Deserialize)]
#[serde(rename_all = "kebab-case")] // match the CLI value names (cyclonedx-json / spdx-json)
pub enum SbomFormat {
    CyclonedxJson,
    SpdxJson,
}

/// A request to generate an SBOM to `path` in `format`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SbomRequest {
    pub path: PathBuf,
    pub format: SbomFormat,
}

impl SbomFormat {
    fn syft_name(self) -> &'static str {
        match self {
            SbomFormat::CyclonedxJson => "cyclonedx-json",
            SbomFormat::SpdxJson => "spdx-json",
        }
    }

    /// The `cosign attest --type` value matching this SBOM format.
    pub fn cosign_predicate_type(self) -> &'static str {
        match self {
            SbomFormat::CyclonedxJson => "cyclonedx",
            SbomFormat::SpdxJson => "spdxjson",
        }
    }
}

/// Generate an SBOM of the staged rootfs with syft, written to `out`. A missing syft
/// is a clear error, never a silent skip.
pub fn generate_sbom(rootfs: &Path, format: SbomFormat, out: &Path) -> Result<()> {
    run_tool(
        "syft",
        &syft_args(rootfs, format, out),
        "install syft: https://github.com/anchore/syft",
    )
}

fn syft_args(rootfs: &Path, format: SbomFormat, out: &Path) -> Vec<String> {
    vec![
        format!("dir:{}", rootfs.display()),
        "-o".into(),
        format!("{}={}", format.syft_name(), out.display()),
    ]
}

/// Keyless-sign an image (by registry reference) with cosign. Signs a pushed image by
/// digest, so `pack --push --sign` drives it.
pub fn cosign_sign(image_ref: &str) -> Result<()> {
    run_tool(
        "cosign",
        &cosign_sign_args(image_ref),
        "install cosign: https://github.com/sigstore/cosign",
    )
}

fn cosign_sign_args(image_ref: &str) -> Vec<String> {
    vec!["sign".into(), "--yes".into(), image_ref.into()]
}

/// Attach a signed SBOM attestation to an image (by registry reference) with cosign.
pub fn cosign_attest(image_ref: &str, sbom: &Path, predicate_type: &str) -> Result<()> {
    run_tool(
        "cosign",
        &cosign_attest_args(image_ref, sbom, predicate_type),
        "install cosign: https://github.com/sigstore/cosign",
    )
}

fn cosign_attest_args(image_ref: &str, sbom: &Path, predicate_type: &str) -> Vec<String> {
    vec![
        "attest".into(),
        "--yes".into(),
        "--type".into(),
        predicate_type.into(),
        "--predicate".into(),
        sbom.display().to_string(),
        image_ref.into(),
    ]
}

// Run an external tool, turning a not-found into a clear install hint and a non-zero
// exit into a reported failure — never a silent skip.
fn run_tool(tool: &str, args: &[String], hint: &str) -> Result<()> {
    let output = match Command::new(tool).args(args).output() {
        Ok(o) => o,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            bail!("{tool} not found; {hint}")
        }
        Err(e) => return Err(e).with_context(|| format!("running {tool}")),
    };
    if !output.status.success() {
        bail!(
            "{tool} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn syft_args_encode_source_and_format() {
        let args = syft_args(
            Path::new("/tmp/rootfs"),
            SbomFormat::CyclonedxJson,
            Path::new("/tmp/sbom.json"),
        );
        assert_eq!(
            args,
            vec![
                "dir:/tmp/rootfs".to_string(),
                "-o".into(),
                "cyclonedx-json=/tmp/sbom.json".into(),
            ]
        );
    }

    #[test]
    fn spdx_format_switches_the_syft_name() {
        let args = syft_args(Path::new("/r"), SbomFormat::SpdxJson, Path::new("/o"));
        assert!(args.iter().any(|a| a == "spdx-json=/o"));
    }

    #[test]
    fn cosign_sign_args_are_well_formed() {
        assert_eq!(
            cosign_sign_args("ghcr.io/you/app@sha256:abc"),
            vec![
                "sign".to_string(),
                "--yes".into(),
                "ghcr.io/you/app@sha256:abc".into()
            ]
        );
    }

    #[test]
    fn cosign_predicate_type_matches_the_sbom_format() {
        assert_eq!(
            SbomFormat::CyclonedxJson.cosign_predicate_type(),
            "cyclonedx"
        );
        assert_eq!(SbomFormat::SpdxJson.cosign_predicate_type(), "spdxjson");
    }

    #[test]
    fn cosign_attest_args_are_well_formed() {
        let args = cosign_attest_args("reg/img@sha256:abc", Path::new("/s.json"), "cyclonedx");
        assert_eq!(args[0], "attest");
        assert!(args.contains(&"--type".to_string()));
        assert!(args.contains(&"cyclonedx".to_string()));
        assert!(args.contains(&"reg/img@sha256:abc".to_string()));
    }

    #[test]
    fn a_missing_tool_reports_a_clear_hint() {
        let err = run_tool(
            "scratchsmith-no-such-tool",
            &["x".into()],
            "install the thing",
        )
        .unwrap_err();
        assert!(err.to_string().contains("not found"));
        assert!(err.to_string().contains("install the thing"));
    }
}
