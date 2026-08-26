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

/// A vulnerability severity, ordered lowest → highest so `--scan-fail-on` can gate at
/// or above a threshold. Names match grype's severity strings (kebab on the CLI).
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, clap::ValueEnum, serde::Deserialize,
)]
#[serde(rename_all = "kebab-case")]
pub enum Severity {
    Negligible,
    Low,
    Medium,
    High,
    Critical,
}

/// Where grype reads its packages from: the SBOM syft already wrote (reuse it), or the
/// staged rootfs directly when no SBOM was generated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScanSource {
    Sbom(PathBuf),
    Rootfs(PathBuf),
}

/// A request to vulnerability-scan during a pack. `fail_on` (when set) gates the pack:
/// a finding at or above that severity aborts before delivery.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScanRequest {
    pub fail_on: Option<Severity>,
}

/// Vulnerability counts by severity from a grype scan. Serialized into the pack report.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct ScanSummary {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub negligible: usize,
    pub unknown: usize,
    pub total: usize,
}

impl ScanSummary {
    /// How many findings are at or above `threshold` — what `--scan-fail-on` gates on.
    /// `unknown`-severity findings never count toward a gate.
    pub fn at_or_above(&self, threshold: Severity) -> usize {
        [
            (Severity::Critical, self.critical),
            (Severity::High, self.high),
            (Severity::Medium, self.medium),
            (Severity::Low, self.low),
            (Severity::Negligible, self.negligible),
        ]
        .into_iter()
        .filter(|(sev, _)| *sev >= threshold)
        .map(|(_, n)| n)
        .sum()
    }
}

/// Scan `source` with grype and return the severity breakdown. A missing grype is a
/// clear error, never a silent skip. Gating is the caller's job (see `at_or_above`);
/// grype is run without `--fail-on`, so a non-zero exit is a real tool failure.
pub fn run_grype(source: &ScanSource) -> Result<ScanSummary> {
    let out = run_tool_capture(
        "grype",
        &grype_args(source),
        "install grype: https://github.com/anchore/grype",
    )?;
    parse_grype(&out)
}

fn grype_args(source: &ScanSource) -> Vec<String> {
    let src = match source {
        ScanSource::Sbom(p) => format!("sbom:{}", p.display()),
        ScanSource::Rootfs(p) => format!("dir:{}", p.display()),
    };
    vec![src, "-o".into(), "json".into()]
}

fn parse_grype(json: &[u8]) -> Result<ScanSummary> {
    #[derive(serde::Deserialize)]
    struct Doc {
        matches: Vec<Match>,
    }
    #[derive(serde::Deserialize)]
    struct Match {
        vulnerability: Vuln,
    }
    #[derive(serde::Deserialize)]
    struct Vuln {
        #[serde(default)]
        severity: String,
    }
    let doc: Doc = serde_json::from_slice(json).context("parsing grype JSON output")?;
    let mut s = ScanSummary::default();
    for m in &doc.matches {
        match m.vulnerability.severity.to_ascii_lowercase().as_str() {
            "critical" => s.critical += 1,
            "high" => s.high += 1,
            "medium" => s.medium += 1,
            "low" => s.low += 1,
            "negligible" => s.negligible += 1,
            _ => s.unknown += 1,
        }
        s.total += 1;
    }
    Ok(s)
}

// Run an external tool, turning a not-found into a clear install hint and a non-zero
// exit into a reported failure — never a silent skip.
fn run_tool(tool: &str, args: &[String], hint: &str) -> Result<()> {
    run_tool_capture(tool, args, hint).map(|_| ())
}

// As `run_tool`, but returns captured stdout (for tools whose output we parse).
fn run_tool_capture(tool: &str, args: &[String], hint: &str) -> Result<Vec<u8>> {
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
    Ok(output.stdout)
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

    #[test]
    fn grype_args_pick_the_source_prefix() {
        assert_eq!(
            grype_args(&ScanSource::Sbom(PathBuf::from("/tmp/sbom.json"))),
            vec![
                "sbom:/tmp/sbom.json".to_string(),
                "-o".into(),
                "json".into()
            ]
        );
        assert_eq!(
            grype_args(&ScanSource::Rootfs(PathBuf::from("/tmp/rootfs")))[0],
            "dir:/tmp/rootfs"
        );
    }

    #[test]
    fn parse_grype_counts_by_severity() {
        let json = br#"{"matches":[
            {"vulnerability":{"severity":"Critical"}},
            {"vulnerability":{"severity":"high"}},
            {"vulnerability":{"severity":"High"}},
            {"vulnerability":{"severity":"Low"}},
            {"vulnerability":{"severity":"Unknown"}},
            {"vulnerability":{"severity":""}}
        ]}"#;
        let s = parse_grype(json).unwrap();
        assert_eq!(s.critical, 1);
        assert_eq!(s.high, 2);
        assert_eq!(s.low, 1);
        assert_eq!(s.unknown, 2); // "Unknown" + the empty severity
        assert_eq!(s.total, 6);
    }

    #[test]
    fn empty_matches_is_a_clean_zero() {
        let s = parse_grype(br#"{"matches":[]}"#).unwrap();
        assert_eq!(s, ScanSummary::default());
        assert_eq!(s.at_or_above(Severity::Negligible), 0);
    }

    #[test]
    fn at_or_above_gates_from_the_threshold_up() {
        let s = ScanSummary {
            critical: 1,
            high: 2,
            medium: 3,
            low: 4,
            negligible: 5,
            unknown: 9, // never counts toward a gate
            total: 24,
        };
        assert_eq!(s.at_or_above(Severity::High), 3); // critical + high
        assert_eq!(s.at_or_above(Severity::Medium), 6); // + medium
        assert_eq!(s.at_or_above(Severity::Critical), 1);
        assert_eq!(s.at_or_above(Severity::Negligible), 15); // all real severities, not unknown
    }

    #[test]
    fn malformed_grype_json_is_an_error_not_a_panic() {
        assert!(parse_grype(b"not json").is_err());
    }
}
