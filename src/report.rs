//! Render the size + security report as text or JSON (`--format json` for CI gates).
//! See Tasks 2.4, 2.8.

use crate::stager::SizeReport;
use crate::supplychain::ScanSummary;
use serde::Serialize;

/// The outcome of a pack, emitted as text or JSON (Task 2.8). Fields are stable so
/// the JSON can gate CI.
#[derive(Debug, Clone, Serialize)]
pub struct PackReport {
    /// Image tag when an image was built (loaded into Docker).
    pub tag: Option<String>,
    /// Path of the OCI archive when `--oci-archive` was used (daemonless).
    pub archive: Option<String>,
    /// The pushed image reference when `--push` was used (daemonless).
    pub pushed: Option<String>,
    /// Staging directory when `-n -o` was used instead of building an image.
    pub staged_dir: Option<String>,
    /// Entrypoint path inside the image.
    pub entrypoint: String,
    /// Per-file and total payload sizes.
    pub size: SizeReport,
    /// Best-effort include warnings (e.g. an absent NSS module).
    pub warnings: Vec<String>,
    /// Smoke-run result: `Some(true)` if started, `None` if not run.
    pub smoke_ok: Option<bool>,
    /// Path of the generated SBOM, if `--sbom` was requested.
    pub sbom: Option<String>,
    /// Vulnerability counts by severity, if `--scan` was requested.
    pub scan: Option<ScanSummary>,
    /// The signed by-digest reference, if `--sign` signed the pushed image.
    pub signed: Option<String>,
}

impl PackReport {
    /// Human-readable rendering (the `--format text` output).
    pub fn to_text(&self) -> String {
        let mut out = String::new();
        for w in &self.warnings {
            out.push_str(&format!("warning: {w}\n"));
        }
        out.push_str("payload size:\n");
        out.push_str(&format!("{}\n", self.size));
        if let Some(tag) = &self.tag {
            out.push_str(&format!("loaded image {tag}\n"));
        }
        if let Some(archive) = &self.archive {
            out.push_str(&format!("wrote OCI archive {archive}\n"));
        }
        if let Some(reference) = &self.pushed {
            out.push_str(&format!("pushed {reference}\n"));
        }
        if let Some(dir) = &self.staged_dir {
            out.push_str(&format!("staged to {dir}\n"));
        }
        if let Some(sbom) = &self.sbom {
            out.push_str(&format!("sbom: {sbom}\n"));
        }
        if let Some(scan) = &self.scan {
            out.push_str(&format!(
                "vulnerabilities: {} total (critical={}, high={}, medium={}, low={}, negligible={})\n",
                scan.total, scan.critical, scan.high, scan.medium, scan.low, scan.negligible
            ));
        }
        if let Some(signed) = &self.signed {
            out.push_str(&format!("signed {signed}\n"));
        }
        if self.smoke_ok == Some(true) {
            out.push_str("smoke-run ok: the binary starts inside the image\n");
        }
        out.trim_end().to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_report() -> PackReport {
        PackReport {
            tag: Some("scratchsmith/app:packed".into()),
            archive: None,
            pushed: None,
            staged_dir: None,
            entrypoint: "/opt/app".into(),
            size: SizeReport {
                entries: vec![],
                total_before: 200,
                total_after: 123,
                stripped: true,
                upx: false,
            },
            warnings: vec!["NSS module not found: libnss_dns.so.2".into()],
            smoke_ok: Some(true),
            sbom: Some("sbom.json".into()),
            scan: None,
            signed: None,
        }
    }

    #[test]
    fn json_report_has_stable_fields() {
        let json = serde_json::to_value(sample_report()).unwrap();
        assert_eq!(json["tag"], "scratchsmith/app:packed");
        assert_eq!(json["entrypoint"], "/opt/app");
        assert_eq!(json["size"]["total_after"], 123);
        assert_eq!(json["size"]["stripped"], true);
        assert!(json["staged_dir"].is_null());
        assert!(json["warnings"].is_array());
        assert_eq!(json["smoke_ok"], true);
    }

    #[test]
    fn text_report_renders_the_key_lines() {
        let text = sample_report().to_text();
        assert!(text.contains("warning: NSS module not found"));
        assert!(text.contains("loaded image scratchsmith/app:packed"));
        assert!(text.contains("smoke-run ok"));
        assert!(text.contains("200 -> 123"));
    }

    #[test]
    fn text_report_renders_a_pushed_reference() {
        let report = PackReport {
            tag: None,
            archive: None,
            pushed: Some("ghcr.io/you/app:latest".into()),
            staged_dir: None,
            entrypoint: "/opt/app".into(),
            size: SizeReport {
                entries: vec![],
                total_before: 10,
                total_after: 10,
                stripped: false,
                upx: false,
            },
            warnings: vec![],
            smoke_ok: None,
            sbom: None,
            scan: None,
            signed: None,
        };
        assert!(report.to_text().contains("pushed ghcr.io/you/app:latest"));
    }

    #[test]
    fn text_and_json_report_a_signed_digest() {
        let mut report = sample_report();
        report.signed = Some("ghcr.io/you/app@sha256:abc".into());
        assert!(report
            .to_text()
            .contains("signed ghcr.io/you/app@sha256:abc"));
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["signed"], "ghcr.io/you/app@sha256:abc");
    }

    #[test]
    fn text_and_json_report_vulnerability_counts() {
        let mut report = sample_report();
        report.scan = Some(crate::supplychain::ScanSummary {
            critical: 1,
            high: 2,
            medium: 0,
            low: 3,
            negligible: 0,
            unknown: 1,
            total: 7,
        });
        let text = report.to_text();
        assert!(text.contains("vulnerabilities: 7 total"));
        assert!(text.contains("critical=1, high=2"));
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["scan"]["total"], 7);
        assert_eq!(json["scan"]["critical"], 1);
    }

    #[test]
    fn text_report_renders_a_staged_dir() {
        let report = PackReport {
            tag: None,
            archive: None,
            pushed: None,
            staged_dir: Some("/out/rootfs".into()),
            entrypoint: "/opt/app".into(),
            size: SizeReport {
                entries: vec![],
                total_before: 1,
                total_after: 1,
                stripped: false,
                upx: false,
            },
            warnings: vec![],
            smoke_ok: None,
            sbom: None,
            scan: None,
            signed: None,
        };
        assert!(report.to_text().contains("staged to /out/rootfs"));
    }
}
