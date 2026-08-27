//! Render the size + security report as text or JSON (`--format json` for CI gates).
//! See Tasks 2.4, 2.8.

use crate::stager::SizeReport;
use crate::supplychain::ScanSummary;
use anyhow::{bail, Context, Result};
use serde::Serialize;

/// Parse a human size like `10MB`, `512KiB`, `2.5G`, or a bare byte count into bytes.
/// Decimal units (K/M/G) are powers of 1000; binary units (Ki/Mi/Gi) are powers of 1024.
/// Used for `--max-size` and the `max-size` config key.
pub fn parse_size(s: &str) -> Result<u64> {
    let s = s.trim();
    let split = s
        .find(|c: char| !c.is_ascii_digit() && c != '.')
        .unwrap_or(s.len());
    let (num, unit) = s.split_at(split);
    let num: f64 = num.parse().with_context(|| {
        format!("invalid size '{s}': expected a number, optionally with a unit")
    })?;
    let mult: f64 = match unit.trim().to_ascii_lowercase().as_str() {
        "" | "b" => 1.0,
        "k" | "kb" => 1_000.0,
        "ki" | "kib" => 1_024.0,
        "m" | "mb" => 1_000_000.0,
        "mi" | "mib" => 1_048_576.0,
        "g" | "gb" => 1_000_000_000.0,
        "gi" | "gib" => 1_073_741_824.0,
        other => bail!("invalid size unit '{other}' in '{s}' (use B, KB/MB/GB, or KiB/MiB/GiB)"),
    };
    // A leading '-' is the split point (a non-digit), so `num` parses empty and errors
    // above — a negative value can never reach here, so no explicit non-negative guard.
    Ok((num * mult) as u64)
}

/// Format a byte count as a human-readable decimal size (e.g. `8.4 MB`) for messages.
pub fn human_size(bytes: u64) -> String {
    for (unit, div) in [("GB", 1_000_000_000u64), ("MB", 1_000_000), ("KB", 1_000)] {
        if bytes >= div {
            return format!("{:.1} {unit}", bytes as f64 / div as f64);
        }
    }
    format!("{bytes} B")
}

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
                "vulnerabilities: {} total (critical={}, high={}, medium={}, low={}, negligible={}, unknown={})\n",
                scan.total, scan.critical, scan.high, scan.medium, scan.low, scan.negligible, scan.unknown
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
        // The breakdown includes unknown so the parts reconcile with the total (1+2+0+3+0+1 = 7).
        assert!(text.contains("negligible=0, unknown=1"));
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["scan"]["total"], 7);
        assert_eq!(json["scan"]["critical"], 1);
        assert_eq!(json["scan"]["unknown"], 1);
    }

    #[test]
    fn parse_size_handles_bytes_decimal_and_binary_units() {
        assert_eq!(parse_size("1024").unwrap(), 1024);
        assert_eq!(parse_size("10MB").unwrap(), 10_000_000);
        assert_eq!(parse_size("10MiB").unwrap(), 10_485_760);
        assert_eq!(parse_size("2.5MB").unwrap(), 2_500_000);
        assert_eq!(parse_size("512KiB").unwrap(), 524_288);
        assert_eq!(parse_size(" 1G ").unwrap(), 1_000_000_000);
        assert_eq!(parse_size("100b").unwrap(), 100);
    }

    #[test]
    fn parse_size_rejects_junk() {
        assert!(parse_size("abc").is_err());
        assert!(parse_size("10furlongs").is_err());
        assert!(parse_size("-5MB").is_err());
    }

    #[test]
    fn human_size_picks_a_readable_unit() {
        assert_eq!(human_size(8_400_000), "8.4 MB");
        assert_eq!(human_size(1_500_000_000), "1.5 GB");
        assert_eq!(human_size(2_048), "2.0 KB");
        assert_eq!(human_size(512), "512 B");
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
