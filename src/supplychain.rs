//! SBOM (syft) and image signing/attestation (cosign), shelled out and feature-gated
//! so their absence never breaks a core pack.
//!
//! Signing/attestation act on a registry image reference (cosign works by digest in a
//! registry), so `pack --push --sign` runs them against the digest the push returns.
//! SBOM runs against the staged rootfs and is usable on its own.

use anyhow::{bail, Context, Result};
use std::ffi::OsString;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// SBOM output format. CycloneDX is the default (better security-tool support);
/// SPDX is offered for license/compliance consumers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum, serde::Deserialize)]
#[serde(rename_all = "kebab-case")] // match the CLI value names (cyclonedx-json / spdx-json)
#[non_exhaustive] // may gain formats in a minor; not a stable exhaustive library API
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
        Io::Captured,
    )
}

fn syft_args(rootfs: &Path, format: SbomFormat, out: &Path) -> Vec<OsString> {
    vec![
        prefixed("dir:", rootfs),
        "-o".into(),
        prefixed(&format!("{}=", format.syft_name()), out),
    ]
}

const COSIGN_HINT: &str = "install cosign: https://github.com/sigstore/cosign";

/// Check that cosign runs. `--sign` calls it before the push, since a signing that fails
/// after the push leaves a public image that is not signed.
pub fn check_cosign() -> Result<()> {
    run_tool("cosign", &["version".into()], COSIGN_HINT, Io::Captured)
        .context("--sign needs cosign, so nothing was pushed")
}

// `prefix` then `path`, byte for byte. A path's `display()` replaces a byte that is not UTF-8,
// so the tool would read or write a different file.
fn prefixed(prefix: &str, path: &Path) -> OsString {
    let mut arg = OsString::from(prefix);
    arg.push(path);
    arg
}

/// Keyless-sign an image (by registry reference) with cosign. Signs a pushed image by
/// digest, so `pack --push --sign` drives it.
pub fn cosign_sign(image_ref: &str) -> Result<()> {
    run_tool(
        "cosign",
        &cosign_sign_args(image_ref),
        COSIGN_HINT,
        Io::Terminal,
    )
}

fn cosign_sign_args(image_ref: &str) -> Vec<OsString> {
    vec!["sign".into(), "--yes".into(), image_ref.into()]
}

/// Attach a signed SBOM attestation to an image (by registry reference) with cosign.
pub fn cosign_attest(image_ref: &str, sbom: &Path, predicate_type: &str) -> Result<()> {
    run_tool(
        "cosign",
        &cosign_attest_args(image_ref, sbom, predicate_type),
        COSIGN_HINT,
        Io::Terminal,
    )
}

fn cosign_attest_args(image_ref: &str, sbom: &Path, predicate_type: &str) -> Vec<OsString> {
    vec![
        "attest".into(),
        "--yes".into(),
        "--type".into(),
        predicate_type.into(),
        "--predicate".into(),
        sbom.into(),
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
#[non_exhaustive] // may gain scan sources in a minor; not a stable exhaustive library API
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
    /// Findings grype couldn't rank (`unknown`) count only at the lowest threshold,
    /// `negligible`, so `--scan-fail-on negligible` truly blocks *everything*; a stricter
    /// threshold ignores them (an unrankable finding is not evidence of a high/critical).
    pub fn at_or_above(&self, threshold: Severity) -> usize {
        let ranked: usize = [
            (Severity::Critical, self.critical),
            (Severity::High, self.high),
            (Severity::Medium, self.medium),
            (Severity::Low, self.low),
            (Severity::Negligible, self.negligible),
        ]
        .into_iter()
        .filter(|(sev, _)| *sev >= threshold)
        .map(|(_, n)| n)
        .sum();
        if threshold == Severity::Negligible {
            ranked + self.unknown
        } else {
            ranked
        }
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
        Io::Captured,
    )?;
    parse_grype(&out)
}

fn grype_args(source: &ScanSource) -> Vec<OsString> {
    let src = match source {
        ScanSource::Sbom(p) => prefixed("sbom:", p),
        ScanSource::Rootfs(p) => prefixed("dir:", p),
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

// Where a tool's stdin and stderr go. stdout is always captured, so `--format json` on
// scratchsmith's stdout stays parseable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Io {
    // stdin closed, stderr captured and quoted in the error on a failure.
    Captured,
    // stdin and stderr are scratchsmith's own. Keyless cosign prints a login URL on stderr and
    // can read a code from stdin, so outside CI the user has to see it and answer it.
    Terminal,
}

// Run an external tool, turning a not-found into a clear install hint and a non-zero
// exit into a reported failure — never a silent skip.
fn run_tool(tool: &str, args: &[OsString], hint: &str, io: Io) -> Result<()> {
    run_tool_capture(tool, args, hint, io).map(|_| ())
}

// The longest each tool may run. syft and grype read the whole rootfs, and grype's first run
// downloads its vulnerability database (some hundreds of MB), so grype gets the most time.
// cosign's keyless login waits for the user.
fn limit_for(tool: &str) -> Duration {
    let minutes = match tool {
        "syft" => 15,
        "grype" => 30,
        _ => 10, // cosign
    };
    Duration::from_secs(minutes * 60)
}

// As `run_tool`, but returns captured stdout (for tools whose output we parse).
fn run_tool_capture(tool: &str, args: &[OsString], hint: &str, io: Io) -> Result<Vec<u8>> {
    run_tool_within(tool, args, hint, io, limit_for(tool))
}

// As `run_tool_capture`, but a run past `limit` is killed and reported, naming the tool and
// the limit. A stalled tool otherwise blocks the pack with no output at all.
fn run_tool_within(
    tool: &str,
    args: &[OsString],
    hint: &str,
    io: Io,
    limit: Duration,
) -> Result<Vec<u8>> {
    let mut command = Command::new(tool);
    command.args(args).stdout(Stdio::piped());
    match io {
        Io::Captured => command.stdin(Stdio::null()).stderr(Stdio::piped()),
        Io::Terminal => command.stdin(Stdio::inherit()).stderr(Stdio::inherit()),
    };
    let mut child = match command.spawn() {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            bail!("{tool} not found; {hint}")
        }
        Err(e) => return Err(e).with_context(|| format!("running {tool}")),
    };
    // Drain both pipes on their own threads, so a tool that fills one cannot block on it.
    let drain = |pipe: Option<Box<dyn Read + Send>>| {
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            if let Some(mut pipe) = pipe {
                let _ = pipe.read_to_end(&mut buf);
            }
            buf
        })
    };
    let stdout = drain(child.stdout.take().map(|p| Box::new(p) as _));
    let stderr = drain(child.stderr.take().map(|p| Box::new(p) as _));
    let deadline = Instant::now() + limit;
    let status = loop {
        if let Some(status) = child
            .try_wait()
            .with_context(|| format!("waiting for {tool}"))?
        {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            bail!(
                "{tool} did not finish within {}, so scratchsmith stopped it",
                limit_text(limit)
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let stdout = stdout.join().unwrap_or_default();
    let stderr = stderr.join().unwrap_or_default();
    if !status.success() {
        match io {
            Io::Captured => bail!("{tool} failed: {}", String::from_utf8_lossy(&stderr).trim()),
            Io::Terminal => bail!("{tool} failed ({status}); its messages are above"),
        }
    }
    Ok(stdout)
}

fn limit_text(limit: Duration) -> String {
    let secs = limit.as_secs();
    match (secs / 60, secs % 60) {
        (1, 0) => "1 minute".into(),
        (m, 0) if m > 0 => format!("{m} minutes"),
        _ if secs == 1 => "1 second".into(),
        _ => format!("{secs} seconds"),
    }
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
            ["dir:/tmp/rootfs", "-o", "cyclonedx-json=/tmp/sbom.json"].map(OsString::from)
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
            ["sign", "--yes", "ghcr.io/you/app@sha256:abc"].map(OsString::from)
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
        assert!(args.iter().any(|a| a == "--type"));
        assert!(args.iter().any(|a| a == "cyclonedx"));
        assert!(args.iter().any(|a| a == "reg/img@sha256:abc"));
    }

    #[test]
    fn a_missing_tool_reports_a_clear_hint() {
        let err = run_tool(
            "scratchsmith-no-such-tool",
            &["x".into()],
            "install the thing",
            Io::Captured,
        )
        .unwrap_err();
        assert!(err.to_string().contains("not found"));
        assert!(err.to_string().contains("install the thing"));
    }

    #[test]
    fn grype_args_pick_the_source_prefix() {
        assert_eq!(
            grype_args(&ScanSource::Sbom(PathBuf::from("/tmp/sbom.json"))),
            ["sbom:/tmp/sbom.json", "-o", "json"].map(OsString::from)
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
            unknown: 9,
            total: 24,
        };
        assert_eq!(s.at_or_above(Severity::High), 3); // critical + high; unknown excluded
        assert_eq!(s.at_or_above(Severity::Medium), 6); // + medium; unknown excluded
        assert_eq!(s.at_or_above(Severity::Critical), 1);
        // negligible = "block everything": all five ranked severities (15) PLUS the 9 unrankable.
        assert_eq!(s.at_or_above(Severity::Negligible), 24);
    }

    #[test]
    fn malformed_grype_json_is_an_error_not_a_panic() {
        assert!(parse_grype(b"not json").is_err());
    }

    #[test]
    fn run_tool_capture_returns_stdout_on_success() {
        let out = run_tool_capture("echo", &["scratchsmith".into()], "hint", Io::Captured).unwrap();
        assert_eq!(String::from_utf8_lossy(&out).trim(), "scratchsmith");
    }

    #[test]
    fn a_tool_that_stalls_is_stopped_and_named_with_its_limit() {
        // TASK-245. `sleep 30` stands in for a stalled syft, grype or cosign.
        let started = Instant::now();
        let err = run_tool_within(
            "sleep",
            &["30".into()],
            "hint",
            Io::Captured,
            Duration::from_secs(1),
        )
        .unwrap_err()
        .to_string();
        assert_eq!(
            err,
            "sleep did not finish within 1 second, so scratchsmith stopped it"
        );
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    #[test]
    fn each_tool_has_its_own_limit() {
        assert_eq!(limit_text(limit_for("syft")), "15 minutes");
        assert_eq!(limit_text(limit_for("grype")), "30 minutes");
        assert_eq!(limit_text(limit_for("cosign")), "10 minutes");
        assert_eq!(limit_text(Duration::from_secs(60)), "1 minute");
        assert_eq!(limit_text(Duration::from_secs(90)), "90 seconds");
    }

    #[test]
    fn a_tool_with_a_large_output_is_not_blocked_by_its_pipes() {
        // More than a pipe holds on both streams at once, so both must drain while it runs.
        let script = "head -c 1000000 /dev/zero; head -c 1000000 /dev/zero >&2; exit 0";
        let out = run_tool_within(
            "sh",
            &["-c".into(), script.into()],
            "hint",
            Io::Captured,
            Duration::from_secs(20),
        )
        .unwrap();
        assert_eq!(out.len(), 1_000_000);
    }

    #[test]
    fn run_tool_capture_reports_a_nonzero_exit() {
        let err = run_tool_capture("false", &[], "hint", Io::Captured).unwrap_err();
        assert!(err.to_string().contains("false failed"));
    }

    // Where the child's fd `n` points, read by the child itself, as /proc shows it.
    fn child_fd(n: u8, io: Io) -> String {
        let script = format!("readlink /proc/self/fd/{n}");
        let out = run_tool_capture("sh", &["-c".into(), script.into()], "hint", io).unwrap();
        String::from_utf8(out).unwrap().trim().to_string()
    }

    fn own_fd(n: u8) -> String {
        std::fs::read_link(format!("/proc/self/fd/{n}"))
            .unwrap()
            .display()
            .to_string()
    }

    #[test]
    fn a_terminal_tool_shares_stdin_and_stderr_and_a_captured_one_does_not() {
        // TASK-233. cosign's login URL and code prompt have to reach the user.
        assert_eq!(child_fd(0, Io::Terminal), own_fd(0));
        assert_eq!(child_fd(2, Io::Terminal), own_fd(2));
        assert_eq!(child_fd(0, Io::Captured), "/dev/null");
        assert_ne!(child_fd(2, Io::Captured), own_fd(2));
        // stdout is captured either way, so the JSON report on stdout stays clean.
        assert_ne!(child_fd(1, Io::Terminal), own_fd(1));
    }

    #[test]
    fn a_terminal_tool_failure_points_to_its_own_messages() {
        let err = run_tool_capture("sh", &["-c".into(), "exit 3".into()], "hint", Io::Terminal)
            .unwrap_err()
            .to_string();
        assert!(
            err.starts_with("sh failed (exit status: 3); its messages are above"),
            "{err}"
        );
    }
}
