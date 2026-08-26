//! `scratchsmith doctor`: report which external tools are available and what each
//! is for, so a user can see what will and won't work before packing. See Task 2.7.

use anyhow::Result;
use std::path::PathBuf;
use std::process::Command;

struct Tool {
    name: &'static str,
    version_args: &'static [&'static str],
    purpose: &'static str,
    hint: &'static str,
}

// ldconfig lives in a system sbin that may be off PATH, so it gets extra candidates.
const TOOLS: &[Tool] = &[
    Tool {
        name: "ldconfig",
        version_args: &["--version"],
        purpose: "regenerate the loader cache (core pack)",
        hint: "install glibc tools (libc-bin)",
    },
    Tool {
        name: "docker",
        version_args: &["--version"],
        purpose: "load the image into the Docker daemon",
        hint: "install Docker",
    },
    Tool {
        name: "strip",
        version_args: &["--version"],
        purpose: "--strip (shrink the binary and libraries)",
        hint: "install binutils",
    },
    Tool {
        name: "syft",
        version_args: &["version"],
        purpose: "SBOM generation (--sbom, v0.2)",
        hint: "https://github.com/anchore/syft",
    },
    Tool {
        name: "grype",
        version_args: &["version"],
        purpose: "--scan (vulnerability scan)",
        hint: "https://github.com/anchore/grype",
    },
    Tool {
        name: "cosign",
        version_args: &["version"],
        purpose: "image signing (v0.2)",
        hint: "https://github.com/sigstore/cosign",
    },
    Tool {
        name: "upx",
        version_args: &["--version"],
        purpose: "--upx (compress the packed binary further)",
        hint: "install upx",
    },
];

/// One tool's availability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolStatus {
    pub name: &'static str,
    /// First line of the tool's version output when found; `None` when absent.
    pub version: Option<String>,
    pub purpose: &'static str,
    pub hint: &'static str,
}

/// Probe every known tool. Always succeeds — reporting absence is the job.
pub fn probe() -> Vec<ToolStatus> {
    TOOLS.iter().map(probe_tool).collect()
}

/// Print the report. `doctor` itself always exits 0; missing tools are informational.
pub fn run() -> Result<()> {
    for status in probe() {
        match &status.version {
            Some(v) => println!("  ok    {:9} {}  ({})", status.name, v, status.purpose),
            None => println!(
                "  MISS  {:9} not found — {}; {}",
                status.name, status.purpose, status.hint
            ),
        }
    }
    Ok(())
}

fn probe_tool(tool: &Tool) -> ToolStatus {
    let version = locate(tool.name)
        .and_then(|path| run_version(&path, tool.version_args))
        .map(|out| first_line(&out));
    ToolStatus {
        name: tool.name,
        version,
        purpose: tool.purpose,
        hint: tool.hint,
    }
}

// Try the bare name (PATH) then the system sbins where ldconfig usually lives.
fn locate(name: &str) -> Option<PathBuf> {
    for candidate in [
        name.to_string(),
        format!("/usr/sbin/{name}"),
        format!("/sbin/{name}"),
    ] {
        let path = PathBuf::from(&candidate);
        if candidate.contains('/') && !path.exists() {
            continue;
        }
        if run_version(&path, &["--version"]).is_some() || path.exists() {
            return Some(path);
        }
    }
    None
}

fn run_version(path: &std::path::Path, args: &[&str]) -> Option<String> {
    let out = Command::new(path).args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let text = if text.trim().is_empty() {
        String::from_utf8_lossy(&out.stderr).into_owned()
    } else {
        text.into_owned()
    };
    Some(text)
}

fn first_line(s: &str) -> String {
    s.lines().next().unwrap_or("").trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_reports_every_known_tool() {
        let statuses = probe();
        assert_eq!(statuses.len(), TOOLS.len());
        // strip is optional; when the host does have it, probe() must report it —
        // a regression signal on capable hosts (incl. CI), without requiring the tool.
        let host_has_strip = Command::new("strip")
            .arg("--version")
            .output()
            .is_ok_and(|o| o.status.success());
        if host_has_strip {
            let strip = statuses.iter().find(|s| s.name == "strip").unwrap();
            assert!(
                strip.version.is_some(),
                "strip is on PATH but probe missed it"
            );
        }
    }

    #[test]
    fn a_missing_tool_reports_no_version() {
        assert!(locate("scratchsmith-definitely-not-a-real-tool").is_none());
    }
}
