//! `scratchsmith doctor`: report which external tools are available and what each
//! is for, so a user can see what will and won't work before packing.

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
        purpose: "load the image into a container engine (default --runtime)",
        hint: "install Docker",
    },
    Tool {
        name: "podman",
        version_args: &["--version"],
        purpose: "load the image (--runtime podman) — a Docker alternative",
        hint: "install Podman",
    },
    Tool {
        name: "nerdctl",
        version_args: &["--version"],
        purpose: "load the image (--runtime nerdctl) — a Docker alternative",
        hint: "install nerdctl",
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
        purpose: "--sbom (generate the SBOM)",
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
        purpose: "--sign (sign the pushed image or index, attest any SBOM)",
        hint: "https://github.com/sigstore/cosign",
    },
    Tool {
        name: "upx",
        version_args: &["--version"],
        purpose: "--upx (compress the packed binary further)",
        hint: "install upx",
    },
    Tool {
        name: "tini",
        version_args: &["--version"],
        purpose: "--init (minimal pid-1 init wrapping the entrypoint)",
        hint: "install tini",
    },
    // On a host that keeps every locale in a locale-archive, compiling is the only way to
    // stage one, so a missing localedef turns --locale into a pack-time failure.
    Tool {
        name: "localedef",
        version_args: &["--version"],
        purpose: "--locale (compile a locale the host has no directory for)",
        hint: "install glibc tools (libc-bin) and the locale sources (locales)",
    },
    // Absent on every host that is not Debian-based, and that is fine: without it the
    // package list is empty and the SBOM is as it was.
    Tool {
        name: "dpkg-query",
        version_args: &["--version"],
        purpose: "--packages (name the package that owns each bundled library)",
        hint: "present on Debian and Ubuntu; an rpm host uses rpm, below",
    },
    // The rpm half of --packages. `rpmdb` ships in the same package as `rpm`.
    Tool {
        name: "rpm",
        version_args: &["--version"],
        purpose: "--packages on an rpm host (Fedora, RHEL and their relatives)",
        hint: "present on rpm-based hosts; a host with neither gets no package data",
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
    /// Set when the tool is present and cannot do all of its job on this host.
    pub limit: Option<&'static str>,
}

/// Probe every known tool. Always succeeds — reporting absence is the job.
pub fn probe() -> Vec<ToolStatus> {
    TOOLS.iter().map(probe_tool).collect()
}

/// Print the report. `doctor` itself always exits 0; missing tools are informational.
pub fn run() -> Result<()> {
    for status in probe() {
        match &status.version {
            Some(v) => match status.limit {
                None => println!("  ok    {:10} {}  ({})", status.name, v, status.purpose),
                Some(limit) => println!(
                    "  warn  {:10} {}  ({}) — {}",
                    status.name, v, status.purpose, limit
                ),
            },
            None => println!(
                "  MISS  {:10} not found — {}; {}",
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
    // `rpmdb` ships with `rpm`, so its help text is asked only where rpm answered.
    let limit = (tool.name == "rpm" && version.is_some())
        .then(|| {
            let help = Command::new("rpmdb").arg("--help").output().ok();
            rpm_records_limit(
                help.as_ref()
                    .map(|out| String::from_utf8_lossy(&out.stdout)),
            )
        })
        .flatten();
    ToolStatus {
        name: tool.name,
        version,
        purpose: tool.purpose,
        hint: tool.hint,
        limit,
    }
}

// The package records for `--packages sbom` and `image` come from `rpmdb --exportdb`, and an
// old rpm (4.11 on CentOS 7 and Amazon Linux 2) does not have it. It answers every other
// question, so without this line the user learns it from a failed pack. The help text is the
// cheap way to ask: the export itself reads every package on the host.
fn rpm_records_limit(rpmdb_help: Option<impl AsRef<str>>) -> Option<&'static str> {
    let has_export = rpmdb_help.is_some_and(|help| help.as_ref().contains("--exportdb"));
    (!has_export).then_some(
        "this rpm has no `rpmdb --exportdb`, so `--packages sbom` and `--packages image` \
         fail here; `--packages report` works",
    )
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
    fn an_rpm_without_the_export_option_is_limited() {
        // The line that matters from the help of rpm 4.14 and newer, and from rpm 4.11.
        let new = "  --exportdb    export database to stdout header list";
        let old = "  --initdb      initialize database\n  --rebuilddb   rebuild database";
        assert!(rpm_records_limit(Some(new)).is_none());
        assert!(rpm_records_limit(Some(old)).is_some_and(|l| l.contains("--exportdb")));
        // No rpmdb to ask at all: the records cannot be built either.
        assert!(rpm_records_limit(None::<&str>).is_some());
    }

    #[test]
    fn a_missing_tool_reports_no_version() {
        assert!(locate("scratchsmith-definitely-not-a-real-tool").is_none());
    }
}
