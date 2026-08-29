//! Command-line surface and dispatch.

use anyhow::{bail, Context, Result};
use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use clap_complete::generate;
use std::path::PathBuf;

/// Output format for the pack report.
#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum Format {
    Text,
    Json,
}

/// Shells Scratchsmith generates completion scripts for. Deliberately just the
/// three we document and exercise in CI, so `--help` lists exactly what is
/// supported rather than clap_complete's wider (untested) set.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Shell {
    Bash,
    Zsh,
    Fish,
}

impl Shell {
    fn generator(self) -> clap_complete::Shell {
        match self {
            Shell::Bash => clap_complete::Shell::Bash,
            Shell::Zsh => clap_complete::Shell::Zsh,
            Shell::Fish => clap_complete::Shell::Fish,
        }
    }
}

#[derive(Parser, Debug)]
#[command(name = "scratchsmith", version, about, long_about = None)]
// A completion dump needs no subcommand, so the subcommand is optional; an empty
// invocation still prints help rather than doing nothing.
#[command(arg_required_else_help = true)]
pub struct Cli {
    /// Emit a shell completion script to stdout and exit (bash, zsh, fish).
    #[arg(long, value_enum, value_name = "SHELL")]
    pub completions: Option<Shell>,
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Subcommand, Debug)]
// Pack carries many flags, dwarfing Lint/Doctor. This enum is parsed once at startup,
// so the size difference is irrelevant; boxing it would only add noise.
#[allow(clippy::large_enum_variant)]
pub enum Command {
    /// Pack a dynamic ELF binary into a minimal scratch image.
    Pack {
        /// Path to the dynamically linked binary to pack (or set `binary` in --config).
        binary: Option<PathBuf>,
        /// Read defaults from a scratchsmith.toml; CLI flags override it.
        #[arg(long, value_name = "FILE")]
        config: Option<PathBuf>,
        /// Apply a named `[profile.<name>]` from the config (layered over its base). Needs --config.
        #[arg(long, value_name = "NAME", requires = "config")]
        profile: Option<String>,
        /// After loading, run the image once and fail if the binary can't start.
        #[arg(long, conflicts_with = "no_build")]
        smoke: bool,
        /// Stage the rootfs only; build no image. Requires --output.
        #[arg(short = 'n', long, requires = "output")]
        no_build: bool,
        /// Directory to stage into (with --no-build).
        #[arg(short = 'o', long, value_name = "DIR", requires = "no_build")]
        output: Option<PathBuf>,
        /// Write a daemonless OCI-archive tarball instead of loading into Docker.
        #[arg(long, value_name = "FILE", conflicts_with = "no_build")]
        oci_archive: Option<PathBuf>,
        /// Push the image straight to a registry reference, daemonless (uses your docker login).
        #[arg(long, value_name = "REF", conflicts_with_all = ["no_build", "oci_archive"])]
        push: Option<String>,
        /// Sign the pushed image with cosign (keyless) and attest the SBOM, if one was
        /// generated. Requires --push (cosign signs a registry image by digest).
        #[arg(long, requires = "push")]
        sign: bool,
        /// Image entrypoint (defaults to the packed binary's path).
        #[arg(long, value_name = "PATH")]
        entrypoint: Option<String>,
        /// Default argument for the entrypoint; repeatable. Flag-like values are
        /// allowed, so `--cmd --version` passes `--version` through.
        #[arg(long = "cmd", value_name = "ARG", allow_hyphen_values = true)]
        cmd: Vec<String>,
        /// Environment entry `KEY=VALUE`; repeatable.
        #[arg(long = "env", value_name = "KEY=VALUE")]
        env: Vec<String>,
        /// Working directory inside the image.
        #[arg(long, value_name = "DIR")]
        workdir: Option<String>,
        /// Image user `UID[:GID]` (defaults to a non-root user; root warns).
        #[arg(long, value_name = "USER")]
        user: Option<String>,
        /// OCI image label `KEY=VALUE`; repeatable.
        #[arg(long = "label", value_name = "KEY=VALUE")]
        label: Vec<String>,
        /// HEALTHCHECK command; repeatable, exec form (must be runnable in the scratch
        /// image, e.g. the packed binary). Flag-like values pass through.
        #[arg(long = "healthcheck", value_name = "CMD", allow_hyphen_values = true)]
        healthcheck: Vec<String>,
        /// Strip symbols from the binary and libraries (strip --strip-unneeded).
        #[arg(long)]
        strip: bool,
        /// Compress the packed binary with UPX (it self-decompresses at runtime).
        #[arg(long)]
        upx: bool,
        /// Fail the pack if the packed payload exceeds this size, e.g. `12MB` or `512KiB`.
        #[arg(long = "max-size", value_name = "SIZE")]
        max_size: Option<String>,
        /// Generate an SBOM of the packed rootfs (requires syft).
        #[arg(long)]
        sbom: bool,
        /// SBOM output path (with --sbom; defaults to sbom.json).
        #[arg(long = "sbom-file", value_name = "FILE")]
        sbom_file: Option<PathBuf>,
        /// SBOM format (with --sbom; defaults to cyclonedx-json).
        #[arg(long = "sbom-format", value_enum)]
        sbom_format: Option<crate::supplychain::SbomFormat>,
        /// Vulnerability-scan the packed rootfs with grype (reuses the SBOM if --sbom is set).
        #[arg(long)]
        scan: bool,
        /// Fail the pack if grype finds a vuln at or above this severity (implies --scan).
        #[arg(long = "scan-fail-on", value_enum, value_name = "SEVERITY")]
        scan_fail_on: Option<crate::supplychain::Severity>,
        /// Add the TLS CA bundle (/etc/ssl/certs/ca-certificates.crt).
        #[arg(long = "ca-certs")]
        ca_certs: bool,
        /// Add the resolved local timezone (/etc/localtime).
        #[arg(long)]
        tz: bool,
        /// Add a minimal init (tini) as pid 1 wrapping the entrypoint.
        #[arg(long)]
        init: bool,
        /// Force-stage an extra library (soname or path), e.g. a dlopen'd plugin;
        /// repeatable.
        #[arg(long = "include", value_name = "LIB")]
        include: Vec<String>,
        /// Report format.
        #[arg(long, value_enum, default_value_t = Format::Text)]
        format: Format,
    },
    /// Report a binary's ELF hardening posture (PIE/RELRO/NX).
    Lint {
        /// Path to the binary to inspect.
        binary: PathBuf,
        /// Fail (non-zero) if a mitigation is missing; repeatable.
        #[arg(long = "fail-on", value_enum, value_name = "CHECK")]
        fail_on: Vec<crate::lint::Gate>,
    },
    /// Check for the external tools Scratchsmith can use (syft, cosign, ...).
    Doctor,
    /// Assemble per-arch images already pushed to a registry into a multi-arch image index
    /// (the daemonless `docker manifest create`).
    Index {
        /// The index reference to create and push, e.g. `ghcr.io/you/app:1.0`.
        target: String,
        /// Per-arch source images already in the target's registry (one or more), e.g.
        /// `ghcr.io/you/app:1.0-amd64 ghcr.io/you/app:1.0-arm64`.
        #[arg(required = true, num_args = 1..)]
        sources: Vec<String>,
        /// Sign the pushed index with cosign (keyless), by digest.
        #[arg(long)]
        sign: bool,
        /// Report format.
        #[arg(long, value_enum, default_value_t = Format::Text)]
        format: Format,
    },
}

/// Parse process arguments and run the chosen subcommand.
///
/// Clap handles `--help`/`--version` by printing and exiting before dispatch.
pub fn run() -> Result<()> {
    dispatch(Cli::parse())
}

// Write a shell completion script for `shell` to `out`. Split out so tests can
// capture the output into a buffer instead of stdout.
fn write_completions<W: std::io::Write>(shell: Shell, out: &mut W) {
    let mut cmd = Cli::command();
    let name = cmd.get_name().to_string();
    generate(shell.generator(), &mut cmd, name, out);
}

// Split from `run` so tests drive dispatch directly on a parsed `Cli`, without
// touching argv or spawning a process.
fn dispatch(cli: Cli) -> Result<()> {
    if let Some(shell) = cli.completions {
        // Fail loud rather than silently dropping a subcommand passed alongside.
        if cli.command.is_some() {
            bail!("--completions cannot be combined with a subcommand");
        }
        write_completions(shell, &mut std::io::stdout());
        return Ok(());
    }
    // `arg_required_else_help` prints help for an empty invocation before we get
    // here; any remaining `None` means flags were given without a subcommand.
    let Some(command) = cli.command else {
        bail!("no command given; run with --help to see available commands");
    };
    match command {
        Command::Pack {
            binary,
            config,
            profile,
            smoke,
            no_build,
            output,
            oci_archive,
            push,
            sign,
            entrypoint,
            cmd,
            env,
            workdir,
            user,
            label,
            healthcheck,
            strip,
            upx,
            max_size,
            sbom,
            sbom_file,
            sbom_format,
            scan,
            scan_fail_on,
            ca_certs,
            tz,
            init,
            include,
            format,
        } => {
            // Load the config file (if any), apply a selected profile, then let CLI flags win.
            let file = match &config {
                Some(path) => crate::config::Config::load(path)?,
                None => crate::config::Config::default(),
            };
            let file = match &profile {
                Some(name) => file.select_profile(name)?,
                None => file,
            };
            let Some(binary) = binary.or(file.binary) else {
                bail!(
                    "no binary to pack: pass one on the command line or set `binary` in --config"
                );
            };

            let opts = crate::pack::PackOptions {
                smoke: smoke || file.smoke,
                strip: strip || file.strip, // either source enabling an option is enough
                upx: upx || file.upx,
                sbom: (sbom || file.sbom).then(|| crate::supplychain::SbomRequest {
                    path: sbom_file
                        .or(file.sbom_file)
                        .unwrap_or_else(|| PathBuf::from("sbom.json")),
                    format: sbom_format
                        .or(file.sbom_format)
                        .unwrap_or(crate::supplychain::SbomFormat::CyclonedxJson),
                }),
                scan: {
                    let fail_on = scan_fail_on.or(file.scan_fail_on);
                    (scan || file.scan || fail_on.is_some())
                        .then_some(crate::supplychain::ScanRequest { fail_on })
                },
                extras: crate::stager::RuntimeExtras {
                    ca_certs: ca_certs || file.ca_certs,
                    tz: tz || file.tz,
                    init: init || file.init,
                },
                includes: if include.is_empty() {
                    file.include
                } else {
                    include
                },
                image: crate::image::ImageConfig {
                    entrypoint: entrypoint
                        .or(file.entrypoint)
                        .map(|e| vec![e])
                        .unwrap_or_default(),
                    cmd: if cmd.is_empty() { file.cmd } else { cmd },
                    env: if env.is_empty() { file.env } else { env },
                    workdir: workdir.or(file.workdir),
                    user: user.or(file.user),
                    labels: if label.is_empty() { file.label } else { label },
                    healthcheck: if healthcheck.is_empty() {
                        file.healthcheck
                    } else {
                        healthcheck
                    },
                },
                sign: sign || file.sign,
                max_size: max_size
                    .or(file.max_size)
                    .map(|s| crate::report::parse_size(&s))
                    .transpose()?,
            };

            // An explicit CLI delivery sink always wins; `push` from the config/profile is only
            // the default when no CLI sink flag was given — otherwise a `[profile.ci]` `push`
            // would silently override `--oci-archive`/`--no-build` and turn a local pack into a
            // registry publish.
            let sink = if let Some(reference) = push {
                crate::pack::Sink::Push(reference)
            } else if let Some(archive) = oci_archive {
                crate::pack::Sink::OciArchive(archive)
            } else if no_build {
                // clap guarantees output is present when no_build is set.
                crate::pack::Sink::Rootfs(output.expect("--no-build requires --output"))
            } else if let Some(reference) = file.push {
                crate::pack::Sink::Push(reference)
            } else {
                crate::pack::Sink::DockerLoad
            };
            // Signing needs a registry image (cosign signs by digest); a profile that set `sign`
            // without a push target would otherwise be silently dropped.
            if opts.sign && !matches!(sink, crate::pack::Sink::Push(_)) {
                bail!(
                    "--sign needs a push target — pass --push or set `push` in the config/profile"
                );
            }
            let report = crate::pack::pack(&binary, &opts, sink)?;

            match format {
                Format::Text => println!("{}", report.to_text()),
                Format::Json => println!("{}", serde_json::to_string_pretty(&report)?),
            }
            Ok(())
        }
        Command::Doctor => crate::doctor::run(),
        Command::Lint { binary, fail_on } => crate::lint::run(&binary, &fail_on),
        Command::Index {
            target,
            sources,
            sign,
            format,
        } => {
            let outcome = crate::registry::push_index(&target, &sources)?;
            let signed = if sign {
                // cosign signs a registry image by digest; the push must have returned one.
                let dref = outcome.digest_ref.clone().context(
                    "cannot sign: the registry did not return a digest for the pushed index",
                )?;
                crate::supplychain::cosign_sign(&dref)?;
                Some(dref)
            } else {
                None
            };
            let report = crate::report::IndexReport {
                pushed: target,
                manifests: outcome
                    .entries
                    .into_iter()
                    .map(|e| crate::report::IndexManifest {
                        source: e.source,
                        platform: e.platform,
                        digest: e.digest,
                    })
                    .collect(),
                signed,
            };
            match format {
                Format::Text => println!("{}", report.to_text()),
                Format::Json => println!("{}", serde_json::to_string_pretty(&report)?),
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::error::ErrorKind;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_valid() {
        // Catches malformed clap attributes (arg conflicts, bad names) at test time.
        Cli::command().debug_assert();
    }

    #[test]
    fn pack_parses_binary_path_and_smoke_flag() {
        let cli = Cli::try_parse_from(["scratchsmith", "pack", "--smoke", "/bin/ls"]).unwrap();
        match cli.command {
            Some(Command::Pack { binary, smoke, .. }) => {
                assert_eq!(binary, Some(PathBuf::from("/bin/ls")));
                assert!(smoke);
            }
            other => panic!("expected Pack, got {other:?}"),
        }
    }

    #[test]
    fn pack_parses_no_build_with_output() {
        let cli =
            Cli::try_parse_from(["scratchsmith", "pack", "-n", "-o", "out", "/bin/ls"]).unwrap();
        match cli.command {
            Some(Command::Pack {
                no_build, output, ..
            }) => {
                assert!(no_build);
                assert_eq!(output, Some(PathBuf::from("out")));
            }
            other => panic!("expected Pack, got {other:?}"),
        }
    }

    #[test]
    fn no_build_requires_output() {
        // -n without -o is a usage error (clap `requires`).
        let err = Cli::try_parse_from(["scratchsmith", "pack", "-n", "/bin/ls"]).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::MissingRequiredArgument);
    }

    #[test]
    fn pack_parses_scan_flags() {
        let cli = Cli::try_parse_from([
            "scratchsmith",
            "pack",
            "--scan",
            "--scan-fail-on",
            "high",
            "/bin/ls",
        ])
        .unwrap();
        // `matches!` (not a match arm) so there is no unreachable panic branch to leave uncovered.
        assert!(matches!(
            cli.command,
            Some(Command::Pack {
                scan: true,
                scan_fail_on: Some(crate::supplychain::Severity::High),
                ..
            })
        ));
    }

    #[test]
    fn sign_requires_push() {
        // --sign signs a registry image by digest, so it needs --push.
        let err = Cli::try_parse_from(["scratchsmith", "pack", "--sign", "/bin/ls"]).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::MissingRequiredArgument);
    }

    #[test]
    fn sign_with_push_parses() {
        let cli = Cli::try_parse_from([
            "scratchsmith",
            "pack",
            "--push",
            "ghcr.io/you/app:latest",
            "--sign",
            "/bin/ls",
        ])
        .unwrap();
        match cli.command {
            Some(Command::Pack { sign, push, .. }) => {
                assert!(sign);
                assert_eq!(push, Some("ghcr.io/you/app:latest".into()));
            }
            other => panic!("expected Pack, got {other:?}"),
        }
    }

    #[test]
    fn smoke_conflicts_with_no_build() {
        let err = Cli::try_parse_from([
            "scratchsmith",
            "pack",
            "-n",
            "-o",
            "out",
            "--smoke",
            "/bin/ls",
        ])
        .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::ArgumentConflict);
    }

    #[test]
    fn lint_parses_binary_path() {
        let cli = Cli::try_parse_from(["scratchsmith", "lint", "/bin/ls"]).unwrap();
        match cli.command {
            Some(Command::Lint { binary, .. }) => assert_eq!(binary, PathBuf::from("/bin/ls")),
            other => panic!("expected Lint, got {other:?}"),
        }
    }

    #[test]
    fn doctor_parses_with_no_args() {
        let cli = Cli::try_parse_from(["scratchsmith", "doctor"]).unwrap();
        assert!(matches!(cli.command, Some(Command::Doctor)));
    }

    #[test]
    fn missing_subcommand_is_an_error() {
        // A subcommand is required, so clap renders help and reports failure.
        let err = Cli::try_parse_from(["scratchsmith"]).unwrap_err();
        assert_eq!(
            err.kind(),
            ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
        );
    }

    #[test]
    fn unknown_subcommand_is_an_error() {
        let err = Cli::try_parse_from(["scratchsmith", "bogus"]).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidSubcommand);
    }

    #[test]
    fn pack_without_binary_or_config_errors_at_dispatch() {
        // binary is now optional at parse (config may supply it); the requirement is
        // enforced at dispatch with a clear message.
        let cli = Cli::try_parse_from(["scratchsmith", "pack"]).unwrap();
        let err = dispatch(cli).unwrap_err();
        assert!(err.to_string().contains("no binary to pack"));
    }

    #[test]
    fn version_flag_short_circuits_parsing() {
        let err = Cli::try_parse_from(["scratchsmith", "--version"]).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::DisplayVersion);
    }

    #[test]
    fn help_flag_short_circuits_parsing() {
        let err = Cli::try_parse_from(["scratchsmith", "--help"]).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::DisplayHelp);
    }

    #[test]
    fn help_lists_all_subcommands() {
        let help = Cli::command().render_help().to_string();
        assert!(help.contains("pack"), "help missing pack: {help}");
        assert!(help.contains("lint"), "help missing lint: {help}");
        assert!(help.contains("doctor"), "help missing doctor: {help}");
        assert!(help.contains("index"), "help missing index: {help}");
    }

    #[test]
    fn lint_runs_on_a_real_binary() {
        // /bin/sh is a real dynamic ELF everywhere the tests run.
        let cli = Cli::try_parse_from(["scratchsmith", "lint", "/bin/sh"]).unwrap();
        assert!(dispatch(cli).is_ok());
    }

    #[test]
    fn doctor_runs_and_succeeds() {
        let cli = Cli::try_parse_from(["scratchsmith", "doctor"]).unwrap();
        assert!(dispatch(cli).is_ok(), "doctor always exits 0");
    }

    #[test]
    fn index_parses_target_sources_and_sign() {
        let cli = Cli::try_parse_from([
            "scratchsmith",
            "index",
            "ghcr.io/you/app:1.0",
            "ghcr.io/you/app:1.0-amd64",
            "ghcr.io/you/app:1.0-arm64",
            "--sign",
        ])
        .unwrap();
        match cli.command {
            Some(Command::Index {
                target,
                sources,
                sign,
                ..
            }) => {
                assert_eq!(target, "ghcr.io/you/app:1.0");
                assert_eq!(
                    sources,
                    ["ghcr.io/you/app:1.0-amd64", "ghcr.io/you/app:1.0-arm64"]
                );
                assert!(sign);
            }
            other => panic!("expected Index, got {other:?}"),
        }
    }

    #[test]
    fn index_requires_at_least_one_source() {
        // Only a target, no sources: the single positional fills `target`, leaving the
        // required variadic `sources` empty -> a clap usage error.
        let err =
            Cli::try_parse_from(["scratchsmith", "index", "ghcr.io/you/app:1.0"]).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::MissingRequiredArgument);
    }

    #[test]
    fn completions_flag_parses_without_a_subcommand() {
        let cli = Cli::try_parse_from(["scratchsmith", "--completions", "zsh"]).unwrap();
        assert_eq!(cli.completions, Some(Shell::Zsh));
        assert!(cli.command.is_none());
    }

    #[test]
    fn completions_with_a_subcommand_is_an_error() {
        // Fail loud instead of silently dropping the subcommand. This also keeps
        // the dispatch completions branch tested without spraying a script onto
        // the test's stdout (generation itself is covered by the buffer test).
        let cli = Cli::try_parse_from(["scratchsmith", "--completions", "fish", "doctor"]).unwrap();
        let err = dispatch(cli).unwrap_err();
        assert!(err
            .to_string()
            .contains("cannot be combined with a subcommand"));
    }

    #[test]
    fn completions_emit_a_script_for_each_supported_shell() {
        for shell in [Shell::Bash, Shell::Zsh, Shell::Fish] {
            let mut buf = Vec::new();
            write_completions(shell, &mut buf);
            let script = String::from_utf8(buf).unwrap();
            assert!(
                script.contains("scratchsmith"),
                "{shell:?} completion script missing the binary name"
            );
        }
    }
}
