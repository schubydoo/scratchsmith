//! Command-line surface and dispatch.

use anyhow::{bail, Result};
use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use clap_complete::{generate, Shell};
use std::path::PathBuf;

/// Output format for the pack report.
#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum Format {
    Text,
    Json,
}

#[derive(Parser, Debug)]
#[command(name = "scratchsmith", version, about, long_about = None)]
// A completion dump needs no subcommand, so the subcommand is optional; an empty
// invocation still prints help rather than doing nothing.
#[command(arg_required_else_help = true)]
pub struct Cli {
    /// Emit a shell completion script to stdout and exit (bash, zsh, fish, ...).
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
        /// After loading, run the image once and fail if the binary can't start.
        #[arg(long, conflicts_with = "no_build")]
        smoke: bool,
        /// Stage the rootfs only; build no image. Requires --output.
        #[arg(short = 'n', long, requires = "output")]
        no_build: bool,
        /// Directory to stage into (with --no-build).
        #[arg(short = 'o', long, value_name = "DIR", requires = "no_build")]
        output: Option<PathBuf>,
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
        /// Strip symbols from the binary and libraries (strip --strip-unneeded).
        #[arg(long)]
        strip: bool,
        /// Generate an SBOM of the packed rootfs (requires syft).
        #[arg(long)]
        sbom: bool,
        /// SBOM output path (with --sbom).
        #[arg(long = "sbom-file", value_name = "FILE", default_value = "sbom.json")]
        sbom_file: PathBuf,
        /// SBOM format (with --sbom).
        #[arg(long = "sbom-format", value_enum, default_value_t = crate::supplychain::SbomFormat::CyclonedxJson)]
        sbom_format: crate::supplychain::SbomFormat,
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
    generate(shell, &mut cmd, name, out);
}

// Split from `run` so tests drive dispatch directly on a parsed `Cli`, without
// touching argv or spawning a process.
fn dispatch(cli: Cli) -> Result<()> {
    if let Some(shell) = cli.completions {
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
            smoke,
            no_build,
            output,
            entrypoint,
            cmd,
            env,
            workdir,
            user,
            strip,
            sbom,
            sbom_file,
            sbom_format,
            ca_certs,
            tz,
            init,
            include,
            format,
        } => {
            // Load the config file (if any), then let CLI flags override its values.
            let file = match &config {
                Some(path) => crate::config::Config::load(path)?,
                None => crate::config::Config::default(),
            };
            let Some(binary) = binary.or(file.binary) else {
                bail!(
                    "no binary to pack: pass one on the command line or set `binary` in --config"
                );
            };

            let opts = crate::pack::PackOptions {
                smoke,
                strip: strip || file.strip, // either source enabling strip is enough
                sbom: sbom.then_some(crate::supplychain::SbomRequest {
                    path: sbom_file,
                    format: sbom_format,
                }),
                extras: crate::stager::RuntimeExtras { ca_certs, tz, init },
                includes: include,
                image: crate::image::ImageConfig {
                    entrypoint: entrypoint
                        .or(file.entrypoint)
                        .map(|e| vec![e])
                        .unwrap_or_default(),
                    cmd: if cmd.is_empty() { file.cmd } else { cmd },
                    env: if env.is_empty() { file.env } else { env },
                    workdir: workdir.or(file.workdir),
                    user: user.or(file.user),
                },
            };

            let report = if no_build {
                // clap guarantees output is present when no_build is set.
                let dir = output.expect("--no-build requires --output");
                crate::pack::stage_only(&binary, &dir, &opts)?
            } else {
                crate::pack::run(&binary, &opts)?
            };

            match format {
                Format::Text => println!("{}", report.to_text()),
                Format::Json => println!("{}", serde_json::to_string_pretty(&report)?),
            }
            Ok(())
        }
        Command::Doctor => crate::doctor::run(),
        Command::Lint { binary, fail_on } => crate::lint::run(&binary, &fail_on),
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
    fn help_lists_all_three_subcommands() {
        let help = Cli::command().render_help().to_string();
        assert!(help.contains("pack"), "help missing pack: {help}");
        assert!(help.contains("lint"), "help missing lint: {help}");
        assert!(help.contains("doctor"), "help missing doctor: {help}");
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
    fn completions_flag_parses_without_a_subcommand() {
        let cli = Cli::try_parse_from(["scratchsmith", "--completions", "zsh"]).unwrap();
        assert_eq!(cli.completions, Some(Shell::Zsh));
        assert!(cli.command.is_none());
    }

    #[test]
    fn dispatch_handles_completions_without_a_subcommand() {
        let cli = Cli::try_parse_from(["scratchsmith", "--completions", "fish"]).unwrap();
        assert!(dispatch(cli).is_ok());
    }

    #[test]
    fn completions_emit_a_script_for_each_supported_shell() {
        for shell in [Shell::Bash, Shell::Zsh, Shell::Fish] {
            let mut buf = Vec::new();
            write_completions(shell, &mut buf);
            let script = String::from_utf8(buf).unwrap();
            assert!(
                script.contains("scratchsmith"),
                "{shell} completion script missing the binary name"
            );
        }
    }
}
