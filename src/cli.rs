//! Command-line surface and dispatch.

use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "scratchsmith", version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Pack a dynamic ELF binary into a minimal scratch image.
    Pack {
        /// Path to the dynamically linked binary to pack.
        binary: PathBuf,
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
    },
    /// Report a binary's ELF hardening posture (PIE/RELRO/NX).
    Lint {
        /// Path to the binary to inspect.
        binary: PathBuf,
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

// Split from `run` so tests drive dispatch directly on a parsed `Cli`, without
// touching argv or spawning a process.
fn dispatch(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Pack {
            binary,
            smoke,
            no_build,
            output,
            entrypoint,
            cmd,
            env,
            workdir,
        } => {
            if no_build {
                // clap guarantees output is present when no_build is set.
                let dir = output.expect("--no-build requires --output");
                let tree = crate::pack::stage_only(&binary, &dir)?;
                println!("staged to {}", tree.root.display());
            } else {
                let cfg = crate::image::ImageConfig {
                    entrypoint: entrypoint.map(|e| vec![e]).unwrap_or_default(),
                    cmd,
                    env,
                    workdir,
                };
                let tag = crate::pack::run(&binary, smoke, &cfg)?;
                println!("loaded image {tag}");
            }
            Ok(())
        }
        // Lint and doctor are still stubbed; fail loudly rather than exit 0 so a stub
        // is never mistaken for a working command.
        Command::Lint { .. } => bail!("lint: not yet implemented"),
        Command::Doctor => bail!("doctor: not yet implemented"),
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
            Command::Pack { binary, smoke, .. } => {
                assert_eq!(binary, PathBuf::from("/bin/ls"));
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
            Command::Pack {
                no_build, output, ..
            } => {
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
            Command::Lint { binary } => assert_eq!(binary, PathBuf::from("/bin/ls")),
            other => panic!("expected Lint, got {other:?}"),
        }
    }

    #[test]
    fn doctor_parses_with_no_args() {
        let cli = Cli::try_parse_from(["scratchsmith", "doctor"]).unwrap();
        assert!(matches!(cli.command, Command::Doctor));
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
    fn pack_requires_a_binary_argument() {
        let err = Cli::try_parse_from(["scratchsmith", "pack"]).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::MissingRequiredArgument);
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
    fn lint_stub_fails_loudly() {
        let cli = Cli::try_parse_from(["scratchsmith", "lint", "/bin/ls"]).unwrap();
        let err = dispatch(cli).unwrap_err();
        assert!(err.to_string().contains("lint: not yet implemented"));
    }

    #[test]
    fn doctor_stub_fails_loudly() {
        let cli = Cli::try_parse_from(["scratchsmith", "doctor"]).unwrap();
        let err = dispatch(cli).unwrap_err();
        assert!(err.to_string().contains("doctor: not yet implemented"));
    }
}
