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
        Command::Pack { binary } => {
            let tag = crate::pack::run(&binary)?;
            println!("loaded image {tag}");
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
    fn pack_parses_binary_path() {
        let cli = Cli::try_parse_from(["scratchsmith", "pack", "/bin/ls"]).unwrap();
        match cli.command {
            Command::Pack { binary } => assert_eq!(binary, PathBuf::from("/bin/ls")),
            other => panic!("expected Pack, got {other:?}"),
        }
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
