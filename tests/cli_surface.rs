//! Golden snapshot of the **full CLI surface** — every subcommand and every flag with its
//! short alias, whether it takes a value, its default, whether it's required, and its enum
//! values. This pins the v1.0 CLI contract: a removed or renamed flag, a dropped short
//! alias, a changed default, a flipped required-ness, or a removed enum value all change
//! this snapshot and fail the test — forcing a conscious review (and a major bump if the
//! change is breaking). See `COMPATIBILITY.md`.
//!
//! After an INTENTIONAL, reviewed surface change, regenerate the golden:
//!   BLESS=1 cargo test --test cli_surface
//! and confirm in review that the diff is additive (minor) or a deliberate major change.

use clap::{ArgAction, CommandFactory};
use scratchsmith::cli::Cli;

// Render one command's args in a stable, sorted, contract-relevant form. clap's own
// auto-generated `--help`/`--version` are skipped: they are clap-managed and would churn
// the snapshot across clap versions without reflecting our surface.
fn render(cmd: &clap::Command, out: &mut String) {
    let mut args: Vec<_> = cmd
        .get_arguments()
        .filter(|a| !matches!(a.get_id().as_str(), "help" | "version"))
        .collect();
    args.sort_by_key(|a| a.get_id().as_str().to_string());
    for a in args {
        let name = match a.get_long() {
            Some(long) => format!("--{long}"),
            None => format!("<{}>", a.get_id()), // positional
        };
        let short = a.get_short().map(|c| format!(" -{c}")).unwrap_or_default();
        // The action is the contract truth: Set/Append take a value; SetTrue/SetFalse/Count
        // are valueless flags. (`num_args` is usually unset, so it can't be trusted here.)
        let action = a.get_action();
        let takes_value = matches!(action, ArgAction::Set | ArgAction::Append);
        let multiple = matches!(action, ArgAction::Append)
            || a.get_num_args()
                .map(|r| r.max_values() > 1)
                .unwrap_or(false);
        let required = a.is_required_set();
        let defaults: Vec<String> = a
            .get_default_values()
            .iter()
            .map(|v| v.to_string_lossy().into_owned())
            .collect();
        // Enum values only for value-taking args — a boolean flag's clap-internal
        // `[true,false]` possible values are not part of our surface.
        let values: Vec<String> = if takes_value {
            a.get_possible_values()
                .iter()
                .map(|p| p.get_name().to_string())
                .collect()
        } else {
            Vec::new()
        };

        out.push_str(&format!(
            "  {name}{short}  value={takes_value}  multiple={multiple}  required={required}"
        ));
        if !defaults.is_empty() {
            out.push_str(&format!("  default={}", defaults.join(",")));
        }
        if !values.is_empty() {
            out.push_str(&format!("  values=[{}]", values.join(",")));
        }
        out.push('\n');
    }
}

// The whole surface: top-level flags, then each subcommand (sorted) with its flags.
fn dump() -> String {
    let cmd = Cli::command();
    let mut out = String::from("[scratchsmith]\n");
    render(&cmd, &mut out);
    let mut subs: Vec<_> = cmd.get_subcommands().collect();
    subs.sort_by_key(|c| c.get_name().to_string());
    for sub in subs {
        out.push_str(&format!("\n[{}]\n", sub.get_name()));
        render(sub, &mut out);
    }
    out
}

#[test]
fn cli_surface_matches_the_golden_snapshot() {
    let actual = dump();
    let golden = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/cli_surface.txt");

    if std::env::var_os("BLESS").is_some() {
        std::fs::write(golden, &actual).expect("writing the golden snapshot");
        return;
    }

    let expected = std::fs::read_to_string(golden).unwrap_or_default();
    assert_eq!(
        actual, expected,
        "\n\nCLI surface changed vs tests/cli_surface.txt.\n\
         If this is an INTENTIONAL, reviewed change:\n  \
         1. Confirm whether it is BREAKING (a removed/renamed flag, a dropped short alias, a\n     \
            changed default, a newly-required flag, or a removed enum value) — those are\n     \
            major changes and need the deprecation cycle in COMPATIBILITY.md.\n  \
         2. Regenerate the golden: BLESS=1 cargo test --test cli_surface\n"
    );
}
