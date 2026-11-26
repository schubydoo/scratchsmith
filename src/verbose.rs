//! `--verbose`: one stderr line for each resolver and stager decision. Off by default, so
//! a run without the flag prints exactly what it printed before (TASK-011).
//!
//! A plain switch, not the `tracing` crate: the lines are for a person reading one run, and
//! a subscriber would add dependencies to the musl build for no line a user could not read.

use std::sync::atomic::{AtomicBool, Ordering};

static ON: AtomicBool = AtomicBool::new(false);

/// Turn the decision lines on or off for the rest of the process.
pub fn set(on: bool) {
    ON.store(on, Ordering::Relaxed);
}

/// Whether `--verbose` is on.
pub fn on() -> bool {
    ON.load(Ordering::Relaxed)
}

/// Print `verbose: <line>` on stderr when `--verbose` is on. The line is built only then.
/// It names paths and sonames out of the packed ELF, so it is escaped: no name can break the
/// line or forge another one.
pub fn line(build: impl FnOnce() -> String) {
    if on() {
        eprintln!("verbose: {}", format_line(&build()));
    }
}

fn format_line(text: &str) -> std::borrow::Cow<'_, str> {
    crate::resolver::escape_if_line_breaking(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_line_out_of_an_elf_cannot_break_the_output() {
        let shown = format_line("needs `libx.so\nerror: forged`");
        assert!(!shown.contains('\n'), "{shown}");
    }

    #[test]
    fn nothing_is_built_while_off() {
        // Tests share the process, so only read the switch here: no test turns it on.
        assert!(!on());
        line(|| unreachable!("the line is built only when --verbose is on"));
    }
}
