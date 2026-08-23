//! ELF hardening checks (PIE/RELRO/NX/canary/fortify) read from goblin. See Task 4.1.
//!
//! Each property is derived from the exact ELF structure that encodes it, so the
//! report matches what checksec-style tools show.

use anyhow::{Context, Result};
use goblin::elf::{dynamic, header, program_header, Elf};
use std::path::Path;

/// RELRO protects the GOT: `Partial` marks the relocations read-only after load,
/// `Full` also resolves them eagerly (BIND_NOW) so the GOT itself is read-only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum Relro {
    Full,
    Partial,
    None,
}

/// A binary's exploit-mitigation posture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct Hardening {
    /// Position-independent executable (ASLR for the main image).
    pub pie: bool,
    pub relro: Relro,
    /// Non-executable stack.
    pub nx: bool,
    /// Stack-smashing protector present.
    pub canary: bool,
    /// `_FORTIFY_SOURCE` buffer-overflow checks present.
    pub fortify: bool,
}

/// Analyze the hardening posture of the ELF at `path`.
pub fn analyze(path: &Path) -> Result<Hardening> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let elf = Elf::parse(&bytes).with_context(|| format!("parsing {}", path.display()))?;
    Ok(analyze_elf(&elf))
}

fn analyze_elf(elf: &Elf) -> Hardening {
    let flags = elf.dynamic.as_ref().map(|d| d.info.flags).unwrap_or(0);
    let flags_1 = elf.dynamic.as_ref().map(|d| d.info.flags_1).unwrap_or(0);

    // PIE: an ET_DYN executable that declares DF_1_PIE. ET_DYN alone is ambiguous
    // (a shared library is also ET_DYN), so the flag is what distinguishes a PIE.
    let pie = elf.header.e_type == header::ET_DYN && flags_1 & dynamic::DF_1_PIE != 0;

    // RELRO: the PT_GNU_RELRO segment makes relocations read-only; BIND_NOW upgrades
    // that to full RELRO by resolving the GOT eagerly.
    let has_relro = elf
        .program_headers
        .iter()
        .any(|ph| ph.p_type == program_header::PT_GNU_RELRO);
    let bind_now = flags & dynamic::DF_BIND_NOW != 0 || flags_1 & dynamic::DF_1_NOW != 0;
    let relro = match (has_relro, bind_now) {
        (true, true) => Relro::Full,
        (true, false) => Relro::Partial,
        (false, _) => Relro::None,
    };

    // NX: the PT_GNU_STACK segment's flags tell whether the stack is executable. No
    // such segment means the old executable-stack default, i.e. NX off.
    let nx = elf
        .program_headers
        .iter()
        .find(|ph| ph.p_type == program_header::PT_GNU_STACK)
        .is_some_and(|ph| ph.p_flags & program_header::PF_X == 0);

    let canary = has_dynsym(elf, |name| {
        name == "__stack_chk_fail" || name == "__stack_chk_guard"
    });
    // Fortified libc wrappers are named `*_chk` (e.g. __printf_chk, __memcpy_chk).
    let fortify = has_dynsym(elf, |name| name.ends_with("_chk"));

    Hardening {
        pie,
        relro,
        nx,
        canary,
        fortify,
    }
}

fn has_dynsym(elf: &Elf, pred: impl Fn(&str) -> bool) -> bool {
    elf.dynsyms
        .iter()
        .filter_map(|sym| elf.dynstrtab.get_at(sym.st_name))
        .any(pred)
}

impl std::fmt::Display for Hardening {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let yn = |b: bool| if b { "yes" } else { "no" };
        let relro = match self.relro {
            Relro::Full => "full",
            Relro::Partial => "partial",
            Relro::None => "none",
        };
        writeln!(f, "  PIE:     {}", yn(self.pie))?;
        writeln!(f, "  RELRO:   {relro}")?;
        writeln!(f, "  NX:      {}", yn(self.nx))?;
        writeln!(f, "  Canary:  {}", yn(self.canary))?;
        write!(f, "  Fortify: {}", yn(self.fortify))
    }
}

/// Analyze and print the hardening report (the `lint` subcommand).
pub fn run(binary: &Path) -> Result<()> {
    let hardening = analyze(binary)?;
    println!("{hardening}");
    Ok(())
}
