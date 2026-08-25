//! ELF hardening checks (PIE/RELRO/NX/canary/fortify) read from goblin. See Task 4.1.
//!
//! Each property is derived from the exact ELF structure that encodes it, so the
//! report matches what checksec-style tools show.

use anyhow::{bail, Context, Result};
use goblin::elf::{dynamic, header, program_header, Elf};
use std::path::Path;

/// A hardening weakness that can gate a build (`--fail-on`). Each variant fails when
/// the corresponding mitigation is missing (or, for `partial-relro`, not full).
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Gate {
    NoPie,
    NoRelro,
    PartialRelro,
    NoNx,
    NoCanary,
    NoFortify,
}

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

/// Analyze hardening from in-memory ELF bytes; `None` if the bytes are not a parseable ELF.
/// A byte-level entry point for fuzzing.
pub fn hardening_from_bytes(bytes: &[u8]) -> Option<Hardening> {
    Elf::parse(bytes).ok().map(|elf| analyze_elf(&elf))
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

impl Hardening {
    /// Which of the requested gates this binary violates.
    pub fn violations(&self, gates: &[Gate]) -> Vec<Gate> {
        gates
            .iter()
            .copied()
            .filter(|g| self.violates(*g))
            .collect()
    }

    fn violates(&self, gate: Gate) -> bool {
        match gate {
            Gate::NoPie => !self.pie,
            Gate::NoRelro => self.relro == Relro::None,
            Gate::PartialRelro => self.relro != Relro::Full,
            Gate::NoNx => !self.nx,
            Gate::NoCanary => !self.canary,
            Gate::NoFortify => !self.fortify,
        }
    }
}

fn gate_name(gate: Gate) -> String {
    use clap::ValueEnum;
    gate.to_possible_value()
        .map(|v| v.get_name().to_string())
        .unwrap_or_default()
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

/// Analyze and print the hardening report (the `lint` subcommand). When `gates` are
/// given, fail (non-zero) if any is violated, naming the offending checks — without
/// a gate, lint only reports and always succeeds.
pub fn run(binary: &Path, gates: &[Gate]) -> Result<()> {
    let hardening = analyze(binary)?;
    println!("{hardening}");

    let violations = hardening.violations(gates);
    if !violations.is_empty() {
        let names: Vec<String> = violations.into_iter().map(gate_name).collect();
        bail!("hardening gate failed: {}", names.join(", "));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strong() -> Hardening {
        Hardening {
            pie: true,
            relro: Relro::Full,
            nx: true,
            canary: true,
            fortify: true,
        }
    }

    #[test]
    fn each_gate_flags_its_own_weakness() {
        // A binary weak on NX/canary/fortify with only partial RELRO: every matching gate fires.
        let weak = Hardening {
            pie: true,
            relro: Relro::Partial,
            nx: false,
            canary: false,
            fortify: false,
        };
        let gates = [
            Gate::NoNx,
            Gate::NoCanary,
            Gate::NoFortify,
            Gate::PartialRelro,
        ];
        assert_eq!(weak.violations(&gates), gates.to_vec());
        // A strong binary violates none of them.
        assert!(strong().violations(&gates).is_empty());
    }

    #[test]
    fn display_renders_partial_relro_and_flags() {
        let partial = Hardening {
            pie: false,
            relro: Relro::Partial,
            nx: true,
            canary: false,
            fortify: true,
        };
        let out = partial.to_string();
        assert!(out.contains("RELRO:   partial"), "{out}");
        assert!(out.contains("PIE:     no"), "{out}");
        assert!(out.contains("NX:      yes"), "{out}");
        assert!(out.contains("Canary:  no"), "{out}");
        assert!(out.contains("Fortify: yes"), "{out}");
    }

    #[test]
    fn gates_flag_only_real_weaknesses() {
        let weak = Hardening {
            pie: false,
            relro: Relro::None,
            nx: false,
            canary: false,
            fortify: false,
        };
        assert_eq!(weak.violations(&[Gate::NoRelro]), vec![Gate::NoRelro]);
        assert!(strong()
            .violations(&[Gate::NoRelro, Gate::NoPie])
            .is_empty());
    }

    #[test]
    fn partial_relro_gate_requires_full() {
        let partial = Hardening {
            relro: Relro::Partial,
            ..strong()
        };
        assert_eq!(
            partial.violations(&[Gate::PartialRelro]),
            vec![Gate::PartialRelro]
        );
        assert!(strong().violations(&[Gate::PartialRelro]).is_empty());
    }

    #[test]
    fn gate_names_are_kebab_case() {
        assert_eq!(gate_name(Gate::NoRelro), "no-relro");
    }
}
