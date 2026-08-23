//! Resolve a binary's shared-library deps by emulating the `ld.so` search order
//! (not by scraping host `ldd`). The correctness core; see Tasks 1.2-1.3.
//!
//! This file covers Task 1.2: read the raw dynamic-linking facts from an ELF. The
//! search-order emulation that turns sonames into real paths lands in Task 1.3.

use anyhow::{Context, Result};
use std::path::Path;

/// How a binary is linked — decides whether it needs dependency staging at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Linking {
    /// Needs an interpreter and/or shared libraries staged.
    Dynamic,
    /// Self-contained; packs as a single file with no dependency resolution.
    Static,
}

/// Dynamic-linking facts read straight from an ELF, before any path resolution.
///
/// RPATH and RUNPATH are kept separate on purpose: they differ in search
/// precedence and scope, and conflating them is the classic resolution bug —
/// RUNPATH is not inherited by a library's own dependencies (see Task 1.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElfInfo {
    /// Program interpreter (PT_INTERP) — the dynamic loader. Absent for static
    /// binaries and shared objects. Not listed in DT_NEEDED, so it must be staged
    /// explicitly; omitting it is the "exit 127 in an empty container" bug.
    pub interpreter: Option<String>,
    /// DT_NEEDED: direct shared-library dependencies, by soname.
    pub needed: Vec<String>,
    /// DT_RPATH: deprecated search paths; searched transitively, only when no RUNPATH.
    pub rpaths: Vec<String>,
    /// DT_RUNPATH: object-local search paths; not inherited by this object's deps.
    pub runpaths: Vec<String>,
    /// DT_SONAME: this object's own soname, if it declares one.
    pub soname: Option<String>,
}

impl ElfInfo {
    /// A binary is static when it has neither an interpreter nor any DT_NEEDED
    /// entries — nothing to resolve, so it packs as a single file.
    pub fn linking(&self) -> Linking {
        if self.interpreter.is_none() && self.needed.is_empty() {
            Linking::Static
        } else {
            Linking::Dynamic
        }
    }
}

/// Read an ELF file and extract its dynamic-linking facts.
pub fn read_elf_info(path: &Path) -> Result<ElfInfo> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    parse_elf_info(&bytes).with_context(|| format!("parsing {} as ELF", path.display()))
}

// Split from `read_elf_info` so parsing is unit-testable on in-memory bytes.
fn parse_elf_info(bytes: &[u8]) -> Result<ElfInfo> {
    let elf = goblin::elf::Elf::parse(bytes).context("not a valid ELF binary")?;
    Ok(ElfInfo {
        interpreter: elf.interpreter.map(str::to_owned),
        needed: elf.libraries.iter().map(|s| s.to_string()).collect(),
        rpaths: elf.rpaths.iter().map(|s| s.to_string()).collect(),
        runpaths: elf.runpaths.iter().map(|s| s.to_string()).collect(),
        soname: elf.soname.map(str::to_owned),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(interpreter: Option<&str>, needed: &[&str]) -> ElfInfo {
        ElfInfo {
            interpreter: interpreter.map(str::to_owned),
            needed: needed.iter().map(|s| s.to_string()).collect(),
            rpaths: vec![],
            runpaths: vec![],
            soname: None,
        }
    }

    #[test]
    fn no_interpreter_and_no_needed_is_static() {
        assert_eq!(info(None, &[]).linking(), Linking::Static);
    }

    #[test]
    fn an_interpreter_means_dynamic() {
        assert_eq!(
            info(Some("/lib64/ld-linux-x86-64.so.2"), &[]).linking(),
            Linking::Dynamic
        );
    }

    #[test]
    fn needed_libs_mean_dynamic_even_without_an_interpreter() {
        // A shared object has DT_NEEDED but no PT_INTERP; it still needs resolution.
        assert_eq!(info(None, &["libc.so.6"]).linking(), Linking::Dynamic);
    }

    #[test]
    fn rpath_and_runpath_are_kept_distinct() {
        let elf = ElfInfo {
            interpreter: None,
            needed: vec![],
            rpaths: vec!["/opt/rpath".into()],
            runpaths: vec!["/opt/runpath".into()],
            soname: None,
        };
        assert_eq!(elf.rpaths, vec!["/opt/rpath".to_string()]);
        assert_eq!(elf.runpaths, vec!["/opt/runpath".to_string()]);
        assert_ne!(elf.rpaths, elf.runpaths);
    }

    #[test]
    fn non_elf_bytes_are_rejected() {
        let err = parse_elf_info(b"not an elf at all").unwrap_err();
        assert!(err.to_string().contains("ELF"));
    }
}
