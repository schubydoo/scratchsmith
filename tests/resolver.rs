//! Parse a real, guaranteed-present dynamic binary: the scratchsmith binary itself.
//! Synthetic fixtures with crafted RPATH/RUNPATH/$ORIGIN layouts come with Task 1.8;
//! this proves the parser reads a genuine glibc-linked executable.

use scratchsmith::resolver::{read_elf_info, Linking};
use std::path::Path;

#[test]
fn reads_a_real_dynamic_binary() {
    let bin = Path::new(env!("CARGO_BIN_EXE_scratchsmith"));
    let info = read_elf_info(bin).expect("scratchsmith binary should parse as ELF");

    // A dynamically linked glibc executable has a loader and at least libc.
    assert_eq!(info.linking(), Linking::Dynamic);
    let interp = info.interpreter.expect("dynamic executable has PT_INTERP");
    assert!(interp.contains("ld-"), "unexpected interpreter: {interp}");
    assert!(
        info.needed.iter().any(|lib| lib.contains("libc")),
        "expected libc in DT_NEEDED, got: {:?}",
        info.needed
    );
}
