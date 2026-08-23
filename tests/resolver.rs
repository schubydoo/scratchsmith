//! Parse a real, guaranteed-present dynamic binary: the scratchsmith binary itself.
//! Synthetic fixtures with crafted RPATH/RUNPATH/$ORIGIN layouts come with Task 1.8;
//! this proves the parser reads a genuine glibc-linked executable.

use scratchsmith::resolver::{read_elf_info, resolve, Linking, Sysroot};
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

#[test]
fn resolves_a_real_binary_against_the_host() {
    // End-to-end: the goblin-backed resolver walks the real dep tree of the
    // scratchsmith binary against the host root. On a glibc host this closes fully.
    let bin = Path::new(env!("CARGO_BIN_EXE_scratchsmith"));
    let res = resolve(bin, &Sysroot::new("/")).expect("resolution should not error");

    let interp = res.interpreter.expect("loader should resolve");
    assert!(
        interp.source.exists(),
        "loader source should be a real file"
    );
    assert!(
        interp.image_path.is_absolute(),
        "loader image path should be the absolute PT_INTERP location"
    );
    assert!(
        res.libs.iter().any(|l| l.soname.contains("libc")),
        "libc should be in the resolved set: {:?}",
        res.libs.iter().map(|l| &l.soname).collect::<Vec<_>>()
    );
    assert!(
        res.missing.is_empty(),
        "all deps should resolve on a normal host, missing: {:?}",
        res.missing
    );
    assert!(
        res.libs.iter().all(|l| l.path.exists()),
        "every resolved lib should be a real file"
    );
}
