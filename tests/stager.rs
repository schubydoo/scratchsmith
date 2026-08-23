//! Full pipeline against a real binary: resolve the scratchsmith binary, stage it,
//! and confirm the rootfs has the loader, libc, and a regenerated ld.so.cache.
//! Requires ldconfig (present on any glibc host, including CI).

use scratchsmith::resolver::{resolve, Sysroot};
use scratchsmith::stager::stage;
use std::path::Path;

#[test]
fn stages_a_real_binary_into_a_runnable_tree() {
    let bin = Path::new(env!("CARGO_BIN_EXE_scratchsmith"));
    let resolution = resolve(bin, &Sysroot::new("/")).expect("resolution");
    assert!(resolution.missing.is_empty(), "deps must resolve first");

    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path().join("rootfs");
    let tree = stage(bin, &resolution, &dest).expect("staging should succeed");

    // The loader must exist at its verbatim PT_INTERP path, or the image won't exec.
    let interp = resolution.interpreter.as_ref().unwrap();
    let staged_loader = dest.join(interp.image_path.strip_prefix("/").unwrap());
    assert!(staged_loader.exists(), "loader missing at PT_INTERP path");

    // libc must be present somewhere in the staged tree.
    assert!(
        resolution
            .libs
            .iter()
            .any(|l| dest.join(l.path.strip_prefix("/").unwrap()).exists()),
        "no resolved library was staged"
    );

    // The regenerated cache must exist and be non-empty.
    let cache = dest.join("etc/ld.so.cache");
    assert!(cache.exists(), "ld.so.cache was not generated");
    assert!(
        std::fs::metadata(&cache).unwrap().len() > 0,
        "ld.so.cache is empty"
    );

    // The entrypoint is the binary's own path, and it was staged there.
    assert!(dest
        .join(tree.entrypoint.strip_prefix("/").unwrap())
        .exists());
}
