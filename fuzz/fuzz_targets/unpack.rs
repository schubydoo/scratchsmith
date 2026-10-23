#![no_main]
//! Fuzz the OCI-archive unpacker (`unpack::run`) — the untrusted-input boundary for an image you
//! did not build. Drives the tar reader, `index.json`/manifest JSON parsing, gzip layer
//! decompression, the whiteout string branching (`.wh.` / `.wh..wh..opq`), and the path-safety
//! that keeps extraction inside the target. The bytes are written to a throwaway archive file and
//! unpacked into a throwaway directory; the target asserts it never panics on an adversarial input
//! and that no error it returns can break a line of output.

use libfuzzer_sys::fuzz_target;
use std::io::Write;

fuzz_target!(|data: &[u8]| {
    let Ok(tmp) = tempfile::tempdir() else {
        return;
    };
    let archive = tmp.path().join("img.tar");
    let Ok(mut f) = std::fs::File::create(&archive) else {
        return;
    };
    if f.write_all(data).is_err() {
        return;
    }
    drop(f);
    // A fresh dir per run. Gzip layers are capped (unpack::MAX_LAYER_BYTES), so a small
    // highly-compressible input cannot expand without bound.
    let dest = tmp.path().join("out");
    // An error quotes text out of the archive (digests, media types, entry paths, tar's own
    // header text) and `main` prints it to the terminal. None may carry a character that
    // breaks or reorders a line, or the archive could forge a line of scratchsmith's output.
    // `is_control` is the Cc category only, so the separators and bidi overrides are listed.
    let breaks_a_line = |c: char| {
        c.is_control() || matches!(c, '\u{2028}' | '\u{2029}' | '\u{202a}'..='\u{202e}')
    };
    if let Err(err) = scratchsmith::unpack::run(&archive, &dest) {
        let shown = format!("{err:#}");
        assert!(
            !shown.chars().any(breaks_a_line),
            "an unpack error carries a character that breaks a line: {shown:?}"
        );
    }
});
