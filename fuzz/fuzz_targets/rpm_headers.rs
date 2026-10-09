#![no_main]
use libfuzzer_sys::fuzz_target;

// Fuzz the rpm header-list reader behind `--packages` on an rpm host. The bytes come from
// `rpmdb --exportdb` on the build host, so they are not hostile in the usual case, but this is
// a hand-written reader of a binary format with lengths and offsets in it: a damaged or
// truncated list must come back as an error, never as a read past the end or a panic.
fuzz_target!(|data: &[u8]| {
    let _ = scratchsmith::rpm::header_names(data);
});
