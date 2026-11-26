#![no_main]
use libfuzzer_sys::fuzz_target;

// Fuzz the symbol-version read behind the glibc version warning: arbitrary bytes -> the
// DT_VERNEED and DT_VERDEF names. A malformed version section must return an error, never
// panic, and every name it yields must order or refuse without panicking.
fuzz_target!(|data: &[u8]| {
    if let Ok(versions) = scratchsmith::resolver::symbol_versions(data) {
        for (_, version) in &versions.needed {
            let _ = scratchsmith::resolver::glibc_release(version);
        }
        for version in &versions.defined {
            let _ = scratchsmith::resolver::glibc_release(version);
        }
    }
});
