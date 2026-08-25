#![no_main]
use libfuzzer_sys::fuzz_target;

// Fuzz the ELF hardening analysis (`lint`): arbitrary bytes -> PIE/RELRO/NX/canary/fortify.
// Must never panic on a malformed binary.
fuzz_target!(|data: &[u8]| {
    let _ = scratchsmith::lint::hardening_from_bytes(data);
});
