#![no_main]
use libfuzzer_sys::fuzz_target;

// Fuzz the untrusted-ELF parsing path: arbitrary bytes -> dynamic-linking facts. Scratchsmith
// is a "point it at any binary" tool, so a malformed ELF must return an error, never panic.
fuzz_target!(|data: &[u8]| {
    let _ = scratchsmith::resolver::parse_elf_info(data);
});
