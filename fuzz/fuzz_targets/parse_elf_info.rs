#![no_main]
use libfuzzer_sys::fuzz_target;

// Fuzz the untrusted-ELF parsing path: arbitrary bytes -> dynamic-linking facts. Scratchsmith
// is a "point it at any binary" tool, so a malformed ELF must return an error, never panic.
fuzz_target!(|data: &[u8]| {
    if let Ok(info) = scratchsmith::resolver::parse_elf_info(data) {
        // Also drive the accessors that classify the parsed (untrusted) facts.
        let _ = info.linking();
        let _ = info.is_musl();
        let _ = scratchsmith::resolver::ensure_glibc(&info);
    }
});
