#![no_main]
use libfuzzer_sys::fuzz_target;

// Fuzz the untrusted-ELF parsing path: arbitrary bytes -> dynamic-linking facts. Scratchsmith
// is a "point it at any binary" tool, so a malformed ELF must return an error, never panic.
fuzz_target!(|data: &[u8]| {
    if let Ok(info) = scratchsmith::resolver::parse_elf_info(data) {
        // Also drive the accessors that classify the parsed (untrusted) facts.
        let _ = info.linking();
        let _ = info.is_musl();
        // The musl rejection quotes PT_INTERP, and main prints it to the user's terminal. It
        // may not carry a character that breaks or reorders a line: a Cc control, a line or
        // paragraph separator, a bidi embedding, override or isolate. The set the escape uses.
        if let Err(err) = scratchsmith::resolver::ensure_glibc(&info) {
            let breaks_a_line = |c: char| {
                c.is_control()
                    || matches!(
                        c,
                        '\u{2028}' | '\u{2029}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'
                    )
            };
            let text = format!("{err:#}");
            assert!(
                !text.chars().any(breaks_a_line),
                "the musl rejection carries a character that breaks a line: {text:?}"
            );
        }
    }
});
