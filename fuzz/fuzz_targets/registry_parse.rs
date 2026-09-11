#![no_main]
//! Fuzz the registry response parsers: `registry::parse_child_manifest`,
//! `registry::parse_child_config`, and `registry::select_token`. A registry and a token host
//! can serve arbitrary bytes, so these three JSON parses sit on the untrusted-input boundary.
//! One input drives all three; the target asserts no panic.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = scratchsmith::registry::parse_child_manifest(data, "fuzz");
    let _ = scratchsmith::registry::parse_child_config(data, "fuzz");
    let _ = scratchsmith::registry::select_token(data, "fuzz");
});
