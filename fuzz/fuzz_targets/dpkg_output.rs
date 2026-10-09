#![no_main]
use libfuzzer_sys::fuzz_target;

// Fuzz the readers of `dpkg-query` output behind `--packages` on a dpkg host. The text comes
// from a tool on the build host, so it is not hostile in the usual case. But a package name
// from it becomes a file name under `var/lib/dpkg/status.d` in the image, and a path from it
// goes into the report, so the two properties below must hold for any text at all.
fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let (owners, records) = scratchsmith::packages::parse_dpkg_output(text);
    for (package, path) in &owners {
        assert!(safe_name(package), "owner name {package:?}");
        assert!(path.starts_with('/'), "owner path {path:?}");
    }
    for (i, file) in records.iter().enumerate() {
        // One path component, and never one with a meaning of its own.
        assert!(safe_name(file), "record file name {file:?}");
        assert!(
            !records[..i].contains(file),
            "record file name twice: {file:?}"
        );
    }
});

// What a name must be to be one file name: no separator, no NUL, not `.` or `..`, and at
// most one `:` (the architecture qualifier), which splits it into two parts with that rule.
fn safe_name(name: &str) -> bool {
    let part =
        |p: &str| !p.is_empty() && p != "." && p != ".." && !p.contains(['/', '\0', ':', '\n']);
    match name.split_once(':') {
        Some((a, b)) => part(a) && part(b),
        None => part(name),
    }
}
