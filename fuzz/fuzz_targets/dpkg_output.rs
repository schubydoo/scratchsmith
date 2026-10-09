#![no_main]
use libfuzzer_sys::fuzz_target;

// Fuzz the readers of `dpkg-query` output behind `--packages` on a dpkg host. The text comes
// from a tool on the build host, so it is not hostile in the usual case. But a package name
// from it becomes a file name under `var/lib/dpkg/status.d` in the image, an argument to the
// next `dpkg-query` call, and a line of the report. So every name must be one safe path
// component, for any text at all.
fuzz_target!(|data: &[u8]| {
    // The same conversion as the real reader, which never rejects a byte.
    let text = String::from_utf8_lossy(data);
    let parsed = scratchsmith::packages::parse_dpkg_output(&text);
    for (package, _path) in &parsed.owners {
        // The path is not judged here. What keeps a forged path out of the report is the
        // filter in `packages::search`, which keeps only a path that was asked for, and a
        // text-level entry point does not reach it.
        assert!(safe_name(package), "owner name {package:?}");
    }
    for name in &parsed.names {
        assert!(safe_name(name), "package row name {name:?}");
    }
    for (i, file) in parsed.record_files.iter().enumerate() {
        assert!(safe_name(file), "record file name {file:?}");
        assert!(
            !parsed.record_files[..i].contains(file),
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
