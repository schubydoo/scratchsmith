//! The rpm half of `--packages`: which rpm package owns each bundled file, and a small rpm
//! database that holds only those packages.
//!
//! dpkg has a text record per package that scanners read, so that half writes text. rpm has
//! none: a scanner reads the rpm database itself. So the records here are package HEADERS,
//! the binary blobs rpm keeps per package. `rpmdb --exportdb` prints every header on the
//! host, this module keeps the ones for the owning packages, and `rpmdb --importdb` builds a
//! database from them in a private directory. rpm writes its own database, in whatever
//! backend the host uses, so nothing here knows the on-disk format.

use crate::packages::Package;
use anyhow::{bail, Context, Result};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// True when this host has an rpm database that can answer.
///
/// A database directory is not enough: a Debian host can carry the `rpm` tool with an empty
/// database, and a broken one must not read as "nothing is owned". So the test is a real
/// question with a known answer, whether the database knows the package that provides `rpm`.
/// The name of that package varies (`rpm-ndb` on openSUSE Leap), so the question is by
/// capability and not by name.
pub fn available() -> bool {
    db_path().is_some_and(|db| db.is_dir())
        && Command::new("rpm")
            .args(["-q", "--qf", "%{NAME}\\n", "--whatprovides", "rpm"])
            .env("LC_ALL", "C")
            .output()
            .is_ok_and(|out| out.status.success())
}

/// Where the host's rpm keeps its database (`%{_dbpath}`), which is also where
/// `rpmdb --importdb --root` puts one. `None` when there is no working rpm.
pub fn db_path() -> Option<PathBuf> {
    let out = Command::new("rpm")
        .args(["--eval", "%{_dbpath}"])
        .env("LC_ALL", "C")
        .output()
        .ok()?;
    let path = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (out.status.success() && path.starts_with('/')).then(|| PathBuf::from(path))
}

/// One package as rpm names it. The five fields together are what tells two installed
/// builds of one name apart, so they are the key for picking headers out of the export.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Nevra {
    name: String,
    epoch: u32,
    version: String,
    release: String,
    arch: String,
}

/// Ask rpm which packages own `files` (`(host path, image path)` pairs), and credit each
/// `(package, image path)` in `conventions` to that package if it is installed. Returns the
/// packages for the report and, when `want_records` is set, their header list for the
/// records. The export behind that list reads every package on the host, so a pack that only
/// fills the report does not pay for it.
pub fn owners(
    files: &[(PathBuf, PathBuf)],
    conventions: &[(&str, PathBuf)],
    want_records: bool,
) -> Result<(Vec<Package>, Vec<u8>)> {
    const ROW: &str = "%{NAME}\\t%{EPOCHNUM}\\t%{VERSION}\\t%{RELEASE}\\t%{ARCH}\\t%{SOURCERPM}\\n";
    // Keyed by package, with the source rpm beside the image paths it owns.
    let mut found: BTreeMap<Nevra, (String, Vec<String>)> = BTreeMap::new();
    let mut credit = |rows: &str, image: &Path| {
        for (nevra, source) in rows.lines().filter_map(parse_row) {
            let entry = found.entry(nevra).or_insert_with(|| (source, Vec::new()));
            entry.1.push(image.to_string_lossy().into_owned());
        }
    };
    for (host, image) in files {
        // `rpm -qf` takes a literal path, and exits 1 for one that no package owns.
        let args = ["-qf", "--qf", ROW, "--"];
        if let Some(rows) = rpm_query(&args, host.as_os_str(), "is not owned by any package")? {
            credit(&rows, image);
        }
    }
    for (package, image) in conventions {
        // `rpm -q` exits 1 for a package that is not installed: nobody to credit.
        let args = ["-q", "--qf", ROW, "--"];
        if let Some(rows) = rpm_query(&args, std::ffi::OsStr::new(package), "is not installed")? {
            credit(&rows, image);
        }
    }
    if found.is_empty() {
        return Ok((Vec::new(), Vec::new()));
    }

    let records = if want_records {
        let export = Command::new("rpmdb")
            .arg("--exportdb")
            .env("LC_ALL", "C")
            .output()
            .context("running rpmdb --exportdb")?;
        if !export.status.success() {
            // An old rpm (4.11 on CentOS 7 and Amazon Linux 2) has no `--exportdb`. It answers
            // every `rpm -qf` and then fails here with an "unknown option" message.
            bail!(
                "rpmdb --exportdb failed ({}): {}. The package records need an rpm that has \
                 --exportdb, which rpm 4.11 does not; --packages report works without them",
                export.status,
                String::from_utf8_lossy(&export.stderr).trim()
            );
        }
        let wanted: Vec<&Nevra> = found.keys().collect();
        filter_headers(&export.stdout, &wanted)?
    } else {
        Vec::new()
    };

    let packages = found
        .into_iter()
        .map(|(nevra, (source, mut files))| {
            files.sort();
            files.dedup();
            Package {
                // An epoch of 0 is "no epoch", and rpm leaves it out of a version.
                version: match nevra.epoch {
                    0 => format!("{}-{}", nevra.version, nevra.release),
                    e => format!("{e}:{}-{}", nevra.version, nevra.release),
                },
                name: nevra.name,
                arch: nevra.arch,
                source,
                kind: "rpm",
                files,
            }
        })
        .collect();
    Ok((packages, records))
}

// Run one rpm query. `None` is rpm's own "no": exit 1 AND the sentence it prints for that
// case (`no_answer`, under LC_ALL=C). Exit 1 alone is not enough, because rpm uses it for
// every failed argument, a database that will not open included, and a broken database must
// never read as "nothing is owned". Anything else is an error with rpm's own words.
fn rpm_query(args: &[&str], subject: &std::ffi::OsStr, no_answer: &str) -> Result<Option<String>> {
    let out = Command::new("rpm")
        .args(args)
        .arg(subject)
        .env("LC_ALL", "C")
        .output()
        .context("running rpm")?;
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr);
    match out.status.code() {
        Some(0) => Ok(Some(stdout)),
        Some(1) if said_no(&stdout, &stderr, no_answer, &subject.to_string_lossy()) => Ok(None),
        _ => bail!(
            "rpm {} failed ({}): {} {}",
            args[0],
            out.status,
            stdout.trim(),
            stderr.trim()
        ),
    }
}

// rpm's negative answer, on either stream: `-qf` prints it on stdout, and for a path that
// does not exist it prints `file <path>: No such file or directory` on stderr, which is the
// same "no owner". That second form must name the SUBJECT: rpm puts the same errno text in
// the message for a database it cannot open, and that one is not a "no".
fn said_no(stdout: &str, stderr: &str, no_answer: &str, subject: &str) -> bool {
    stdout.contains(no_answer)
        || stderr.contains(no_answer)
        || stderr.contains(&format!("{subject}: No such file or directory"))
}

// One `ROW` line into the package key and its source package name. A line that is not a
// row (rpm prints "file ... is not owned by any package" on stdout) yields nothing.
fn parse_row(line: &str) -> Option<(Nevra, String)> {
    let fields: Vec<&str> = line.split('\t').collect();
    let [name, epoch, version, release, arch, source_rpm] = fields[..] else {
        return None;
    };
    let nevra = Nevra {
        name: name.to_string(),
        epoch: epoch.parse().ok()?,
        version: version.to_string(),
        release: release.to_string(),
        arch: arch.to_string(),
    };
    Some((nevra, source_name(source_rpm)))
}

// `glibc-2.43-9.fc44.src.rpm` -> `glibc`: the source package's name, which is the name an
// advisory uses. The version and the release are the last two dash-separated parts. A value
// that does not have that shape is kept whole, so nothing is guessed.
fn source_name(source_rpm: &str) -> String {
    let stem = source_rpm
        .strip_suffix(".src.rpm")
        .or_else(|| source_rpm.strip_suffix(".nosrc.rpm"))
        .unwrap_or(source_rpm);
    let mut parts = stem.rsplitn(3, '-');
    match (parts.next(), parts.next(), parts.next()) {
        (Some(_release), Some(_version), Some(name)) if !name.is_empty() => name.to_string(),
        _ => source_rpm.to_string(),
    }
}

// The eight bytes every exported header starts with: the three magic bytes, the format
// version, and four reserved bytes.
const MAGIC: [u8; 8] = [0x8e, 0xad, 0xe8, 0x01, 0, 0, 0, 0];
// Header tags, and the two data types they are read as.
const TAG_NAME: u32 = 1000;
const TAG_VERSION: u32 = 1001;
const TAG_RELEASE: u32 = 1002;
const TAG_EPOCH: u32 = 1003;
const TAG_ARCH: u32 = 1022;
const TYPE_INT32: u32 = 4;
const TYPE_STRING: u32 = 6;

/// Keep the headers of `wanted` packages out of an `rpmdb --exportdb` header list, byte for
/// byte and in their original order.
///
/// Every wanted package must be found. One that is not means the database changed between
/// the two rpm calls, or that this reader misread a header, and either way the records would
/// name fewer packages than the report does. That is an error, not a shorter list.
///
/// A header is the magic, an entry count, a data length, that many 16-byte index entries,
/// and the data. Every length is checked against the buffer, so a list that is cut short or
/// is not a header list is an error and never a read past the end.
fn filter_headers(list: &[u8], wanted: &[&Nevra]) -> Result<Vec<u8>> {
    let mut kept = Vec::new();
    let mut matched: Vec<Nevra> = Vec::new();
    let mut rest = list;
    while !rest.is_empty() {
        let size = header_size(rest)?;
        let (header, tail) = rest.split_at(size);
        if let Some(nevra) = header_nevra(header).filter(|n| wanted.contains(&n)) {
            kept.extend_from_slice(header);
            matched.push(nevra);
        }
        rest = tail;
    }
    if let Some(lost) = wanted.iter().find(|w| !matched.contains(w)) {
        bail!(
            "the rpm database has no header for {}-{}-{}.{}, which rpm named as an owner",
            lost.name,
            lost.version,
            lost.release,
            lost.arch
        );
    }
    Ok(kept)
}

/// The package name of every header in a header list, in order, with `None` for a header
/// that carries no readable key. A byte-level entry point for fuzzing: it runs the same
/// split and the same field reads that the filter does, on any bytes.
pub fn header_names(list: &[u8]) -> Result<Vec<Option<String>>> {
    let mut names = Vec::new();
    let mut rest = list;
    while !rest.is_empty() {
        let (header, tail) = rest.split_at(header_size(rest)?);
        names.push(header_nevra(header).map(|n| n.name));
        rest = tail;
    }
    Ok(names)
}

fn be32(bytes: &[u8], at: usize) -> Option<u32> {
    let raw = bytes.get(at..at.checked_add(4)?)?;
    Some(u32::from_be_bytes(raw.try_into().ok()?))
}

// The byte length of the header at the start of `bytes`.
fn header_size(bytes: &[u8]) -> Result<usize> {
    if bytes.len() < 16 || bytes[..8] != MAGIC {
        bail!("rpmdb --exportdb did not print a header list");
    }
    let entries = be32(bytes, 8).context("a header is cut short")? as usize;
    let data = be32(bytes, 12).context("a header is cut short")? as usize;
    let size = entries
        .checked_mul(16)
        .and_then(|index| index.checked_add(data))
        .and_then(|body| body.checked_add(16))
        .context("a header declares an impossible size")?;
    if size > bytes.len() {
        bail!("a header runs past the end of the header list");
    }
    Ok(size)
}

// Read the package key out of one header. `None` when a field is absent or malformed: such
// a header matches no wanted package and is left out.
fn header_nevra(header: &[u8]) -> Option<Nevra> {
    let entries = be32(header, 8)? as usize;
    let data_start = 16usize.checked_add(entries.checked_mul(16)?)?;
    let data = header.get(data_start..)?;
    let string = |offset: u32| -> Option<String> {
        let from = data.get(offset as usize..)?;
        let end = from.iter().position(|&b| b == 0)?;
        String::from_utf8(from[..end].to_vec()).ok()
    };
    let (mut name, mut version, mut release, mut arch) = (None, None, None, None);
    let mut epoch = 0u32;
    for i in 0..entries {
        let at = 16 + i * 16;
        let (tag, kind, offset) = (
            be32(header, at)?,
            be32(header, at + 4)?,
            be32(header, at + 8)?,
        );
        match (tag, kind) {
            (TAG_NAME, TYPE_STRING) => name = string(offset),
            (TAG_VERSION, TYPE_STRING) => version = string(offset),
            (TAG_RELEASE, TYPE_STRING) => release = string(offset),
            (TAG_ARCH, TYPE_STRING) => arch = string(offset),
            (TAG_EPOCH, TYPE_INT32) => epoch = be32(data, offset as usize)?,
            _ => {}
        }
    }
    Some(Nevra {
        name: name?,
        epoch,
        version: version?,
        release: release?,
        arch: arch?,
    })
}

/// Build an rpm database from `headers` and return its files as `(file name, bytes)`.
///
/// The database is built in a private temporary root, never in the staged tree. rpm opens
/// its database by name and follows whatever is at that name, and the staged tree can hold
/// links and files the user asked for, so rpm is not pointed at it at all. The caller places
/// the bytes with the same checks as every other record.
///
/// rpm leaves working files beside the database: its lock, and for the sqlite backend a
/// shared-memory index and a write-ahead log that is empty once rpm has finished. None is
/// part of the data and a reader rebuilds what it needs, so they are left behind here. For
/// the sqlite backend that leaves one file.
pub fn build_database(headers: &[u8]) -> Result<Vec<(std::ffi::OsString, Vec<u8>)>> {
    let db = db_path().context("asking rpm where its database lives")?;
    let tmp = tempfile::tempdir().context("creating a directory to build the rpm database in")?;
    // rpm ignores a `--root` that is not absolute and would then write to the HOST database
    // path, so the root is made absolute first. A failure to do so is an error, never a
    // fallback to the path as given.
    let root = std::fs::canonicalize(tmp.path())
        .with_context(|| format!("resolving {}", tmp.path().display()))?;
    if !root.is_absolute() || root == Path::new("/") {
        bail!("refusing to build the rpm database in {}", root.display());
    }
    let mut child = Command::new("rpmdb")
        .arg("--importdb")
        .arg("--root")
        .arg(&root)
        .env("LC_ALL", "C")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .context("running rpmdb --importdb")?;
    // The stdin handle is dropped at the end of this statement, so rpmdb sees the end of
    // the list. If rpmdb exits early the write fails with a broken pipe, which is held in
    // `fed` so that rpm's own words are reported first.
    let fed = child
        .stdin
        .take()
        .context("rpmdb has no stdin")?
        .write_all(headers);
    let out = child.wait_with_output().context("waiting for rpmdb")?;
    if !out.status.success() {
        bail!(
            "rpmdb --importdb failed ({}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    fed.context("writing the package headers to rpmdb")?;

    let db_dir = root.join(db.strip_prefix("/").unwrap_or(&db));
    let mut files = Vec::new();
    for entry in
        std::fs::read_dir(&db_dir).with_context(|| format!("reading {}", db_dir.display()))?
    {
        let entry = entry?;
        let name = entry.file_name();
        let text = name.to_string_lossy();
        let meta = entry.metadata()?;
        // `__db.NNN` are the Berkeley DB backend's region files: per-machine state, not
        // data, and rebuilt by a reader like the others.
        let working_file = text == ".rpm.lock"
            || text == ".dbenv.lock"
            || text.starts_with("__db.")
            || text.ends_with("-shm")
            || (text.ends_with("-wal") && meta.len() == 0);
        if meta.is_file() && !working_file {
            files.push((name.clone(), std::fs::read(entry.path())?));
        }
    }
    if files.is_empty() {
        bail!("rpmdb --importdb wrote no database");
    }
    files.sort();
    Ok(files)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Build one header the way rpm lays it out: index entries, then the data they point at.
    fn header(name: &str, epoch: Option<u32>, version: &str, release: &str, arch: &str) -> Vec<u8> {
        let mut index = Vec::new();
        let mut data = Vec::new();
        let string = |tag: u32, value: &str, data: &mut Vec<u8>, index: &mut Vec<u8>| {
            for field in [tag, TYPE_STRING, data.len() as u32, 1] {
                index.extend_from_slice(&field.to_be_bytes());
            }
            data.extend_from_slice(value.as_bytes());
            data.push(0);
        };
        string(TAG_NAME, name, &mut data, &mut index);
        string(TAG_VERSION, version, &mut data, &mut index);
        string(TAG_RELEASE, release, &mut data, &mut index);
        string(TAG_ARCH, arch, &mut data, &mut index);
        if let Some(epoch) = epoch {
            // An INT32 is aligned to four bytes in a real header.
            while data.len() % 4 != 0 {
                data.push(0);
            }
            for field in [TAG_EPOCH, TYPE_INT32, data.len() as u32, 1] {
                index.extend_from_slice(&field.to_be_bytes());
            }
            data.extend_from_slice(&epoch.to_be_bytes());
        }
        let mut out = MAGIC.to_vec();
        out.extend_from_slice(&((index.len() / 16) as u32).to_be_bytes());
        out.extend_from_slice(&(data.len() as u32).to_be_bytes());
        out.extend_from_slice(&index);
        out.extend_from_slice(&data);
        out
    }

    fn nevra(name: &str, epoch: u32, version: &str, release: &str, arch: &str) -> Nevra {
        Nevra {
            name: name.into(),
            epoch,
            version: version.into(),
            release: release.into(),
            arch: arch.into(),
        }
    }

    #[test]
    fn a_row_parses_and_a_message_line_does_not() {
        let (n, source) =
            parse_row("glibc\t0\t2.43\t9.fc44\tx86_64\tglibc-2.43-9.fc44.src.rpm").unwrap();
        assert_eq!(n, nevra("glibc", 0, "2.43", "9.fc44", "x86_64"));
        assert_eq!(source, "glibc");
        assert_eq!(parse_row("file /x is not owned by any package"), None);
        // Exit 1 counts as "no" only with rpm's own sentence for it, on either stream.
        let not_owned = "is not owned by any package";
        let owned_by_none = "file /x is not owned by any package\n";
        assert!(said_no(owned_by_none, "", not_owned, "/x"));
        let gone = "error: file /x: No such file or directory\n";
        assert!(said_no("", gone, not_owned, "/x"));
        let absent = "package nope is not installed\n";
        assert!(said_no(absent, "", "is not installed", "nope"));
        // A database that will not open also exits 1, and must not read as "no owner". Its
        // message can carry the same errno text, so that text counts only with the subject.
        let broken = "error: cannot open Packages database in /var/lib/rpm\n";
        assert!(!said_no("", broken, not_owned, "/x"));
        let old = "error: cannot open Packages index using db5 - No such file or directory (2)\n";
        assert!(!said_no("", old, not_owned, "/x"));
        assert_eq!(parse_row("a\tnot-a-number\tb\tc\td\te"), None);
    }

    #[test]
    fn the_source_name_drops_the_version_and_release_only() {
        assert_eq!(source_name("glibc-2.43-9.fc44.src.rpm"), "glibc");
        // A name with dashes of its own keeps them.
        assert_eq!(
            source_name("ca-certificates-2025.2.80-1.fc44.src.rpm"),
            "ca-certificates"
        );
        assert_eq!(source_name("kmod-x-1-2.nosrc.rpm"), "kmod-x");
        // Not that shape: kept whole, not guessed at.
        assert_eq!(source_name("(none)"), "(none)");
        assert_eq!(source_name("odd.src.rpm"), "odd.src.rpm");
    }

    #[test]
    fn only_the_wanted_headers_are_kept_byte_for_byte() {
        let glibc = header("glibc", None, "2.43", "9.fc44", "x86_64");
        let other = header("bash", None, "5.3", "1.fc44", "x86_64");
        // The same name in another architecture is a different package.
        let glibc_i686 = header("glibc", None, "2.43", "9.fc44", "i686");
        // An epoch is part of the key too.
        let epoch = header("openssl", Some(1), "3.5", "2.fc44", "x86_64");
        let list = [&glibc[..], &other, &glibc_i686, &epoch].concat();

        let want_glibc = nevra("glibc", 0, "2.43", "9.fc44", "x86_64");
        let want_openssl = nevra("openssl", 1, "3.5", "2.fc44", "x86_64");
        let kept = filter_headers(&list, &[&want_glibc, &want_openssl]).unwrap();
        assert_eq!(kept, [&glibc[..], &epoch].concat());

        // The right name with the wrong epoch is not the package. A wanted package with no
        // header is an error: the records must not name fewer packages than the report.
        let no_epoch = nevra("openssl", 0, "3.5", "2.fc44", "x86_64");
        let err = filter_headers(&list, &[&want_glibc, &no_epoch]).unwrap_err();
        assert!(
            format!("{err:#}").contains("openssl-3.5-2.fc44.x86_64"),
            "{err:#}"
        );
        assert!(filter_headers(&[], &[&want_glibc]).is_err());
        // Nothing wanted is nothing kept, from any list.
        assert!(filter_headers(&list, &[]).unwrap().is_empty());
    }

    #[test]
    fn header_names_reads_the_seed_the_fuzzer_starts_from() {
        // The same bytes .clusterfuzzlite/build.sh writes as the rpm_headers seed. If this
        // stops parsing, the seed is dead weight and the fuzzer is back at the magic check.
        let seed = header("a", None, "1", "1", "x");
        assert_eq!(seed.len(), 16 + 4 * 16 + 8);
        assert_eq!(header_names(&seed).unwrap(), [Some("a".to_string())]);
        // Two headers, and one with no name: still split, and reported as nameless.
        let mut nameless = MAGIC.to_vec();
        nameless.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0]);
        let list = [&seed[..], &nameless, &seed].concat();
        let names = header_names(&list).unwrap();
        assert_eq!(names, [Some("a".to_string()), None, Some("a".to_string())]);
    }

    #[test]
    fn a_damaged_header_list_is_an_error_not_a_read_past_the_end() {
        let good = header("glibc", None, "2.43", "9.fc44", "x86_64");
        let want = nevra("glibc", 0, "2.43", "9.fc44", "x86_64");
        // Cut short at every length: an error each time, and never a panic.
        for cut in 1..good.len() {
            assert!(
                filter_headers(&good[..cut], &[&want]).is_err(),
                "cut at {cut}"
            );
        }
        // Not a header list at all.
        assert!(filter_headers(b"this is not rpm output", &[&want]).is_err());
        // A header that claims more entries than fit in memory.
        let mut huge = MAGIC.to_vec();
        huge.extend_from_slice(&u32::MAX.to_be_bytes());
        huge.extend_from_slice(&u32::MAX.to_be_bytes());
        assert!(filter_headers(&huge, &[&want]).is_err());
        // A string offset that points outside the data: the header has no readable key, so
        // the wanted package is not found, which is an error and never a panic.
        let mut bad = good.clone();
        bad[16 + 8..16 + 12].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(filter_headers(&bad, &[&want]).is_err());
        assert_eq!(header_names(&bad).unwrap(), [None]);
    }
}
