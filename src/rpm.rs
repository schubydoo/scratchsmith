//! The rpm half of `--packages`: which rpm package owns each bundled file, and a small rpm
//! database that holds only those packages.
//!
//! dpkg has a text record per package that scanners read, so that half writes text. rpm has
//! none: a scanner reads the rpm database itself. So the records here are package HEADERS,
//! the binary blobs rpm keeps per package. `rpmdb --exportdb` prints every header on the
//! host, this module keeps the ones for the owning packages, and `rpmdb --importdb` builds a
//! database from them inside the staged tree. rpm writes its own database, in whatever
//! backend the host uses, so nothing here knows the on-disk format.

use crate::packages::Package;
use anyhow::{bail, Context, Result};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// True when this host has an rpm database to ask.
pub fn available() -> bool {
    db_path().is_some_and(|db| db.is_dir())
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
/// packages for the report and the header list for the records.
pub fn owners(
    files: &[(PathBuf, PathBuf)],
    conventions: &[(&str, PathBuf)],
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
        if let Some(rows) = rpm_query(&args, host.as_os_str())? {
            credit(&rows, image);
        }
    }
    for (package, image) in conventions {
        // `rpm -q` exits 1 for a package that is not installed: nobody to credit.
        let args = ["-q", "--qf", ROW, "--"];
        if let Some(rows) = rpm_query(&args, std::ffi::OsStr::new(package))? {
            credit(&rows, image);
        }
    }
    if found.is_empty() {
        return Ok((Vec::new(), Vec::new()));
    }

    let export = Command::new("rpmdb")
        .arg("--exportdb")
        .env("LC_ALL", "C")
        .output()
        .context("running rpmdb --exportdb")?;
    if !export.status.success() {
        bail!(
            "rpmdb --exportdb failed ({}): {}",
            export.status,
            String::from_utf8_lossy(&export.stderr).trim()
        );
    }
    let wanted: Vec<&Nevra> = found.keys().collect();
    let records = filter_headers(&export.stdout, &wanted)?;

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

// Run one rpm query. `None` is exit 1, rpm's answer for "no such file or package"; any other
// failure is an error with rpm's own words.
fn rpm_query(args: &[&str], subject: &std::ffi::OsStr) -> Result<Option<String>> {
    let out = Command::new("rpm")
        .args(args)
        .arg(subject)
        .env("LC_ALL", "C")
        .output()
        .context("running rpm")?;
    match out.status.code() {
        Some(0) => Ok(Some(String::from_utf8_lossy(&out.stdout).into_owned())),
        Some(1) => Ok(None),
        _ => bail!(
            "rpm {} failed ({}): {}",
            args[0],
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ),
    }
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
/// A header is the magic, an entry count, a data length, that many 16-byte index entries,
/// and the data. Every length is checked against the buffer, so a list that is cut short or
/// is not a header list is an error and never a read past the end.
fn filter_headers(list: &[u8], wanted: &[&Nevra]) -> Result<Vec<u8>> {
    let mut kept = Vec::new();
    let mut rest = list;
    while !rest.is_empty() {
        let size = header_size(rest)?;
        let (header, tail) = rest.split_at(size);
        if header_nevra(header).is_some_and(|n| wanted.contains(&&n)) {
            kept.extend_from_slice(header);
        }
        rest = tail;
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

/// Build an rpm database from `headers` inside `rootfs`, at the host's own database path,
/// and return the files it wrote.
///
/// The caller has already made sure that no part of the path under `rootfs` is a symlink,
/// and created the directory. A database from an earlier pack into the same directory is
/// replaced: `rpmdb --importdb` would add to it, and the result must hold these packages and
/// no others.
pub fn import(rootfs: &Path, db_dir: &Path, headers: &[u8]) -> Result<Vec<PathBuf>> {
    // rpm opens its database by NAME inside this directory and follows whatever is there.
    // The tree can hold links the user asked for, so a link at one of those names would send
    // rpm's writes outside the rootfs and onto the host. Nothing but a regular file may be
    // in the way: a regular file is an earlier database and is replaced, and anything else
    // stops the pack.
    for entry in
        std::fs::read_dir(db_dir).with_context(|| format!("reading {}", db_dir.display()))?
    {
        let path = entry?.path();
        if !path.symlink_metadata()?.is_file() {
            bail!(
                "cannot record packages: {} is in the way of the rpm database and is not a \
                 regular file; writing through it could leave the image",
                path.display()
            );
        }
        std::fs::remove_file(&path).with_context(|| format!("removing {}", path.display()))?;
    }
    // rpm ignores a `--root` that is not absolute and would then write to the HOST database
    // path, so the rootfs is made absolute first. A failure to do so is an error, never a
    // fallback to the path as given.
    let root =
        std::fs::canonicalize(rootfs).with_context(|| format!("resolving {}", rootfs.display()))?;
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
    // Written from here while rpmdb reads: a header list is a few megabytes at most, and
    // rpmdb drains stdin before it reports, so this cannot block on its stderr.
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
    // rpm leaves working files beside the database: its lock, and for the sqlite backend a
    // shared-memory index and a write-ahead log that is empty once rpm has finished. None
    // is part of the data, a reader rebuilds what it needs, and a lock file has no place
    // in an image. Dropping them leaves one file, which is the same bytes on every pack.
    for file in db_files(db_dir)? {
        let name = file.file_name().unwrap_or_default().to_string_lossy();
        let empty = || std::fs::metadata(&file).is_ok_and(|m| m.len() == 0);
        if name == ".rpm.lock" || name.ends_with("-shm") || (name.ends_with("-wal") && empty()) {
            std::fs::remove_file(&file).with_context(|| format!("removing {}", file.display()))?;
        }
    }
    db_files(db_dir)
}

// The regular files directly in the database directory: the database and its sidecars
// (the lock, and a write-ahead log for the sqlite backend).
fn db_files(db_dir: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    for entry in
        std::fs::read_dir(db_dir).with_context(|| format!("reading {}", db_dir.display()))?
    {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            files.push(entry.path());
        }
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

        // The right name with the wrong epoch is not the package.
        let no_epoch = nevra("openssl", 0, "3.5", "2.fc44", "x86_64");
        assert!(filter_headers(&list, &[&no_epoch]).unwrap().is_empty());
        assert!(filter_headers(&[], &[&want_glibc]).unwrap().is_empty());
    }

    #[test]
    fn import_refuses_a_link_where_the_database_goes() {
        // The refusal comes before rpmdb is started, so this runs on a host with no rpm.
        let tmp = tempfile::tempdir().unwrap();
        let rootfs = tmp.path().join("rootfs");
        let db_dir = rootfs.join("usr/lib/sysimage/rpm");
        std::fs::create_dir_all(&db_dir).unwrap();
        let victim = tmp.path().join("victim");
        std::fs::write(&victim, b"untouched").unwrap();
        std::os::unix::fs::symlink(&victim, db_dir.join("rpmdb.sqlite")).unwrap();

        let err = import(&rootfs, &db_dir, b"not reached").unwrap_err();
        assert!(format!("{err:#}").contains("not a regular file"), "{err:#}");
        assert_eq!(std::fs::read(&victim).unwrap(), b"untouched");
        assert!(db_dir
            .join("rpmdb.sqlite")
            .symlink_metadata()
            .unwrap()
            .is_symlink());

        // A directory in the way is refused the same way, and left alone.
        let rootfs = tmp.path().join("second");
        let db_dir = rootfs.join("usr/lib/sysimage/rpm");
        std::fs::create_dir_all(db_dir.join("subdir")).unwrap();
        assert!(import(&rootfs, &db_dir, b"not reached").is_err());
        assert!(db_dir.join("subdir").is_dir());
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
        // A string offset that points outside the data: no match, and no panic.
        let mut bad = good.clone();
        bad[16 + 8..16 + 12].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(filter_headers(&bad, &[&want]).unwrap().is_empty());
    }
}
