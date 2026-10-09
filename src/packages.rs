//! Which distribution package each bundled file came from (`--packages`).
//!
//! A scratch image carries libraries copied from the build host and no package database, so
//! an SBOM of it names almost none of them: syft finds what a binary classifier can guess and
//! nothing else. The host does know. This module asks dpkg which package owns each file, and
//! hands that to three places the user can pick from: the JSON report, the SBOM, and the
//! image itself.
//!
//! The SBOM and image outputs use one mechanism: distroless-style records under
//! `var/lib/dpkg/status.d/`, plus the host's `etc/os-release`. syft and every scanner that
//! reads a Debian image already understand both, in every SBOM format, so nothing here writes
//! SBOM JSON. The os-release file is not optional: without it syft has no distribution, every
//! package URL comes out empty, and a scanner has nothing to match on.
//!
//! dpkg and rpm. The rpm half is in `crate::rpm`: an rpm database is binary, so its records
//! are a small database built by rpm itself, where dpkg's are text files.

use anyhow::{bail, Context, Result};
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

/// A place the package data can go, selectable with `--packages` / the `packages` config key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive] // may gain outputs in a minor; not a stable exhaustive library API
pub enum PackagesOutput {
    /// A `packages` field in the `--format json` report.
    Report,
    /// Name the packages in the SBOM (`--sbom`) and show them to the scan (`--scan`).
    Sbom,
    /// Keep the package records in the image, so any scanner that reads it finds them.
    Image,
    /// Look nothing up and write nothing. Must be the only value.
    None,
}

/// Where the package data goes. Built from `--packages`; the default is the report alone.
///
/// The default stops there on purpose. With `sbom`, a scan starts to see the bundled glibc
/// and openssl, so a `--scan-fail-on` gate that passes today could fail after an upgrade
/// with nothing changed on the user's side. That is for the user to switch on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PackagesSelection {
    pub report: bool,
    pub sbom: bool,
    pub image: bool,
    /// The user named the outputs. A default selection stays quiet on a host with no dpkg;
    /// an explicit one warns, or fails when it asked for records (`needs_records`).
    pub explicit: bool,
}

impl Default for PackagesSelection {
    fn default() -> Self {
        Self {
            report: true,
            sbom: false,
            image: false,
            explicit: false,
        }
    }
}

impl PackagesSelection {
    /// Build a selection from the `--packages` values. Empty means the default. A `none`
    /// value must stand alone; combining it with an output is a usage error.
    pub fn from_outputs(outputs: &[PackagesOutput]) -> Result<Self> {
        if outputs.is_empty() {
            return Ok(Self::default());
        }
        if outputs.contains(&PackagesOutput::None) && outputs.len() > 1 {
            bail!("--packages none cannot be combined with another output");
        }
        Ok(Self {
            report: outputs.contains(&PackagesOutput::Report),
            sbom: outputs.contains(&PackagesOutput::Sbom),
            image: outputs.contains(&PackagesOutput::Image),
            explicit: true,
        })
    }

    /// Drop the default `report` output where nothing reads it. The text report prints no
    /// package list, so a pack that did not name `--packages` would run the lookup (most of
    /// the time of a small pack) for a list that no one sees. An explicit selection is kept
    /// as given: its warnings were asked for.
    pub fn for_text_report(mut self) -> Self {
        if !self.explicit {
            self.report = false;
        }
        self
    }

    /// True when any output is on, so the lookup is worth running.
    pub fn any(&self) -> bool {
        self.report || self.sbom || self.image
    }

    /// True when the user asked for records in the SBOM or the image. Only an explicit
    /// selection can, so a pack that cannot write them fails instead of shipping an SBOM or
    /// an image that silently lacks what was asked for.
    pub fn needs_records(&self) -> bool {
        self.sbom || self.image
    }
}

/// One distribution package that owns at least one bundled file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Package {
    /// The binary package name, e.g. `libc6`.
    pub name: String,
    /// The package version exactly as the package manager reports it.
    pub version: String,
    /// The package architecture, e.g. `amd64` or `all`.
    pub arch: String,
    /// The source package it was built from, e.g. `glibc`. This is the name advisories use.
    pub source: String,
    /// The package format: `deb` or `rpm`.
    #[serde(rename = "type")]
    pub kind: &'static str,
    /// The files in the image whose host path this package owns, by image path, sorted.
    /// Ownership is of the path: the bytes are not compared with the package's.
    pub files: Vec<String>,
}

/// The result of a lookup: the packages for the report, and each one's database record for
/// the SBOM and the image.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Owners {
    pub packages: Vec<Package>,
    /// Bundled files dpkg was NOT asked about, because their host path holds a character it
    /// would read as a pattern. They look unowned in `packages`, so the caller says so.
    pub unasked: Vec<String>,
    records: Records,
}

/// What a scanner reads to learn the packages, in the form the host's package manager uses.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Records {
    /// `(record file name, dpkg status stanza)`, one per package, for `status.d`.
    Dpkg(Vec<(String, String)>),
    /// The owning packages' rpm headers, as one header list for `rpmdb --importdb`.
    Rpm(Vec<u8>),
}

impl Default for Records {
    fn default() -> Self {
        Records::Dpkg(Vec::new())
    }
}

/// The package manager whose database names the owners.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Manager {
    Dpkg,
    Rpm,
}

/// The package manager this host has a database for. dpkg is asked first: a Debian host can
/// carry the `rpm` tool with an empty database, and its files are dpkg's.
pub fn manager() -> Option<Manager> {
    if dpkg_available() {
        Some(Manager::Dpkg)
    } else if crate::rpm::available() {
        Some(Manager::Rpm)
    } else {
        None
    }
}

/// True when this host has a dpkg database to ask.
pub fn dpkg_available() -> bool {
    // A status file that holds nothing is a database that knows no package: an rpm host can
    // carry the `dpkg` tool, and its files are rpm's.
    std::fs::metadata("/var/lib/dpkg/status").is_ok_and(|m| m.len() > 0)
        && Command::new("dpkg-query")
            .arg("--version")
            .output()
            .is_ok_and(|o| o.status.success())
}

/// Ask dpkg which packages own the given files. Each file is `(host path, image path)`: the
/// host path is what dpkg is asked about, and the image path is what the report names, so
/// the list joins with the rest of the report. A path no package owns (the user's own
/// binary, a library under /opt) is simply absent from the result.
///
/// `conventions` are `(package, image path)` pairs for files that no package owns but one
/// package is the source of: the CA bundle is generated on the host from `ca-certificates`.
/// Such a package is named only if it is installed. The package name must be a literal:
/// `dpkg-query -W` reads its argument as a name pattern, as `-S` reads a path pattern.
///
/// `want_records` says whether the SBOM or image output is on. The rpm half reads every
/// package on the host to build its records, so it skips that for a report-only pack.
pub fn owners(
    manager: Manager,
    files: &[(PathBuf, PathBuf)],
    conventions: &[(&str, PathBuf)],
    want_records: bool,
) -> Result<Owners> {
    match manager {
        Manager::Dpkg => dpkg_owners(files, conventions),
        Manager::Rpm => {
            // rpm takes a literal path, so no path is left unasked.
            let (packages, headers) = crate::rpm::owners(files, conventions, want_records)?;
            Ok(Owners {
                packages,
                unasked: Vec::new(),
                records: Records::Rpm(headers),
            })
        }
    }
}

fn dpkg_owners(files: &[(PathBuf, PathBuf)], conventions: &[(&str, PathBuf)]) -> Result<Owners> {
    let host_paths: Vec<PathBuf> = files.iter().map(|(host, _)| host.clone()).collect();
    let mut unasked: Vec<String> = host_paths
        .iter()
        .map(|p| p.to_string_lossy().into_owned())
        .filter(|p| is_pattern(p))
        .collect();
    unasked.sort();
    unasked.dedup();
    // One host file can be in the image twice: the loader is staged where PT_INTERP names
    // it, and again at its real path when libc lists it as a library. Both are named.
    let mut by_package: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (package, host) in search(&host_paths)? {
        let image_paths = files
            .iter()
            .filter(|(h, _)| h.to_string_lossy() == host)
            .map(|(_, image)| image.to_string_lossy().into_owned());
        by_package.entry(package).or_default().extend(image_paths);
    }
    for (package, image) in conventions {
        // Exit 1 is "no such package", which just means there is nobody to credit.
        //
        // `-W` also lists a package that is known and NOT installed (removed with its
        // configuration left behind, or never installed), so the status is checked. Only an
        // installed package can be what the bundle on this host was built from.
        let known = dpkg_query(
            &["-W", "-f", "${binary:Package}\\t${db:Status-Status}\\n"],
            &[package],
            &[0, 1],
        )?;
        for qualified in installed_packages(&known) {
            by_package
                .entry(qualified.to_string())
                .or_default()
                .push(image.to_string_lossy().into_owned());
        }
    }
    if by_package.is_empty() {
        return Ok(Owners {
            unasked,
            ..Owners::default()
        });
    }
    let names: Vec<String> = by_package.keys().cloned().collect();
    let qualified = as_strs(&names);

    let shown = dpkg_query(
        &[
            "-W",
            "-f",
            "${binary:Package}\\t${Package}\\t${Version}\\t${Architecture}\\t${source:Package}\\n",
        ],
        &qualified,
        &[0],
    )?;
    let mut packages = parse_show(&shown, &mut by_package);
    packages.sort_by(|a, b| (&a.name, &a.arch).cmp(&(&b.name, &b.arch)));

    // Keep a record only for a package the report names, so the SBOM and the report cannot
    // disagree about what is in the image.
    let mut records = parse_records(&dpkg_query(&["-s"], &qualified, &[0])?)?;
    records.retain(|(file, _)| {
        let name = file.split(':').next().unwrap_or(file);
        packages.iter().any(|p| p.name == name)
    });
    Ok(Owners {
        packages,
        unasked,
        records: Records::Dpkg(records),
    })
}

// `dpkg-query -S` for every path, returning `(qualified package, path as asked)`.
//
// A merged-/usr host can know a file under either spelling: the resolver hands over the real
// path (/usr/lib/...), and an older package lists it as shipped (/lib/...). So a path dpkg
// does not know under /usr is asked again without the prefix.
//
// `-S` reads each argument as a GLOB PATTERN, not a path: `/usr/bin/i?` answers for both
// /usr/bin/id and /usr/bin/ip. A path with a pattern character is therefore not asked at
// all (it reads as unowned), and every answer is kept only when it is for a path that was
// asked, so a package can never enter the report for a file the image does not hold.
fn search(host_paths: &[PathBuf]) -> Result<Vec<(String, String)>> {
    let asked: Vec<String> = host_paths
        .iter()
        .map(|p| p.to_string_lossy().into_owned())
        .filter(|p| !is_pattern(p))
        .collect();
    // Exit 1 is normal: one path with no owner, and every found owner is still printed.
    let mut found = parse_search(&dpkg_query(&["-S"], &as_strs(&asked), &[0, 1])?);
    found.retain(|(_, path)| asked.contains(path));

    let retry: Vec<(String, String)> = asked
        .iter()
        .filter(|p| !found.iter().any(|(_, path)| path == *p))
        // The `/usr/` component, not the letters: `/usrlocal/x` is not under /usr.
        .filter_map(|p| Some((format!("/{}", p.strip_prefix("/usr/")?), p.clone())))
        // Only where the two spellings are ONE file. On a host that is not merged, /lib/x
        // and /usr/lib/x are different files, and the owner of one says nothing about the
        // other: crediting it would put a package in the SBOM that did not supply the file.
        .filter(|(short, full)| same_file(short, full))
        .collect();
    if !retry.is_empty() {
        let short: Vec<&str> = retry.iter().map(|(short, _)| short.as_str()).collect();
        for (package, short_path) in parse_search(&dpkg_query(&["-S"], &short, &[0, 1])?) {
            if let Some((_, full)) = retry.iter().find(|(short, _)| *short == short_path) {
                found.push((package, full.clone()));
            }
        }
    }
    Ok(found)
}

/// What the readers of `dpkg-query` output hand on from one text.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct DpkgParse {
    /// The `(package, path)` owners from `-S`.
    pub owners: Vec<(String, String)>,
    /// The names from `-W`: each package row's name and architecture, and each name whose
    /// status is `installed`.
    pub names: Vec<String>,
    /// The record file names from `-s`.
    pub record_files: Vec<String>,
}

/// Run every reader of `dpkg-query` output over one text. A text-level entry point for
/// fuzzing. The text comes from a tool on the build host, so it is not hostile in the usual
/// case, but a package name from it becomes a file name in the image and a line of the report.
pub fn parse_dpkg_output(text: &str) -> DpkgParse {
    let owners = parse_search(text);
    let mut files: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (package, path) in &owners {
        files.entry(package.clone()).or_default().push(path.clone());
    }
    let mut names: Vec<String> = installed_packages(text).map(str::to_string).collect();
    for package in parse_show(text, &mut files) {
        names.extend([package.name, package.arch]);
    }
    let records = parse_records(text).unwrap_or_default();
    DpkgParse {
        owners,
        names,
        record_files: records.into_iter().map(|(file, _)| file).collect(),
    }
}

// The qualified names in `-W` rows (`binary:Package`, `db:Status-Status`) whose status is
// exactly `installed`.
fn installed_packages(rows: &str) -> impl Iterator<Item = &str> {
    rows.lines().filter_map(|row| {
        let (name, status) = row.split_once('\t')?;
        (status == "installed" && is_package_name(name)).then_some(name)
    })
}

// True when dpkg would read `path` as a pattern and not as one literal path.
fn is_pattern(path: &str) -> bool {
    path.contains(['*', '?', '[', '\\'])
}

// True when both paths resolve to the same real file.
fn same_file(a: &str, b: &str) -> bool {
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

fn as_strs(v: &[String]) -> Vec<&str> {
    v.iter().map(String::as_str).collect()
}

// Run dpkg-query and return its stdout. `ok` lists the exit codes that are an answer; any
// other one is an error that carries dpkg's own words, so a broken database is never read
// as "no packages".
fn dpkg_query(flags: &[&str], args: &[&str], ok: &[i32]) -> Result<String> {
    if args.is_empty() {
        return Ok(String::new());
    }
    let out = Command::new("dpkg-query")
        .args(flags)
        // `--` so a path can never be read as an option.
        .arg("--")
        .args(args)
        // Parsed below, so the text must not depend on the user's locale.
        .env("LC_ALL", "C")
        .output()
        .context("running dpkg-query")?;
    if !out.status.code().is_some_and(|code| ok.contains(&code)) {
        bail!(
            "dpkg-query {} failed ({}): {}",
            flags[0],
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

// Parse `dpkg-query -S` output into `(qualified package, path)` pairs.
//
// A line is `pkg[:arch][, pkg2[:arch]]: /path`.
//
// A diversion needs care. `diversion by X from: /path` (or `local diversion from: /path`)
// says that the file a package ships at /path was moved aside, and that what sits at /path
// now came from X, or from the administrator for a local one. The owner lines for /path
// still list every package that ships it. So for a diverted path only the diverting package
// keeps the credit, and only if it is an owner too; otherwise nobody does.
fn parse_search(stdout: &str) -> Vec<(String, String)> {
    let mut found = Vec::new();
    let mut diverted: BTreeMap<String, Option<String>> = BTreeMap::new();
    for line in stdout.lines() {
        if let Some(rest) = line.strip_prefix("diversion by ") {
            if let Some((diverter, path)) = rest.split_once(" from: /") {
                diverted.insert(format!("/{path}"), Some(diverter.to_string()));
            }
            continue;
        }
        if let Some(path) = line.strip_prefix("local diversion from: /") {
            diverted.insert(format!("/{path}"), None);
            continue;
        }
        if line.contains("diversion ") {
            continue; // the matching `to:` line
        }
        let Some((packages, path)) = line.split_once(": /") else {
            continue;
        };
        for package in packages.split(", ") {
            if is_package_name(package) {
                found.push((package.to_string(), format!("/{path}")));
            }
        }
    }
    found.retain(|(package, path)| match diverted.get(path) {
        None => true,
        Some(diverter) => {
            let name = package.split(':').next().unwrap_or(package);
            diverter.as_deref() == Some(name)
        }
    });
    found
}

// Parse the `-W` rows (`binary:Package`, `Package`, `Version`, `Architecture`,
// `source:Package`) and attach each package's files, keyed by the qualified name `-S` gave.
fn parse_show(stdout: &str, files: &mut BTreeMap<String, Vec<String>>) -> Vec<Package> {
    let mut packages = Vec::new();
    for line in stdout.lines() {
        let fields: Vec<&str> = line.split('\t').collect();
        let [qualified, name, version, arch, source] = fields[..] else {
            continue;
        };
        // The name and the architecture go into the report as they are, so each must be one
        // bare name. dpkg prints nothing else there; a row that differs is not a package row.
        let bare = |field: &str| !field.contains(':') && is_package_name(field);
        if !bare(name) || !bare(arch) {
            continue;
        }
        // `-S` qualifies a name with its architecture only for a multi-arch package, and
        // `binary:Package` follows the same rule, so one of these two is the key.
        let Some(mut owned) = files
            .remove(qualified)
            .or_else(|| files.remove(&format!("{name}:{arch}")))
            .or_else(|| files.remove(name))
        else {
            continue;
        };
        owned.sort();
        owned.dedup();
        packages.push(Package {
            name: name.to_string(),
            version: version.to_string(),
            arch: arch.to_string(),
            source: source.to_string(),
            kind: "deb",
            files: owned,
        });
    }
    packages
}

// Split `dpkg-query -s` output into one stanza per package, named for its record file.
//
// The name becomes a file name, so it is checked against the characters a Debian package
// name can hold. Two architectures of one package would share a name; the second keeps its
// architecture in the file name.
fn parse_records(stdout: &str) -> Result<Vec<(String, String)>> {
    let mut records: Vec<(String, String)> = Vec::new();
    for stanza in stdout
        .split("\n\n")
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        let field = |key: &str| {
            stanza
                .lines()
                .find_map(|l| l.strip_prefix(key)?.strip_prefix(": "))
        };
        let Some(name) = field("Package") else {
            continue;
        };
        // A stanza names the package bare. A qualified name here would take a second
        // qualifier below (`name:arch:arch`), so only one part is a name in this field.
        if name.contains(':') || !is_package_name(name) {
            bail!("dpkg reported a package name that is not one: {name:?}");
        }
        // The second architecture of a name is qualified. The architecture goes into the
        // file name too, so it gets the same character check as the name.
        let file = if records.iter().any(|(f, _)| f == name) {
            let arch = field("Architecture").unwrap_or("unknown");
            if arch.contains(':') || !is_package_name(arch) {
                bail!("dpkg reported an architecture that is not one: {arch:?}");
            }
            format!("{name}:{arch}")
        } else {
            name.to_string()
        };
        // The same name and architecture twice is one package reported twice.
        if records.iter().any(|(f, _)| *f == file) {
            continue;
        }
        records.push((file, format!("{stanza}\n")));
    }
    Ok(records)
}

// A Debian package name, optionally `:arch`-qualified: lower-case letters, digits, `+`, `-`
// and `.`. Nothing that could be a path component with meaning (`/`, `..`).
fn is_package_name(s: &str) -> bool {
    let ok = |part: &str| {
        !part.is_empty()
            && part != "."
            && part != ".."
            && part
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "+-.".contains(c))
    };
    match s.split_once(':') {
        Some((name, arch)) => ok(name) && ok(arch),
        None => ok(s),
    }
}

/// The package records written into a rootfs. Dropping it removes them again, which is how
/// the `sbom` output shows the packages to syft and grype without changing the image; call
/// `keep` for the `image` output.
///
/// A record that was already there (a second pack into the same `--output` directory) is
/// replaced, and it is removed like the rest: it can only be one an earlier pack kept, and
/// the `sbom` promise is that the image does not carry the records. Directories are removed
/// only when this call created them, and an os-release that was already there is not
/// touched, because that one can be the user's.
#[derive(Debug, Default)]
pub struct StagedRecords {
    files: Vec<PathBuf>,
    dirs: Vec<PathBuf>,
}

impl StagedRecords {
    /// True when the records are a Berkeley DB rpm database (the backend before rpm 4.16).
    /// rpm gives those files a new identifier on every build, so two packs of the same
    /// input never give the same bytes. `Packages` is that backend's main file.
    pub fn berkeley_db(&self) -> bool {
        self.files
            .iter()
            .any(|file| file.file_name().is_some_and(|name| name == "Packages"))
    }

    /// Leave the records in the rootfs.
    pub fn keep(mut self) {
        self.files.clear();
        self.dirs.clear();
    }
}

impl Drop for StagedRecords {
    fn drop(&mut self) {
        for file in &self.files {
            let _ = std::fs::remove_file(file);
        }
        // Deepest first, so each directory is empty by its turn. `remove_dir` refuses a
        // directory that is not empty, so nothing the user staged is lost.
        self.dirs
            .sort_by_key(|d| std::cmp::Reverse(d.components().count()));
        for dir in &self.dirs {
            let _ = std::fs::remove_dir(dir);
        }
    }
}

/// Write `owners`' records under `rootfs/var/lib/dpkg/status.d/`, and the host's os-release
/// to `rootfs/etc/os-release` unless the rootfs already has one.
///
/// On an error the guard built so far is dropped, so a failed call leaves nothing behind.
///
/// `protected` are image paths the user staged in this pack (`--add-file` destinations). A
/// record that would land on one stops the pack: a file the user asked for is never replaced
/// or removed behind their back.
pub fn stage_records(
    rootfs: &Path,
    owners: &Owners,
    protected: &[PathBuf],
) -> Result<StagedRecords> {
    let mut staged = StagedRecords::default();
    let write = |path: &Path, bytes: &[u8]| -> Result<()> {
        let image = Path::new("/").join(path.strip_prefix(rootfs).unwrap_or(path));
        if protected.contains(&image) {
            bail!(
                "cannot record packages: {} is a file you added with --add-file, and the \
                 package records need that path",
                image.display()
            );
        }
        write_record(path, bytes)
    };

    match &owners.records {
        Records::Dpkg(records) => {
            let status_d = rootfs.join("var/lib/dpkg/status.d");
            create_dirs(rootfs, &status_d, &mut staged.dirs)?;
            for (file, stanza) in records {
                let path = status_d.join(file);
                write(&path, stanza.as_bytes())?;
                staged.files.push(path);
            }
        }
        // Staging is only asked for when there are owners, and every owner has a header, so
        // an empty list means the export and the report disagreed. An image or an SBOM that
        // was asked to carry the packages must not go out with none.
        Records::Rpm(headers) if headers.is_empty() => {
            bail!("cannot record packages: rpm named owners and exported no header for them")
        }
        Records::Rpm(headers) => {
            // rpm builds the database in a directory of its own, and only its bytes come
            // here. They are placed like any other record, at the host's database path: no
            // write goes through a link, and an earlier database is replaced by a rename.
            let files = crate::rpm::build_database(headers)?;
            let db = crate::rpm::db_path().context("asking rpm where its database lives")?;
            let db_dir = rootfs.join(db.strip_prefix("/").unwrap_or(&db));
            create_dirs(rootfs, &db_dir, &mut staged.dirs)?;
            for (name, bytes) in files {
                let path = db_dir.join(name);
                write(&path, &bytes)?;
                staged.files.push(path);
            }
        }
    }

    let os_release = rootfs.join("etc/os-release");
    if os_release.symlink_metadata().is_err() {
        // /etc/os-release is usually a link to /usr/lib/os-release; read through either.
        let host = ["/etc/os-release", "/usr/lib/os-release"]
            .iter()
            .find_map(|p| std::fs::read(p).ok())
            .context("reading the host's os-release, which names the distribution")?;
        create_dirs(rootfs, &rootfs.join("etc"), &mut staged.dirs)?;
        write(&os_release, &host)?;
        staged.files.push(os_release);
    }
    Ok(staged)
}

// Write one record, replacing a regular file that is already there.
//
// Never through a link. A new file is opened O_EXCL, which does not follow a link at the
// final component. An existing REGULAR file is replaced by a rename, which swaps the name
// and does not follow one either. Anything else at that name (a link, a directory) is not
// ours to touch.
fn write_record(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let context = || format!("writing {}", path.display());
    match path.symlink_metadata() {
        Err(_) => std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .and_then(|mut f| f.write_all(bytes))
            .with_context(context),
        Ok(meta) if meta.is_file() => {
            use std::os::unix::fs::PermissionsExt;
            let dir = path.parent().context("a record path has a parent")?;
            let mut tmp = tempfile::Builder::new()
                .permissions(std::fs::Permissions::from_mode(0o666))
                .tempfile_in(dir)
                .with_context(context)?;
            tmp.write_all(bytes).with_context(context)?;
            tmp.persist(path).with_context(context)?;
            Ok(())
        }
        Ok(_) => bail!(
            "cannot record packages: {} exists and is not a regular file",
            path.display()
        ),
    }
}

// Create `dir` and record each directory that did not exist before, so a later removal takes
// away exactly what this call added.
//
// Refuses to go through a symlink. The rootfs can hold links the user asked for
// (`--symlinks preserve`, an `--add-file` link), and a link at `var` or `etc` would send
// these writes to wherever it points, outside the rootfs and onto the host.
fn create_dirs(rootfs: &Path, dir: &Path, created: &mut Vec<PathBuf>) -> Result<()> {
    let relative = dir.strip_prefix(rootfs).unwrap_or(dir);
    let mut walked = rootfs.to_path_buf();
    for part in relative.components() {
        walked.push(part);
        if walked.symlink_metadata().is_ok_and(|m| m.is_symlink()) {
            bail!(
                "cannot record packages: {} is a symlink in the staged tree, and writing \
                 through it would leave the image",
                walked.display()
            );
        }
        if !walked.exists() {
            std::fs::create_dir(&walked)
                .with_context(|| format!("creating {}", walked.display()))?;
            created.push(walked.clone());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_selection_defaults_to_the_report_alone_and_none_stands_alone() {
        let default = PackagesSelection::from_outputs(&[]).unwrap();
        assert!(default.report && !default.sbom && !default.image && !default.explicit);
        assert!(
            !default.needs_records(),
            "the default must never have to fail a pack"
        );

        let all = PackagesSelection::from_outputs(&[
            PackagesOutput::Report,
            PackagesOutput::Sbom,
            PackagesOutput::Image,
        ])
        .unwrap();
        assert!(all.report && all.sbom && all.image && all.explicit && all.any());
        assert!(all.needs_records());

        let image = PackagesSelection::from_outputs(&[PackagesOutput::Image]).unwrap();
        assert!(image.image && !image.report && !image.sbom);

        let none = PackagesSelection::from_outputs(&[PackagesOutput::None]).unwrap();
        assert!(!none.any() && none.explicit);

        // A text report shows no list, so only a selection that the user named survives it.
        assert!(!default.for_text_report().any());
        assert_eq!(all.for_text_report(), all);
        let report = PackagesSelection::from_outputs(&[PackagesOutput::Report]).unwrap();
        assert_eq!(report.for_text_report(), report);
        assert!(
            PackagesSelection::from_outputs(&[PackagesOutput::None, PackagesOutput::Sbom]).is_err()
        );
    }

    #[test]
    fn search_output_yields_owners_and_skips_diversions() {
        let out = "libc6:amd64: /usr/lib/x86_64-linux-gnu/libc.so.6\n\
                   diversion by libc6 from: /lib64/ld-linux-x86-64.so.2\n\
                   diversion by libc6 to: /lib64/ld-linux-x86-64.so.2.usr-is-merged\n\
                   zlib1g:amd64, zlib1g:i386: /usr/share/doc/zlib1g/copyright\n\
                   tzdata: /usr/share/zoneinfo/UTC\n\
                   garbage with no path\n\
                   ../evil: /etc/passwd\n\
                   diversion by dash from: /usr/bin/sh\n\
                   diversion by dash to: /usr/bin/sh.distrib\n\
                   dash, bash: /usr/bin/sh\n\
                   local diversion from: /usr/bin/vi\n\
                   local diversion to: /usr/bin/vi.orig\n\
                   vim: /usr/bin/vi\n";
        assert_eq!(
            parse_search(out),
            [
                ("libc6:amd64", "/usr/lib/x86_64-linux-gnu/libc.so.6"),
                ("zlib1g:amd64", "/usr/share/doc/zlib1g/copyright"),
                ("zlib1g:i386", "/usr/share/doc/zlib1g/copyright"),
                ("tzdata", "/usr/share/zoneinfo/UTC"),
                // Diverted by dash: what is at the path is dash's, not bash's.
                ("dash", "/usr/bin/sh"),
                // Diverted locally: what is at /usr/bin/vi is the administrator's, so vim
                // gets no credit and neither does anyone else.
            ]
            .map(|(p, f)| (p.to_string(), f.to_string()))
        );
    }

    #[test]
    fn show_rows_attach_files_by_either_spelling_of_the_name() {
        let mut files = BTreeMap::from([
            (
                "libc6:amd64".to_string(),
                vec!["/b".to_string(), "/a".to_string(), "/a".to_string()],
            ),
            ("tzdata".to_string(), vec!["/z".to_string()]),
            ("ghost".to_string(), vec!["/g".to_string()]),
        ]);
        let rows = "libc6:amd64\tlibc6\t2.41-12\tamd64\tglibc\n\
                    tzdata\ttzdata\t2025b-4\tall\ttzdata\n\
                    short\trow\n";
        let packages = parse_show(rows, &mut files);
        assert_eq!(packages.len(), 2);
        assert_eq!(packages[0].name, "libc6");
        assert_eq!(packages[0].source, "glibc");
        assert_eq!(packages[0].files, ["/a", "/b"], "sorted and deduplicated");
        assert_eq!(packages[1].arch, "all");
        // A package -S named and -W did not show is dropped, not invented.
        assert!(files.contains_key("ghost"));
    }

    #[test]
    fn records_are_split_per_package_and_a_bad_name_is_refused() {
        let out = "Package: libc6\nStatus: install ok installed\nArchitecture: amd64\n\
                   Version: 2.41-12\nDescription: GNU C Library\n one more line\n\n\
                   Package: libc6\nArchitecture: i386\nVersion: 2.41-12\n\n\
                   Package: tzdata\nVersion: 2025b-4\n";
        let records = parse_records(out).unwrap();
        let names: Vec<&str> = records.iter().map(|(f, _)| f.as_str()).collect();
        assert_eq!(names, ["libc6", "libc6:i386", "tzdata"]);
        assert!(records[0].1.starts_with("Package: libc6\n"));
        assert!(records[0].1.ends_with(" one more line\n"));

        // The name becomes a file name under status.d, so it must not be a path.
        assert!(parse_records("Package: ../../etc/passwd\nVersion: 1\n").is_err());
        // So does the architecture of a second stanza with the same name.
        let two = "Package: a\nArchitecture: amd64\n\nPackage: a\nArchitecture: ../x\n";
        assert!(parse_records(two).is_err());
        // A stanza names its package bare. A qualified name would be qualified a second
        // time when the name repeats (`a:amd64:unknown`). Found by the dpkg_output fuzz target.
        assert!(parse_records("Package: a:amd64\n\nPackage: a:amd64\n").is_err());
        let arch = "Package: a\nArchitecture: amd64\n\nPackage: a\nArchitecture: i386:x\n";
        assert!(parse_records(arch).is_err());
        // The same package twice is kept one time, not written twice.
        let twice = "Package: a\nArchitecture: i386\n\nPackage: a\nArchitecture: i386\n\n\
                     Package: a\nArchitecture: i386\n";
        let names: Vec<String> = parse_records(twice)
            .unwrap()
            .into_iter()
            .map(|r| r.0)
            .collect();
        assert_eq!(names, ["a", "a:i386"]);

        for pattern in ["/usr/bin/i?", "/usr/lib/*", "/opt/[ab]/x", "/a\\b"] {
            assert!(is_pattern(pattern), "{pattern}");
        }
        assert!(!is_pattern("/usr/lib/x86_64-linux-gnu/libstdc++.so.6"));
    }

    #[test]
    fn every_reader_runs_over_one_text_and_hands_on_only_safe_names() {
        let text = "diversion by dash from: /bin/sh\ndash: /bin/sh\nlibc6:amd64: /lib/libc.so.6\n\
                    libc6:amd64\tlibc6\t2.41-12\tamd64\tglibc\nlibc6:amd64\tinstalled\n\
                    dash\t../x\t1\tamd64\tdash\ndash\tdash\t1\t\tdash\n\n\
                    Package: libc6\nArchitecture: amd64\n";
        let parsed = parse_dpkg_output(text);
        let owner = |package: &str, path: &str| (package.to_string(), path.to_string());
        assert_eq!(
            parsed.owners,
            [
                owner("dash", "/bin/sh"),
                owner("libc6:amd64", "/lib/libc.so.6")
            ]
        );
        // The two `dash` rows are not package rows: one has a path for a name, and the other
        // has no architecture. Found by the dpkg_output fuzz target.
        assert_eq!(parsed.names, ["libc6:amd64", "libc6", "amd64"]);
        assert_eq!(parsed.record_files, ["libc6"]);
    }

    #[test]
    fn package_names_exclude_anything_path_like() {
        for good in [
            "libc6",
            "libstdc++6",
            "libssl3t64",
            "zlib1g:amd64",
            "g++-14",
        ] {
            assert!(is_package_name(good), "{good}");
        }
        for bad in [
            "", "..", ".", "a/b", "a b", "Libc6", "a:", ":amd64", "a:b:c",
        ] {
            assert!(!is_package_name(bad), "{bad:?}");
        }
    }

    #[test]
    fn staged_records_are_removed_on_drop_and_kept_on_keep() {
        let owners = Owners {
            records: Records::Dpkg(vec![("libc6".into(), "Package: libc6\n".into())]),
            ..Owners::default()
        };
        let tmp = tempfile::tempdir().unwrap();
        let rootfs = tmp.path();
        // Something the user staged: its directory must survive the cleanup.
        std::fs::create_dir_all(rootfs.join("var/lib/mine")).unwrap();
        std::fs::write(rootfs.join("var/lib/mine/data"), b"x").unwrap();

        if !["/etc/os-release", "/usr/lib/os-release"]
            .iter()
            .any(|p| Path::new(p).exists())
        {
            eprintln!("skipping: this host has no os-release to copy");
            return;
        }
        let staged = stage_records(rootfs, &owners, &[]).unwrap();
        assert_eq!(
            std::fs::read_to_string(rootfs.join("var/lib/dpkg/status.d/libc6")).unwrap(),
            "Package: libc6\n"
        );
        assert!(rootfs.join("etc/os-release").is_file());
        drop(staged);
        assert!(!rootfs.join("var/lib/dpkg").exists(), "created dirs go too");
        assert!(!rootfs.join("etc").exists());
        assert!(
            rootfs.join("var/lib/mine/data").exists(),
            "the user's file stays"
        );

        // An os-release the user staged is theirs: it is neither replaced nor removed.
        std::fs::create_dir_all(rootfs.join("etc")).unwrap();
        std::fs::write(rootfs.join("etc/os-release"), b"ID=mine\n").unwrap();
        drop(stage_records(rootfs, &owners, &[]).unwrap());
        assert_eq!(
            std::fs::read_to_string(rootfs.join("etc/os-release")).unwrap(),
            "ID=mine\n"
        );

        stage_records(rootfs, &owners, &[]).unwrap().keep();
        assert!(rootfs.join("var/lib/dpkg/status.d/libc6").is_file());

        // A second `image` pack into the same directory finds the kept record. It is
        // replaced, not refused.
        let newer = Owners {
            records: Records::Dpkg(vec![(
                "libc6".into(),
                "Package: libc6\nVersion: 2\n".into(),
            )]),
            ..Owners::default()
        };
        stage_records(rootfs, &newer, &[]).unwrap().keep();
        assert_eq!(
            std::fs::read_to_string(rootfs.join("var/lib/dpkg/status.d/libc6")).unwrap(),
            "Package: libc6\nVersion: 2\n"
        );
        // An `sbom`-only pack into that directory must not leave the record behind: the
        // guard removes it although an earlier pack, not this call, created it.
        drop(stage_records(rootfs, &newer, &[]).unwrap());
        assert!(!rootfs.join("var/lib/dpkg/status.d/libc6").exists());
    }

    #[test]
    fn a_failed_staging_leaves_no_directories_behind() {
        // A directory where a record must go makes the write fail after status.d exists.
        let owners = Owners {
            records: Records::Dpkg(vec![("libc6".into(), "Package: libc6\n".into())]),
            ..Owners::default()
        };
        let tmp = tempfile::tempdir().unwrap();
        let rootfs = tmp.path();
        std::fs::create_dir_all(rootfs.join("var")).unwrap();
        std::fs::create_dir_all(rootfs.join("blocker")).unwrap();
        // Make `var/lib/dpkg/status.d/libc6` a directory by staging it first.
        std::fs::create_dir_all(rootfs.join("var/lib/dpkg/status.d/libc6")).unwrap();
        assert!(stage_records(rootfs, &owners, &[]).is_err());
        assert!(
            rootfs.join("var/lib/dpkg/status.d/libc6").is_dir(),
            "theirs stays"
        );

        // With nothing pre-staged, a failure part-way must take its own directories away.
        let rootfs = tmp.path().join("clean");
        std::fs::create_dir(&rootfs).unwrap();
        std::fs::create_dir(rootfs.join("etc")).unwrap();
        std::os::unix::fs::symlink("/nonexistent", rootfs.join("etc/os-release")).unwrap();
        // os-release "exists" (as a dangling link), so it is left alone and staging succeeds;
        // dropping the guard must then remove var/ entirely.
        drop(stage_records(&rootfs, &owners, &[]).unwrap());
        assert!(!rootfs.join("var").exists());
    }

    #[test]
    fn a_record_never_replaces_a_file_the_user_added() {
        let owners = Owners {
            records: Records::Dpkg(vec![("libc6".into(), "Package: libc6\n".into())]),
            ..Owners::default()
        };
        let tmp = tempfile::tempdir().unwrap();
        let rootfs = tmp.path();
        let record = rootfs.join("var/lib/dpkg/status.d/libc6");
        std::fs::create_dir_all(record.parent().unwrap()).unwrap();
        std::fs::write(&record, b"the user's own file").unwrap();

        // The user staged this path with --add-file in this very pack.
        let protected = [PathBuf::from("/var/lib/dpkg/status.d/libc6")];
        let err = stage_records(rootfs, &owners, &protected).unwrap_err();
        assert!(format!("{err:#}").contains("--add-file"), "{err:#}");
        assert_eq!(std::fs::read(&record).unwrap(), b"the user's own file");
        // The same file with no such claim is an earlier pack's record, and is replaced.
        stage_records(rootfs, &owners, &[]).unwrap().keep();
        assert_eq!(std::fs::read(&record).unwrap(), b"Package: libc6\n");
    }

    #[test]
    fn records_never_follow_a_symlink_out_of_the_rootfs() {
        let owners = Owners {
            records: Records::Dpkg(vec![("libc6".into(), "Package: libc6\n".into())]),
            ..Owners::default()
        };
        let tmp = tempfile::tempdir().unwrap();
        let outside = tmp.path().join("outside");
        std::fs::create_dir(&outside).unwrap();

        // A directory link: `var` points out of the rootfs.
        let rootfs = tmp.path().join("a");
        std::fs::create_dir(&rootfs).unwrap();
        std::os::unix::fs::symlink(&outside, rootfs.join("var")).unwrap();
        let err = stage_records(&rootfs, &owners, &[]).unwrap_err();
        assert!(format!("{err:#}").contains("is a symlink"), "{err:#}");
        assert_eq!(
            std::fs::read_dir(&outside).unwrap().count(),
            0,
            "nothing escaped"
        );

        // A file link at the record's own name must not be written through either.
        let rootfs = tmp.path().join("b");
        std::fs::create_dir_all(rootfs.join("var/lib/dpkg/status.d")).unwrap();
        let target = outside.join("victim");
        std::fs::write(&target, b"untouched").unwrap();
        std::os::unix::fs::symlink(&target, rootfs.join("var/lib/dpkg/status.d/libc6")).unwrap();
        assert!(stage_records(&rootfs, &owners, &[]).is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"untouched");
    }

    #[test]
    fn a_path_dpkg_would_read_as_a_pattern_is_never_asked() {
        // On a dpkg host `dpkg-query -S '/usr/bin/i?'` answers for id AND ip. Neither is
        // the file that was asked about, so the answer must be empty. With no dpkg the
        // query itself fails or is empty, which is the same answer.
        let found = search(&[PathBuf::from("/usr/bin/i?")]).unwrap_or_default();
        assert_eq!(found, Vec::<(String, String)>::new());
        if dpkg_available() && Path::new("/usr/bin/id").exists() {
            // Guard the premise: the literal path IS owned, so an empty answer above is the
            // filter at work and not a host that knows nothing.
            let literal = search(&[PathBuf::from("/usr/bin/id")]).unwrap();
            assert!(
                literal.iter().all(|(_, p)| p == "/usr/bin/id"),
                "{literal:?}"
            );
            assert!(!literal.is_empty(), "dpkg owns /usr/bin/id on this host");
        }
    }

    #[test]
    fn only_an_installed_package_is_credited_by_convention() {
        // `dpkg-query -W` lists every package the database knows. A removed package whose
        // configuration files remain reads `config-files`, and one that was never installed
        // reads `not-installed`. Neither built the file on this host.
        let rows = "ca-certificates\tinstalled\n\
                    ca-certificates-java\tconfig-files\n\
                    never-here\tnot-installed\n\
                    libfoo:amd64\tinstalled\n\
                    ../evil\tinstalled\n\
                    no-tab-in-this-row\n";
        let named: Vec<&str> = installed_packages(rows).collect();
        assert_eq!(named, ["ca-certificates", "libfoo:amd64"]);
    }

    #[test]
    fn the_usr_retry_needs_both_spellings_to_be_one_file() {
        // The retry strips the `/usr/` component, never the bare letters.
        assert_eq!("/usrlocal/x".strip_prefix("/usr/"), None);

        let tmp = tempfile::tempdir().unwrap();
        let real = tmp.path().join("real");
        let link = tmp.path().join("link");
        let other = tmp.path().join("other");
        std::fs::write(&real, b"x").unwrap();
        std::fs::write(&other, b"x").unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let s = |p: &Path| p.to_str().unwrap().to_string();
        assert!(same_file(&s(&real), &s(&link)), "a merged path is one file");
        assert!(
            !same_file(&s(&real), &s(&other)),
            "same bytes, different file"
        );
        assert!(!same_file(&s(&real), "/no/such/path"));
    }
}
