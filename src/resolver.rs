//! Resolve a binary's shared-library deps by emulating the `ld.so` search order
//! (not by scraping host `ldd`). The correctness core.
//!
//! Two halves, both here: `parse_elf_info` reads the raw dynamic-linking facts out of an
//! ELF, and `resolve_with` turns each soname into a real path by searching DT_RPATH (the
//! object's own, then its ancestors' — RPATH is transitive, and all of it is ignored when
//! the object also declares RUNPATH), then its own DT_RUNPATH, then the sysroot default dirs.
//! Each RPATH or RUNPATH string is split on ':' into entries, and `$ORIGIN`, `$LIB` and
//! `$PLATFORM` are expanded inside each entry, not searched. After all split entries miss, a
//! string that holds ':' is also tried whole as one directory, before the default dirs. ld.so
//! finds a library there only through the image's ld.so.cache, so a DT_NEEDED file counts only
//! when ldconfig caches it under the NEEDED name. An `--include` file there counts as in 1.x.

use anyhow::{bail, Context, Result};
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};

/// How a binary is linked — decides whether it needs dependency staging at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Linking {
    /// Needs an interpreter and/or shared libraries staged.
    Dynamic,
    /// Self-contained; packs as a single file with no dependency resolution.
    Static,
}

/// Dynamic-linking facts read straight from an ELF, before any path resolution.
///
/// RPATH and RUNPATH are kept separate on purpose: they differ in search
/// precedence and scope, and conflating them is the classic resolution bug —
/// RUNPATH is not inherited by a library's own dependencies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElfInfo {
    /// Program interpreter (PT_INTERP) — the dynamic loader. Absent for static
    /// binaries and shared objects. Not listed in DT_NEEDED, so it must be staged
    /// explicitly; omitting it is the "exit 127 in an empty container" bug.
    pub interpreter: Option<String>,
    /// DT_NEEDED: direct shared-library dependencies, by soname.
    pub needed: Vec<String>,
    /// DT_RPATH: deprecated search paths; searched transitively, only when no RUNPATH.
    pub rpaths: Vec<String>,
    /// DT_RUNPATH: object-local search paths; not inherited by this object's deps.
    pub runpaths: Vec<String>,
    /// DT_SONAME: this object's own soname, if it declares one.
    pub soname: Option<String>,
    /// 64-bit ELF. Drives `$LIB` expansion (lib64 vs lib) during resolution.
    pub is_64: bool,
    /// ELF machine (`e_machine`). Drives `$PLATFORM` and the default lib triplet.
    pub machine: u16,
    /// References `dlopen` or `dlmopen` — its runtime plugins are NOT in the dependency
    /// graph, so resolution can be incomplete (the user may need `--include`).
    pub uses_dlopen: bool,
    /// ELF object type (`e_type`): `ET_DYN` for a shared object or a PIE, `ET_EXEC` for a
    /// fixed-address executable, `ET_CORE` for a core dump.
    pub e_type: u16,
}

impl ElfInfo {
    /// A binary is static when it has neither an interpreter nor any DT_NEEDED
    /// entries — nothing to resolve, so it packs as a single file.
    pub fn linking(&self) -> Linking {
        if self.interpreter.is_none() && self.needed.is_empty() {
            Linking::Static
        } else {
            Linking::Dynamic
        }
    }

    /// True when the interpreter is the musl loader. musl differs fundamentally from
    /// glibc (no NSS, libc-is-the-loader), so Scratchsmith detects and rejects it.
    pub fn is_musl(&self) -> bool {
        self.interpreter
            .as_deref()
            .is_some_and(|i| i.contains("ld-musl") || i.contains("libc.musl"))
    }

    // The `$PLATFORM` token value. Only the arches Scratchsmith targets are named; anything
    // else falls back to an empty string rather than guessing wrong.
    fn platform(&self) -> &'static str {
        match self.machine {
            goblin::elf::header::EM_X86_64 => "x86_64",
            goblin::elf::header::EM_AARCH64 => "aarch64",
            _ => "",
        }
    }
}

/// Reject binaries Scratchsmith cannot correctly pack. musl is fundamentally
/// different (loader path, no NSS module system), so it is hard-failed loudly rather
/// than packed into a subtly broken image.
pub fn ensure_glibc(info: &ElfInfo) -> Result<()> {
    if info.is_musl() {
        bail!(
            "musl binaries are out of scope; Scratchsmith packs glibc binaries only (interpreter: {})",
            escape_if_line_breaking(info.interpreter.as_deref().unwrap_or_default())
        );
    }
    Ok(())
}

/// Read an ELF file and extract its dynamic-linking facts.
pub fn read_elf_info(path: &Path) -> Result<ElfInfo> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    match parse_elf_info(&bytes) {
        Err(e) if bytes.starts_with(b"\x7fELF") => Err(damaged_binary(path, &format!("{e:#}"))),
        parsed => parsed.with_context(|| format!("parsing {} as ELF", path.display())),
    }
}

// The user's own binary, not a library: keep goblin's cause and advise a rebuild.
fn damaged_binary(path: &Path, cause: &str) -> anyhow::Error {
    anyhow::anyhow!(
        "{} starts like an ELF and cannot be parsed (truncated or corrupt). Rebuild the binary \
         or replace it with an intact copy: {cause}",
        printable(path)
    )
}

/// Parse ELF dynamic-linking facts from in-memory bytes. Split from `read_elf_info` so it is
/// unit-testable — and fuzzable — on arbitrary input (this is the untrusted binary a user packs).
pub fn parse_elf_info(bytes: &[u8]) -> Result<ElfInfo> {
    let elf = goblin::elf::Elf::parse(bytes).context("not a valid ELF binary")?;
    Ok(ElfInfo {
        interpreter: elf.interpreter.map(str::to_owned),
        needed: elf.libraries.iter().map(|s| s.to_string()).collect(),
        rpaths: elf.rpaths.iter().map(|s| s.to_string()).collect(),
        runpaths: elf.runpaths.iter().map(|s| s.to_string()).collect(),
        soname: elf.soname.map(str::to_owned),
        is_64: elf.is_64,
        machine: elf.header.e_machine,
        uses_dlopen: references_dlopen(&elf),
        e_type: elf.header.e_type,
    })
}

// A binary that calls dlopen imports the symbol, so finding it among the dynamic symbols
// means the binary loads plugins at run time, which the static graph cannot see.
fn references_dlopen(elf: &goblin::elf::Elf) -> bool {
    elf.dynsyms
        .iter()
        .filter_map(|sym| elf.dynstrtab.get_at(sym.st_name))
        .any(|name| name == "dlopen" || name == "dlmopen")
}

// ---------------------------------------------------------------------------
// Emulate the ld.so search order.
// ---------------------------------------------------------------------------

/// A pinned root filesystem to resolve against, plus the loader's default search
/// dirs under it. Pinning the root (rather than trusting the host) is what makes
/// resolution reproducible; the host environment is never consulted.
pub struct Sysroot {
    root: PathBuf,
    default_dirs: Vec<PathBuf>,
}

impl Sysroot {
    /// Build a sysroot rooted at `root`. Default dirs cover the glibc lib
    /// locations for the arches Scratchsmith targets; non-existent dirs are simply skipped.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        let rel = [
            "lib64",
            "usr/lib64",
            "lib",
            "usr/lib",
            "lib/x86_64-linux-gnu",
            "usr/lib/x86_64-linux-gnu",
            "lib/aarch64-linux-gnu",
            "usr/lib/aarch64-linux-gnu",
        ];
        let default_dirs = rel.iter().map(|d| root.join(d)).collect();
        Sysroot { root, default_dirs }
    }
}

/// A library located during resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedLib {
    /// The soname the loader searched for (`libfoo.so.1`).
    pub soname: String,
    /// The real file it resolved to, symlinks followed.
    pub path: PathBuf,
}

/// The dynamic loader. Staging needs both facts: the kernel execs `PT_INTERP`
/// verbatim, so the loader must live at `image_path`, but the bytes come from the
/// real file at `source` (the `PT_INTERP` symlink is often canonicalized away).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedInterp {
    /// The `PT_INTERP` path the loader must occupy in the image (e.g. `/lib64/ld-...`).
    pub image_path: PathBuf,
    /// The real file to copy the loader bytes from.
    pub source: PathBuf,
}

/// One resolved dependency edge: a parent object needed `soname`, which resolved to `to`
/// (or `None` when it could not be located). Recorded for every DT_NEEDED entry, including
/// repeats and already-visited targets, so the full graph can be reconstructed without the
/// per-path deduplication that `libs` applies. Consumed by the `graph` subcommand.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DepEdge {
    /// The real path of the object that declared the dependency (the binary or a library).
    pub from: PathBuf,
    /// The DT_NEEDED soname as the loader searched for it.
    pub soname: String,
    /// The child's real path, or `None` when the soname did not resolve.
    pub to: Option<PathBuf>,
}

/// The closed set of what a binary needs at runtime.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Resolution {
    /// The dynamic loader. `None` only for a static binary or when the loader is
    /// absent from the sysroot.
    pub interpreter: Option<ResolvedInterp>,
    /// Every transitive shared library, deduplicated by real path.
    pub libs: Vec<ResolvedLib>,
    /// Sonames that could not be located. Non-empty means the image would be broken,
    /// so callers must fail loudly rather than ship it.
    pub missing: Vec<String>,
    /// Parent->child edges, keyed by real path, for graph reconstruction. Unlike `libs`,
    /// this keeps every edge (repeats, diamonds, unresolved), so no edge dangles.
    pub edges: Vec<DepEdge>,
    /// Why a soname in `missing` is missing, when the resolver can tell, one line each.
    /// Diagnosis only: nothing here is resolved or staged. Callers print them with
    /// `print_hints`.
    pub hints: Vec<String>,
    /// A search-path entry that a library resolved through but ld.so does not search, one
    /// line each. The image still loads the library through its ld.so.cache, so nothing here
    /// changes what resolves or stages. `pack` prints them with `print_notes`.
    pub notes: Vec<String>,
    /// A staged library of another ELF class or machine than the binary, which ld.so will not
    /// load, one line each. It is the only copy found, or the binary names it by path. `pack`
    /// prints them with `print_notes`, and stages the library as it did before.
    pub arch_warnings: Vec<String>,
}

impl Resolution {
    /// The loader's image path, rendered for a report. `None` when the ELF carries no
    /// `PT_INTERP`. Both the `pack` and `graph` reports publish this under the same
    /// `interpreter` JSON key, and a consumer can compare the two, so they render it once
    /// here rather than each spelling it out.
    pub fn interpreter_path(&self) -> Option<String> {
        self.interpreter
            .as_ref()
            .map(|i| i.image_path.display().to_string())
    }

    /// Print each hint as one stderr line, never stdout: stdout carries the `--format json`
    /// report (`COMPATIBILITY.md`).
    pub fn print_hints(&self) {
        for h in &self.hints {
            eprintln!("note: {h}");
        }
    }

    /// Print each note as one stderr line, the way `print_hints` does.
    pub fn print_notes(&self) {
        for n in &self.notes {
            eprintln!("note: {n}");
        }
        for w in &self.arch_warnings {
            eprintln!("warning: {w}");
        }
    }
}

/// Supplies the dynamic-linking facts for a file. Abstracted so the search order
/// can be tested against scripted dependency graphs without building real ELFs.
pub trait LinkInfoSource {
    /// The dynamic-linking facts for `path`.
    ///
    /// The two failure shapes are deliberately DIFFERENT types, because conflating them
    /// drops a whole subtree from the resolution, with nothing landing in `missing`:
    ///
    /// - `Ok(None)` — the file was read, and it is not an ELF. For a data file the operator
    ///   named with `--include` that is correct: it has no `DT_NEEDED` of its own, so it is a
    ///   leaf. A file without the magic, reached through a name out of an ELF, fails the
    ///   resolution.
    /// - `Err` — the file could not be READ, or it starts with the ELF magic and does not
    ///   parse ([`UnparsableElf`]). Nothing is known about its dependencies, so treating it as
    ///   a leaf would drop its whole subtree from the resolution without anything landing in
    ///   `Resolution::missing`.
    fn read(&self, path: &Path) -> Result<Option<ElfInfo>>;
}

/// The production source: parse the real file with goblin.
pub struct GoblinSource;

impl LinkInfoSource for GoblinSource {
    fn read(&self, path: &Path) -> Result<Option<ElfInfo>> {
        // Decide from the bytes already read, not a second open: a FIFO cannot be read twice,
        // and an IO error on a re-read would let a corrupt ELF pass as a data file.
        let bytes = read_bounded(path, DEVICE_READ_CAP)?;
        match parse_elf_info(&bytes) {
            Ok(info) => Ok(Some(info)),
            // Keep goblin's cause in the chain for the top-level binary's message.
            Err(e) if bytes.starts_with(b"\x7fELF") => {
                Err(e.context(UnparsableElf(path.to_path_buf())))
            }
            Err(_) => Ok(None),
        }
    }
}

/// The file starts with the ELF magic and does not parse: a truncated or corrupt ELF, not a
/// data file. Its `DT_NEEDED` entries are unknown, so nothing below it can be resolved.
#[derive(Debug)]
pub struct UnparsableElf(pub PathBuf);

impl std::fmt::Display for UnparsableElf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} starts like an ELF and cannot be parsed (truncated or corrupt). Replace it with \
             an intact copy: reinstall the package that owns it, or rebuild it.",
            printable(&self.0)
        )
    }
}

impl std::error::Error for UnparsableElf {}

// The most read from a device or a FIFO. No real library is one, but `/dev/zero` never ends,
// and neither does a FIFO that `yes` feeds.
const DEVICE_READ_CAP: u64 = 256 << 20;

// Read a whole file, as `std::fs::read` does, with the stop chosen by fstat on the open handle.
// A device or a FIFO stops one byte past `device_cap` and fails. A regular file may read past
// the length it reported, because a procfs file reports 0 and still has content, but not past
// `device_cap` too: a tracefs pipe is a regular file of length 0 that never ends. A FIFO ends
// when its writer closes, so an operator can still pipe a real library into `graph`
// (`--include <(cat lib.so)`); `pack`'s stager then refuses it. Only the operator names one: `resolve_with` refuses a FIFO that
// a name out of an ELF resolves to, and PT_INTERP must be a regular file.
fn read_bounded(path: &Path, device_cap: u64) -> Result<Vec<u8>> {
    use std::io::Read;

    let reading = || format!("reading {}", path.display());
    // A blocking open, as before: a FIFO's open waits for a writer that starts late.
    let file = std::fs::File::open(path).with_context(reading)?;
    let meta = file.metadata().with_context(reading)?;
    let mut bytes = Vec::new();
    if meta.is_file() {
        let len = meta.len();
        bytes
            .try_reserve_exact(usize::try_from(len).unwrap_or(usize::MAX))
            .map_err(std::io::Error::from)
            .with_context(reading)?;
        let cap = len.max(device_cap);
        file.take(cap.saturating_add(1))
            .read_to_end(&mut bytes)
            .with_context(reading)?;
        if bytes.len() as u64 > cap {
            bail!(
                "{} yields more than {cap} bytes, more than its own length, so it is not \
                 read as an ELF",
                printable(path)
            );
        }
    } else {
        // A device or a FIFO: its size is no length to reserve, so grow as bytes arrive.
        file.take(device_cap.saturating_add(1))
            .read_to_end(&mut bytes)
            .with_context(reading)?;
        if bytes.len() as u64 > device_cap {
            bail!(
                "{} is a device or a FIFO that yields more than {device_cap} bytes, so it is \
                 not read as an ELF",
                printable(path)
            );
        }
    }
    Ok(bytes)
}

/// Resolve a binary's transitive dependencies against a sysroot, using goblin.
pub fn resolve(binary: &Path, sysroot: &Sysroot) -> Result<Resolution> {
    resolve_with(binary, sysroot, &[], &GoblinSource)
}

/// Resolve, additionally pulling in `includes` (sonames or paths) as if the binary
/// had needed them — the `--include` escape hatch for `dlopen`'d plugins the static
/// graph cannot see.
pub fn resolve_with_includes(
    binary: &Path,
    sysroot: &Sysroot,
    includes: &[String],
) -> Result<Resolution> {
    resolve_with(binary, sysroot, includes, &GoblinSource)
}

/// Resolve using an explicit link-info source (the testable entry point).
pub fn resolve_with(
    binary: &Path,
    sysroot: &Sysroot,
    includes: &[String],
    source: &dyn LinkInfoSource,
) -> Result<Resolution> {
    let root_path =
        std::fs::canonicalize(binary).with_context(|| format!("locating {}", binary.display()))?;
    let mut root_info = source
        .read(&root_path)
        .map_err(|e| match e.is::<UnparsableElf>() {
            true => {
                let cause: Vec<_> = e.chain().skip(1).map(ToString::to_string).collect();
                damaged_binary(&root_path, &cause.join(": "))
            }
            false => e,
        })?
        .ok_or_else(|| anyhow::anyhow!("{} is not a valid ELF binary", root_path.display()))?;
    // Treat --include entries as extra direct dependencies of the binary, so they and
    // their own transitive deps are resolved and staged like anything else. They go after
    // the binary's own DT_NEEDED, so the count of those tells the two apart below.
    let declared_needed = root_info.needed.len();
    root_info.needed.extend(includes.iter().cloned());

    let mut resolution = Resolution::default();

    // The loader answers to its PT_INTERP string and its DT_SONAME.
    let mut loader_names: Vec<(String, PathBuf)> = Vec::new();
    // The loader is named by PT_INTERP, not DT_NEEDED, so resolve it separately.
    // Keep the verbatim PT_INTERP path (where it must live) alongside the real file.
    if let Some(interp) = &root_info.interpreter {
        let loader = reroot(&sysroot.root, Path::new(interp));
        if loader.exists() {
            // PT_INTERP is a string out of the packed binary and can name any host file, which
            // would then ship in the image. Stage only a regular file that starts like an ELF.
            // `is_file` goes first, so a FIFO is never opened and cannot block the read.
            if !loader.is_file() || !has_elf_magic(&loader) {
                bail!(
                    "the program interpreter (PT_INTERP) `{}` is not an ELF file: {}. Refusing \
                     it, because that path can name any host file. Rebuild the binary with a \
                     real loader path.",
                    escape_for_display(interp),
                    printable(&canonical(&loader))
                );
            }
            // The kernel loads an ET_DYN or an ET_EXEC interpreter. An ELF of another type (a
            // core dump holds a process's memory) is a host file the binary picked.
            // A corrupt loader fails here, before the walk, so the error is the same whether or
            // not a library lists it as DT_NEEDED.
            let parsed = source.read(&canonical(&loader)).with_context(|| {
                format!(
                    "the program interpreter (PT_INTERP) `{}`",
                    escape_for_display(interp)
                )
            })?;
            if let Some(info) = &parsed {
                if info.e_type != goblin::elf::header::ET_DYN
                    && info.e_type != goblin::elf::header::ET_EXEC
                {
                    bail!(
                        "the program interpreter (PT_INTERP) `{}` is {}, which the kernel cannot \
                         load as an interpreter: {}. Refusing it, because that path can name \
                         any host file. Rebuild the binary with a real loader path.",
                        escape_for_display(interp),
                        elf_type_name(info.e_type),
                        printable(&canonical(&loader))
                    );
                }
            }
            loader_names.push((interp.clone(), canonical(&loader)));
            if let Some(name) = parsed.and_then(|info| info.soname) {
                loader_names.push((name, canonical(&loader)));
            }
            crate::verbose::line(|| {
                format!(
                    "{} loads through the interpreter {interp}, copied from {}",
                    root_path.display(),
                    canonical(&loader).display()
                )
            });
            resolution.interpreter = Some(ResolvedInterp {
                image_path: PathBuf::from(interp),
                source: canonical(&loader),
            });
        } else {
            crate::verbose::line(|| format!("the interpreter {interp} is not in the sysroot"));
            resolution.missing.push(interp.clone());
        }
    }
    crate::verbose::line(|| {
        format!(
            "the default library dirs are {}",
            dirs_for_display(&sysroot.default_dirs)
        )
    });

    // Breadth-first walk. Each item carries the transitive RPATH dirs contributed
    // by its ancestors — RPATH is inherited down the tree, RUNPATH is not. The two lists are
    // the split entries and the whole-string fallbacks (see `literal_dirs`).
    let mut visited = HashSet::new();
    visited.insert(root_path.clone());
    // Each name a loaded object answers to, with its real file. The first object loaded wins.
    let mut loaded: HashMap<String, PathBuf> = HashMap::new();
    for (name, real) in &loader_names {
        loaded.entry(name.clone()).or_insert_with(|| real.clone());
    }
    let mut queue = VecDeque::new();
    // Fields: the real path, where the object was found, its ELF info, what it inherits, the
    // count of leading `needed` entries the ELF itself declared (only the binary carries more:
    // its --include entries), and whether it loads at program start (false for an object
    // reached only through an --include, which is dlopen'd later). Where it was found is what
    // `$ORIGIN` names: glibc takes it from the name it opened, not the symlink target, and
    // from the real path for the binary.
    queue.push_back((
        root_path.clone(),
        root_path.clone(),
        root_info.clone(),
        (
            Vec::<PathBuf>::new(),
            Vec::<PathBuf>::new(),
            Vec::<Option<Gap>>::new(),
            Vec::<Option<CpuEntry>>::new(),
        ),
        declared_needed,
        true,
    ));
    // Each entry that ld.so does not search, with the sonames found only through it, in the
    // order they were found, and why ldconfig would not cache one. One note per entry
    // (decision-019: no behavior change).
    let mut gaps: Vec<(Gap, Vec<GapLib>)> = Vec::new();
    // A library that ships while ld.so loads another copy on some Intel CPUs (decision-018).
    let mut cpu_notes: Vec<String> = Vec::new();

    while let Some((
        obj_path,
        found_at,
        obj,
        (inherited_rpaths, inherited_literals, inherited_gaps, inherited_cpu),
        declared,
        at_start,
    )) = queue.pop_front()
    {
        let obj_dir = obj_path.parent().unwrap_or(Path::new("/"));
        let origin_dir = found_at.parent().unwrap_or(Path::new("/"));

        // One glibc rule, read twice below: an object that declares RUNPATH searches NO
        // RPATH for its own lookups, neither its own nor one inherited from an ancestor
        // (`_dl_map_object`: "when the object has the RUNPATH information we don't use any
        // RPATHs").
        let searches_rpath = obj.runpaths.is_empty();
        let used_rpaths: &[String] = if searches_rpath { &obj.rpaths } else { &[] };
        // `$PLATFORM` has no value here, so the entry is searched with the token gone and a
        // same-named file in that other directory can stage in place of the arch-specific
        // one. Refuse only where a search can use the entry. A soname with a slash is a path
        // and skips the search list, so a RUNPATH entry needs a bare soname on this object.
        // An RPATH entry is also handed to every child, so any DT_NEEDED at all is enough.
        if root_info.platform().is_empty() {
            let bare_soname = obj.needed.iter().any(|n| !n.contains('/'));
            let rpaths = search_entries(used_rpaths).filter(|_| !obj.needed.is_empty());
            let runpaths = search_entries(&obj.runpaths).filter(|_| bare_soname);
            for entry in rpaths.chain(runpaths) {
                if entry.contains("$PLATFORM") || entry.contains("${PLATFORM}") {
                    bail!(
                        "`$PLATFORM` has no value for this architecture ({}), so the search \
                         path `{}` in {} would be searched as `{}` and a library from the \
                         wrong directory could ship. Write the directory name in the search \
                         path in place of `$PLATFORM`, and link that file again.",
                        goblin::elf::header::machine_to_str(root_info.machine),
                        entry.escape_debug(),
                        printable(&obj_path),
                        expand_tokens(entry, origin_dir, &root_info).escape_debug()
                    );
                }
            }
        }
        let own_rpaths = build_dirs(used_rpaths, origin_dir, &sysroot.root, &root_info);
        let runpath_dirs = build_dirs(&obj.runpaths, origin_dir, &sysroot.root, &root_info);
        // Index for index with the dirs above, so a hit in `search` names its entry.
        let own_rpath_gaps = entry_gaps(used_rpaths, "RPATH", &obj_path, &root_info);
        let runpath_gaps = entry_gaps(&obj.runpaths, "RUNPATH", &obj_path, &root_info);
        let own_rpath_cpu = cpu_entries(
            used_rpaths,
            "RPATH",
            &obj_path,
            origin_dir,
            sysroot,
            &root_info,
        );
        let runpath_cpu = cpu_entries(
            &obj.runpaths,
            "RUNPATH",
            &obj_path,
            origin_dir,
            sysroot,
            &root_info,
        );
        let own_literals = literal_dirs(used_rpaths, origin_dir, &sysroot.root, &root_info);
        let runpath_literals = literal_dirs(&obj.runpaths, origin_dir, &sysroot.root, &root_info);

        // Search order: RPATH (own, then ancestors' — transitive) -> RUNPATH (this
        // object only) -> the whole-string fallbacks, in the same order -> default dirs.
        // LD_LIBRARY_PATH is deliberately omitted, and so is the host's /etc/ld.so.cache:
        // resolution never trusts the host's loader state.
        let mut search: Vec<PathBuf> = Vec::new();
        search.extend(own_rpaths.iter().cloned());
        if searches_rpath {
            search.extend(inherited_rpaths.iter().cloned());
        }
        search.extend(runpath_dirs);
        let mut search_gaps = own_rpath_gaps.clone();
        if searches_rpath {
            search_gaps.extend(inherited_gaps.iter().cloned());
        }
        search_gaps.extend(runpath_gaps);
        let mut search_cpu = own_rpath_cpu.clone();
        if searches_rpath {
            search_cpu.extend(inherited_cpu.iter().cloned());
        }
        search_cpu.extend(runpath_cpu);
        if !obj.needed.is_empty() {
            crate::verbose::line(|| {
                let hidden = !obj.rpaths.is_empty() || !inherited_rpaths.is_empty();
                let skipped = if !searches_rpath && hidden {
                    ", and no RPATH, because it has RUNPATH"
                } else {
                    ""
                };
                if search.is_empty() {
                    format!(
                        "{} searches only the default dirs{skipped}",
                        obj_path.display()
                    )
                } else {
                    format!(
                        "{} searches {} before the default dirs{skipped}",
                        obj_path.display(),
                        dirs_for_display(&search)
                    )
                }
            });
        }
        let mut literals: Vec<PathBuf> = own_literals.clone();
        if searches_rpath {
            literals.extend(inherited_literals.iter().cloned());
        }
        literals.extend(runpath_literals);

        // Children inherit the RPATH view this object searched (own + ancestors'), never its
        // RUNPATH — that is the "RUNPATH is not inherited" rule. An object with RUNPATH
        // still passes its ANCESTORS' RPATH on. Its OWN RPATH, if it carries both tags, is
        // not passed on, and glibc agrees. `elf_get_dynamic_info` (elf/get-dynamic-info.h):
        // "If both RUNPATH and RPATH are given, the latter is ignored", and it clears the
        // DT_RPATH entry there, so no later ancestor walk sees it. Measured on glibc 2.41.
        let mut child_rpaths = own_rpaths;
        child_rpaths.extend(inherited_rpaths.iter().cloned());
        let mut child_literals = own_literals;
        child_literals.extend(inherited_literals.iter().cloned());
        let mut child_gaps = own_rpath_gaps;
        child_gaps.extend(inherited_gaps.iter().cloned());
        let mut child_cpu = own_rpath_cpu;
        child_cpu.extend(inherited_cpu.iter().cloned());
        for (i, soname) in obj.needed.iter().enumerate() {
            // A DT_NEEDED name in a whole-string dir loads only through the cache. An
            // --include is the operator's file, which the program may open by path or by its
            // SONAME, so it stages from there as in 1.x.
            let in_literals = |dirs: &[PathBuf], not_cached: &mut Vec<String>| {
                if i < declared {
                    find_cached(soname, dirs, source, not_cached)
                } else {
                    find_lib(soname, dirs, obj_dir, &sysroot.root)
                }
            };
            let mut not_cached = Vec::new();
            // ld.so uses an object that is already loaded under this name and does not search,
            // so the notes about a search (a gap entry, a CPU copy) do not apply to the edge.
            let declared_bare = i < declared && !soname.contains('/');
            let already = declared_bare.then(|| loaded.get(soname).cloned()).flatten();
            let matched = already.is_some();
            // ld.so skips a file of another class or machine and keeps searching (glibc's
            // open_verify), so a 32-bit copy early on the path does not hide the right one.
            // When every copy is of another arch, the first stays the pick, as before, and a
            // warning says the image cannot load it: refusing would fail a pack that passes.
            let mut skipped = Vec::new();
            let fits = |path: &Path| arch_fits(source, path, &root_info);
            let found = already
                .or_else(|| {
                    find_fitting(soname, &search, obj_dir, &sysroot.root, &fits, &mut skipped)
                })
                .or_else(|| in_literals(&literals, &mut not_cached))
                .or_else(|| {
                    find_fitting(
                        soname,
                        &sysroot.default_dirs,
                        obj_dir,
                        &sysroot.root,
                        &fits,
                        &mut skipped,
                    )
                })
                .or_else(|| skipped.first().cloned());
            // The gap note is about the copy that was picked, so a wrong-arch copy skipped in a
            // gap entry does not raise one.
            let gap = found
                .as_ref()
                .filter(|_| !matched)
                .and_then(|hit| gap_hit(soname, hit, &search, &search_gaps, &sysroot.default_dirs));
            if let Some((gap, hit)) = gap {
                // The note says the image's cache loads it, so check that ldconfig caches it.
                let lib = (soname.clone(), cache_miss(soname, &hit, source));
                match gaps.iter_mut().find(|(g, _)| g == gap) {
                    Some((_, libs)) if !libs.iter().any(|(s, _)| s == soname) => libs.push(lib),
                    Some(_) => {}
                    None => gaps.push((gap.clone(), vec![lib])),
                }
            }
            if let Some(path) = found.as_ref().filter(|path| !matched && !fits(path)) {
                let how = if soname.contains('/') {
                    "named by path"
                } else {
                    "the only copy found"
                };
                // An --include loads later through dlopen, so the image still starts.
                let effect = if i < declared {
                    "the image cannot start"
                } else {
                    "the program cannot open it"
                };
                push_unique(
                    &mut resolution.arch_warnings,
                    format!(
                        "`{}` resolved to {}, {how}, which is a {} library. {} is {}, so the \
                         loader will not load it and {effect}. Put a {4} copy on the search \
                         path.",
                        soname.escape_debug(),
                        printable(path),
                        arch_of(source, path),
                        printable(&root_path),
                        arch_label(root_info.is_64, root_info.machine),
                    ),
                );
            }
            let Some(found) = found else {
                for hint in not_cached {
                    push_unique(&mut resolution.hints, hint);
                }
                for hint in cpu_copy_hints(soname, &search, &search_cpu) {
                    push_unique(&mut resolution.hints, hint);
                }
                // RUNPATH hides an ancestor's RPATH from this object. If the library sits
                // there, say so, so the user is not told only that it is missing. The probe
                // names the cause and nothing more: the soname stays missing. An inherited
                // whole-string dir counts only as a RUNPATH entry of this object would count.
                if !searches_rpath {
                    let probe = find_lib(soname, &inherited_rpaths, obj_dir, &sysroot.root)
                        .or_else(|| in_literals(&inherited_literals, &mut Vec::new()));
                    if let Some(hit) = probe {
                        let dir = hit.parent().unwrap_or(Path::new("/"));
                        push_unique(
                            &mut resolution.hints,
                            format!(
                                "`{}` is in {}, an RPATH that {} inherits from a parent. {2} \
                                 has RUNPATH, so the loader does not search an inherited RPATH \
                                 for it. Give {2} a RUNPATH that lists {1}.",
                                soname.escape_debug(),
                                printable(dir),
                                printable(&obj_path)
                            ),
                        );
                    }
                }
                crate::verbose::line(|| {
                    format!("{} needs `{soname}`: not found", obj_path.display())
                });
                push_unique(&mut resolution.missing, soname.clone());
                resolution.edges.push(DepEdge {
                    from: obj_path.clone(),
                    soname: soname.clone(),
                    to: None,
                });
                continue;
            };
            let real = canonical(&found);
            let loads_at_start = at_start && i < declared;
            if loads_at_start {
                loaded.entry(soname.clone()).or_insert_with(|| real.clone());
            }
            let reach = CpuReach {
                search: &search,
                cpu: &search_cpu,
                gaps: &search_gaps,
                default_dirs: &sysroot.default_dirs,
            };
            if let Some(note) = (!matched)
                .then(|| cpu_copy_note(soname, &found, &reach, source))
                .flatten()
            {
                push_unique(&mut cpu_notes, note);
            }
            crate::verbose::line(|| {
                let how = if matched { ", already loaded" } else { "" };
                format!(
                    "{} needs `{soname}`: {}{how}",
                    obj_path.display(),
                    real.display()
                )
            });
            // Record the edge before the visited check, so a diamond or a repeat keeps its
            // edge even though the target is staged only once.
            resolution.edges.push(DepEdge {
                from: obj_path.clone(),
                soname: soname.clone(),
                to: Some(real.clone()),
            });
            if !visited.insert(real.clone()) {
                continue;
            }
            resolution.libs.push(ResolvedLib {
                soname: soname.clone(),
                path: real.clone(),
            });
            // An --include'd data file is kept as a leaf rather than aborting the whole
            // resolution. A file that cannot be READ, or a corrupt ELF, is not: its own
            // DT_NEEDED children are never queued, never resolved and never staged, and they
            // never reach `missing` either, because nothing asked for them.
            //
            // What the user saw depended on the command. `graph` resolves without staging, so
            // it exited 0 and reported a tree with a whole branch absent. `pack` did fail, but
            // only later and for the wrong reason: the library is pushed to `resolution.libs`
            // just above, and the stager's copy of that same unreadable file failed, so the
            // error named a copy. `check_lib_policy` runs after `stager::stage`, so the
            // --require/--deny gate was never reached rather than blind.
            //
            // No library is a FIFO, a device or a socket, and the name came out of an ELF. A
            // FIFO with no writer blocks the open forever, and one with a writer never has to
            // end. Refuse it before the read opens it. An unreadable path is left to the read.
            if i < declared && std::fs::metadata(&real).is_ok_and(|meta| !meta.is_file()) {
                bail!(
                    "{} needs `{}`, which resolved to {}, and that is not a regular file. \
                     Refusing it, because that name can point at any host file. Rebuild the \
                     binary so it names a real library.",
                    printable(&obj_path),
                    escape_for_display(soname),
                    printable(&real)
                );
            }
            // A corrupt ELF fails here. A corrupt loader already failed at PT_INTERP above.
            match source.read(&real)? {
                // A library the ELF named must be a shared object: glibc (2.17 to 2.41 at
                // least) fails any other type with "cannot dynamically load executable". So it
                // is a host file the name happened to reach, a core dump with a process's
                // memory for one, and it is not staged. --include stays the operator's.
                Some(child) if i < declared && child.e_type != goblin::elf::header::ET_DYN => {
                    bail!(
                        "{} needs `{}`, which resolved to {}, and that file is {}, not a shared \
                         object. Refusing it, because that name can point at any host file. \
                         Rebuild the binary so it names a real library.",
                        printable(&obj_path),
                        escape_for_display(soname),
                        printable(&real),
                        elf_type_name(child.e_type)
                    )
                }
                Some(child) => {
                    if let (true, Some(name)) = (loads_at_start, &child.soname) {
                        loaded.entry(name.clone()).or_insert_with(|| real.clone());
                    }
                    let declared = child.needed.len();
                    // A relative search entry finds a relative path; its real path is the
                    // only absolute directory there is.
                    let found_at = if found.is_absolute() {
                        found
                    } else {
                        real.clone()
                    };
                    queue.push_back((
                        real,
                        found_at,
                        child,
                        (
                            child_rpaths.clone(),
                            child_literals.clone(),
                            child_gaps.clone(),
                            child_cpu.clone(),
                        ),
                        declared,
                        loads_at_start,
                    ));
                }
                // The name came out of an ELF: a path, or a bare name found through a search
                // path the ELF set, can point at any host file, which would then ship in the
                // image. Only the operator's --include may stage a file that is not an ELF.
                None if i < declared => bail!(
                    "{} needs `{}`, which resolved to {}, and that file is not an ELF. \
                     Refusing it, because that name can point at any host file. Rebuild the \
                     binary so it names a real library.",
                    printable(&obj_path),
                    escape_for_display(soname),
                    printable(&real)
                ),
                None => {}
            }
        }
    }

    resolution.notes = gaps
        .iter()
        .map(|(gap, sonames)| gap.note(sonames))
        .collect();
    resolution.notes.extend(cpu_notes);
    Ok(resolution)
}

// A search-path entry that this resolver searches but ld.so does not. Decision-019 keeps the
// search as it is, because the image's ld.so.cache lists the directory and still loads the
// library, so a pack that works today keeps working. The entry only earns a note.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Gap {
    owner: PathBuf,
    tag: &'static str,
    entry: String,
    kind: GapKind,
}

// A soname found through a gap, and why ldconfig would not cache it, if it would not.
type GapLib = (String, Option<String>);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GapKind {
    // A wholly empty RPATH or RUNPATH string, which glibc ignores. It is read here as $ORIGIN.
    Empty,
    // `$ORIGINX`, `$LIB_x` and the like. glibc's `is_dst` takes the name only when no
    // letter, digit or `_` follows it, and keeps the rest literal. It is expanded here.
    Token,
    // ld.so reads a relative entry against the working directory. It is read here against
    // the object's directory.
    Relative,
}

impl Gap {
    // `libs` pairs each soname with why ldconfig does not cache it, if it does not.
    fn note(&self, libs: &[GapLib]) -> String {
        let (tag, owner) = (self.tag, printable(&self.owner));
        let cached: Vec<String> = libs
            .iter()
            .filter(|(_, miss)| miss.is_none())
            .map(|(s, _)| format!("`{}`", s.escape_debug()))
            .collect();
        let loads = if cached.len() == 1 { "loads" } else { "load" };
        let (entry, why) = match self.kind {
            GapKind::Empty => (
                format!("{owner} has an empty {tag} string"),
                "it ignores an empty string",
            ),
            GapKind::Token => (
                format!("{tag} entry `{}` of {owner}", self.entry.escape_debug()),
                "it expands `$ORIGIN`, `$LIB` and `$PLATFORM` only when no letter, digit or `_` \
                 follows the name",
            ),
            GapKind::Relative => (
                format!("{tag} entry `{}` of {owner}", self.entry.escape_debug()),
                "it reads a relative entry against the working directory, not the object's \
                 directory",
            ),
        };
        let mut note = format!("{entry}: ld.so does not search this entry, because {why}");
        if !cached.is_empty() {
            note.push_str(&format!(
                ", so {} {loads} only through the image's ld.so.cache",
                cached.join(", ")
            ));
        }
        for (soname, miss) in libs {
            if let Some(miss) = miss {
                note.push_str(&format!(
                    ". The image's ld.so cannot find `{}` either, because ldconfig does not \
                     cache it under that name: {miss}",
                    soname.escape_debug()
                ));
            }
        }
        note
    }
}

// One `Option<Gap>` per entry of `search_entries(raw)`, in the same order as `build_dirs`.
fn entry_gaps(
    raw: &[String],
    tag: &'static str,
    owner: &Path,
    root_info: &ElfInfo,
) -> Vec<Option<Gap>> {
    let origin_dir = owner.parent().unwrap_or(Path::new("/"));
    search_entries(raw)
        .map(|entry| {
            let kind = if entry.is_empty() {
                // `search_entries` drops an empty entry of a list, so this is a whole string.
                GapKind::Empty
            } else if holds_unknown_token(entry) {
                GapKind::Token
            } else if !Path::new(&expand_tokens(entry, origin_dir, root_info)).is_absolute() {
                GapKind::Relative
            } else {
                return None;
            };
            Some(Gap {
                owner: owner.to_path_buf(),
                tag,
                entry: entry.to_owned(),
                kind,
            })
        })
        .collect()
}

// True when `$ORIGIN`, `$LIB` or `$PLATFORM` is followed by a letter, digit or `_`, which
// `expand_tokens` expands and glibc's `is_dst` (elf/dl-load.c, 2.41) keeps literal.
fn holds_unknown_token(entry: &str) -> bool {
    entry.match_indices('$').any(|(at, _)| {
        ["ORIGIN", "LIB", "PLATFORM"].iter().any(|name| {
            entry[at + 1..].strip_prefix(name).is_some_and(|after| {
                after
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
            })
        })
    })
}

// The entry a bare `soname` resolved through to `found`, when ld.so would not search it there,
// and that file. A slash soname skips the search list. A hit counts only when neither an entry
// that ld.so does search nor a default directory names the same directory, because then ld.so
// finds the same file.
fn gap_hit<'a>(
    soname: &str,
    found: &Path,
    search: &[PathBuf],
    gaps: &'a [Option<Gap>],
    default_dirs: &[PathBuf],
) -> Option<(&'a Gap, PathBuf)> {
    if soname.contains('/') {
        return None;
    }
    let at = search.iter().position(|dir| dir.join(soname) == found)?;
    let gap = gaps[at].as_ref()?;
    let dir = &search[at];
    let searched = search
        .iter()
        .zip(gaps)
        .any(|(d, g)| g.is_none() && d == dir)
        || default_dirs.contains(dir);
    (!searched).then(|| (gap, dir.join(soname)))
}

// glibc's own values of `$PLATFORM` on x86_64. On an Intel CPU with the features each one
// needs, `init_cpu_features` (sysdeps/x86/cpu-features.c, 2.26 to 2.41) sets `dl_platform` to
// one of them in place of the kernel's `x86_64`. Decision-018 keeps `x86_64` here, because the
// other copies are optimized builds that not every CPU can run, and staging them grows the
// image. They only earn a hint or a note.
const X86_64_CPU_PLATFORMS: [&str; 2] = ["haswell", "xeon_phi"];

// A search-path entry that names `$PLATFORM` on x86_64, with the directory it names under
// each value in `X86_64_CPU_PLATFORMS`.
#[derive(Debug, Clone)]
struct CpuEntry {
    owner: PathBuf,
    tag: &'static str,
    entry: String,
    dirs: Vec<(&'static str, PathBuf)>,
}

impl CpuEntry {
    fn describe(&self) -> String {
        format!(
            "{} entry `{}` of {}",
            self.tag,
            self.entry.escape_debug(),
            printable(&self.owner)
        )
    }
}

// One `Option<CpuEntry>` per entry of `search_entries(raw)`, in the same order as `build_dirs`.
// An entry that ld.so does not search at all is a `Gap` and gets its own note instead.
// `origin_dir` is where `owner` was found, which may be a symlink's directory.
fn cpu_entries(
    raw: &[String],
    tag: &'static str,
    owner: &Path,
    origin_dir: &Path,
    sysroot: &Sysroot,
    root_info: &ElfInfo,
) -> Vec<Option<CpuEntry>> {
    search_entries(raw)
        .map(|entry| {
            let names_platform = entry.contains("$PLATFORM") || entry.contains("${PLATFORM}");
            let searched = !entry.is_empty()
                && !holds_unknown_token(entry)
                && Path::new(&expand_tokens(entry, origin_dir, root_info)).is_absolute();
            (root_info.machine == goblin::elf::header::EM_X86_64 && names_platform && searched)
                .then(|| CpuEntry {
                    owner: owner.to_path_buf(),
                    tag,
                    entry: entry.to_owned(),
                    dirs: X86_64_CPU_PLATFORMS
                        .iter()
                        .map(|&p| {
                            (
                                p,
                                entry_dir_as(entry, origin_dir, &sysroot.root, root_info, p),
                            )
                        })
                        .collect(),
                })
        })
        .collect()
}

// One hint for each CPU-specific copy of a missing bare `soname`. `search` and `cpu` are index
// for index, as `search` and `search_gaps` are in the walk.
fn cpu_copy_hints(soname: &str, search: &[PathBuf], cpu: &[Option<CpuEntry>]) -> Vec<String> {
    if soname.contains('/') {
        return Vec::new();
    }
    let s = soname.escape_debug();
    search
        .iter()
        .zip(cpu)
        .filter_map(|(dir, entry)| Some((dir, entry.as_ref()?)))
        .flat_map(|(dir, entry)| {
            let s = &s;
            entry
                .dirs
                .iter()
                .filter(|(_, alt)| alt.join(soname).exists())
                .map(move |(name, alt)| {
                    format!(
                        "`{s}` is in {}, which {} names only on an Intel CPU that glibc names \
                         `{name}`. Scratchsmith reads `$PLATFORM` as `x86_64`, as glibc does on \
                         every other x86_64 CPU, so it does not use that copy. Put an `x86_64` \
                         build of `{s}` in {}.",
                        printable(alt),
                        entry.describe(),
                        printable(dir)
                    )
                })
        })
        .collect()
}

// The search list of one object, index for index, for `cpu_copy_note`.
struct CpuReach<'a> {
    search: &'a [PathBuf],
    cpu: &'a [Option<CpuEntry>],
    gaps: &'a [Option<Gap>],
    default_dirs: &'a [PathBuf],
}

// A note when bare `soname` ships from `found` while ld.so, on an Intel CPU that glibc names
// `haswell` or `xeon_phi`, would load another copy through a `$PLATFORM` entry. That search is
// the one ld.so runs on such a CPU: every entry it searches, each `$PLATFORM` read as that name,
// then the default directories. The CPU copy is not staged, so on such a CPU the image's ld.so
// still finds the shipped copy through an entry that names its directory outright, a default
// directory, or its ld.so.cache, if ldconfig caches it under the needed name.
fn cpu_copy_note(
    soname: &str,
    found: &Path,
    reach: &CpuReach,
    source: &dyn LinkInfoSource,
) -> Option<String> {
    if soname.contains('/') {
        return None;
    }
    let real = canonical(found);
    let searched = || {
        reach
            .search
            .iter()
            .zip(reach.cpu.iter().zip(reach.gaps))
            .filter(|(_, (_, gap))| gap.is_none())
            .map(|(dir, (cpu, _))| (dir, cpu.as_ref()))
    };
    let copies: Vec<(&CpuEntry, &str, PathBuf)> = X86_64_CPU_PLATFORMS
        .iter()
        .enumerate()
        .filter_map(|(i, &name)| {
            let (entry, copy) = searched()
                .map(|(dir, cpu)| match cpu {
                    Some(entry) => (Some(entry), entry.dirs[i].1.join(soname)),
                    None => (None, dir.join(soname)),
                })
                .chain(reach.default_dirs.iter().map(|d| (None, d.join(soname))))
                .find(|(_, copy)| copy.exists())?;
            // Only a hit through a `$PLATFORM` entry differs by CPU. Any other hit is the same
            // file on every CPU, and a gap there has its own note.
            let entry = entry?;
            (canonical(&copy) != real).then_some((entry, name, copy))
        })
        .collect();
    if copies.is_empty() {
        return None;
    }
    let s = soname.escape_debug();
    let mut note = format!("`{s}` ships from {}", printable(found));
    for (entry, name, copy) in &copies {
        note.push_str(&format!(
            ". On an Intel CPU that glibc names `{name}`, ld.so reads `$PLATFORM` in {} as \
             `{name}` and loads the copy in {} instead, which the image leaves out",
            entry.describe(),
            printable(copy.parent().unwrap_or(Path::new("/")))
        ));
    }
    let shipped_dir = found.parent().unwrap_or(Path::new("/"));
    let direct = searched().any(|(dir, cpu)| cpu.is_none() && dir == shipped_dir)
        || reach.default_dirs.iter().any(|d| d == shipped_dir);
    match cache_miss(soname, found, source).filter(|_| !direct) {
        Some(miss) => note.push_str(&format!(
            ". On such a CPU the image's ld.so cannot find `{s}` at all, because ldconfig does \
             not cache the shipped copy under that name: {miss}"
        )),
        None => note.push_str(". The image loads the shipped copy on every CPU"),
    }
    Some(note)
}

// Expand ld.so tokens in a search path against the object that owns it. `$ORIGIN`
// is the owning object's directory — not the top binary's — which is the whole
// point of the token; expanding it wrong is a classic staging bug.
fn expand_tokens(raw: &str, origin_dir: &Path, root: &ElfInfo) -> String {
    expand_tokens_as(raw, origin_dir, root, root.platform())
}

// `expand_tokens`, with `platform` as the value of `$PLATFORM`.
fn expand_tokens_as(raw: &str, origin_dir: &Path, root: &ElfInfo, platform: &str) -> String {
    let origin = origin_dir.to_string_lossy();
    let lib = if root.is_64 { "lib64" } else { "lib" };
    raw.replace("${ORIGIN}", &origin)
        .replace("$ORIGIN", &origin)
        .replace("${LIB}", lib)
        .replace("$LIB", lib)
        .replace("${PLATFORM}", platform)
        .replace("$PLATFORM", platform)
}

// The entries of RPATH or RUNPATH strings, in order. ld joins several -rpath flags into one
// string, and ld.so splits it on ':' (`decompose_rpath`). An empty entry in a list is the
// working directory at run time to ld.so, which a build cannot know, so it is skipped. A
// string with no ':' stays one entry, exactly as before the split.
fn search_entries(raw: &[String]) -> impl Iterator<Item = &str> {
    raw.iter().flat_map(|list| {
        let is_list = list.contains(':');
        list.split(':')
            .filter(move |entry| !(is_list && entry.is_empty()))
    })
}

// Turn raw RPATH/RUNPATH strings into concrete directories: split them, expand tokens, root
// absolute paths inside the sysroot, and treat anything relative as origin-relative.
fn build_dirs(raw: &[String], origin_dir: &Path, root: &Path, root_info: &ElfInfo) -> Vec<PathBuf> {
    search_entries(raw)
        .map(|entry| entry_dir(entry, origin_dir, root, root_info))
        .collect()
}

// Each string that holds a ':', read whole as one directory, as 1.x read it. ld.so never
// searches that directory, but the staged ld.so.cache lists every directory a library came
// from, and ldconfig keeps a `:` in a directory name. So a library found only there loads from
// the cache, after RPATH and RUNPATH miss, if ldconfig caches it (`find_cached`). Measured with
// a v1.9.0 image on glibc 2.41.
fn literal_dirs(
    raw: &[String],
    origin_dir: &Path,
    root: &Path,
    root_info: &ElfInfo,
) -> Vec<PathBuf> {
    raw.iter()
        .filter(|list| list.contains(':'))
        .map(|list| entry_dir(list, origin_dir, root, root_info))
        .collect()
}

// The first copy of `soname` in a whole-string directory that ld.so finds through the cache.
// glibc 2.41 ldconfig (`search_dir`) caches a file only if its name passes `_dl_is_dso`, and
// keys it by DT_SONAME (the file name only without one), while ld.so looks up the NEEDED name.
// Each copy that fails either rule adds a hint to `not_cached`. A file whose name passes but that
// is not regular, or does not read as an ELF, is kept: the walk refuses it with its own error.
fn find_cached(
    soname: &str,
    dirs: &[PathBuf],
    source: &dyn LinkInfoSource,
    not_cached: &mut Vec<String>,
) -> Option<PathBuf> {
    if soname.contains('/') {
        return None;
    }
    for candidate in dirs.iter().map(|dir| dir.join(soname)) {
        if !candidate.exists() {
            continue;
        }
        let Some(why) = cache_miss(soname, &candidate, source) else {
            return Some(candidate);
        };
        not_cached.push(format!(
            "`{}` is in {}, a directory whose name holds ':'. ld.so splits RPATH and RUNPATH on \
             ':', so only the image's ld.so.cache can find it there, and ldconfig does not cache \
             it under that name: {why}. Move the library to a directory with no ':' in its \
             name, and list that directory in RUNPATH.",
            soname.escape_debug(),
            printable(candidate.parent().unwrap_or(Path::new("/")))
        ));
    }
    None
}

// Why ldconfig would not cache `candidate` under the name `soname`, or `None` when it would.
// A file that is not regular, or does not read as an ELF, counts as cached: the walk refuses
// it with its own error.
fn cache_miss(soname: &str, candidate: &Path, source: &dyn LinkInfoSource) -> Option<String> {
    if !ldconfig_caches_name(soname) {
        return Some(
            "it caches only names that start with `lib` or `ld-` and hold `.so`, or start with \
             `ld.so.` or `ld64.so.`"
                .to_string(),
        );
    }
    let read = candidate
        .is_file()
        .then(|| source.read(&canonical(candidate)));
    match read {
        Some(Ok(Some(ElfInfo {
            soname: Some(own), ..
        }))) if own != soname => Some(format!(
            "it lists the file by its SONAME `{}`",
            own.escape_debug()
        )),
        _ => None,
    }
}

// glibc's `_dl_is_dso` (elf/dl-is_dso.h, 2.41): the file names ldconfig puts in the cache.
fn ldconfig_caches_name(name: &str) -> bool {
    ((name.starts_with("lib") || name.starts_with("ld-")) && name.contains(".so"))
        || name.starts_with("ld.so.")
        || name.starts_with("ld64.so.")
}

// One search-path entry as a concrete directory.
fn entry_dir(entry: &str, origin_dir: &Path, root: &Path, root_info: &ElfInfo) -> PathBuf {
    entry_dir_as(entry, origin_dir, root, root_info, root_info.platform())
}

// `entry_dir`, with `platform` as the value of `$PLATFORM`.
fn entry_dir_as(
    entry: &str,
    origin_dir: &Path,
    root: &Path,
    root_info: &ElfInfo,
    platform: &str,
) -> PathBuf {
    let expanded = expand_tokens_as(entry, origin_dir, root_info, platform);
    let p = Path::new(&expanded);
    if p.is_absolute() {
        reroot(root, p)
    } else {
        origin_dir.join(p)
    }
}

// Find the first search dir containing `soname`. A soname with a slash is a path,
// not a bare name, and is resolved directly (rerooted / origin-relative).
fn find_lib(soname: &str, search: &[PathBuf], origin_dir: &Path, root: &Path) -> Option<PathBuf> {
    if soname.contains('/') {
        let p = Path::new(soname);
        let candidate = if p.is_absolute() {
            reroot(root, p)
        } else {
            origin_dir.join(p)
        };
        return candidate.exists().then_some(candidate);
    }
    search
        .iter()
        .map(|dir| dir.join(soname))
        .find(|candidate| candidate.exists())
}

// As `find_lib`, but a bare soname skips a file that `fits` refuses and keeps searching, and
// records it in `skipped`. A name with a `/` is the one file it names, as ld.so takes it.
fn find_fitting(
    soname: &str,
    search: &[PathBuf],
    origin_dir: &Path,
    root: &Path,
    fits: &dyn Fn(&Path) -> bool,
    skipped: &mut Vec<PathBuf>,
) -> Option<PathBuf> {
    if soname.contains('/') {
        return find_lib(soname, search, origin_dir, root);
    }
    for candidate in search.iter().map(|dir| dir.join(soname)) {
        if !candidate.exists() {
            continue;
        }
        if fits(&candidate) {
            return Some(candidate);
        }
        skipped.push(candidate);
    }
    None
}

// True unless `path` is an ELF of another class or machine than `binary`. A file that is not
// an ELF, or cannot be read, fits here, and the checks after the pick report it as before. A
// path that is not a regular file is never opened: a FIFO with no writer blocks the open.
fn arch_fits(source: &dyn LinkInfoSource, path: &Path, binary: &ElfInfo) -> bool {
    if !std::fs::metadata(path).is_ok_and(|meta| meta.is_file()) {
        return true;
    }
    match source.read(path) {
        Ok(Some(info)) => info.is_64 == binary.is_64 && info.machine == binary.machine,
        _ => true,
    }
}

// Only called on a path that `arch_fits` read and refused, so it is a regular file.
fn arch_of(source: &dyn LinkInfoSource, path: &Path) -> String {
    match source.read(path) {
        Ok(Some(info)) => arch_label(info.is_64, info.machine),
        _ => "different".into(),
    }
}

fn arch_label(is_64: bool, machine: u16) -> String {
    format!(
        "{}-bit {}",
        if is_64 { 64 } else { 32 },
        goblin::elf::header::machine_to_str(machine)
    )
}

// Reroot an absolute path inside the sysroot. Paths already under the root (e.g.
// $ORIGIN results) are left alone so we do not double-root them.
fn reroot(root: &Path, path: &Path) -> PathBuf {
    if root == Path::new("/") || path.starts_with(root) {
        return path.to_path_buf();
    }
    match path.strip_prefix("/") {
        Ok(rel) => root.join(rel),
        Err(_) => path.to_path_buf(),
    }
}

// A path for a warning line. The search-path text comes out of the packed binary, and a file
// name can hold anything but `/` and NUL, so escape control characters: a raw newline or
// terminal escape would let the input forge a line of scratchsmith's own output.
fn printable(path: &Path) -> String {
    escape_for_display(&path.to_string_lossy())
}

/// A string from the packed binary, an image's file names, or a registry, made safe to print:
/// control characters are escaped, so it cannot break or forge a line. Warnings and errors
/// escape this way on every call; a report line uses `escape_if_line_breaking`, which leaves
/// an honest name as it is.
pub fn escape_for_display(text: &str) -> String {
    text.escape_debug().to_string()
}

/// True for a character that breaks or reorders a printed line: the set
/// `escape_if_line_breaking` escapes. Public so the tests and fuzz targets share one copy.
pub fn breaks_a_line(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{2028}' | '\u{2029}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'
        )
}

/// An untrusted name for a report line: as it is, unless it holds a character that breaks
/// or reorders a line, and then `escape_for_display` whole. So an honest name with a quote,
/// a backslash or a non-ASCII space reads exactly as it is.
///
/// The set: the Cc controls (C0, DEL, C1: newline, CR, ESC, CSI), the line and paragraph
/// separators, and the bidi embeddings, overrides and isolates, which reorder the rest of
/// the line. LRM/RLM are left out: each acts as one invisible strong letter, no more than
/// a Latin or Hebrew letter an honest name prints raw.
pub(crate) fn escape_if_line_breaking(text: &str) -> std::borrow::Cow<'_, str> {
    if text.chars().any(breaks_a_line) {
        escape_for_display(text).into()
    } else {
        text.into()
    }
}

// A list of directories for a `--verbose` line.
fn dirs_for_display(dirs: &[PathBuf]) -> String {
    let shown: Vec<_> = dirs.iter().map(|d| d.display().to_string()).collect();
    shown.join(", ")
}

// A readable name for an ELF `e_type`, for the refusal messages above.
fn elf_type_name(e_type: u16) -> String {
    use goblin::elf::header::{ET_CORE, ET_EXEC, ET_REL};
    match e_type {
        ET_EXEC => "an executable (ET_EXEC)".into(),
        ET_CORE => "a core dump (ET_CORE)".into(),
        ET_REL => "an object file (ET_REL)".into(),
        other => format!("an ELF of type {other}"),
    }
}

// True when the file opens and begins with the ELF magic. Any IO failure reads as "no",
// which fails closed where a missing magic is an error. A rejection of a file that HAS the
// magic must not gate on this: it would fail open.
// Only a regular file is opened: a FIFO was already read to EOF, so a second open waits
// forever for a writer that is gone.
fn has_elf_magic(path: &Path) -> bool {
    use std::io::Read;
    let mut magic = [0u8; 4];
    path.is_file()
        && std::fs::File::open(path)
            .and_then(|mut f| f.read_exact(&mut magic))
            .is_ok()
        && magic == *b"\x7fELF"
}

// Best-effort real path; falls back to the input if canonicalization fails so a
// transient error never silently drops a dependency.
fn canonical(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

/// The unresolved sonames, joined for an error line.
///
/// A soname is a raw `DT_NEEDED` string out of the packed binary, and it can hold any byte
/// but NUL. Printed as it is, a newline or a terminal escape in one would let the binary
/// forge a line of scratchsmith's own output, so each is escaped. `missing` itself stays
/// raw: `--require` and `--deny` match on it.
///
/// Each one is also quoted. The list is joined with a comma, and a soname can hold a comma
/// and a space, so without the quotes one crafted name would read as two libraries.
pub fn missing_for_display(missing: &[String]) -> String {
    missing
        .iter()
        .map(|soname| format!("\"{}\"", escape_for_display(soname)))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Append `item` to `v` unless already present. A parent can list a soname twice.
pub(crate) fn push_unique(v: &mut Vec<String>, item: String) {
    if !v.contains(&item) {
        v.push(item);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(interpreter: Option<&str>, needed: &[&str]) -> ElfInfo {
        ElfInfo {
            interpreter: interpreter.map(str::to_owned),
            needed: needed.iter().map(|s| s.to_string()).collect(),
            rpaths: vec![],
            runpaths: vec![],
            soname: None,
            is_64: true,
            machine: goblin::elf::header::EM_X86_64,
            uses_dlopen: false,
            e_type: goblin::elf::header::ET_DYN,
        }
    }

    #[test]
    fn no_interpreter_and_no_needed_is_static() {
        assert_eq!(info(None, &[]).linking(), Linking::Static);
    }

    #[test]
    fn an_interpreter_means_dynamic() {
        assert_eq!(
            info(Some("/lib64/ld-linux-x86-64.so.2"), &[]).linking(),
            Linking::Dynamic
        );
    }

    #[test]
    fn needed_libs_mean_dynamic_even_without_an_interpreter() {
        // A shared object has DT_NEEDED but no PT_INTERP; it still needs resolution.
        assert_eq!(info(None, &["libc.so.6"]).linking(), Linking::Dynamic);
    }

    #[test]
    fn rpath_and_runpath_are_kept_distinct() {
        let elf = ElfInfo {
            interpreter: None,
            needed: vec![],
            rpaths: vec!["/opt/rpath".into()],
            runpaths: vec!["/opt/runpath".into()],
            soname: None,
            is_64: true,
            machine: goblin::elf::header::EM_X86_64,
            uses_dlopen: false,
            e_type: goblin::elf::header::ET_DYN,
        };
        assert_eq!(elf.rpaths, vec!["/opt/rpath".to_string()]);
        assert_eq!(elf.runpaths, vec!["/opt/runpath".to_string()]);
        assert_ne!(elf.rpaths, elf.runpaths);
    }

    #[test]
    fn non_elf_bytes_are_rejected() {
        let err = parse_elf_info(b"not an elf at all").unwrap_err();
        assert!(err.to_string().contains("ELF"));
    }

    #[test]
    fn musl_is_detected_and_rejected() {
        let musl = info(Some("/lib/ld-musl-x86_64.so.1"), &["libc.so"]);
        assert!(musl.is_musl());
        let err = ensure_glibc(&musl).unwrap_err();
        assert!(err.to_string().contains("musl"));
    }

    #[test]
    fn the_musl_rejection_escapes_the_interpreter() {
        // An honest loader path reads exactly as before.
        let honest = info(Some("/lib/ld-musl-x86_64.so.1"), &[]);
        assert_eq!(
            format!("{:#}", ensure_glibc(&honest).unwrap_err()),
            "musl binaries are out of scope; Scratchsmith packs glibc binaries only \
             (interpreter: /lib/ld-musl-x86_64.so.1)"
        );

        // PT_INTERP is a raw string out of the packed binary, and main prints this error to
        // the terminal. A newline, a terminal escape, a line separator or a bidi isolate in it
        // must not let the binary forge a line of scratchsmith's own output.
        let forged = info(
            Some("/lib/ld-musl-x86_64.so.1\nerror: forged\r\x1b[2J\u{2028}\u{2067}"),
            &[],
        );
        let err = format!("{:#}", ensure_glibc(&forged).unwrap_err());
        assert!(!err.chars().any(breaks_a_line), "{err:?}");
        assert!(
            err.ends_with(
                "(interpreter: /lib/ld-musl-x86_64.so.1\\nerror: forged\\r\
                 \\u{1b}[2J\\u{2028}\\u{2067})"
            ),
            "{err}"
        );
    }

    #[test]
    fn only_a_line_breaking_character_gets_a_name_escaped() {
        // Each one alone escapes the whole name, and what comes out holds none of them.
        for c in [
            '\0', '\t', '\n', '\r', '\x1b', '\x7f', '\u{85}', '\u{9b}', '\u{2028}', '\u{2029}',
            '\u{202a}', '\u{202b}', '\u{202c}', '\u{202d}', '\u{202e}', '\u{2066}', '\u{2067}',
            '\u{2068}', '\u{2069}',
        ] {
            let name = format!("a'{c}b");
            let shown = escape_if_line_breaking(&name);
            assert_eq!(shown, escape_for_display(&name), "{name:?}");
            assert!(!shown.contains(c), "{shown:?}");
            // The escaped text is printable, so it reads as itself from here on.
            assert_eq!(escape_if_line_breaking(&shown), shown);
        }
        // Anything else is left as it is, even what `escape_debug` would rewrite.
        for name in [
            "O'Reilly",
            "quote\"d",
            "back\\slash",
            "no\u{a0}break",
            "zero\u{200b}width",
            "\u{301}mark",
            "\u{5e9}\u{200f}\u{200e}",
            "na\u{ef}ve",
        ] {
            assert_eq!(escape_if_line_breaking(name), name);
        }
    }

    #[test]
    fn glibc_is_accepted() {
        let glibc = info(Some("/lib64/ld-linux-x86-64.so.2"), &["libc.so.6"]);
        assert!(!glibc.is_musl());
        assert!(ensure_glibc(&glibc).is_ok());
    }

    // --- ld.so search-order emulation ------------------------------------------
    // These drive the search logic through a scripted dependency graph so we can
    // exercise RPATH/RUNPATH/$ORIGIN precisely without building real ELF files.

    use std::collections::HashMap;
    use std::fs;

    struct MapSource {
        infos: HashMap<PathBuf, ElfInfo>,
    }

    impl LinkInfoSource for MapSource {
        // A path with no scripted entry is a LEAF, not a read failure. That is what these
        // fixtures always meant; it used to be spelled as an `Err` that the resolver swallowed.
        fn read(&self, path: &Path) -> Result<Option<ElfInfo>> {
            Ok(self.infos.get(&canonical(path)).cloned())
        }
    }

    fn elf(needed: &[&str], rpaths: &[&str], runpaths: &[&str], interp: Option<&str>) -> ElfInfo {
        ElfInfo {
            interpreter: interp.map(str::to_owned),
            needed: needed.iter().map(|s| s.to_string()).collect(),
            rpaths: rpaths.iter().map(|s| s.to_string()).collect(),
            runpaths: runpaths.iter().map(|s| s.to_string()).collect(),
            soname: None,
            is_64: true,
            machine: goblin::elf::header::EM_X86_64,
            uses_dlopen: false,
            e_type: goblin::elf::header::ET_DYN,
        }
    }

    fn touch(path: &Path) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, b"\x7fELF-ish").unwrap();
    }

    fn has(res: &Resolution, soname: &str) -> bool {
        res.libs.iter().any(|l| l.soname == soname)
    }

    // A source that READS every scripted path but fails on one, to separate the two shapes
    // the resolver must treat differently.
    struct FailingSource {
        infos: HashMap<PathBuf, ElfInfo>,
        unreadable: PathBuf,
    }

    impl LinkInfoSource for FailingSource {
        fn read(&self, path: &Path) -> Result<Option<ElfInfo>> {
            let key = canonical(path);
            if key == canonical(&self.unreadable) {
                anyhow::bail!("simulated IO failure reading {}", key.display());
            }
            Ok(self.infos.get(&key).cloned())
        }
    }

    // Graph shared by the two tests below: exe -> libmid -> libleaf, all resolvable.
    fn chain_fixture(root: &Path) -> (PathBuf, PathBuf, PathBuf, HashMap<PathBuf, ElfInfo>) {
        let loader = root.join("lib64/ld-linux-x86-64.so.2");
        let exe = root.join("app/exe");
        let mid = root.join("app/libs/libmid.so");
        let leaf = root.join("app/libs/libleaf.so");
        for p in [&loader, &exe, &mid, &leaf] {
            touch(p);
        }
        let mut infos = HashMap::new();
        infos.insert(
            canonical(&exe),
            elf(
                &["libmid.so"],
                &["$ORIGIN/libs"],
                &[],
                Some("/lib64/ld-linux-x86-64.so.2"),
            ),
        );
        infos.insert(canonical(&mid), elf(&["libleaf.so"], &[], &[], None));
        infos.insert(canonical(&leaf), elf(&[], &[], &[], None));
        infos.insert(canonical(&loader), elf(&[], &[], &[], None));
        (exe, mid, leaf, infos)
    }

    #[test]
    fn a_library_that_cannot_be_read_fails_the_resolution() {
        // libmid resolves and is staged, but cannot be READ. Swallowing that used to leave
        // libmid in `libs` while libleaf -- its only DT_NEEDED -- was never queued, never
        // resolved and never staged, and never reached `missing` either, because nothing ever
        // asked for it. `graph` then exited 0 reporting a tree with that branch absent, and
        // `pack` failed only later, at the stager's copy of the same file, naming a copy
        // rather than the read.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let (exe, mid, leaf, infos) = chain_fixture(root);
        let sysroot = Sysroot::new(root);

        let src = FailingSource {
            infos,
            unreadable: mid.clone(),
        };
        let err = match resolve_with(&exe, &sysroot, &[], &src) {
            Ok(res) => panic!(
                "an unreadable library must fail the resolution, but it returned {} libs \
                 and missing={:?} (libleaf present: {})",
                res.libs.len(),
                res.missing,
                has(&res, "libleaf.so")
            ),
            Err(e) => format!("{e:#}"),
        };
        assert!(
            err.contains(&mid.display().to_string()),
            "the error must name the library that could not be read ({}), got: {err}",
            mid.display()
        );
        // Guard the fixture itself: libleaf must be reachable, so the failure above is the
        // simulated read and not an unresolvable graph.
        let ok = resolve_with(
            &exe,
            &sysroot,
            &[],
            &MapSource {
                infos: chain_fixture(root).3,
            },
        )
        .unwrap();
        assert!(has(&ok, "libleaf.so"), "fixture must resolve {leaf:?}");
    }

    // Scripted facts where the fixture has them, and the real parse of the file's bytes where
    // it does not, so the magic-byte split in `GoblinSource` is what decides.
    struct ScriptedOrGoblin {
        infos: HashMap<PathBuf, ElfInfo>,
    }

    impl LinkInfoSource for ScriptedOrGoblin {
        fn read(&self, path: &Path) -> Result<Option<ElfInfo>> {
            match self.infos.get(&canonical(path)) {
                Some(info) => Ok(Some(info.clone())),
                None => GoblinSource.read(path),
            }
        }
    }

    #[test]
    fn an_unparsable_elf_library_fails_and_a_data_file_fails() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let (exe, mid, _leaf, mut infos) = chain_fixture(root);
        // No scripted facts for libmid, and `touch` wrote the ELF magic into it: an ELF by
        // its own claim that does not parse. Its DT_NEEDED entries are unknown.
        infos.remove(&canonical(&mid));
        let src = ScriptedOrGoblin { infos };

        let err = resolve_with(&exe, &Sysroot::new(root), &[], &src).unwrap_err();
        assert!(err.is::<UnparsableElf>(), "{err:#}");
        let msg = format!("{err:#}");
        assert!(
            msg.contains(&canonical(&mid).display().to_string())
                && msg.contains("cannot be parsed")
                && msg.contains("Replace it"),
            "the error must name the file and the fix: {msg}"
        );

        // Same graph, but the file makes no claim to be an ELF. The binary's DT_NEEDED picked
        // it, and that name can point at any host file, so it must not ship in the image.
        fs::write(&mid, b"just data").unwrap();
        let err = format!(
            "{:#}",
            resolve_with(&exe, &Sysroot::new(root), &[], &src).unwrap_err()
        );
        assert!(
            err.contains("`libmid.so`")
                && err.contains(&canonical(&mid).display().to_string())
                && err.contains("not an ELF"),
            "{err}"
        );
    }

    // A host file no packed binary may pull into an image, standing in for a credential.
    fn secret(root: &Path) -> PathBuf {
        let p = root.join("home/user/.docker/config.json");
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(&p, br#"{"auths":{"registry.example":{"auth":"c2VjcmV0"}}}"#).unwrap();
        p
    }

    fn resolve_err(exe: &Path, root: &Path, includes: &[String], src: &MapSource) -> String {
        match resolve_with(exe, &Sysroot::new(root), includes, src) {
            Ok(res) => panic!("must fail, but staged {:?}", res.libs),
            Err(e) => format!("{e:#}"),
        }
    }

    #[test]
    fn a_needed_path_to_a_data_file_fails_the_resolution() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let exe = root.join("app/exe");
        touch(&exe);
        let secret = secret(root);

        // Absolute, as the finding describes. The sysroot reroots it under `root`.
        let abs = "/home/user/.docker/config.json";
        let infos = HashMap::from([(canonical(&exe), elf(&[abs], &[], &[], None))]);
        let err = resolve_err(&exe, root, &[], &MapSource { infos });
        assert!(
            err.contains(&format!("`{abs}`"))
                && err.contains(&canonical(&secret).display().to_string()),
            "{err}"
        );

        // Origin-relative, the other shape a soname with a slash takes.
        fs::create_dir_all(root.join("app/conf")).unwrap();
        fs::write(root.join("app/conf/token"), b"hunter2").unwrap();
        let infos = HashMap::from([(canonical(&exe), elf(&["conf/token"], &[], &[], None))]);
        let err = resolve_err(&exe, root, &[], &MapSource { infos });
        assert!(err.contains("`conf/token`"), "{err}");

        // A lower object's DT_NEEDED came out of an ELF too, not only the binary's.
        let mid = root.join("usr/lib/libmid.so");
        touch(&mid);
        let infos = HashMap::from([
            (canonical(&exe), elf(&["libmid.so"], &[], &[], None)),
            (canonical(&mid), elf(&[abs], &[], &[], None)),
        ]);
        let err = resolve_err(&exe, root, &[], &MapSource { infos });
        assert!(
            err.contains(&canonical(&mid).display().to_string()) && err.contains(abs),
            "{err}"
        );
    }

    #[test]
    fn origin_of_a_library_reached_through_a_symlink_is_the_symlinks_directory() {
        // TASK-231. A/lib/libbar.so -> ../../B/libbar.so has RUNPATH $ORIGIN/deps, and
        // libdep.so is in A/lib/deps. glibc names A/lib, the directory it found the link in.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let exe = root.join("A/bin/app");
        let real_bar = root.join("B/libbar.so");
        let dep = root.join("A/lib/deps/libdep.so");
        for f in [&exe, &real_bar, &dep] {
            touch(f);
        }
        std::os::unix::fs::symlink("../../B/libbar.so", root.join("A/lib/libbar.so")).unwrap();
        let infos = HashMap::from([
            (
                canonical(&exe),
                elf(&["libbar.so"], &[], &["$ORIGIN/../lib"], None),
            ),
            (
                canonical(&real_bar),
                elf(&["libdep.so"], &[], &["$ORIGIN/deps"], None),
            ),
            (canonical(&dep), elf(&[], &[], &[], None)),
        ]);
        let res = resolve_with(&exe, &Sysroot::new(root), &[], &MapSource { infos }).unwrap();
        assert!(res.missing.is_empty(), "{:?}", res.missing);
        // Dedup and staging still use the real file.
        let paths: Vec<_> = res.libs.iter().map(|l| l.path.clone()).collect();
        assert_eq!(paths, [canonical(&real_bar), canonical(&dep)]);
    }

    #[test]
    fn a_cpu_copy_beside_a_symlinked_library_is_noted_from_the_links_directory() {
        // The `$PLATFORM` probes take `$ORIGIN` from the link's directory too, as the search does.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let exe = root.join("A/bin/app");
        let real_bar = root.join("B/libbar.so");
        let dep = root.join("A/lib/x86_64/libdep.so");
        for f in [&exe, &real_bar, &dep, &root.join("A/lib/haswell/libdep.so")] {
            touch(f);
        }
        std::os::unix::fs::symlink("../../B/libbar.so", root.join("A/lib/libbar.so")).unwrap();
        let infos = HashMap::from([
            (
                canonical(&exe),
                elf(&["libbar.so"], &[], &["$ORIGIN/../lib"], None),
            ),
            (
                canonical(&real_bar),
                elf(&["libdep.so"], &[], &["$ORIGIN/$PLATFORM"], None),
            ),
            (canonical(&dep), elf(&[], &[], &[], None)),
        ]);
        let res = resolve_with(&exe, &Sysroot::new(root), &[], &MapSource { infos }).unwrap();
        assert!(res.missing.is_empty(), "{:?}", res.missing);
        // The binary's `$ORIGIN/../lib` is not normalized, as ld.so does not normalize it.
        let haswell = canonical(&exe).parent().unwrap().join("../lib/haswell");
        assert_eq!(res.notes.len(), 1, "{:?}", res.notes);
        assert!(
            res.notes[0].contains(&format!("loads the copy in {} instead", haswell.display())),
            "{}",
            res.notes[0]
        );
    }

    #[test]
    fn a_bare_needed_found_through_the_binarys_search_path_must_be_an_elf() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let exe = root.join("app/exe");
        touch(&exe);
        secret(root);

        // The binary sets the directory and names the file in it: through RPATH, then RUNPATH.
        let dir = ["/home/user/.docker"];
        for (rpaths, runpaths) in [(&dir[..], &[][..]), (&[][..], &dir[..])] {
            let infos = HashMap::from([(
                canonical(&exe),
                elf(&["config.json"], rpaths, runpaths, None),
            )]);
            let err = resolve_err(&exe, root, &[], &MapSource { infos });
            assert!(
                err.contains("`config.json`") && err.contains("not an ELF"),
                "rpaths={rpaths:?} runpaths={runpaths:?}: {err}"
            );
        }

        // The same search reaching an ELF still resolves, so the check is on content alone.
        let lib = root.join("home/user/.docker/libok.so");
        touch(&lib);
        let infos = HashMap::from([
            (canonical(&exe), elf(&["libok.so"], &dir, &[], None)),
            (canonical(&lib), elf(&[], &[], &[], None)),
        ]);
        let res = resolve_with(&exe, &Sysroot::new(root), &[], &MapSource { infos }).unwrap();
        assert!(has(&res, "libok.so"));
    }

    #[test]
    fn a_needed_elf_that_is_not_a_shared_object_fails_but_an_include_stays() {
        use goblin::elf::header::{ET_CORE, ET_EXEC, ET_REL};
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let (exe, mid, _leaf, base) = chain_fixture(root);
        for (e_type, what) in [
            (ET_CORE, "a core dump (ET_CORE)"),
            (ET_EXEC, "an executable (ET_EXEC)"),
            (ET_REL, "an object file (ET_REL)"),
            (0xfe00, "an ELF of type 65024"),
        ] {
            // libmid parses as an ELF, but not as a shared object: the binary's DT_NEEDED
            // reached a host file such as a core dump.
            let mut infos = base.clone();
            infos.get_mut(&canonical(&mid)).unwrap().e_type = e_type;
            let err = resolve_with(
                &exe,
                &Sysroot::new(root),
                &[],
                &MapSource {
                    infos: infos.clone(),
                },
            )
            .expect_err("a non-shared-object library is refused");
            let msg = format!("{err:#}");
            assert!(msg.contains(what) && msg.contains("not a shared"), "{msg}");

            // The same file named with --include is the operator's choice and stages.
            let mut infos = base.clone();
            infos.get_mut(&canonical(&exe)).unwrap().needed.clear();
            infos.get_mut(&canonical(&mid)).unwrap().e_type = e_type;
            let include = mid.display().to_string();
            let res = resolve_with(
                &exe,
                &Sysroot::new(root),
                std::slice::from_ref(&include),
                &MapSource { infos },
            )
            .expect("an --include of any ELF stages");
            assert!(has(&res, &include), "{:?}", res.libs);
        }
    }

    #[test]
    fn a_pt_interp_the_kernel_cannot_load_fails() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let (exe, _mid, _leaf, mut infos) = chain_fixture(root);
        let loader = canonical(&root.join("lib64/ld-linux-x86-64.so.2"));
        let mut core = elf(&[], &[], &[], None);
        core.e_type = goblin::elf::header::ET_CORE;
        infos.insert(loader.clone(), core);
        let err = resolve_with(
            &exe,
            &Sysroot::new(root),
            &[],
            &MapSource {
                infos: infos.clone(),
            },
        )
        .expect_err("a core dump as PT_INTERP is refused");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("PT_INTERP") && msg.contains("a core dump (ET_CORE)"),
            "{msg}"
        );

        // The kernel loads an ET_EXEC interpreter, so a static non-PIE loader still stages.
        let mut exec = elf(&[], &[], &[], None);
        exec.e_type = goblin::elf::header::ET_EXEC;
        infos.insert(loader.clone(), exec);
        let res = resolve_with(&exe, &Sysroot::new(root), &[], &MapSource { infos }).unwrap();
        assert_eq!(res.interpreter.map(|i| i.source), Some(loader));
    }

    #[test]
    fn a_pt_interp_that_does_not_parse_fails() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let (exe, _mid, _leaf, mut infos) = chain_fixture(root);
        let loader = canonical(&root.join("lib64/ld-linux-x86-64.so.2"));
        infos.remove(&loader);
        // The loader's bytes go through `GoblinSource`, which fails them as corrupt. No
        // library in this graph lists the loader as DT_NEEDED, so only PT_INTERP reaches it.
        let src = ScriptedOrGoblin { infos };
        let err = resolve_with(&exe, &Sysroot::new(root), &[], &src).unwrap_err();
        assert!(err.is::<UnparsableElf>(), "{err:#}");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("PT_INTERP")
                && msg.contains(&format!(
                    "{} starts like an ELF and cannot be parsed",
                    loader.display()
                )),
            "{msg}"
        );
    }

    #[test]
    fn an_include_of_a_data_file_stays_a_quiet_leaf_and_a_corrupt_elf_fails() {
        // --include is the operator's own choice, and it is how a non-ELF plugin asset ships.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let exe = root.join("app/exe");
        touch(&exe);
        let data = root.join("usr/lib/plugin.conf");
        fs::create_dir_all(data.parent().unwrap()).unwrap();
        fs::write(&data, b"just data").unwrap();
        // The binary's own DT_NEEDED comes first, so the include sits past it in `needed`.
        let lib = root.join("usr/lib/libok.so");
        touch(&lib);
        let infos = HashMap::from([
            (canonical(&exe), elf(&["libok.so"], &[], &[], None)),
            (canonical(&lib), elf(&[], &[], &[], None)),
        ]);
        let src = ScriptedOrGoblin { infos };

        for include in ["plugin.conf".to_string(), data.display().to_string()] {
            let res = resolve_with(
                &exe,
                &Sysroot::new(root),
                std::slice::from_ref(&include),
                &src,
            )
            .unwrap();
            assert!(has(&res, &include), "{include}: {:?}", res.libs);
        }

        // The operator's choice does not cover a corrupt ELF: its own DT_NEEDED are unknown.
        let corrupt = root.join("usr/lib/plugin.so");
        touch(&corrupt);
        let err =
            resolve_with(&exe, &Sysroot::new(root), &["plugin.so".to_string()], &src).unwrap_err();
        assert!(err.is::<UnparsableElf>(), "{err:#}");
    }

    #[test]
    fn the_interpreter_must_be_a_regular_elf_file() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let exe = root.join("app/exe");
        touch(&exe);
        secret(root);
        let loader = root.join("lib64/ld-linux-x86-64.so.2");
        touch(&loader);
        let resolve_interp = |interp: &str| {
            let infos = HashMap::from([(canonical(&exe), elf(&[], &[], &[], Some(interp)))]);
            resolve_with(&exe, &Sysroot::new(root), &[], &MapSource { infos })
        };

        let res = resolve_interp("/lib64/ld-linux-x86-64.so.2").unwrap();
        let interp = res.interpreter.expect("a real loader resolves");
        assert_eq!(interp.source, canonical(&loader));

        // A data file, then a directory.
        for bad in ["/home/user/.docker/config.json", "/home/user/.docker"] {
            let err = format!("{:#}", resolve_interp(bad).unwrap_err());
            assert!(
                err.contains(&format!("`{bad}`")) && err.contains("not an ELF"),
                "{err}"
            );
        }

        // An absent loader is still reported as missing, not as an error.
        let res = resolve_interp("/lib64/ld-absent.so.2").unwrap();
        assert_eq!(res.missing, ["/lib64/ld-absent.so.2"]);
    }

    #[test]
    fn a_fifo_interpreter_fails_without_blocking() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let exe = root.join("app/exe");
        touch(&exe);
        let fifo = root.join("lib64/ld-fifo.so.2");
        fs::create_dir_all(fifo.parent().unwrap()).unwrap();
        let made = std::process::Command::new("mkfifo").arg(&fifo).status();
        if !made.is_ok_and(|s| s.success()) {
            crate::test_support::skip_required("mkfifo unavailable");
            return;
        }
        let infos = HashMap::from([(
            canonical(&exe),
            elf(&[], &[], &[], Some("/lib64/ld-fifo.so.2")),
        )]);
        let err = resolve_with(&exe, &Sysroot::new(root), &[], &MapSource { infos }).unwrap_err();
        assert!(format!("{err:#}").contains("not an ELF"), "{err:#}");
    }

    #[test]
    fn a_dotdot_path_to_a_real_elf_still_resolves() {
        // `..` reads nothing an absolute path cannot, so content is the only thing checked.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let exe = root.join("app/exe");
        let loader = root.join("lib64/ld-linux-x86-64.so.2");
        let lib = root.join("lib/libfoo.so");
        for p in [&exe, &loader, &lib] {
            touch(p);
        }
        let interp = "/lib64/../lib64/ld-linux-x86-64.so.2";
        let infos = HashMap::from([
            (
                canonical(&exe),
                elf(&["../lib/libfoo.so"], &[], &[], Some(interp)),
            ),
            (canonical(&lib), elf(&[], &[], &[], None)),
            (canonical(&loader), elf(&[], &[], &[], None)),
        ]);
        let res = resolve_with(&exe, &Sysroot::new(root), &[], &MapSource { infos }).unwrap();
        let resolved = res
            .interpreter
            .as_ref()
            .expect("in-tree `..` loader resolves");
        assert_eq!(resolved.image_path, PathBuf::from(interp));
        assert_eq!(resolved.source, canonical(&loader));
        assert!(has(&res, "../lib/libfoo.so"), "{:?}", res.libs);
        assert!(res.missing.is_empty());
    }

    #[test]
    fn a_rejected_name_is_escaped_in_the_error() {
        // Both strings come out of the packed binary; neither may forge a line of output.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let exe = root.join("app/exe");
        touch(&exe);
        let evil = root.join("data\nerror: forged\x1b[2J");
        fs::write(&evil, b"just data").unwrap();
        let name = "/data\nerror: forged\x1b[2J";

        let as_needed = HashMap::from([(canonical(&exe), elf(&[name], &[], &[], None))]);
        let as_interp = HashMap::from([(canonical(&exe), elf(&[], &[], &[], Some(name)))]);
        for infos in [as_needed, as_interp] {
            let err = resolve_err(&exe, root, &[], &MapSource { infos });
            assert!(!err.contains('\n') && !err.contains('\x1b'), "{err:?}");
            assert!(err.contains("data\\nerror: forged\\u{1b}[2J"), "{err:?}");
        }
    }

    #[test]
    fn goblin_source_fails_a_corrupt_or_unreadable_file_and_keeps_a_data_file() {
        let tmp = tempfile::tempdir().unwrap();
        let junk = tmp.path().join("libjunk.so");
        fs::write(&junk, b"\x7fELF then nothing an ELF parser accepts").unwrap();
        let err = GoblinSource.read(&junk).unwrap_err();
        assert!(err.is::<UnparsableElf>(), "{err:#}");
        assert!(has_elf_magic(&junk));

        let data = tmp.path().join("plugin.conf");
        fs::write(&data, b"key = value").unwrap();
        assert_eq!(GoblinSource.read(&data).unwrap(), None);

        let short = tmp.path().join("short");
        fs::write(&short, b"\x7fE").unwrap();
        assert!(
            !has_elf_magic(&short),
            "fewer than four bytes is not the magic"
        );

        let absent = tmp.path().join("absent.so");
        assert!(GoblinSource.read(&absent).is_err());
        assert!(!has_elf_magic(&absent));
    }

    #[test]
    fn read_elf_info_keeps_the_parse_cause_and_advises_a_rebuild_for_a_truncated_binary() {
        let tmp = tempfile::tempdir().unwrap();
        let exe = tmp.path().join("app");
        fs::write(&exe, b"\x7fELF and then the file ends").unwrap();
        let msg = format!("{:#}", read_elf_info(&exe).unwrap_err());
        assert!(
            msg.contains("starts like an ELF and cannot be parsed")
                && msg.contains("Rebuild the binary")
                && msg.contains("not a valid ELF binary:")
                && !msg.contains("reinstall"),
            "{msg}"
        );
        fs::write(&exe, b"not an elf").unwrap();
        let msg = format!("{:#}", read_elf_info(&exe).unwrap_err());
        assert!(
            msg.contains("parsing ") && !msg.contains("starts like an ELF"),
            "{msg}"
        );
    }

    // A small device cap, so a test that reads an endless device to it allocates little.
    const TEST_CAP: u64 = 64 << 10;

    // Scripted facts for the binary, real reads for everything it resolves to.
    struct ScriptedRoot {
        root: PathBuf,
        info: ElfInfo,
    }

    impl LinkInfoSource for ScriptedRoot {
        fn read(&self, path: &Path) -> Result<Option<ElfInfo>> {
            if canonical(path) == canonical(&self.root) {
                return Ok(Some(self.info.clone()));
            }
            GoblinSource.read(path)
        }
    }

    fn mkfifo(path: &Path) {
        rustix::fs::mknodat(
            rustix::fs::CWD,
            path,
            rustix::fs::FileType::Fifo,
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
            0,
        )
        .unwrap();
    }

    // Run `f` on a thread, and fail rather than hang the suite if it never returns.
    fn returns<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(f());
        });
        rx.recv_timeout(std::time::Duration::from_secs(30))
            .expect("the read blocked")
    }

    #[test]
    fn a_needed_fifo_with_no_writer_fails_without_opening_it() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        let exe = root.join("app/exe");
        touch(&exe);
        let fifo = root.join("usr/lib/libfifo.so");
        fs::create_dir_all(fifo.parent().unwrap()).unwrap();
        mkfifo(&fifo);
        // The library goes through GoblinSource, so a read that ran would open the FIFO.
        let src = ScriptedRoot {
            root: exe.clone(),
            info: elf(&["/usr/lib/libfifo.so"], &[], &[], None),
        };
        let err = returns(move || {
            format!(
                "{:#}",
                resolve_with(&exe, &Sysroot::new(&root), &[], &src).unwrap_err()
            )
        });
        assert!(
            err.contains("`/usr/lib/libfifo.so`") && err.contains("not a regular file"),
            "{err}"
        );
    }

    #[test]
    fn an_included_fifo_that_starts_like_an_elf_fails_in_2_0() {
        // 1.x did not warn for a file that is not a regular file, and kept it as a leaf.
        // The bytes decide now, so a FIFO whose writer sends the ELF magic and junk fails.
        let tmp = tempfile::tempdir().unwrap();
        let fifo = tmp.path().join("plugin.fifo");
        mkfifo(&fifo);
        let writer = fifo.clone();
        std::thread::spawn(move || {
            let _ = fs::write(&writer, b"\x7fELF and junk");
        });
        let err = returns(move || GoblinSource.read(&fifo).unwrap_err());
        assert!(err.is::<UnparsableElf>(), "{err:#}");
    }

    #[test]
    fn the_magic_check_does_not_reopen_a_fifo() {
        // An --include'd FIFO was already read to its end, so its writer is gone, and a second
        // open would wait for a new one forever.
        let tmp = tempfile::tempdir().unwrap();
        let fifo = tmp.path().join("plugin.conf");
        mkfifo(&fifo);
        assert!(!returns(move || has_elf_magic(&fifo)));
    }

    #[test]
    fn an_endless_device_fails_at_the_cap() {
        for dev in ["/dev/zero", "/dev/urandom"] {
            let err = read_bounded(Path::new(dev), TEST_CAP).unwrap_err();
            assert!(
                err.to_string()
                    .contains("is a device or a FIFO that yields more than 65536 bytes"),
                "{err}"
            );
        }
    }

    #[test]
    fn an_elf_that_names_dev_zero_fails_instead_of_exhausting_memory() {
        // The read of /dev/zero used to grow one buffer until the host ran out of memory. A
        // name out of an ELF is now refused before the read; the cap still bounds --include.
        let tmp = tempfile::tempdir().unwrap();
        let exe = tmp.path().join("exe");
        touch(&exe);
        // A DT_NEEDED path, and a search dir plus a bare soname: both reach /dev/zero.
        for info in [
            elf(&["/dev/zero"], &[], &[], None),
            elf(&["zero"], &["/dev"], &[], None),
        ] {
            let src = ScriptedRoot {
                root: exe.clone(),
                info,
            };
            let err = resolve_with(&exe, &Sysroot::new("/"), &[], &src).unwrap_err();
            assert!(
                format!("{err:#}").contains("/dev/zero, and that is not a regular file"),
                "{err:#}"
            );
        }
    }

    #[test]
    fn a_procfs_file_reads_past_its_reported_length() {
        // A regular file that reports a length of 0, as every procfs file does.
        let path = Path::new("/proc/self/status");
        assert_eq!(fs::metadata(path).unwrap().len(), 0);
        let bytes = read_bounded(path, DEVICE_READ_CAP).unwrap();
        assert!(bytes.starts_with(b"Name:"), "{bytes:?}");
    }

    #[test]
    fn a_regular_file_past_its_length_and_the_cap_fails() {
        // A small cap stands in for a file that grows without end, like a tracefs pipe.
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("grows");
        fs::write(&path, [0u8; 64]).unwrap();
        assert_eq!(
            read_bounded(&path, 16).unwrap().len(),
            64,
            "its own length is fine"
        );
        let err = read_bounded(Path::new("/proc/self/status"), 16).unwrap_err();
        assert!(err.to_string().contains("more than 16 bytes"), "{err}");
    }

    #[test]
    fn a_finite_device_and_a_directory_read_as_before() {
        // /dev/null reads empty, as a plain read made it: a leaf, not an error.
        assert_eq!(
            read_bounded(Path::new("/dev/null"), 0).unwrap(),
            Vec::<u8>::new()
        );
        assert_eq!(GoblinSource.read(Path::new("/dev/null")).unwrap(), None);
        let tmp = tempfile::tempdir().unwrap();
        assert!(GoblinSource.read(tmp.path()).is_err());
    }

    #[test]
    fn a_fifo_whose_writer_starts_late_is_read_whole() {
        use std::io::Write;
        let tmp = tempfile::tempdir().unwrap();
        let fifo = tmp.path().join("liblate.so");
        mkfifo(&fifo);
        // An ELF (this test binary), bigger than the pipe buffer, and under the read cap.
        let exe = fs::read(std::env::current_exe().unwrap()).unwrap();
        assert!(
            (exe.len() as u64) < DEVICE_READ_CAP,
            "the test binary outgrew the cap"
        );
        let want = parse_elf_info(&exe).unwrap();
        let writer_fifo = fifo.clone();
        // The writer opens only after the read has begun, and pauses mid-stream. If the read
        // returned first, this thread waits forever in its open, and the test still fails.
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(300));
            let mut w = fs::OpenOptions::new()
                .write(true)
                .open(&writer_fifo)
                .unwrap();
            let (head, tail) = exe.split_at(exe.len() / 2);
            let _ = w.write_all(head);
            std::thread::sleep(std::time::Duration::from_millis(100));
            let _ = w.write_all(tail);
        });
        let got = returns(move || GoblinSource.read(&fifo).map_err(|e| e.to_string()));
        assert_eq!(got, Ok(Some(want)));
    }

    #[test]
    fn a_fifo_fed_then_closed_reads_byte_identical() {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let fifo = tmp.path().join("libfed.so");
        mkfifo(&fifo);
        // Bigger than the pipe buffer.
        let exe: Vec<u8> = (0..(1u32 << 20)).map(|i| (i % 251) as u8).collect();
        // A reader that never reads, so the writer opens at once and is mid-write (the data is
        // bigger than the pipe buffer) when the real read opens.
        let _hold = fs::OpenOptions::new()
            .read(true)
            .custom_flags(rustix::fs::OFlags::NONBLOCK.bits() as i32)
            .open(&fifo)
            .unwrap();
        let mut w = fs::OpenOptions::new().write(true).open(&fifo).unwrap();
        let data = exe.clone();
        std::thread::spawn(move || {
            let _ = w.write_all(&data);
        });
        let got = returns(move || read_bounded(&fifo, 2 << 20).map_err(|e| e.to_string()));
        let got = got.unwrap();
        assert!(got == exe, "read {} of {} bytes", got.len(), exe.len());
    }

    #[test]
    fn an_endless_fifo_fails_at_the_cap() {
        use std::io::Write;
        let tmp = tempfile::tempdir().unwrap();
        let fifo = tmp.path().join("libyes.so");
        mkfifo(&fifo);
        let writer_fifo = fifo.clone();
        // `yes > fifo`: the writer never closes, so only the cap ends the read.
        std::thread::spawn(move || {
            let mut w = fs::OpenOptions::new()
                .write(true)
                .open(&writer_fifo)
                .unwrap();
            while w.write_all(&[b'y'; 4096]).is_ok() {}
        });
        let err = returns(move || read_bounded(&fifo, TEST_CAP).unwrap_err().to_string());
        assert!(
            err.contains("is a device or a FIFO that yields more than 65536 bytes"),
            "{err}"
        );
    }

    #[test]
    fn a_regular_file_is_read_whole() {
        let tmp = tempfile::tempdir().unwrap();
        // Bigger than any one read, so stopping at a chunk boundary would show.
        let big = tmp.path().join("big");
        let data: Vec<u8> = (0..3 * 1024 * 1024 + 7u32)
            .map(|i| (i % 251) as u8)
            .collect();
        fs::write(&big, &data).unwrap();
        // The device cap does not apply to a regular file.
        assert!(read_bounded(&big, 0).unwrap() == fs::read(&big).unwrap());
        let empty = tmp.path().join("empty");
        fs::write(&empty, b"").unwrap();
        assert_eq!(read_bounded(&empty, 0).unwrap(), Vec::<u8>::new());

        // A real ELF (this test binary) yields the facts a plain read yields.
        let exe = std::env::current_exe().unwrap();
        let plain = fs::read(&exe).unwrap();
        assert!(read_bounded(&exe, 0).unwrap() == plain);
        assert_eq!(
            GoblinSource.read(&exe).unwrap(),
            Some(parse_elf_info(&plain).unwrap())
        );
    }

    #[test]
    fn a_regular_file_too_big_to_hold_fails_as_a_plain_read_does() {
        // Sparse, and bigger than any 64-bit address space maps, so the reserve always fails.
        // tmpfs holds that length, while ext4 caps a file far below it, so skip without tmpfs.
        let Ok(tmp) = tempfile::tempdir_in("/dev/shm") else {
            return;
        };
        let huge = tmp.path().join("huge");
        if fs::File::create(&huge).unwrap().set_len(1 << 62).is_err() {
            return;
        }
        let err = read_bounded(&huge, 0).unwrap_err();
        assert_eq!(
            format!("{err:#}"),
            format!("reading {}: out of memory", huge.display())
        );
    }

    #[test]
    fn a_platform_token_fails_only_where_it_has_no_value() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let exe = root.join("app/exe");
        touch(&exe);
        // `Err` carries the error text, `Ok` a resolution that went through.
        let resolve_with_needed =
            |machine: u16, needed: &[&str], rpaths: &[&str], runpaths: &[&str]| {
                // One bare soname, so the object has a search to run. It need not resolve.
                let mut info = elf(needed, rpaths, runpaths, None);
                info.machine = machine;
                let infos = HashMap::from([(canonical(&exe), info)]);
                resolve_with(&exe, &Sysroot::new(root), &[], &MapSource { infos })
                    .map(|_| ())
                    .map_err(|e| format!("{e:#}"))
            };
        let resolve_as = |machine: u16, rpaths: &[&str], runpaths: &[&str]| {
            resolve_with_needed(machine, &["libx.so"], rpaths, runpaths)
        };
        let clean = |r: Result<(), String>| r.is_ok();
        let riscv = goblin::elf::header::EM_RISCV;

        let e = resolve_as(riscv, &[], &["/opt/$PLATFORM/lib", "/opt/plain"]).unwrap_err();
        assert!(e.contains("`/opt/$PLATFORM/lib`"), "{e}");
        // It names the architecture, the file, the directory searched in its place, and the fix.
        assert!(
            e.contains("(RISCV)")
                && e.contains(&canonical(&exe).display().to_string())
                && e.contains("as `/opt//lib`")
                && e.contains("Write the directory name"),
            "{e}"
        );
        assert!(resolve_as(riscv, &["/opt/${PLATFORM}"], &[]).is_err());

        // The entry is text from an untrusted binary. It must not reach the terminal raw.
        let e = resolve_as(riscv, &[], &["/opt/$PLATFORM\nwarning forged\x1b[2J"]).unwrap_err();
        assert!(!e.contains('\n') && !e.contains('\x1b'), "{e}");
        assert!(e.contains("\\nwarning forged\\u{1b}[2J"), "{e}");

        // No bare soname means no search: nothing is needed, or the one entry is a path.
        let tokened = ["/opt/$PLATFORM/lib"];
        assert!(clean(resolve_with_needed(riscv, &[], &[], &tokened)));
        assert!(clean(resolve_with_needed(
            riscv,
            &["/abs/libx.so"],
            &[],
            &tokened
        )));
        // RPATH differs: a child inherits it, so one path-style entry is enough to fail.
        assert!(resolve_with_needed(riscv, &["/abs/libx.so"], &tokened, &[]).is_err());
        assert!(clean(resolve_with_needed(riscv, &[], &tokened, &[])));

        // A named architecture expands the token, so there is nothing to refuse.
        let x86 = goblin::elf::header::EM_X86_64;
        assert!(clean(resolve_as(x86, &[], &["/opt/$PLATFORM/lib"])));
        // glibc ignores RPATH when RUNPATH is set, so the token in it is never searched.
        assert!(clean(resolve_as(
            riscv,
            &["/opt/$PLATFORM"],
            &["/opt/plain"]
        )));
    }

    #[test]
    fn rpath_is_inherited_but_runpath_is_not() {
        // Graph: exe -> libmid -> libleaf. libleaf sits in a dir only reachable from
        // the exe's search path, so it resolves only when that path is transitive.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let loader = root.join("lib64/ld-linux-x86-64.so.2");
        let exe = root.join("app/exe");
        let mid = root.join("app/libs/libmid.so");
        let leaf = root.join("app/libs/libleaf.so");
        for p in [&loader, &exe, &mid, &leaf] {
            touch(p);
        }
        let sysroot = Sysroot::new(root);

        // RPATH on the exe is inherited by libmid's own lookups, so libleaf resolves.
        let mut infos = HashMap::new();
        infos.insert(
            canonical(&exe),
            elf(
                &["libmid.so"],
                &["$ORIGIN/libs"],
                &[],
                Some("/lib64/ld-linux-x86-64.so.2"),
            ),
        );
        infos.insert(canonical(&mid), elf(&["libleaf.so"], &[], &[], None));
        infos.insert(canonical(&leaf), elf(&[], &[], &[], None));
        let res = resolve_with(&exe, &sysroot, &[], &MapSource { infos }).unwrap();
        assert!(res.missing.is_empty(), "rpath variant: {:?}", res.missing);
        assert!(has(&res, "libleaf.so"));
        assert!(res.interpreter.is_some(), "loader should resolve");

        // Same graph, but the exe uses RUNPATH. It applies to libmid (the exe's own
        // NEEDED) yet must NOT carry to libmid's search for libleaf.
        let mut infos = HashMap::new();
        infos.insert(
            canonical(&exe),
            elf(
                &["libmid.so"],
                &[],
                &["$ORIGIN/libs"],
                Some("/lib64/ld-linux-x86-64.so.2"),
            ),
        );
        infos.insert(canonical(&mid), elf(&["libleaf.so"], &[], &[], None));
        infos.insert(canonical(&leaf), elf(&[], &[], &[], None));
        let res = resolve_with(&exe, &sysroot, &[], &MapSource { infos }).unwrap();
        assert!(has(&res, "libmid.so"), "runpath resolves the direct dep");
        assert!(
            res.missing.contains(&"libleaf.so".to_string()),
            "runpath must not be inherited by children"
        );
    }

    #[test]
    fn an_rpath_beside_a_runpath_is_ignored_and_not_inherited() {
        // Graph: exe -> libmid (RUNPATH run, RPATH rp) -> libown, and -> libleaf -> libdeep.
        // glibc ignores the RPATH of an object that also has RUNPATH, for that object and
        // for everything below it. libown and libdeep are only in the RPATH directory: libmid
        // itself does not find the first, and libleaf does not inherit a path to the second.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let exe = root.join("app/exe");
        let mid = root.join("usr/lib/libmid.so");
        let leaf = root.join("usr/lib/run/libleaf.so");
        let deep = root.join("usr/lib/rp/libdeep.so");
        let own = root.join("usr/lib/rp/libown.so");
        for p in [&exe, &mid, &leaf, &deep, &own] {
            touch(p);
        }
        let infos = HashMap::from([
            (canonical(&exe), elf(&["libmid.so"], &[], &[], None)),
            (
                canonical(&mid),
                elf(
                    &["libleaf.so", "libown.so"],
                    &["$ORIGIN/rp"],
                    &["$ORIGIN/run"],
                    None,
                ),
            ),
            (canonical(&leaf), elf(&["libdeep.so"], &[], &[], None)),
            (canonical(&deep), elf(&[], &[], &[], None)),
            (canonical(&own), elf(&[], &[], &[], None)),
        ]);
        let res = resolve_with(&exe, &Sysroot::new(root), &[], &MapSource { infos }).unwrap();

        let sonames: Vec<&str> = res.libs.iter().map(|l| l.soname.as_str()).collect();
        assert_eq!(sonames, ["libmid.so", "libleaf.so"]);
        let mut missing = res.missing.clone();
        missing.sort();
        assert_eq!(missing, ["libdeep.so", "libown.so"]);
    }

    #[test]
    fn an_object_with_runpath_does_not_search_an_inherited_rpath() {
        // Graph: exe (RPATH app/libs) -> libmid (RUNPATH elsewhere) -> libleaf.
        // glibc skips every RPATH, the ancestors' included, for an object that has RUNPATH.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let exe = root.join("app/exe");
        let mid = root.join("app/libs/libmid.so");
        let rpath_leaf = root.join("app/libs/libleaf.so");
        let system_leaf = root.join("usr/lib/libleaf.so");
        for p in [&exe, &mid, &rpath_leaf] {
            touch(p);
        }
        let graph = |mid_runpaths: &[&str]| {
            HashMap::from([
                (
                    canonical(&exe),
                    elf(&["libmid.so"], &["$ORIGIN/libs"], &[], None),
                ),
                (
                    canonical(&mid),
                    elf(&["libleaf.so"], &[], mid_runpaths, None),
                ),
                // Both copies are plain parsable leaves, wherever they are found.
                (canonical(&rpath_leaf), elf(&[], &[], &[], None)),
                (
                    canonical(root).join("usr/lib/libleaf.so"),
                    elf(&[], &[], &[], None),
                ),
            ])
        };
        let resolve = |infos| resolve_with(&exe, &Sysroot::new(root), &[], &MapSource { infos });
        let leaf_path = |res: &Resolution| {
            res.libs
                .iter()
                .find(|l| l.soname == "libleaf.so")
                .map(|l| l.path.clone())
        };

        // Only the RPATH copy exists. The loader would not find it, so the program cannot
        // start on the host: unresolved, with no fallback to the old search.
        let res = resolve(graph(&["/opt/elsewhere"])).unwrap();
        assert_eq!(leaf_path(&res), None);
        assert_eq!(res.missing, ["libleaf.so"]);
        // The exe's own lookup still searches its RPATH.
        assert!(has(&res, "libmid.so"));
        // One hint names the cause and the fix: the dir, the object, RUNPATH.
        assert_eq!(res.hints.len(), 1, "{:?}", res.hints);
        let hint = &res.hints[0];
        let libs_dir = canonical(root).join("app/libs").display().to_string();
        assert!(
            hint.contains("`libleaf.so`")
                && hint.contains(&format!("is in {libs_dir},"))
                && hint.contains(&canonical(&mid).display().to_string())
                && hint.contains(&format!("a RUNPATH that lists {libs_dir}")),
            "{hint}"
        );
        assert!(!hint.chars().any(breaks_a_line), "{hint:?}");

        // A second copy sits in a default directory. That is the one the loader uses, so it
        // is the one to stage: the old search staged the RPATH copy, a different file than
        // the program runs with on the host. Found the faithful way, so no warning.
        touch(&system_leaf);
        let res = resolve(graph(&["/opt/elsewhere"])).unwrap();
        assert_eq!(leaf_path(&res), Some(canonical(&system_leaf)));
        assert!(res.hints.is_empty(), "{:?}", res.hints);

        // Without RUNPATH on libmid the inherited RPATH is in force and comes first, as it
        // always did, with nothing to warn about.
        let res = resolve(graph(&[])).unwrap();
        assert_eq!(leaf_path(&res), Some(canonical(&rpath_leaf)));
    }

    #[test]
    fn a_child_of_a_runpath_object_still_inherits_the_ancestors_rpath() {
        // Graph: exe (RPATH app/libs) -> libmid (RUNPATH elsewhere) -> libchild (no tags)
        // -> libleaf, only in app/libs. RUNPATH stops RPATH for libmid's own lookups only:
        // glibc walks libchild's loader chain past libmid to the exe's RPATH.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let exe = root.join("app/exe");
        let mid = root.join("usr/lib/libmid.so");
        let child = root.join("usr/lib/libchild.so");
        let leaf = root.join("app/libs/libleaf.so");
        for p in [&exe, &mid, &child, &leaf] {
            touch(p);
        }
        let infos = HashMap::from([
            (
                canonical(&exe),
                elf(&["libmid.so"], &["$ORIGIN/libs"], &[], None),
            ),
            (
                canonical(&mid),
                elf(&["libchild.so"], &[], &["/opt/elsewhere"], None),
            ),
            (canonical(&child), elf(&["libleaf.so"], &[], &[], None)),
            (canonical(&leaf), elf(&[], &[], &[], None)),
        ]);
        let res = resolve_with(&exe, &Sysroot::new(root), &[], &MapSource { infos }).unwrap();
        let leaf_path = res
            .libs
            .iter()
            .find(|l| l.soname == "libleaf.so")
            .map(|l| l.path.clone());
        assert_eq!(leaf_path, Some(canonical(&leaf)));
        assert!(res.missing.is_empty(), "{:?}", res.missing);
    }

    // Where one direct dep of app/exe resolved to, for the colon-list tests below.
    fn resolve_one(root: &Path, rpaths: &[&str], runpaths: &[&str]) -> Option<PathBuf> {
        let exe = root.join("app/exe");
        touch(&exe);
        let mut infos =
            HashMap::from([(canonical(&exe), elf(&["libfoo.so"], rpaths, runpaths, None))]);
        // Every copy the tests place is a parsable leaf.
        for dir in ["app", "app/a", "app/b", "app/x86_64", "app/x", "app/x:y"] {
            infos.insert(
                canonical(&root.join(dir).join("libfoo.so")),
                elf(&[], &[], &[], None),
            );
        }
        let res = resolve_with(&exe, &Sysroot::new(root), &[], &MapSource { infos }).unwrap();
        res.libs.first().map(|l| l.path.clone())
    }

    #[test]
    fn each_colon_entry_of_rpath_and_runpath_is_searched_in_order() {
        // ld joins several -rpath flags into one string, and ld.so splits it on ':'
        // (`decompose_rpath`). A missing first entry does not hide a later one.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let a = root.join("app/a/libfoo.so");
        touch(&a);
        for list in [
            "/opt/none:$ORIGIN/a",
            "$ORIGIN/a:/opt/none",
            "${ORIGIN}/a/:/x",
        ] {
            assert_eq!(
                resolve_one(root, &[list], &[]),
                Some(canonical(&a)),
                "RPATH {list}"
            );
            assert_eq!(
                resolve_one(root, &[], &[list]),
                Some(canonical(&a)),
                "RUNPATH {list}"
            );
        }
        // A library in two entries comes from the first, as the loader takes it.
        let b = root.join("app/b/libfoo.so");
        touch(&b);
        for (list, first) in [("$ORIGIN/a:$ORIGIN/b", &a), ("$ORIGIN/b:$ORIGIN/a", &b)] {
            assert_eq!(
                resolve_one(root, &[list], &[]),
                Some(canonical(first)),
                "{list}"
            );
            assert_eq!(
                resolve_one(root, &[], &[list]),
                Some(canonical(first)),
                "{list}"
            );
        }
        // Each entry expands its own tokens: `$PLATFORM` here, `$ORIGIN` in the next one.
        let arch = root.join("app/x86_64/libfoo.so");
        touch(&arch);
        let list = "/opt/none:$ORIGIN/$PLATFORM:$ORIGIN/a";
        assert_eq!(resolve_one(root, &[], &[list]), Some(canonical(&arch)));
    }

    #[test]
    fn an_empty_colon_entry_is_not_searched() {
        // To ld.so an empty entry (a leading, trailing or doubled ':') is the working
        // directory the program starts in, which a build cannot know. So it is skipped, and
        // in particular it does not stand for the object's own directory.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let beside = root.join("app/libfoo.so");
        touch(&beside);
        for list in [":/opt/none", "/opt/none:", "/opt/none::/x", ":"] {
            assert_eq!(resolve_one(root, &[list], &[]), None, "RPATH {list}");
            assert_eq!(resolve_one(root, &[], &[list]), None, "RUNPATH {list}");
        }
        // The entries around an empty one are still searched.
        let a = root.join("app/a/libfoo.so");
        touch(&a);
        for list in [":$ORIGIN/a", "$ORIGIN/a:", "/opt/none::$ORIGIN/a"] {
            assert_eq!(
                resolve_one(root, &[list], &[]),
                Some(canonical(&a)),
                "RPATH {list}"
            );
            assert_eq!(
                resolve_one(root, &[], &[list]),
                Some(canonical(&a)),
                "RUNPATH {list}"
            );
        }
    }

    #[test]
    fn a_platform_token_is_judged_per_colon_entry() {
        // The `$PLATFORM` refusal names the one entry that holds the token, not the list.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let exe = root.join("app/exe");
        touch(&exe);
        let resolve_riscv = |rpaths: &[&str], runpaths: &[&str]| {
            let mut info = elf(&["libx.so"], rpaths, runpaths, None);
            info.machine = goblin::elf::header::EM_RISCV;
            let infos = HashMap::from([(canonical(&exe), info)]);
            resolve_with(&exe, &Sysroot::new(root), &[], &MapSource { infos })
                .map(|_| ())
                .map_err(|e| format!("{e:#}"))
        };
        for (rpaths, runpaths) in [
            (&["/opt/plain:/opt/$PLATFORM/lib"][..], &[][..]),
            (&[][..], &["/opt/plain:/opt/$PLATFORM/lib:$ORIGIN"][..]),
        ] {
            let e = resolve_riscv(rpaths, runpaths).unwrap_err();
            assert!(
                e.contains("search path `/opt/$PLATFORM/lib` in") && e.contains("as `/opt//lib`"),
                "{e}"
            );
        }
        // A list with no token in any entry is not refused.
        assert!(resolve_riscv(&[], &["/opt/plain:$ORIGIN::"]).is_ok());
    }

    #[test]
    fn an_inherited_rpath_list_is_split_too() {
        // Graph: exe (RPATH "/opt/none:$ORIGIN/libs") -> libmid -> libleaf, both in app/libs.
        // The child searches the split list it inherits. With RUNPATH on libmid it searches
        // none of it, and the hint names the one directory that holds the library.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let exe = root.join("app/exe");
        let mid = root.join("app/libs/libmid.so");
        let leaf = root.join("app/libs/libleaf.so");
        for p in [&exe, &mid, &leaf] {
            touch(p);
        }
        let graph = |mid_runpaths: &[&str]| {
            HashMap::from([
                (
                    canonical(&exe),
                    elf(&["libmid.so"], &["/opt/none:$ORIGIN/libs"], &[], None),
                ),
                (
                    canonical(&mid),
                    elf(&["libleaf.so"], &[], mid_runpaths, None),
                ),
                (canonical(&leaf), elf(&[], &[], &[], None)),
            ])
        };
        let resolve = |infos| resolve_with(&exe, &Sysroot::new(root), &[], &MapSource { infos });

        let res = resolve(graph(&[])).unwrap();
        assert!(has(&res, "libleaf.so") && res.missing.is_empty(), "{res:?}");

        let res = resolve(graph(&["/opt/a:/opt/b"])).unwrap();
        assert_eq!(res.missing, ["libleaf.so"]);
        let libs_dir = canonical(root).join("app/libs").display().to_string();
        assert_eq!(res.hints.len(), 1, "{:?}", res.hints);
        assert!(
            res.hints[0].contains(&format!("is in {libs_dir},")),
            "{}",
            res.hints[0]
        );
    }

    #[test]
    fn a_directory_named_with_a_colon_is_still_found_after_the_split_misses() {
        // ld.so splits `$ORIGIN/x:y` into `$ORIGIN/x` and `y`, but the image's ld.so.cache
        // lists the staged `x:y` directory, so 1.x images with it start. Keep that result.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let colon = root.join("app/x:y/libfoo.so");
        touch(&colon);
        let list = "$ORIGIN/x:y";
        assert_eq!(
            resolve_one(root, &[list], &[]),
            Some(canonical(&colon)),
            "RPATH"
        );
        assert_eq!(
            resolve_one(root, &[], &[list]),
            Some(canonical(&colon)),
            "RUNPATH"
        );
        // A copy that a split entry reaches comes first, as the loader takes it.
        let split = root.join("app/x/libfoo.so");
        touch(&split);
        assert_eq!(resolve_one(root, &[], &[list]), Some(canonical(&split)));

        // An inherited RPATH keeps the whole-string reading for the child too.
        let exe = root.join("app/exe");
        let mid = root.join("app/x:y/libmid.so");
        let leaf = root.join("app/x:y/libleaf.so");
        for p in [&mid, &leaf] {
            touch(p);
        }
        let infos = HashMap::from([
            (canonical(&exe), elf(&["libmid.so"], &[list], &[], None)),
            (canonical(&mid), elf(&["libleaf.so"], &[], &[], None)),
            (canonical(&leaf), elf(&[], &[], &[], None)),
        ]);
        let res = resolve_with(&exe, &Sysroot::new(root), &[], &MapSource { infos }).unwrap();
        assert!(has(&res, "libleaf.so") && res.missing.is_empty(), "{res:?}");
    }

    // Resolve app/exe, which needs `needed` through the search path `list` (RPATH or
    // RUNPATH), with the only copy at app/x:y/<needed>, whose DT_SONAME is `file_soname`.
    fn resolve_in_colon_dir(
        root: &Path,
        needed: &str,
        file_soname: Option<&str>,
        rpath: bool,
    ) -> Resolution {
        let exe = root.join("app/exe");
        let lib = root.join("app/x:y").join(needed);
        touch(&exe);
        touch(&lib);
        let list = ["$ORIGIN/x:y"];
        let (rpaths, runpaths): (&[&str], &[&str]) =
            if rpath { (&list, &[]) } else { (&[], &list) };
        let mut lib_info = elf(&[], &[], &[], None);
        lib_info.soname = file_soname.map(str::to_owned);
        let infos = HashMap::from([
            (canonical(&exe), elf(&[needed], rpaths, runpaths, None)),
            (canonical(&lib), lib_info),
        ]);
        resolve_with(&exe, &Sysroot::new(root), &[], &MapSource { infos }).unwrap()
    }

    #[test]
    fn the_whole_string_fallback_finds_only_names_that_ldconfig_caches() {
        // A library in a directory named `x:y` loads only through the image's ld.so.cache,
        // and glibc's ldconfig (`_dl_is_dso`) caches only `lib*.so*`, `ld-*.so*`, `ld.so.*`
        // and `ld64.so.*`. Measured on glibc 2.41: `foo.so` there packed and exited 127.
        for needed in [
            "libfoo.so",
            "libfoo.so.1",
            "libfoo-2.0.so",
            "libfoo.sox",
            "ld-linux-x86-64.so.2",
            "ld-2.12.so",
            "ld.so.1",
            "ld64.so.1",
        ] {
            for rpath in [true, false] {
                let tmp = tempfile::tempdir().unwrap();
                let res = resolve_in_colon_dir(tmp.path(), needed, None, rpath);
                assert!(
                    has(&res, needed) && res.missing.is_empty() && res.hints.is_empty(),
                    "{needed} (rpath {rpath}): {res:?}"
                );
            }
        }
        for needed in [
            "foo.so",
            "foo.so.1",
            "libfoo",
            "libfoo.a",
            "ld.so",
            "ld64.so",
            "ld-linux",
            "Libfoo.so",
            "xlibfoo.so",
        ] {
            for rpath in [true, false] {
                let tmp = tempfile::tempdir().unwrap();
                let res = resolve_in_colon_dir(tmp.path(), needed, None, rpath);
                assert_eq!(res.missing, [needed], "{needed} (rpath {rpath}): {res:?}");
                assert!(res.libs.is_empty(), "{needed}: {res:?}");
                let dir = canonical(tmp.path()).join("app/x:y").display().to_string();
                assert_eq!(res.hints.len(), 1, "{needed}: {:?}", res.hints);
                let hint = &res.hints[0];
                assert!(
                    hint.contains(&format!("`{needed}` is in {dir}, a directory"))
                        && hint.contains("ld.so splits")
                        && hint.contains("caches only names that start with `lib` or `ld-`"),
                    "{hint}"
                );
                assert!(!hint.chars().any(breaks_a_line), "{hint:?}");
            }
        }
    }

    #[test]
    fn the_whole_string_fallback_needs_the_soname_that_ldconfig_keys_on() {
        // ldconfig keys the cache by DT_SONAME, and by the file name only when there is none.
        // ld.so looks up the NEEDED name, so a file with another SONAME is not found.
        for (soname, found) in [(None, true), (Some("libfoo.so"), true)] {
            let tmp = tempfile::tempdir().unwrap();
            let res = resolve_in_colon_dir(tmp.path(), "libfoo.so", soname, false);
            assert_eq!(has(&res, "libfoo.so"), found, "{soname:?}: {res:?}");
            assert!(res.hints.is_empty(), "{:?}", res.hints);
        }
        for rpath in [true, false] {
            let tmp = tempfile::tempdir().unwrap();
            let res = resolve_in_colon_dir(tmp.path(), "libfoo.so", Some("libbar.so.1"), rpath);
            assert_eq!(res.missing, ["libfoo.so"], "{res:?}");
            assert_eq!(res.hints.len(), 1, "{:?}", res.hints);
            assert!(
                res.hints[0].contains("its SONAME `libbar.so.1`"),
                "{}",
                res.hints[0]
            );
        }
    }

    #[test]
    fn an_inherited_whole_string_rpath_applies_the_ldconfig_rule_too() {
        // exe (RPATH `$ORIGIN/x:y`) -> libmid in x:y -> foo.so, also in x:y. libmid loads
        // from the cache, foo.so has no cache entry, so it is missing.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let exe = root.join("app/exe");
        let mid = root.join("app/x:y/libmid.so");
        let leaf = root.join("app/x:y/foo.so");
        for p in [&exe, &mid, &leaf] {
            touch(p);
        }
        let infos = HashMap::from([
            (
                canonical(&exe),
                elf(&["libmid.so"], &["$ORIGIN/x:y"], &[], None),
            ),
            (canonical(&mid), elf(&["foo.so"], &[], &[], None)),
            (canonical(&leaf), elf(&[], &[], &[], None)),
        ]);
        let res = resolve_with(&exe, &Sysroot::new(root), &[], &MapSource { infos }).unwrap();
        assert!(has(&res, "libmid.so"), "{res:?}");
        assert_eq!(res.missing, ["foo.so"], "{res:?}");
        assert_eq!(res.hints.len(), 1, "{:?}", res.hints);
    }

    #[test]
    fn a_name_ldconfig_skips_in_a_colon_dir_comes_from_a_default_dir() {
        // The skipped copy does not hide a copy in a default directory, which ld.so finds.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let exe = root.join("app/exe");
        let colon = root.join("app/x:y/foo.so");
        let default = root.join("usr/lib/foo.so");
        for p in [&exe, &colon, &default] {
            touch(p);
        }
        let infos = HashMap::from([
            (
                canonical(&exe),
                elf(&["foo.so"], &[], &["$ORIGIN/x:y"], None),
            ),
            (canonical(&colon), elf(&[], &[], &[], None)),
            (canonical(&default), elf(&[], &[], &[], None)),
        ]);
        let res = resolve_with(&exe, &Sysroot::new(root), &[], &MapSource { infos }).unwrap();
        assert_eq!(
            res.libs.first().map(|l| l.path.clone()),
            Some(canonical(&default)),
            "{res:?}"
        );
        assert!(res.missing.is_empty() && res.hints.is_empty(), "{res:?}");
    }

    #[test]
    fn an_include_in_a_colon_dir_stages_whatever_its_name_and_soname() {
        // --include is the operator's request to stage a file, which the program may open by
        // path or by its SONAME. So the ldconfig rule for DT_NEEDED names does not apply: a
        // data file, a plugin with a non-lib name and a dev name with another SONAME all
        // stage from x:y, as in 1.x, and a same-named default-dir copy does not take over.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let exe = root.join("app/exe");
        let conf = root.join("app/x:y/app.conf");
        let plugin = root.join("app/x:y/plugin.so");
        let default_plugin = root.join("usr/lib/plugin.so");
        let devname = root.join("app/x:y/libfoo.so");
        for p in [&exe, &conf, &plugin, &default_plugin, &devname] {
            touch(p);
        }
        let mut dev_info = elf(&[], &[], &[], None);
        dev_info.soname = Some("libfoo.so.1".into());
        // app.conf has no facts: the source reads it as a file that is not an ELF.
        let infos = HashMap::from([
            (canonical(&exe), elf(&[], &[], &["$ORIGIN/x:y"], None)),
            (canonical(&plugin), elf(&[], &[], &[], None)),
            (canonical(&default_plugin), elf(&[], &[], &[], None)),
            (canonical(&devname), dev_info),
        ]);
        let includes = ["app.conf", "plugin.so", "libfoo.so"].map(String::from);
        let res = resolve_with(&exe, &Sysroot::new(root), &includes, &MapSource { infos }).unwrap();
        assert!(res.missing.is_empty() && res.hints.is_empty(), "{res:?}");
        let staged: Vec<_> = res.libs.iter().map(|l| l.path.clone()).collect();
        assert_eq!(
            staged,
            [canonical(&conf), canonical(&plugin), canonical(&devname)],
            "{res:?}"
        );
    }

    #[test]
    fn the_runpath_hint_does_not_advise_a_colon_dir_that_ldconfig_skips() {
        // exe (RPATH `$ORIGIN/x:y`) -> libmid (RUNPATH elsewhere) -> foo.so and libbar.so,
        // both only in x:y. A RUNPATH that lists x:y would find libbar.so through the cache,
        // but not foo.so, so only libbar.so gets that advice.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let exe = root.join("app/exe");
        let mid = root.join("app/x:y/libmid.so");
        let foo = root.join("app/x:y/foo.so");
        let bar = root.join("app/x:y/libbar.so");
        for p in [&exe, &mid, &foo, &bar] {
            touch(p);
        }
        let infos = HashMap::from([
            (
                canonical(&exe),
                elf(&["libmid.so"], &["$ORIGIN/x:y"], &[], None),
            ),
            (
                canonical(&mid),
                elf(&["foo.so", "libbar.so"], &[], &["/opt/none"], None),
            ),
            (canonical(&foo), elf(&[], &[], &[], None)),
            (canonical(&bar), elf(&[], &[], &[], None)),
        ]);
        let res = resolve_with(&exe, &Sysroot::new(root), &[], &MapSource { infos }).unwrap();
        assert_eq!(res.missing, ["foo.so", "libbar.so"], "{res:?}");
        assert_eq!(res.hints.len(), 1, "{:?}", res.hints);
        assert!(
            res.hints[0].starts_with("`libbar.so` is in ")
                && res.hints[0].contains("a RUNPATH that lists"),
            "{}",
            res.hints[0]
        );
    }

    // decision-019: an entry ld.so does not search resolves as before and earns one note.
    // Returns the resolution, the exe's path and the library's.
    fn resolve_through(
        rpaths: &[&str],
        runpaths: &[&str],
        lib_dir: &str,
    ) -> (Resolution, PathBuf, PathBuf) {
        let tmp = tempfile::tempdir().unwrap();
        let root = canonical(tmp.path());
        let exe = root.join("a/exe");
        let lib = root.join(lib_dir).join("libfoo.so.1");
        touch(&exe);
        touch(&lib);
        let mut infos = HashMap::new();
        infos.insert(exe.clone(), elf(&["libfoo.so.1"], rpaths, runpaths, None));
        infos.insert(lib.clone(), elf(&[], &[], &[], None));
        let res = resolve_with(&exe, &Sysroot::new(&root), &[], &MapSource { infos }).unwrap();
        (res, exe, lib)
    }

    #[test]
    fn an_entry_ld_so_does_not_search_resolves_as_before_and_is_noted_once() {
        let skip = "ld.so does not search this entry, because";
        let cache = "so `libfoo.so.1` loads only through the image's ld.so.cache";
        let empty = "it ignores an empty string";
        let relative =
            "it reads a relative entry against the working directory, not the object's directory";
        let token = "it expands `$ORIGIN`, `$LIB` and `$PLATFORM` only when no letter, digit or \
                     `_` follows the name";
        let cases: [(&[&str], &[&str], &str, &str); 7] = [
            (
                &[""],
                &[],
                "a",
                "{exe} has an empty RPATH string: {skip} {empty}, {cache}",
            ),
            (
                &[],
                &[""],
                "a",
                "{exe} has an empty RUNPATH string: {skip} {empty}, {cache}",
            ),
            (
                &["lib"],
                &[],
                "a/lib",
                "RPATH entry `lib` of {exe}: {skip} {relative}, {cache}",
            ),
            (
                &[],
                &["lib"],
                "a/lib",
                "RUNPATH entry `lib` of {exe}: {skip} {relative}, {cache}",
            ),
            (
                &[],
                &["$ORIGINX"],
                "aX",
                "RUNPATH entry `$ORIGINX` of {exe}: {skip} {token}, {cache}",
            ),
            (
                &[],
                &["$ORIGIN_x"],
                "a_x",
                "RUNPATH entry `$ORIGIN_x` of {exe}: {skip} {token}, {cache}",
            ),
            (
                &[],
                &["/$LIBx"],
                "lib64x",
                "RUNPATH entry `/$LIBx` of {exe}: {skip} {token}, {cache}",
            ),
        ];
        for (rpaths, runpaths, lib_dir, note) in cases {
            let (res, exe, lib) = resolve_through(rpaths, runpaths, lib_dir);
            // The result is what it always was: the library resolves where it sits.
            assert!(
                res.missing.is_empty(),
                "{rpaths:?} {runpaths:?}: {:?}",
                res.missing
            );
            assert_eq!(res.libs.len(), 1, "{rpaths:?} {runpaths:?}");
            assert_eq!(res.libs[0].path, lib, "{rpaths:?} {runpaths:?}");
            let want = note
                .replace("{exe}", &printable(&exe))
                .replace("{skip}", skip)
                .replace("{empty}", empty)
                .replace("{relative}", relative)
                .replace("{token}", token)
                .replace("{cache}", cache);
            assert_eq!(res.notes, vec![want], "{rpaths:?} {runpaths:?}");
        }
    }

    #[test]
    fn an_entry_ld_so_searches_gets_no_note() {
        // `${ORIGIN}x` expands in glibc too, and an absolute entry is searched as written.
        for (runpaths, lib_dir) in [(&["${ORIGIN}x"][..], "ax"), (&["$ORIGIN/lib"], "a/lib")] {
            let (res, ..) = resolve_through(&[], runpaths, lib_dir);
            assert!(
                res.missing.is_empty() && res.notes.is_empty(),
                "{runpaths:?}: {res:?}"
            );
        }
        // An empty string beside `$ORIGIN`: ld.so finds the same file through `$ORIGIN`.
        let (res, ..) = resolve_through(&["", "$ORIGIN"], &[], "a");
        assert!(res.missing.is_empty() && res.notes.is_empty(), "{res:?}");
    }

    #[test]
    fn a_noted_library_ldconfig_does_not_cache_is_named_as_unloadable() {
        // The note promises the image's ld.so.cache, so it must hold only where ldconfig
        // caches the file under the needed name. The result is still the same.
        let tmp = tempfile::tempdir().unwrap();
        let root = canonical(tmp.path());
        let exe = root.join("a/exe");
        let plugin = root.join("a/lib/foo.so");
        let other = root.join("a/lib/libbar.so.1");
        for p in [&exe, &plugin, &other] {
            touch(p);
        }
        let mut infos = HashMap::new();
        infos.insert(
            exe.clone(),
            elf(&["foo.so", "libbar.so.1"], &[], &["lib"], None),
        );
        infos.insert(plugin.clone(), elf(&[], &[], &[], None));
        let mut bar = elf(&[], &[], &[], None);
        bar.soname = Some("libbar.so.2".into());
        infos.insert(other.clone(), bar);
        let res = resolve_with(&exe, &Sysroot::new(&root), &[], &MapSource { infos }).unwrap();
        assert_eq!(res.libs.len(), 2, "{res:?}");
        assert_eq!(
            res.notes,
            vec![format!(
                "RUNPATH entry `lib` of {}: ld.so does not search this entry, because it reads a \
                 relative entry against the working directory, not the object's directory. The \
                 image's ld.so cannot find `foo.so` either, because ldconfig does not cache it \
                 under that name: it caches only names that start with `lib` or `ld-` and hold \
                 `.so`, or start with `ld.so.` or `ld64.so.`. The image's ld.so cannot find \
                 `libbar.so.1` either, because ldconfig does not cache it under that name: it \
                 lists the file by its SONAME `libbar.so.2`",
                printable(&exe)
            )]
        );
    }

    #[test]
    fn an_entry_that_names_a_default_directory_gets_no_note() {
        // ld.so searches the default directories after RUNPATH, on the host and in the image.
        let tmp = tempfile::tempdir().unwrap();
        let root = canonical(tmp.path());
        let exe = root.join("usr/lib64/exe");
        let lib = root.join("usr/lib64/libfoo.so.1");
        touch(&exe);
        touch(&lib);
        let mut infos = HashMap::new();
        infos.insert(exe.clone(), elf(&["libfoo.so.1"], &[], &[""], None));
        infos.insert(lib.clone(), elf(&[], &[], &[], None));
        let res = resolve_with(&exe, &Sysroot::new(&root), &[], &MapSource { infos }).unwrap();
        assert_eq!(res.libs.len(), 1);
        assert!(res.notes.is_empty(), "{:?}", res.notes);
    }

    // Resolve `a/exe`, which needs `needed`, with `files` (relative to the root) present.
    fn resolve_files(
        needed: &str,
        rpaths: &[&str],
        runpaths: &[&str],
        files: &[&str],
    ) -> (Resolution, PathBuf) {
        let tmp = tempfile::tempdir().unwrap();
        let root = canonical(tmp.path());
        let exe = root.join("a/exe");
        touch(&exe);
        let mut infos = HashMap::new();
        infos.insert(exe.clone(), elf(&[needed], rpaths, runpaths, None));
        for file in files {
            let path = root.join(file);
            touch(&path);
            infos.insert(path, elf(&[], &[], &[], None));
        }
        let res = resolve_with(&exe, &Sysroot::new(&root), &[], &MapSource { infos }).unwrap();
        (res, root)
    }

    #[test]
    fn a_missing_library_under_a_cpu_platform_name_gets_a_hint() {
        // decision-018: `$PLATFORM` stays `x86_64`, so the library is still missing, and the
        // hint names the copy that glibc would load on some Intel CPUs.
        let cases: [(&[&str], &[&str], &str, &str); 3] = [
            (
                &[],
                &["$ORIGIN/$PLATFORM"],
                "haswell",
                "RUNPATH entry `$ORIGIN/$PLATFORM`",
            ),
            (
                &["$ORIGIN/${PLATFORM}"],
                &[],
                "xeon_phi",
                "RPATH entry `$ORIGIN/${PLATFORM}`",
            ),
            (
                &[],
                &["/opt/none:$ORIGIN/$PLATFORM/lib"],
                "haswell",
                "RUNPATH entry `$ORIGIN/$PLATFORM/lib`",
            ),
        ];
        for (rpaths, runpaths, name, entry) in cases {
            let sub = if entry.ends_with("lib`") { "/lib" } else { "" };
            let (res, root) = resolve_files(
                "libfoo.so.1",
                rpaths,
                runpaths,
                &[&format!("a/{name}{sub}/libfoo.so.1")],
            );
            assert_eq!(res.missing, ["libfoo.so.1"], "{entry}");
            assert!(
                res.libs.is_empty() && res.notes.is_empty(),
                "{entry}: {res:?}"
            );
            let a = root.join("a");
            let want = format!(
                "`libfoo.so.1` is in {}, which {entry} of {} names only on an Intel CPU that \
                 glibc names `{name}`. Scratchsmith reads `$PLATFORM` as `x86_64`, as glibc does \
                 on every other x86_64 CPU, so it does not use that copy. Put an `x86_64` build \
                 of `libfoo.so.1` in {}.",
                a.join(format!("{name}{sub}")).display(),
                a.join("exe").display(),
                a.join(format!("x86_64{sub}")).display(),
            );
            assert_eq!(res.hints, [want], "{entry}");
        }
    }

    #[test]
    fn a_shipped_library_notes_an_unused_cpu_platform_copy_next_to_it() {
        let (res, root) = resolve_files(
            "libfoo.so.1",
            &[],
            &["$ORIGIN/$PLATFORM"],
            &["a/x86_64/libfoo.so.1", "a/haswell/libfoo.so.1"],
        );
        let a = root.join("a");
        // Staged as before: the x86_64 copy only.
        assert_eq!(res.libs.len(), 1);
        assert_eq!(res.libs[0].path, a.join("x86_64/libfoo.so.1"));
        assert!(res.missing.is_empty() && res.hints.is_empty(), "{res:?}");
        let want = format!(
            "`libfoo.so.1` ships from {}. On an Intel CPU that glibc names `haswell`, ld.so reads \
             `$PLATFORM` in RUNPATH entry `$ORIGIN/$PLATFORM` of {} as `haswell` and loads the \
             copy in {} instead, which the image leaves out. The image loads the shipped copy on \
             every CPU",
            a.join("x86_64/libfoo.so.1").display(),
            a.join("exe").display(),
            a.join("haswell").display(),
        );
        assert_eq!(res.notes, [want]);
    }

    #[test]
    fn an_unused_cpu_copy_of_a_name_ldconfig_does_not_cache_says_the_image_cannot_load_it() {
        let files = ["a/x86_64/foo.so", "a/xeon_phi/foo.so"];
        let (res, _) = resolve_files("foo.so", &[], &["$ORIGIN/$PLATFORM"], &files);
        assert_eq!(res.libs.len(), 1);
        assert_eq!(res.notes.len(), 1, "{:?}", res.notes);
        assert!(
            res.notes[0].contains("`xeon_phi`")
                && res.notes[0].ends_with(
                    ". On such a CPU the image's ld.so cannot find `foo.so` at all, because \
                     ldconfig does not cache the shipped copy under that name: it caches only \
                     names that start with `lib` or `ld-` and hold `.so`, or start with `ld.so.` \
                     or `ld64.so.`"
                ),
            "{}",
            res.notes[0]
        );
        // An entry that names the shipped directory outright still finds it on such a CPU.
        let (res, _) = resolve_files("foo.so", &[], &["$ORIGIN/$PLATFORM:$ORIGIN/x86_64"], &files);
        assert_eq!(res.notes.len(), 1, "{:?}", res.notes);
        assert!(
            res.notes[0].ends_with(". The image loads the shipped copy on every CPU"),
            "{}",
            res.notes[0]
        );
    }

    #[test]
    fn a_cpu_platform_copy_that_ld_so_reaches_later_is_noted_too() {
        // On `haswell`, ld.so reads every `$PLATFORM` entry so, so it can miss the entry that
        // found the shipped copy and load a copy through a later one.
        let (res, root) = resolve_files(
            "libfoo.so.1",
            &[],
            &["$ORIGIN/$PLATFORM:/opt/$PLATFORM"],
            &["a/x86_64/libfoo.so.1", "opt/haswell/libfoo.so.1"],
        );
        assert_eq!(res.libs[0].path, root.join("a/x86_64/libfoo.so.1"));
        assert_eq!(res.notes.len(), 1, "{:?}", res.notes);
        assert!(
            res.notes[0].contains(&format!(
                "in RUNPATH entry `/opt/$PLATFORM` of {} as `haswell` and loads the copy in {} \
                 instead",
                root.join("a/exe").display(),
                root.join("opt/haswell").display()
            )),
            "{}",
            res.notes[0]
        );
        // A library that ships from a default directory, with a CPU copy that only a `$PLATFORM`
        // entry names. The image finds the shipped copy there on every CPU.
        let (res, root) = resolve_files(
            "libfoo.so.1",
            &[],
            &["$ORIGIN/$PLATFORM"],
            &["a/haswell/libfoo.so.1", "usr/lib64/libfoo.so.1"],
        );
        assert_eq!(res.libs[0].path, root.join("usr/lib64/libfoo.so.1"));
        assert_eq!(res.notes.len(), 1, "{:?}", res.notes);
        assert!(
            res.notes[0].starts_with(&format!(
                "`libfoo.so.1` ships from {}. On an Intel CPU that glibc names `haswell`",
                root.join("usr/lib64/libfoo.so.1").display()
            )) && res.notes[0].ends_with(". The image loads the shipped copy on every CPU"),
            "{}",
            res.notes[0]
        );
    }

    #[test]
    fn a_cpu_platform_name_with_no_other_copy_gets_no_hint_or_note() {
        // No CPU-specific copy.
        let (res, _) = resolve_files(
            "libfoo.so.1",
            &[],
            &["$ORIGIN/$PLATFORM"],
            &["a/x86_64/libfoo.so.1"],
        );
        assert!(res.notes.is_empty() && res.hints.is_empty(), "{res:?}");
        // The CPU-specific name is a link to the shipped copy, so it is the same file.
        let tmp = tempfile::tempdir().unwrap();
        let root = canonical(tmp.path());
        let exe = root.join("a/exe");
        let lib = root.join("a/x86_64/libfoo.so.1");
        touch(&exe);
        touch(&lib);
        std::os::unix::fs::symlink("x86_64", root.join("a/haswell")).unwrap();
        let mut infos = HashMap::new();
        infos.insert(
            exe.clone(),
            elf(&["libfoo.so.1"], &[], &["$ORIGIN/$PLATFORM"], None),
        );
        infos.insert(lib, elf(&[], &[], &[], None));
        let res = resolve_with(&exe, &Sysroot::new(&root), &[], &MapSource { infos }).unwrap();
        assert_eq!(res.libs.len(), 1);
        assert!(res.notes.is_empty(), "{:?}", res.notes);
        // A name glued to the token is an entry ld.so does not search, noted on its own.
        let (res, _) = resolve_files(
            "libfoo.so.1",
            &[],
            &["$ORIGIN/$PLATFORMx"],
            &["a/x86_64x/libfoo.so.1", "a/haswellx/libfoo.so.1"],
        );
        assert_eq!(res.notes.len(), 1, "{:?}", res.notes);
        assert!(
            res.notes[0].contains("ld.so does not search this entry"),
            "{}",
            res.notes[0]
        );
    }

    #[test]
    fn a_cpu_platform_copy_on_another_arch_gets_no_hint_or_note() {
        // Only x86_64 glibc swaps `$PLATFORM` for a CPU name.
        let tmp = tempfile::tempdir().unwrap();
        let root = canonical(tmp.path());
        let exe = root.join("a/exe");
        let lib = root.join("a/aarch64/libfoo.so.1");
        touch(&exe);
        touch(&lib);
        touch(&root.join("a/haswell/libfoo.so.1"));
        let mut arm = elf(&["libfoo.so.1"], &[], &["$ORIGIN/$PLATFORM"], None);
        arm.machine = goblin::elf::header::EM_AARCH64;
        let mut infos = HashMap::new();
        infos.insert(exe.clone(), arm);
        infos.insert(lib, elf(&[], &[], &[], None));
        let res = resolve_with(&exe, &Sysroot::new(&root), &[], &MapSource { infos }).unwrap();
        assert_eq!(res.libs.len(), 1);
        assert!(res.notes.is_empty() && res.hints.is_empty(), "{res:?}");
    }

    #[test]
    fn two_libraries_through_one_entry_share_one_note() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let exe = root.join("a/exe");
        for p in [
            &exe,
            &root.join("a/lib/libfoo.so.1"),
            &root.join("a/lib/libbar.so.1"),
        ] {
            touch(p);
        }
        let mut infos = HashMap::new();
        infos.insert(
            canonical(&exe),
            elf(&["libfoo.so.1", "libbar.so.1"], &[], &["lib"], None),
        );
        for lib in ["libfoo.so.1", "libbar.so.1"] {
            infos.insert(
                canonical(&root.join("a/lib").join(lib)),
                elf(&[], &[], &[], None),
            );
        }
        let res = resolve_with(&exe, &Sysroot::new(root), &[], &MapSource { infos }).unwrap();
        assert_eq!(res.libs.len(), 2);
        assert_eq!(res.notes.len(), 1, "{:?}", res.notes);
        assert!(
            res.notes[0].ends_with(
                "so `libfoo.so.1`, `libbar.so.1` load only through the image's ld.so.cache"
            ),
            "{}",
            res.notes[0]
        );
    }

    // An exe with RPATH `$ORIGIN/lib:$ORIGIN/lib64` that needs libx.so.1, and a copy of it in
    // each of `dirs` with the given class. Returns the exe and the resolution.
    fn resolve_with_copies(
        root: &Path,
        needed: &str,
        copies: &[(&str, bool)],
    ) -> (PathBuf, Resolution) {
        resolve_with_copies_on(root, "$ORIGIN/lib:$ORIGIN/lib64", &[needed], &[], copies)
    }

    // As `resolve_with_copies`, with the exe's RPATH string, its needed list and the
    // `--include` names given.
    fn resolve_with_copies_on(
        root: &Path,
        rpath: &str,
        needed: &[&str],
        includes: &[String],
        copies: &[(&str, bool)],
    ) -> (PathBuf, Resolution) {
        let loader = root.join("lib64/ld-linux-x86-64.so.2");
        let exe = root.join("a/exe");
        touch(&loader);
        touch(&exe);
        let mut infos = HashMap::new();
        infos.insert(
            canonical(&exe),
            elf(needed, &[rpath], &[], Some("/lib64/ld-linux-x86-64.so.2")),
        );
        for (dir, is_64) in copies {
            let lib = root.join("a").join(dir).join("libx.so.1");
            touch(&lib);
            let mut info = elf(&[], &[], &[], None);
            info.is_64 = *is_64;
            if !is_64 {
                info.machine = goblin::elf::header::EM_386;
            }
            infos.insert(canonical(&lib), info);
        }
        let res = resolve_with(&exe, &Sysroot::new(root), includes, &MapSource { infos }).unwrap();
        (exe, res)
    }

    #[test]
    fn a_library_of_another_class_is_skipped_and_the_search_goes_on() {
        // TASK-213. ld.so skips a 32-bit copy in `lib` and loads the 64-bit one in `lib64`.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let (_, res) = resolve_with_copies(root, "libx.so.1", &[("lib", false), ("lib64", true)]);
        let lib = res.libs.iter().find(|l| l.soname == "libx.so.1").unwrap();
        assert_eq!(lib.path, canonical(&root.join("a/lib64/libx.so.1")));
        assert!(
            res.missing.is_empty() && res.arch_warnings.is_empty(),
            "{res:?}"
        );
    }

    #[test]
    fn a_library_of_another_class_that_is_the_only_copy_stages_with_a_warning() {
        // TASK-213, decision: no refusal. The pick is the one copy, as before, and a warning
        // names it and says the image cannot load it.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let (exe, res) = resolve_with_copies(root, "libx.so.1", &[("lib", false)]);
        let lib = res.libs.iter().find(|l| l.soname == "libx.so.1").unwrap();
        assert_eq!(lib.path, canonical(&root.join("a/lib/libx.so.1")));
        assert!(res.missing.is_empty(), "{res:?}");
        let [warning] = &res.arch_warnings[..] else {
            panic!("one warning: {:?}", res.arch_warnings);
        };
        for part in [
            "`libx.so.1` resolved to",
            "a/lib/libx.so.1, the only copy found, which is a 32-bit 386 library",
            &format!("{} is 64-bit X86_64", canonical(&exe).display()),
            "Put a 64-bit X86_64 copy on the search path",
        ] {
            assert!(warning.contains(part), "{part:?} in {warning}");
        }
    }

    #[test]
    fn a_wrong_arch_copy_skipped_in_a_gap_entry_raises_no_gap_note() {
        // Review nit on PR 551. `lib` is relative, a gap entry. Its 32-bit copy is skipped, so
        // the pick is the 64-bit one in `$ORIGIN/lib64`, which ld.so searches: no note.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let (_, res) = resolve_with_copies_on(
            root,
            "lib:$ORIGIN/lib64",
            &["libx.so.1"],
            &[],
            &[("lib", false), ("lib64", true)],
        );
        let lib = res.libs.iter().find(|l| l.soname == "libx.so.1").unwrap();
        assert_eq!(lib.path, canonical(&root.join("a/lib64/libx.so.1")));
        assert!(res.notes.is_empty(), "{:?}", res.notes);
        // With only the 32-bit copy, the pick is in the gap entry, so the note stays.
        let tmp = tempfile::tempdir().unwrap();
        let (_, res) = resolve_with_copies_on(
            tmp.path(),
            "lib:$ORIGIN/lib64",
            &["libx.so.1"],
            &[],
            &[("lib", false)],
        );
        assert!(
            res.notes.iter().any(|n| n.contains("RPATH entry `lib`")),
            "{:?}",
            res.notes
        );
    }

    #[test]
    fn a_wrong_arch_include_warns_that_the_program_cannot_open_it() {
        // Review nit on PR 551. An --include loads later through dlopen, so the image starts.
        let tmp = tempfile::tempdir().unwrap();
        let (_, res) = resolve_with_copies_on(
            tmp.path(),
            "$ORIGIN/lib",
            &[],
            &["libx.so.1".to_string()],
            &[("lib", false)],
        );
        let [warning] = &res.arch_warnings[..] else {
            panic!("one warning: {:?}", res.arch_warnings);
        };
        assert!(
            warning.contains("will not load it and the program cannot open it"),
            "{warning}"
        );
    }

    #[test]
    fn a_library_of_another_class_named_by_path_stages_with_a_warning() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let path = root.join("a/lib/libx.so.1");
        let (_, res) = resolve_with_copies(
            root,
            path.to_str().unwrap(),
            &[("lib", false), ("lib64", true)],
        );
        assert!(
            res.libs.iter().any(|l| l.path == canonical(&path)),
            "{res:?}"
        );
        assert!(
            res.arch_warnings.len() == 1 && res.arch_warnings[0].contains("named by path"),
            "{:?}",
            res.arch_warnings
        );
    }

    #[test]
    fn origin_expands_relative_to_the_owning_object() {
        // libmid's $ORIGIN must be libmid's own dir (a/lib), not the exe's (a).
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let loader = root.join("lib64/ld-linux-x86-64.so.2");
        let exe = root.join("a/exe");
        let mid = root.join("a/lib/libmid.so");
        let leaf = root.join("a/lib/deep/libleaf.so");
        for p in [&loader, &exe, &mid, &leaf] {
            touch(p);
        }
        let mut infos = HashMap::new();
        infos.insert(
            canonical(&exe),
            elf(
                &["libmid.so"],
                &["$ORIGIN/lib"],
                &[],
                Some("/lib64/ld-linux-x86-64.so.2"),
            ),
        );
        infos.insert(
            canonical(&mid),
            elf(&["libleaf.so"], &["$ORIGIN/deep"], &[], None),
        );
        infos.insert(canonical(&leaf), elf(&[], &[], &[], None));
        let res = resolve_with(&exe, &Sysroot::new(root), &[], &MapSource { infos }).unwrap();
        assert!(
            res.missing.is_empty(),
            "origin should be object-local: {:?}",
            res.missing
        );
        assert!(has(&res, "libleaf.so"));
    }

    #[test]
    fn ld_library_path_is_ignored() {
        // The lib exists only in a dir named by LD_LIBRARY_PATH; resolution must miss
        // it, proving the host environment never influences the result.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let loader = root.join("lib64/ld-linux-x86-64.so.2");
        let exe = root.join("bin/exe");
        let stray_dir = root.join("elsewhere");
        let stray = stray_dir.join("libonlyhere.so");
        for p in [&loader, &exe, &stray] {
            touch(p);
        }
        let mut infos = HashMap::new();
        infos.insert(
            canonical(&exe),
            elf(
                &["libonlyhere.so"],
                &[],
                &[],
                Some("/lib64/ld-linux-x86-64.so.2"),
            ),
        );
        infos.insert(canonical(&stray), elf(&[], &[], &[], None));

        std::env::set_var("LD_LIBRARY_PATH", &stray_dir);
        let res = resolve_with(&exe, &Sysroot::new(root), &[], &MapSource { infos }).unwrap();
        std::env::remove_var("LD_LIBRARY_PATH");
        assert!(
            res.missing.contains(&"libonlyhere.so".to_string()),
            "LD_LIBRARY_PATH must be ignored"
        );
    }

    #[test]
    fn diamond_dependencies_resolve_shared_lib_once() {
        // exe -> {a, b}; a -> c; b -> c. c is a single real file, so the closed set
        // must contain it exactly once (dedup by real path).
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let dir = root.join("usr/lib/x86_64-linux-gnu");
        let loader = root.join("lib64/ld-linux-x86-64.so.2");
        let (exe, a, b, c) = (
            root.join("bin/exe"),
            dir.join("liba.so"),
            dir.join("libb.so"),
            dir.join("libc_shared.so"),
        );
        for p in [&loader, &exe, &a, &b, &c] {
            touch(p);
        }
        let mut infos = HashMap::new();
        infos.insert(
            canonical(&exe),
            elf(
                &["liba.so", "libb.so"],
                &[],
                &[],
                Some("/lib64/ld-linux-x86-64.so.2"),
            ),
        );
        infos.insert(canonical(&a), elf(&["libc_shared.so"], &[], &[], None));
        infos.insert(canonical(&b), elf(&["libc_shared.so"], &[], &[], None));
        infos.insert(canonical(&c), elf(&[], &[], &[], None));
        let res = resolve_with(&exe, &Sysroot::new(root), &[], &MapSource { infos }).unwrap();
        assert!(res.missing.is_empty(), "{:?}", res.missing);
        let count = res
            .libs
            .iter()
            .filter(|l| l.soname == "libc_shared.so")
            .count();
        assert_eq!(count, 1, "shared dep must appear once, got {count}");
        // ...but the graph edges keep BOTH parents' edge to it, so a diamond can be
        // reconstructed even though the file is staged once.
        let edges_to_c = res
            .edges
            .iter()
            .filter(|e| e.to.as_deref() == Some(canonical(&c).as_path()))
            .count();
        assert_eq!(
            edges_to_c, 2,
            "both a and b must keep an edge to c, got {edges_to_c}"
        );
    }

    // exe (RUNPATH $ORIGIN/../lib) -> {libbar, libfoo}; libbar -> libfoo, with no search path.
    fn app_layout(root: &Path) -> (PathBuf, PathBuf, PathBuf) {
        let exe = root.join("app/bin/exe");
        let bar = root.join("app/lib/libbar.so.1");
        let foo = root.join("app/lib/libfoo.so.1");
        for p in [&exe, &bar, &foo, &root.join("lib64/ld-linux-x86-64.so.2")] {
            touch(p);
        }
        (exe, bar, foo)
    }

    #[test]
    fn a_soname_already_loaded_resolves_without_a_search() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let (exe, bar, foo) = app_layout(root);
        let mut infos = HashMap::new();
        infos.insert(
            canonical(&exe),
            elf(
                &["libbar.so.1", "libfoo.so.1"],
                &[],
                &["$ORIGIN/../lib"],
                Some("/lib64/ld-linux-x86-64.so.2"),
            ),
        );
        infos.insert(canonical(&bar), elf(&["libfoo.so.1"], &[], &[], None));
        infos.insert(canonical(&foo), elf(&[], &[], &[], None));
        let res = resolve_with(&exe, &Sysroot::new(root), &[], &MapSource { infos }).unwrap();
        assert!(res.missing.is_empty(), "{:?}", res.missing);
        let count = res
            .libs
            .iter()
            .filter(|l| l.soname == "libfoo.so.1")
            .count();
        assert_eq!(count, 1, "{:?}", res.libs);
        let to_foo = res
            .edges
            .iter()
            .filter(|e| e.to.as_deref() == Some(canonical(&foo).as_path()))
            .count();
        assert_eq!(to_foo, 2, "{:?}", res.edges);
    }

    #[test]
    fn an_edge_to_a_loaded_object_gets_no_search_note() {
        // libbar's empty RUNPATH entry would be a gap note if ld.so searched for libfoo.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let (exe, bar, foo) = app_layout(root);
        let mut infos = HashMap::new();
        infos.insert(
            canonical(&exe),
            elf(
                &["libbar.so.1", "libfoo.so.1"],
                &[],
                &["$ORIGIN/../lib"],
                Some("/lib64/ld-linux-x86-64.so.2"),
            ),
        );
        infos.insert(canonical(&bar), elf(&["libfoo.so.1"], &[], &[""], None));
        infos.insert(canonical(&foo), elf(&[], &[], &[], None));
        let res = resolve_with(&exe, &Sysroot::new(root), &[], &MapSource { infos }).unwrap();
        assert!(res.missing.is_empty(), "{:?}", res.missing);
        assert!(res.notes.is_empty(), "{:?}", res.notes);
    }

    #[test]
    fn a_loaded_object_matches_by_its_dt_soname() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let exe = root.join("app/bin/exe");
        let bar = root.join("app/lib/libbar.so.1");
        let foo = root.join("app/lib/libfoo.so");
        for p in [&exe, &bar, &foo] {
            touch(p);
        }
        let mut infos = HashMap::new();
        infos.insert(
            canonical(&exe),
            elf(
                &["libfoo.so", "libbar.so.1"],
                &[],
                &["$ORIGIN/../lib"],
                None,
            ),
        );
        infos.insert(canonical(&bar), elf(&["libfoo.so.1"], &[], &[], None));
        infos.insert(
            canonical(&foo),
            ElfInfo {
                soname: Some("libfoo.so.1".into()),
                ..elf(&[], &[], &[], None)
            },
        );
        let res = resolve_with(&exe, &Sysroot::new(root), &[], &MapSource { infos }).unwrap();
        assert!(res.missing.is_empty(), "{:?}", res.missing);
        let edge = res
            .edges
            .iter()
            .find(|e| e.from == canonical(&bar) && e.soname == "libfoo.so.1")
            .unwrap();
        assert_eq!(edge.to.as_deref(), Some(canonical(&foo).as_path()));
    }

    #[test]
    fn the_loader_matches_by_its_soname_and_no_host_copy_is_staged() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let exe = root.join("app/bin/exe");
        let loader = root.join("opt/glibc/lib/ld-linux-x86-64.so.2");
        let libdir = root.join("usr/lib/x86_64-linux-gnu");
        let (libc, host_loader) = (
            libdir.join("libc.so.6"),
            libdir.join("ld-linux-x86-64.so.2"),
        );
        for p in [&exe, &loader, &libc, &host_loader] {
            touch(p);
        }
        let mut infos = HashMap::new();
        infos.insert(
            canonical(&exe),
            elf(
                &["libc.so.6"],
                &[],
                &[],
                Some("/opt/glibc/lib/ld-linux-x86-64.so.2"),
            ),
        );
        infos.insert(
            canonical(&loader),
            ElfInfo {
                soname: Some("ld-linux-x86-64.so.2".into()),
                ..elf(&[], &[], &[], None)
            },
        );
        infos.insert(
            canonical(&libc),
            elf(&["ld-linux-x86-64.so.2"], &[], &[], None),
        );
        let res = resolve_with(&exe, &Sysroot::new(root), &[], &MapSource { infos }).unwrap();
        assert!(res.missing.is_empty(), "{:?}", res.missing);
        let edge = res
            .edges
            .iter()
            .find(|e| e.from == canonical(&libc))
            .unwrap();
        assert_eq!(edge.to.as_deref(), Some(canonical(&loader).as_path()));
        assert!(
            !res.libs.iter().any(|l| l.path == canonical(&host_loader)),
            "{:?}",
            res.libs
        );
    }

    #[test]
    fn an_include_does_not_count_as_loaded() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let exe = root.join("app/bin/exe");
        let bar = root.join("app/lib/libbar.so.1");
        let plug = root.join("app/lib/libplug.so");
        for p in [&exe, &bar, &plug] {
            touch(p);
        }
        let mut infos = HashMap::new();
        infos.insert(
            canonical(&exe),
            elf(&["libbar.so.1"], &[], &["$ORIGIN/../lib"], None),
        );
        infos.insert(canonical(&bar), elf(&["libplug.so"], &[], &[], None));
        let includes = ["libplug.so".to_string()];
        let res = resolve_with(&exe, &Sysroot::new(root), &includes, &MapSource { infos }).unwrap();
        assert!(res.missing.contains(&"libplug.so".to_string()), "{:?}", res);
    }

    #[test]
    fn missing_dependency_is_reported_not_fatal() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let exe = root.join("bin/exe");
        touch(&exe);
        let mut infos = HashMap::new();
        infos.insert(canonical(&exe), elf(&["libghost.so"], &[], &[], None));
        let res = resolve_with(&exe, &Sysroot::new(root), &[], &MapSource { infos }).unwrap();
        assert_eq!(res.missing, vec!["libghost.so".to_string()]);
    }

    #[test]
    fn missing_sonames_are_escaped_for_display_and_stay_raw_in_the_list() {
        // A DT_NEEDED entry that does not resolve, holding a newline and a terminal escape.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let exe = root.join("app/exe");
        touch(&exe);
        let evil = "libx.so\nerror: forged\x1b[2J";
        let infos = HashMap::from([(canonical(&exe), elf(&[evil, "libok.so"], &[], &[], None))]);
        let res = resolve_with(&exe, &Sysroot::new(root), &[], &MapSource { infos }).unwrap();
        // The list keeps the real soname: `--require` and `--deny` match on it.
        assert_eq!(res.missing, [evil, "libok.so"]);
        let shown = missing_for_display(&res.missing);
        assert!(
            !shown.contains('\n') && !shown.contains('\x1b'),
            "{shown:?}"
        );
        assert_eq!(shown, r#""libx.so\nerror: forged\u{1b}[2J", "libok.so""#);
        // A comma inside one name stays inside its quotes: one library, not two.
        let two = missing_for_display(&["liba.so, libb.so".to_string()]);
        assert_eq!(two, r#""liba.so, libb.so""#);
    }

    #[test]
    fn platform_maps_the_machine() {
        let mut e = info(None, &[]);
        e.machine = goblin::elf::header::EM_AARCH64;
        assert_eq!(e.platform(), "aarch64");
        e.machine = goblin::elf::header::EM_X86_64;
        assert_eq!(e.platform(), "x86_64");
        e.machine = 0xffff; // anything else → empty, rather than guessing wrong
        assert_eq!(e.platform(), "");
    }

    #[test]
    fn reroot_handles_sysroot_and_relative_paths() {
        // Root "/" leaves the path unchanged.
        assert_eq!(
            reroot(Path::new("/"), Path::new("/usr/lib/x")),
            PathBuf::from("/usr/lib/x")
        );
        // A path already under the sysroot is not double-rooted.
        assert_eq!(
            reroot(Path::new("/sr"), Path::new("/sr/lib/x")),
            PathBuf::from("/sr/lib/x")
        );
        // A normal absolute path is joined under the sysroot.
        assert_eq!(
            reroot(Path::new("/sr"), Path::new("/lib/x")),
            PathBuf::from("/sr/lib/x")
        );
        // A relative path (no leading "/") is returned as-is (the strip_prefix Err arm).
        assert_eq!(
            reroot(Path::new("/sr"), Path::new("rel/x")),
            PathBuf::from("rel/x")
        );
    }

    #[test]
    fn find_lib_resolves_slash_sonames_and_search_dirs() {
        let tmp = tempfile::tempdir().unwrap();
        let libdir = tmp.path().join("lib");
        std::fs::create_dir_all(&libdir).unwrap();
        let lib = libdir.join("libx.so.1");
        touch(&lib);

        // Bare soname found by scanning the search dirs.
        assert_eq!(
            find_lib(
                "libx.so.1",
                std::slice::from_ref(&libdir),
                Path::new("/"),
                Path::new("/")
            ),
            Some(lib.clone())
        );
        // A missing bare soname is None.
        assert_eq!(
            find_lib(
                "libmissing.so",
                std::slice::from_ref(&libdir),
                Path::new("/"),
                Path::new("/")
            ),
            None
        );
        // A slash-soname with an absolute path is rerooted (root "/" → unchanged).
        assert_eq!(
            find_lib(lib.to_str().unwrap(), &[], Path::new("/"), Path::new("/")),
            Some(lib.clone())
        );
        // A slash-soname with a relative path resolves against origin_dir.
        assert_eq!(
            find_lib("./libx.so.1", &[], &libdir, Path::new("/")),
            Some(libdir.join("./libx.so.1"))
        );
    }
}
