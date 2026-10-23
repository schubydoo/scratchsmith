//! Resolve a binary's shared-library deps by emulating the `ld.so` search order
//! (not by scraping host `ldd`). The correctness core.
//!
//! Two halves, both here: `parse_elf_info` reads the raw dynamic-linking facts out of an
//! ELF, and `resolve_with` turns each soname into a real path by searching DT_RPATH (the
//! object's own, then its ancestors' — RPATH is transitive, and all of it is ignored when
//! the object also declares RUNPATH), then its own DT_RUNPATH, then the sysroot default dirs.
//! `$ORIGIN`, `$LIB` and `$PLATFORM` are expanded inside those entries, not searched.

use anyhow::{bail, Context, Result};
use std::collections::{HashSet, VecDeque};
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
    /// glibc (no NSS, libc-is-the-loader), so v1 detects and rejects it.
    pub fn is_musl(&self) -> bool {
        self.interpreter
            .as_deref()
            .is_some_and(|i| i.contains("ld-musl") || i.contains("libc.musl"))
    }

    // The `$PLATFORM` token value. Only the arches v1 targets are named; anything
    // else falls back to an empty string rather than guessing wrong.
    fn platform(&self) -> &'static str {
        match self.machine {
            goblin::elf::header::EM_X86_64 => "x86_64",
            goblin::elf::header::EM_AARCH64 => "aarch64",
            _ => "",
        }
    }
}

/// Reject binaries Scratchsmith cannot correctly pack at v1. musl is fundamentally
/// different (loader path, no NSS module system), so it is hard-failed loudly rather
/// than packed into a subtly broken image.
pub fn ensure_glibc(info: &ElfInfo) -> Result<()> {
    if info.is_musl() {
        bail!(
            "musl binaries are out of scope; v1 targets glibc (interpreter: {})",
            escape_if_line_breaking(info.interpreter.as_deref().unwrap_or_default())
        );
    }
    Ok(())
}

/// Read an ELF file and extract its dynamic-linking facts.
pub fn read_elf_info(path: &Path) -> Result<ElfInfo> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    parse_elf_info(&bytes).with_context(|| format!("parsing {} as ELF", path.display()))
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
    /// locations for the arches v1 targets; non-existent dirs are simply skipped.
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
    /// Inputs the resolver tolerated and scratchsmith 2.0 will reject, one line each. The
    /// resolution itself is unchanged by them; callers print them with
    /// `warn_about_tolerances`.
    pub warnings: Vec<String>,
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

    /// Print each tolerance warning as one stderr line, never stdout: stdout carries the
    /// `--format json` report (`COMPATIBILITY.md`). The exit code stays where it is.
    pub fn warn_about_tolerances(&self) {
        for w in &self.warnings {
            eprintln!(
                "warning: {w} scratchsmith 2.0 rejects it. See {}",
                crate::image::DEPRECATIONS_URL
            );
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
    /// - `Ok(None)` — the file was read, and it does not parse as an ELF. For a data file the
    ///   operator named with `--include` that is correct: it has no `DT_NEEDED` of its own, so
    ///   it is a leaf. A truncated or corrupt ELF lands here too and is kept as a leaf until
    ///   2.0; `resolve_with` tells the two apart by the magic bytes and warns about the second.
    ///   A file without the magic, reached through a name out of an ELF, fails the resolution.
    /// - `Err` — the file could not be READ. Nothing is known about its dependencies, so
    ///   treating it as a leaf would drop its whole subtree from the resolution without
    ///   anything landing in `Resolution::missing`.
    fn read(&self, path: &Path) -> Result<Option<ElfInfo>>;
}

/// The production source: parse the real file with goblin.
pub struct GoblinSource;

impl LinkInfoSource for GoblinSource {
    fn read(&self, path: &Path) -> Result<Option<ElfInfo>> {
        // The IO error propagates; a PARSE failure stays a leaf, exactly as before.
        //
        // That includes a truncated or corrupt `.so`, which loses its DT_NEEDED subtree.
        // Failing on it would refuse to pack a graph that packs today: such a file survives
        // the stager's copy, the hardening lint returns Option, and only `--strip` rejects it.
        // That is "tighten validation", so it waits for 2.0, and `resolve_with` warns until
        // then.
        let bytes = read_bounded(path, DEVICE_READ_CAP)?;
        Ok(parse_elf_info(&bytes).ok())
    }
}

// The most read from a character or block device. No real library is one, but the packed ELF
// picks the path (a DT_NEEDED with a slash, or a search dir plus a soname), and `/dev/zero`
// never ends.
const DEVICE_READ_CAP: u64 = 256 << 20;

// Read a whole file, as `std::fs::read` does, with the stop chosen by fstat on the open handle.
// A device stops one byte past `device_cap` and fails. A regular file may read past the length
// it reported, because a procfs file reports 0 and still has content, but not past
// `device_cap` too: a tracefs pipe is a regular file of length 0 that never ends. A FIFO or
// pipe reads to EOF as before: it ends when its writer closes, and an operator can pipe in a
// real library (`--include <(cat lib.so)`). Only the operator names one: `resolve_with`
// refuses a FIFO that a name out of an ELF resolves to, and PT_INTERP must be a regular file.
fn read_bounded(path: &Path, device_cap: u64) -> Result<Vec<u8>> {
    use std::io::Read;
    use std::os::unix::fs::FileTypeExt;

    let reading = || format!("reading {}", path.display());
    // A blocking open, as before: a FIFO's open waits for a writer that starts late.
    let mut file = std::fs::File::open(path).with_context(reading)?;
    let meta = file.metadata().with_context(reading)?;
    let kind = meta.file_type();
    let mut bytes = Vec::new();
    if kind.is_file() {
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
    } else if kind.is_char_device() || kind.is_block_device() {
        // Its size is no length to reserve: grow as bytes arrive.
        file.take(device_cap.saturating_add(1))
            .read_to_end(&mut bytes)
            .with_context(reading)?;
        if bytes.len() as u64 > device_cap {
            bail!(
                "{} is a device that yields more than {device_cap} bytes, so it is not read \
                 as an ELF",
                printable(path)
            );
        }
    } else {
        file.read_to_end(&mut bytes).with_context(reading)?;
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
        .read(&root_path)?
        .ok_or_else(|| anyhow::anyhow!("{} is not a valid ELF binary", root_path.display()))?;
    // Treat --include entries as extra direct dependencies of the binary, so they and
    // their own transitive deps are resolved and staged like anything else. They go after
    // the binary's own DT_NEEDED, so the count of those tells the two apart below.
    let declared_needed = root_info.needed.len();
    root_info.needed.extend(includes.iter().cloned());

    let mut resolution = Resolution::default();

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
            match source.read(&loader)? {
                Some(info)
                    if info.e_type != goblin::elf::header::ET_DYN
                        && info.e_type != goblin::elf::header::ET_EXEC =>
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
                Some(_) => {}
                None => resolution.warnings.push(format!(
                    "the program interpreter (PT_INTERP) {} starts like an ELF and cannot be \
                     parsed (truncated or corrupt), so the image cannot start.",
                    printable(&canonical(&loader))
                )),
            }
            resolution.interpreter = Some(ResolvedInterp {
                image_path: PathBuf::from(interp),
                source: canonical(&loader),
            });
        } else {
            resolution.missing.push(interp.clone());
        }
    }

    // Breadth-first walk. Each item carries the transitive RPATH dirs contributed
    // by its ancestors — RPATH is inherited down the tree, RUNPATH is not.
    let mut visited = HashSet::new();
    visited.insert(root_path.clone());
    let mut queue = VecDeque::new();
    // The last field counts the leading `needed` entries the ELF itself declared. Only the
    // binary carries more: its --include entries.
    queue.push_back((
        root_path,
        root_info.clone(),
        Vec::<PathBuf>::new(),
        declared_needed,
    ));

    while let Some((obj_path, obj, inherited_rpaths, declared)) = queue.pop_front() {
        let obj_dir = obj_path.parent().unwrap_or(Path::new("/"));

        // One glibc rule, read twice below: an object that declares RUNPATH searches NO
        // RPATH for its own lookups, neither its own nor one inherited from an ancestor
        // (`_dl_map_object`: "when the object has the RUNPATH information we don't use any
        // RPATHs").
        let searches_rpath = obj.runpaths.is_empty();
        let used_rpaths: &[String] = if searches_rpath { &obj.rpaths } else { &[] };
        // `$PLATFORM` has no value here, so the entry is searched with the token gone and a
        // same-named file in that other directory can stage in place of the arch-specific
        // one. Warn only where a search can use the entry. A soname with a slash is a path
        // and skips the search list, so a RUNPATH entry needs a bare soname on this object.
        // An RPATH entry is also handed to every child, so any DT_NEEDED at all is enough.
        if root_info.platform().is_empty() {
            let bare_soname = obj.needed.iter().any(|n| !n.contains('/'));
            let rpaths = used_rpaths.iter().filter(|_| !obj.needed.is_empty());
            let runpaths = obj.runpaths.iter().filter(|_| bare_soname);
            for entry in rpaths.chain(runpaths) {
                if entry.contains("$PLATFORM") || entry.contains("${PLATFORM}") {
                    push_unique(
                        &mut resolution.warnings,
                        format!(
                            "`$PLATFORM` has no value for this architecture ({}), so the \
                             search path `{}` in {} was searched as `{}` and a library from \
                             the wrong directory can ship.",
                            goblin::elf::header::machine_to_str(root_info.machine),
                            entry.escape_debug(),
                            printable(&obj_path),
                            expand_tokens(entry, obj_dir, &root_info).escape_debug()
                        ),
                    );
                }
            }
        }
        let own_rpaths = build_dirs(used_rpaths, obj_dir, &sysroot.root, &root_info);
        let runpath_dirs = build_dirs(&obj.runpaths, obj_dir, &sysroot.root, &root_info);

        // Search order: RPATH (own, then ancestors' — transitive) -> RUNPATH (this
        // object only) -> default dirs. LD_LIBRARY_PATH is deliberately omitted, and so is
        // the host's /etc/ld.so.cache: resolution never trusts the host's loader state.
        let mut search: Vec<PathBuf> = Vec::new();
        search.extend(own_rpaths.iter().cloned());
        if searches_rpath {
            search.extend(inherited_rpaths.iter().cloned());
        }
        search.extend(runpath_dirs);
        search.extend(sysroot.default_dirs.iter().cloned());
        // The search this resolver ran before it learned that rule: inherited RPATH always.
        // It is the fallback below, so a pack that only worked through it keeps working
        // until 2.0, with a warning.
        let tolerated: &[PathBuf] = if searches_rpath {
            &[]
        } else {
            &inherited_rpaths
        };

        // Children inherit the RPATH view this object searched (own + ancestors'), never its
        // RUNPATH — that is the "RUNPATH is not inherited" rule. An object with RUNPATH
        // still passes its ANCESTORS' RPATH on. Its OWN RPATH, if it carries both tags, is
        // not passed on, and glibc agrees. `elf_get_dynamic_info` (elf/get-dynamic-info.h):
        // "If both RUNPATH and RPATH are given, the latter is ignored", and it clears the
        // DT_RPATH entry there, so no later ancestor walk sees it. Measured on glibc 2.41.
        let mut child_rpaths = own_rpaths;
        child_rpaths.extend(inherited_rpaths.iter().cloned());

        for (i, soname) in obj.needed.iter().enumerate() {
            let faithful = find_lib(soname, &search, obj_dir, &sysroot.root);
            // The loader does not search here for this object: the file sits only in an RPATH
            // directory of a parent, and this object has RUNPATH. Whether the program starts
            // on the host depends on the host's ld.so.cache, which is not read here, so the
            // warning states the search rule and no more.
            let found = faithful.or_else(|| {
                let found = find_lib(soname, tolerated, obj_dir, &sysroot.root)?;
                // A parent can list a soname twice; say it once.
                push_unique(
                    &mut resolution.warnings,
                    format!(
                        "{} needs `{}`, and it was found only at {} through an RPATH \
                         inherited from a parent. {0} has RUNPATH, so the loader does not \
                         search an inherited RPATH for it, and that copy is not the one \
                         the loader uses.",
                        printable(&obj_path),
                        soname.escape_debug(),
                        printable(&found)
                    ),
                );
                Some(found)
            });
            let Some(found) = found else {
                push_unique(&mut resolution.missing, soname.clone());
                resolution.edges.push(DepEdge {
                    from: obj_path.clone(),
                    soname: soname.clone(),
                    to: None,
                });
                continue;
            };
            let real = canonical(&found);
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
            // A resolved file that will not PARSE (an --include'd data file, or a corrupt ELF)
            // is kept as a leaf rather than aborting the whole resolution. A file that cannot
            // be READ is not: its own DT_NEEDED children are never queued, never resolved and
            // never staged, and they never reach `missing` either, because nothing asked for
            // them.
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
                    let declared = child.needed.len();
                    queue.push_back((real, child, child_rpaths.clone(), declared));
                }
                // Not a stray data file: it claims to be an ELF and will not parse, so its
                // own DT_NEEDED entries are unknown and nothing under it was resolved.
                None if has_elf_magic(&real) => resolution.warnings.push(format!(
                    "{} starts like an ELF and cannot be parsed (truncated or corrupt), so the \
                     libraries it needs were not resolved and can be absent from the image.",
                    printable(&real)
                )),
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

    Ok(resolution)
}

// Expand ld.so tokens in a search path against the object that owns it. `$ORIGIN`
// is the owning object's directory — not the top binary's — which is the whole
// point of the token; expanding it wrong is a classic staging bug.
fn expand_tokens(raw: &str, origin_dir: &Path, root: &ElfInfo) -> String {
    let origin = origin_dir.to_string_lossy();
    let lib = if root.is_64 { "lib64" } else { "lib" };
    raw.replace("${ORIGIN}", &origin)
        .replace("$ORIGIN", &origin)
        .replace("${LIB}", lib)
        .replace("$LIB", lib)
        .replace("${PLATFORM}", root.platform())
        .replace("$PLATFORM", root.platform())
}

// Turn raw RPATH/RUNPATH entries into concrete directories: expand tokens, root
// absolute paths inside the sysroot, and treat anything relative as origin-relative.
fn build_dirs(raw: &[String], origin_dir: &Path, root: &Path, root_info: &ElfInfo) -> Vec<PathBuf> {
    raw.iter()
        .map(|entry| {
            let expanded = expand_tokens(entry, origin_dir, root_info);
            let p = Path::new(&expanded);
            if p.is_absolute() {
                reroot(root, p)
            } else {
                origin_dir.join(p)
            }
        })
        .collect()
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
// which loses the corrupt-ELF warning and fails closed where a missing magic is an error. A
// 2.0 rejection of a file that HAS the magic must not gate on this: it would fail open.
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
            "musl binaries are out of scope; v1 targets glibc \
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

    #[test]
    fn a_corrupt_elf_that_reads_fine_stays_a_leaf() {
        // The other half: a file that READS fine and does not parse has no DT_NEEDED of its
        // own, so it is staged as a leaf and the resolution continues.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let (exe, mid, _leaf, mut infos) = chain_fixture(root);
        // Drop libmid's scripted info: MapSource returns Ok(None) for it. `touch` wrote the
        // ELF magic, so this is the corrupt-ELF leaf; a file without the magic fails instead
        // (see the next test).
        infos.remove(&canonical(&mid));

        let res = resolve_with(&exe, &Sysroot::new(root), &[], &MapSource { infos })
            .expect("a non-ELF leaf must not fail the resolution");
        assert!(has(&res, "libmid.so"), "the leaf itself must still stage");
        assert!(
            !has(&res, "libleaf.so"),
            "a leaf contributes no DT_NEEDED children"
        );
    }

    #[test]
    fn an_unparsable_elf_leaf_warns_and_a_data_file_fails() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let (exe, mid, _leaf, mut infos) = chain_fixture(root);
        // No scripted info for libmid, and `touch` wrote the ELF magic into it: an ELF by
        // its own claim that the source could not parse.
        infos.remove(&canonical(&mid));
        let src = MapSource { infos };

        let res = resolve_with(&exe, &Sysroot::new(root), &[], &src).unwrap();
        assert!(has(&res, "libmid.so"), "the tolerance keeps the leaf");
        assert_eq!(res.warnings.len(), 1, "{:?}", res.warnings);
        assert!(
            res.warnings[0].contains(&canonical(&mid).display().to_string()),
            "the warning must name the file: {:?}",
            res.warnings
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
        use goblin::elf::header::{ET_CORE, ET_EXEC};
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let (exe, mid, _leaf, base) = chain_fixture(root);
        for (e_type, what) in [
            (ET_CORE, "a core dump (ET_CORE)"),
            (ET_EXEC, "an executable (ET_EXEC)"),
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
    fn a_pt_interp_that_does_not_parse_warns() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let (exe, _mid, _leaf, mut infos) = chain_fixture(root);
        infos.remove(&canonical(&root.join("lib64/ld-linux-x86-64.so.2")));
        let res = resolve_with(&exe, &Sysroot::new(root), &[], &MapSource { infos }).unwrap();
        assert!(
            res.warnings
                .iter()
                .any(|w| w.contains("PT_INTERP") && w.contains("cannot be parsed")),
            "{:?}",
            res.warnings
        );
    }

    #[test]
    fn an_include_of_a_data_file_stays_a_quiet_leaf() {
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
        let src = MapSource { infos };

        for include in ["plugin.conf".to_string(), data.display().to_string()] {
            let res = resolve_with(
                &exe,
                &Sysroot::new(root),
                std::slice::from_ref(&include),
                &src,
            )
            .unwrap();
            assert!(has(&res, &include), "{include}: {:?}", res.libs);
            assert!(res.warnings.is_empty(), "{include}: {:?}", res.warnings);
        }
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
            eprintln!("skipping: mkfifo unavailable");
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
        assert!(res.missing.is_empty() && res.warnings.is_empty());
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
    fn goblin_source_keeps_an_unparsable_file_and_fails_an_unreadable_one() {
        let tmp = tempfile::tempdir().unwrap();
        let junk = tmp.path().join("libjunk.so");
        fs::write(&junk, b"\x7fELF then nothing an ELF parser accepts").unwrap();
        assert_eq!(GoblinSource.read(&junk).unwrap(), None);
        assert!(has_elf_magic(&junk));

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
        let infos = HashMap::from([(
            canonical(&exe),
            elf(&["/usr/lib/libfifo.so"], &[], &[], None),
        )]);
        let err = returns(move || resolve_err(&exe, &root, &[], &MapSource { infos }));
        assert!(
            err.contains("`/usr/lib/libfifo.so`") && err.contains("not a regular file"),
            "{err}"
        );
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
                    .contains("is a device that yields more than 65536 bytes"),
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
        // An ELF (this test binary), bigger than the pipe buffer and than any device cap here.
        let exe = fs::read(std::env::current_exe().unwrap()).unwrap();
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
        let exe = fs::read(std::env::current_exe().unwrap()).unwrap();
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
        // The device cap does not apply to a FIFO.
        let got = returns(move || read_bounded(&fifo, TEST_CAP).map_err(|e| e.to_string()));
        let got = got.unwrap();
        assert!(got == exe, "read {} of {} bytes", got.len(), exe.len());
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
    fn a_platform_token_warns_only_where_it_has_no_value() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let exe = root.join("app/exe");
        touch(&exe);
        let resolve_with_needed =
            |machine: u16, needed: &[&str], rpaths: &[&str], runpaths: &[&str]| {
                // One bare soname, so the object has a search to run. It need not resolve.
                let mut info = elf(needed, rpaths, runpaths, None);
                info.machine = machine;
                let infos = HashMap::from([(canonical(&exe), info)]);
                resolve_with(&exe, &Sysroot::new(root), &[], &MapSource { infos })
                    .unwrap()
                    .warnings
            };
        let resolve_as = |machine: u16, rpaths: &[&str], runpaths: &[&str]| {
            resolve_with_needed(machine, &["libx.so"], rpaths, runpaths)
        };
        let riscv = goblin::elf::header::EM_RISCV;

        let w = resolve_as(riscv, &[], &["/opt/$PLATFORM/lib", "/opt/plain"]);
        assert_eq!(w.len(), 1, "{w:?}");
        assert!(w[0].contains("`/opt/$PLATFORM/lib`"), "{w:?}");
        // It names the architecture and the directory that was searched in its place.
        assert!(
            w[0].contains("(RISCV)") && w[0].contains("as `/opt//lib`"),
            "{w:?}"
        );
        assert_eq!(resolve_as(riscv, &["/opt/${PLATFORM}"], &[]).len(), 1);

        // The entry is text from an untrusted binary. It must not reach the terminal raw.
        let w = resolve_as(riscv, &[], &["/opt/$PLATFORM\nwarning: forged\x1b[2J"]);
        assert!(!w[0].contains('\n') && !w[0].contains('\x1b'), "{w:?}");
        assert!(w[0].contains("\\nwarning: forged\\u{1b}[2J"), "{w:?}");

        // No bare soname means no search: nothing is needed, or the one entry is a path.
        let tokened = ["/opt/$PLATFORM/lib"];
        assert!(resolve_with_needed(riscv, &[], &[], &tokened).is_empty());
        assert!(resolve_with_needed(riscv, &["/abs/libx.so"], &[], &tokened).is_empty());
        // RPATH differs: a child inherits it, so one path-style entry is enough to warn.
        assert_eq!(
            resolve_with_needed(riscv, &["/abs/libx.so"], &tokened, &[]).len(),
            1
        );
        assert!(resolve_with_needed(riscv, &[], &tokened, &[]).is_empty());

        // A named architecture expands the token, so there is nothing to warn about.
        let x86 = goblin::elf::header::EM_X86_64;
        assert!(resolve_as(x86, &[], &["/opt/$PLATFORM/lib"]).is_empty());
        // glibc ignores RPATH when RUNPATH is set, so the token in it is never searched.
        assert!(resolve_as(riscv, &["/opt/$PLATFORM"], &["/opt/plain"]).is_empty());
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
        assert!(res.warnings.is_empty(), "{:?}", res.warnings);
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
        // start on the host. The pack keeps working until 2.0, and says so.
        let res = resolve(graph(&["/opt/elsewhere"])).unwrap();
        assert_eq!(leaf_path(&res), Some(canonical(&rpath_leaf)));
        assert!(res.missing.is_empty(), "{:?}", res.missing);
        assert_eq!(res.warnings.len(), 1, "{:?}", res.warnings);
        assert!(
            res.warnings[0].contains("`libleaf.so`") && res.warnings[0].contains("inherited"),
            "{:?}",
            res.warnings
        );

        // A second copy sits in a default directory. That is the one the loader uses, so it
        // is the one to stage: the old search staged the RPATH copy, a different file than
        // the program runs with on the host. Found the faithful way, so no warning.
        touch(&system_leaf);
        let res = resolve(graph(&["/opt/elsewhere"])).unwrap();
        assert_eq!(leaf_path(&res), Some(canonical(&system_leaf)));
        assert!(res.warnings.is_empty(), "{:?}", res.warnings);

        // Without RUNPATH on libmid the inherited RPATH is in force and comes first, as it
        // always did, with nothing to warn about.
        let res = resolve(graph(&[])).unwrap();
        assert_eq!(leaf_path(&res), Some(canonical(&rpath_leaf)));
        assert!(res.warnings.is_empty(), "{:?}", res.warnings);
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
