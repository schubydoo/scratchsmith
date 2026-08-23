//! Resolve a binary's shared-library deps by emulating the `ld.so` search order
//! (not by scraping host `ldd`). The correctness core; see Tasks 1.2-1.3.
//!
//! This file covers Task 1.2: read the raw dynamic-linking facts from an ELF. The
//! search-order emulation that turns sonames into real paths lands in Task 1.3.

use anyhow::{Context, Result};
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
/// RUNPATH is not inherited by a library's own dependencies (see Task 1.3).
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

/// Read an ELF file and extract its dynamic-linking facts.
pub fn read_elf_info(path: &Path) -> Result<ElfInfo> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    parse_elf_info(&bytes).with_context(|| format!("parsing {} as ELF", path.display()))
}

// Split from `read_elf_info` so parsing is unit-testable on in-memory bytes.
fn parse_elf_info(bytes: &[u8]) -> Result<ElfInfo> {
    let elf = goblin::elf::Elf::parse(bytes).context("not a valid ELF binary")?;
    Ok(ElfInfo {
        interpreter: elf.interpreter.map(str::to_owned),
        needed: elf.libraries.iter().map(|s| s.to_string()).collect(),
        rpaths: elf.rpaths.iter().map(|s| s.to_string()).collect(),
        runpaths: elf.runpaths.iter().map(|s| s.to_string()).collect(),
        soname: elf.soname.map(str::to_owned),
        is_64: elf.is_64,
        machine: elf.header.e_machine,
    })
}

// ---------------------------------------------------------------------------
// Task 1.3: emulate the ld.so search order.
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

/// The closed set of what a binary needs at runtime.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Resolution {
    /// The dynamic loader (`PT_INTERP`), rerooted into the sysroot. `None` only for
    /// a static binary or when the loader is absent from the sysroot.
    pub interpreter: Option<PathBuf>,
    /// Every transitive shared library, deduplicated by real path.
    pub libs: Vec<ResolvedLib>,
    /// Sonames that could not be located. Non-empty means the image would be broken,
    /// so callers must fail loudly rather than ship it.
    pub missing: Vec<String>,
}

/// Supplies the dynamic-linking facts for a file. Abstracted so the search order
/// can be tested against scripted dependency graphs without building real ELFs.
pub trait LinkInfoSource {
    fn read(&self, path: &Path) -> Result<ElfInfo>;
}

/// The production source: parse the real file with goblin.
pub struct GoblinSource;

impl LinkInfoSource for GoblinSource {
    fn read(&self, path: &Path) -> Result<ElfInfo> {
        read_elf_info(path)
    }
}

/// Resolve a binary's transitive dependencies against a sysroot, using goblin.
pub fn resolve(binary: &Path, sysroot: &Sysroot) -> Result<Resolution> {
    resolve_with(binary, sysroot, &GoblinSource)
}

/// Resolve using an explicit link-info source (the testable entry point).
pub fn resolve_with(
    binary: &Path,
    sysroot: &Sysroot,
    source: &dyn LinkInfoSource,
) -> Result<Resolution> {
    let root_path =
        std::fs::canonicalize(binary).with_context(|| format!("locating {}", binary.display()))?;
    let root_info = source.read(&root_path)?;

    let mut resolution = Resolution::default();

    // The loader is named by PT_INTERP, not DT_NEEDED, so resolve it separately.
    if let Some(interp) = &root_info.interpreter {
        let path = reroot(&sysroot.root, Path::new(interp));
        if path.exists() {
            resolution.interpreter = Some(canonical(&path));
        } else {
            resolution.missing.push(interp.clone());
        }
    }

    // Breadth-first walk. Each item carries the transitive RPATH dirs contributed
    // by its ancestors — RPATH is inherited down the tree, RUNPATH is not.
    let mut visited = HashSet::new();
    visited.insert(root_path.clone());
    let mut queue = VecDeque::new();
    queue.push_back((root_path, root_info.clone(), Vec::<PathBuf>::new()));

    while let Some((obj_path, obj, inherited_rpaths)) = queue.pop_front() {
        let obj_dir = obj_path.parent().unwrap_or(Path::new("/"));

        // An object's own RPATH is ignored when it also declares RUNPATH (glibc rule).
        let own_rpaths: Vec<PathBuf> = if obj.runpaths.is_empty() {
            build_dirs(&obj.rpaths, obj_dir, &sysroot.root, &root_info)
        } else {
            Vec::new()
        };
        let runpath_dirs = build_dirs(&obj.runpaths, obj_dir, &sysroot.root, &root_info);

        // Search order: RPATH (own, then ancestors' — transitive) -> RUNPATH (this
        // object only) -> default dirs. LD_LIBRARY_PATH is deliberately omitted.
        let mut search: Vec<PathBuf> = Vec::new();
        search.extend(own_rpaths.iter().cloned());
        search.extend(inherited_rpaths.iter().cloned());
        search.extend(runpath_dirs);
        search.extend(sysroot.default_dirs.iter().cloned());

        // Children inherit this object's full RPATH view (own + ancestors'), never
        // its RUNPATH — that is exactly the "RUNPATH is not inherited" rule.
        let mut child_rpaths = own_rpaths;
        child_rpaths.extend(inherited_rpaths);

        for soname in &obj.needed {
            let Some(found) = find_lib(soname, &search, obj_dir, &sysroot.root) else {
                push_unique(&mut resolution.missing, soname.clone());
                continue;
            };
            let real = canonical(&found);
            if !visited.insert(real.clone()) {
                continue;
            }
            resolution.libs.push(ResolvedLib {
                soname: soname.clone(),
                path: real.clone(),
            });
            // A resolved file that will not parse (e.g. a stray data file) is kept
            // as a leaf rather than aborting the whole resolution.
            if let Ok(child) = source.read(&real) {
                queue.push_back((real, child, child_rpaths.clone()));
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

// Best-effort real path; falls back to the input if canonicalization fails so a
// transient error never silently drops a dependency.
fn canonical(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

fn push_unique(v: &mut Vec<String>, item: String) {
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

    // --- Task 1.3: ld.so search-order emulation --------------------------------
    // These drive the search logic through a scripted dependency graph so we can
    // exercise RPATH/RUNPATH/$ORIGIN precisely without building real ELF files.

    use std::collections::HashMap;
    use std::fs;

    struct MapSource {
        infos: HashMap<PathBuf, ElfInfo>,
    }

    impl LinkInfoSource for MapSource {
        fn read(&self, path: &Path) -> Result<ElfInfo> {
            let key = canonical(path);
            self.infos
                .get(&key)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("no scripted info for {}", key.display()))
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
        }
    }

    fn touch(path: &Path) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, b"\x7fELF-ish").unwrap();
    }

    fn has(res: &Resolution, soname: &str) -> bool {
        res.libs.iter().any(|l| l.soname == soname)
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
        let res = resolve_with(&exe, &sysroot, &MapSource { infos }).unwrap();
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
        let res = resolve_with(&exe, &sysroot, &MapSource { infos }).unwrap();
        assert!(has(&res, "libmid.so"), "runpath resolves the direct dep");
        assert!(
            res.missing.contains(&"libleaf.so".to_string()),
            "runpath must not be inherited by children"
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
        let res = resolve_with(&exe, &Sysroot::new(root), &MapSource { infos }).unwrap();
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
        let res = resolve_with(&exe, &Sysroot::new(root), &MapSource { infos }).unwrap();
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
        let res = resolve_with(&exe, &Sysroot::new(root), &MapSource { infos }).unwrap();
        assert!(res.missing.is_empty(), "{:?}", res.missing);
        let count = res
            .libs
            .iter()
            .filter(|l| l.soname == "libc_shared.so")
            .count();
        assert_eq!(count, 1, "shared dep must appear once, got {count}");
    }

    #[test]
    fn missing_dependency_is_reported_not_fatal() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let exe = root.join("bin/exe");
        touch(&exe);
        let mut infos = HashMap::new();
        infos.insert(canonical(&exe), elf(&["libghost.so"], &[], &[], None));
        let res = resolve_with(&exe, &Sysroot::new(root), &MapSource { infos }).unwrap();
        assert_eq!(res.missing, vec!["libghost.so".to_string()]);
    }
}
