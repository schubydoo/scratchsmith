#![no_main]
//! Fuzz the ld.so-faithful resolution engine (`resolve_with`): RPATH/RUNPATH/$ORIGIN token
//! expansion, the search-order BFS (RPATH is inherited, RUNPATH is not), and soname lookup.
//! `parse_elf_info` only reaches the parse surface; the resolution core needs a filesystem and a
//! link-info source, so this harness scripts a dependency graph over a throwaway sysroot (mirroring
//! the resolver's own unit tests) and asserts it never panics on an adversarial graph.

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use scratchsmith::resolver::{resolve_with, ElfInfo, LinkInfoSource, Sysroot};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

// The dynamic-linking facts the fuzzer controls for one object. Strings stay arbitrary — they drive
// token expansion and soname lookup, and are only ever read, never used to create files.
#[derive(Arbitrary, Debug)]
struct Facts {
    interpreter: Option<String>,
    needed: Vec<String>,
    rpaths: Vec<String>,
    runpaths: Vec<String>,
    soname: Option<String>,
    is_64: bool,
    machine: u16,
}

impl Facts {
    fn into_elf(self) -> ElfInfo {
        // Cap the string vectors so one object can't blow up the search into a slow unit.
        let cap = |v: Vec<String>| v.into_iter().take(32).collect();
        ElfInfo {
            interpreter: self.interpreter,
            needed: cap(self.needed),
            rpaths: cap(self.rpaths),
            runpaths: cap(self.runpaths),
            soname: self.soname,
            is_64: self.is_64,
            machine: self.machine,
            uses_dlopen: false,
        }
    }
}

// A library that actually exists in the sysroot, so the search can find it.
#[derive(Arbitrary, Debug)]
struct Lib {
    name: String,
    dir: LibDir,
    facts: Facts,
}

// The buckets a real file may sit in: a couple of Sysroot default dirs plus the binary's own
// $ORIGIN tree, so RPATH/$ORIGIN lookups have something to hit.
#[derive(Arbitrary, Debug)]
enum LibDir {
    Lib64,
    UsrLib,
    LibGnu,
    AppLibs,
}

#[derive(Arbitrary, Debug)]
struct Scenario {
    root: Facts,
    libs: Vec<Lib>,
    includes: Vec<String>,
    // Place a real loader file so the interpreter branch resolves instead of only ever missing.
    place_interp: bool,
}

// A fixed, safe interpreter path used when `place_interp` is set — resolution reroots it under the
// sysroot and checks existence, so a controlled path lets us exercise the "loader found" branch.
const INTERP: &str = "/lib64/ld-fuzz.so.2";

// An in-memory link-info source, keyed exactly as the resolver looks up (canonical real path).
struct MapSource(HashMap<PathBuf, ElfInfo>);

impl LinkInfoSource for MapSource {
    fn read(&self, path: &Path) -> anyhow::Result<ElfInfo> {
        self.0
            .get(&canonical(path))
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("no scripted info for {}", path.display()))
    }
}

// Mirror the resolver's own best-effort canonicalization so map keys match its lookups.
fn canonical(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

// Reduce a fuzzer string to one safe filename component, or reject it. Keeps every created file
// strictly inside the throwaway sysroot — no '/', '..', empty, or overlong names.
fn safe_name(raw: &str) -> Option<String> {
    let ok = !raw.is_empty()
        && raw.len() <= 64
        && raw != "."
        && raw != ".."
        && raw
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_');
    ok.then(|| raw.to_string())
}

fn touch(path: &Path) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, b"\x7fELF")
}

fuzz_target!(|scn: Scenario| {
    let Ok(tmp) = tempfile::tempdir() else {
        return;
    };
    let root = tmp.path();

    // The binary under resolution, at a fixed $ORIGIN.
    let exe = root.join("app/exe");
    if touch(&exe).is_err() {
        return;
    }

    let mut root_facts = scn.root;
    // Optionally give the binary a real, resolvable loader.
    if scn.place_interp {
        root_facts.interpreter = Some(INTERP.to_string());
        let _ = touch(&root.join("lib64/ld-fuzz.so.2")); // reroot(INTERP) lands here
    }

    let mut infos: HashMap<PathBuf, ElfInfo> = HashMap::new();
    infos.insert(canonical(&exe), root_facts.into_elf());

    // Materialise a bounded number of libraries as real files, each mapped to its facts.
    for lib in scn.libs.into_iter().take(24) {
        let Some(name) = safe_name(&lib.name) else {
            continue;
        };
        let sub = match lib.dir {
            LibDir::Lib64 => "lib64",
            LibDir::UsrLib => "usr/lib",
            LibDir::LibGnu => "lib/x86_64-linux-gnu",
            LibDir::AppLibs => "app/libs",
        };
        let path = root.join(sub).join(&name);
        if touch(&path).is_err() {
            continue;
        }
        infos.insert(canonical(&path), lib.facts.into_elf());
    }

    let sysroot = Sysroot::new(root);
    let includes: Vec<String> = scn.includes.into_iter().take(8).collect();
    let _ = resolve_with(&exe, &sysroot, &includes, &MapSource(infos));
});
