//! Differential pack-and-run test for musl: musl's own loader is the oracle for every case.
//!
//! The Alpine CI job checks scratchsmith against musl on real Alpine programs, and those almost
//! never use the musl rules that differ from glibc's. This test builds random layouts with
//! `musl-gcc` that reach them on purpose (docs/architecture.md, "The musl backend"):
//!
//! - RPATH and RUNPATH alike are inherited by every dependency below the object that sets them;
//! - a search path holding a `$` token other than `$ORIGIN` is dropped whole;
//! - `DT_SONAME` is never read, so a library whose soname differs is still found by file name;
//! - a name that matches an object already loaded needs no search;
//! - a libc alias (`libpthread.so.0`, `libm.so`, ...) is the loader itself, found with no search;
//! - a library reached through a directory link, or a file link into another directory.
//!
//! musl's system path comes from the host's `/etc/ld-musl-<arch>.path`, which a test must not
//! touch, so the layouts never rely on it. For every case:
//!
//! - `pack` exits 0 or 1, and `graph` agrees with it on success;
//! - `pack` succeeds exactly when the host's musl loader runs the program;
//! - when it does, `graph` resolves exactly the files that `ld-musl --list` maps;
//! - the packed rootfs runs the program with exit 0 (in a chroot inside an unprivileged user
//!   namespace, so neither Docker nor root is needed).
//!
//! `SCRATCHSMITH_DIFF_SEED` picks the first seed and `SCRATCHSMITH_DIFF_CASES` the number of
//! cases, as in `tests/differential.rs`. A failure prints the seed of its case, which repeats it
//! alone with CASES=1.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

mod common;
use common::differential::{chroot_available, env_u64, in_rootfs, run, text, Rng};
use common::skip_required;

const DEFAULT_SEED: u64 = 0x5eed_3000;
// About 140 ms a case. The nightly `differential` workflow runs thousands from a fresh seed.
const DEFAULT_CASES: u64 = 64;
const LOADER: &str = "/lib/ld-musl-x86_64.so.1";

#[derive(Clone, Copy, Debug)]
enum Name {
    // libX.so.1
    LibVersioned,
    // libX.so
    LibPlain,
    // X.so
    Bare,
    // libX.so.1.0.0 with the link libX.so.1 beside it.
    LinkChain,
    // The real file in `real/`, and a link to it at libX.so.1 in the library's directory.
    LinkElsewhere,
}

#[derive(Clone, Copy, Debug)]
enum Soname {
    Match,
    Absent,
    // DT_SONAME differs from the NEEDED name. musl never reads it, so the file still loads.
    Differs,
}

// Directories under the case root. `bin` holds the program, `real` the targets of
// `LinkElsewhere` links, and `ln` is a link to `lib/sub`.
const DIRS: &[&str] = &[
    "bin",
    "lib",
    "lib/sub",
    "x:y",
    "deps/a",
    "opt/lib64",
    "real",
];
const LIB_DIRS: &[&str] = &["lib", "lib/sub", "x:y", "deps/a", "opt/lib64"];
const DIR_LINK: &str = "ln";
const DIR_LINK_TARGET: &str = "lib/sub";

// Names musl maps to its own libc, so the loader, with no search.
const LIBC_ALIASES: &[&str] = &[
    "libpthread.so.0",
    "libm.so",
    "libdl.so.2",
    "librt.so.1",
    "libc.musl-x86_64.so.1",
];

#[derive(Debug)]
struct Lib {
    index: usize,
    name: Name,
    soname: Soname,
    dir: &'static str,
    // None: the program needs it. Some(j): library j needs it.
    parent: Option<usize>,
    // A second needer with no search entry for it: Some(0) is the program, Some(j + 1) library j.
    also: Option<usize>,
}

impl Lib {
    fn stem(&self) -> String {
        match self.name {
            Name::Bare => format!("ssmusl{}", self.index),
            _ => format!("libssmusl{}", self.index),
        }
    }
    fn needed(&self) -> String {
        match self.name {
            Name::LibVersioned | Name::LinkChain | Name::LinkElsewhere => {
                format!("{}.so.1", self.stem())
            }
            Name::LibPlain | Name::Bare => format!("{}.so", self.stem()),
        }
    }
    // Where the real file is, relative to the case root.
    fn file(&self) -> String {
        match self.name {
            Name::LinkChain => format!("{}/{}.so.1.0.0", self.dir, self.stem()),
            Name::LinkElsewhere => format!("real/{}.so.1.0.0", self.stem()),
            _ => format!("{}/{}", self.dir, self.needed()),
        }
    }
    fn value(&self) -> u64 {
        self.index as u64 + 1
    }
}

#[derive(Clone, Copy, Debug)]
enum Tags {
    Rpath,
    Runpath,
}

impl Tags {
    fn flag(self) -> &'static str {
        match self {
            Tags::Rpath => "-Wl,--disable-new-dtags",
            Tags::Runpath => "-Wl,--enable-new-dtags",
        }
    }
}

#[derive(Debug)]
struct Layout {
    libs: Vec<Lib>,
    // Search-path entries and dtags per object: index 0 is the program, i + 1 is library i.
    paths: Vec<Vec<String>>,
    tags: Vec<Tags>,
    // A libc alias per object, or None.
    aliases: Vec<Option<&'static str>>,
}

fn dir_of(layout: &Layout, object: usize) -> &'static str {
    if object == 0 {
        "bin"
    } else {
        layout.libs[object - 1].dir
    }
}

// A search-path entry from `from` to `to`, both relative to `root`. `lib/sub` is sometimes
// named through the directory link.
fn entry(rng: &mut Rng, root: &Path, from: &str, to: &str) -> String {
    let to = if to == DIR_LINK_TARGET && rng.chance(40) {
        DIR_LINK
    } else {
        to
    };
    if rng.chance(25) {
        return root.join(to).display().to_string();
    }
    let up = "../".repeat(from.split('/').count());
    let origin = if rng.chance(20) {
        "${ORIGIN}"
    } else {
        "$ORIGIN"
    };
    if from == to {
        origin.to_string()
    } else {
        format!("{origin}/{up}{to}")
    }
}

fn generate(rng: &mut Rng, root: &Path) -> Layout {
    let count = 1 + rng.below(3);
    let names = [
        Name::LibVersioned,
        Name::LibPlain,
        Name::Bare,
        Name::LinkChain,
        Name::LinkElsewhere,
    ];
    let mut libs = Vec::new();
    for index in 0..count {
        let soname = match rng.below(10) {
            0..=4 => Soname::Match,
            5 | 6 => Soname::Absent,
            _ => Soname::Differs,
        };
        libs.push(Lib {
            index,
            name: rng.pick(&names),
            soname,
            dir: rng.pick(LIB_DIRS),
            parent: if index == 0 || rng.chance(40) {
                None
            } else {
                Some(rng.below(index))
            },
            also: None,
        });
    }
    let objects = count + 1;
    let tags = (0..objects)
        .map(|_| {
            if rng.chance(50) {
                Tags::Rpath
            } else {
                Tags::Runpath
            }
        })
        .collect();
    let mut layout = Layout {
        libs,
        paths: vec![Vec::new(); objects],
        tags,
        aliases: vec![None; objects],
    };
    for i in 0..count {
        let needer = layout.libs[i].parent.map_or(0, |p| p + 1);
        // Usually the needer names the directory. Often an ancestor does, which musl
        // inherits for RUNPATH as for RPATH. Sometimes nobody does.
        let holder = match rng.below(10) {
            0..=5 => needer,
            6..=8 => ancestor(&layout, needer, rng),
            _ => continue,
        };
        let from = dir_of(&layout, holder);
        let e = entry(rng, root, from, layout.libs[i].dir);
        layout.paths[holder].push(e);
    }
    for paths in &mut layout.paths {
        if rng.chance(20) {
            let at = rng.below(paths.len() + 1);
            paths.insert(at, "/opt/ssmusl-none".to_string());
        }
        // musl drops the whole search path of an object that holds any other `$` token.
        if rng.chance(12) {
            let at = rng.below(paths.len() + 1);
            paths.insert(at, "/opt/$LIB".to_string());
        }
    }
    for alias in &mut layout.aliases {
        if rng.chance(15) {
            *alias = Some(rng.pick(LIBC_ALIASES));
        }
    }
    // A second needer with no search entry: musl finds the library only because it is
    // already loaded under that name.
    for (i, lib) in layout.libs.iter_mut().enumerate().skip(1) {
        if rng.chance(30) {
            let pick = rng.below(i + 1);
            if pick != lib.parent.map_or(0, |p| p + 1) {
                lib.also = Some(pick);
            }
        }
    }
    layout
}

// An object above `object` in the needer chain (itself included), picked at random.
fn ancestor(layout: &Layout, object: usize, rng: &mut Rng) -> usize {
    let mut chain = vec![object];
    let mut at = object;
    while at != 0 {
        at = layout.libs[at - 1].parent.map_or(0, |p| p + 1);
        chain.push(at);
    }
    rng.pick(&chain)
}

fn needs(lib: &Lib, object: usize) -> bool {
    lib.parent.map_or(0, |p| p + 1) == object || lib.also == Some(object)
}

fn total(layout: &Layout, object: usize) -> u64 {
    let own = if object == 0 {
        0
    } else {
        layout.libs[object - 1].value()
    };
    let children: u64 = layout
        .libs
        .iter()
        .filter(|l| needs(l, object))
        .map(|l| total(layout, l.index + 1))
        .sum();
    own + children
}

fn musl_gcc(args: &[String]) {
    let out = Command::new("musl-gcc")
        .args(args)
        .output()
        .expect("run musl-gcc");
    assert!(
        out.status.success(),
        "musl-gcc {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn s(p: &Path) -> String {
    p.display().to_string()
}

fn source(layout: &Layout, object: usize) -> String {
    let children: Vec<&Lib> = layout.libs.iter().filter(|l| needs(l, object)).collect();
    let mut src = String::new();
    for c in &children {
        writeln!(src, "extern int f{}(void);", c.index).unwrap();
    }
    let sum: String = children
        .iter()
        .map(|c| format!(" + f{}()", c.index))
        .collect();
    if object == 0 {
        let expect = total(layout, 0);
        writeln!(
            src,
            "int main(void){{ return (0{sum}) == {expect} ? 0 : 3; }}"
        )
        .unwrap();
    } else {
        let own = layout.libs[object - 1].value();
        writeln!(src, "int f{}(void){{ return {own}{sum}; }}", object - 1).unwrap();
    }
    src
}

// Link flags for `object`: each child through its own directory (or the stub that carries the
// NEEDED name when the soname differs), the libc alias through its stub, then the dtags and
// the search path.
fn link_args(layout: &Layout, object: usize, root: &Path) -> Vec<String> {
    let mut args = Vec::new();
    for c in &layout.libs {
        if !needs(c, object) {
            continue;
        }
        let dir = match c.soname {
            Soname::Differs => root.join("stub").join(c.index.to_string()),
            _ => root.join(c.dir),
        };
        args.push(format!("-L{}", s(&dir)));
        args.push(format!("-l:{}", c.needed()));
    }
    if let Some(alias) = layout.aliases[object] {
        // --no-as-needed keeps the NEEDED entry although nothing is used from it.
        args.push(format!("-L{}", s(&root.join("stub/libc"))));
        args.push("-Wl,--no-as-needed".to_string());
        args.push(format!("-l:{alias}"));
        args.push("-Wl,--as-needed".to_string());
    }
    args.push(layout.tags[object].flag().to_string());
    for e in &layout.paths[object] {
        args.push(format!("-Wl,-rpath,{e}"));
    }
    args
}

// An empty shared object at `path` whose soname is `soname`: it gives the linker a NEEDED name.
fn stub(path: &Path, soname: &str, src: &Path) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    musl_gcc(&[
        "-shared".to_string(),
        "-fPIC".to_string(),
        format!("-Wl,-soname,{soname}"),
        "-o".to_string(),
        s(path),
        s(src),
    ]);
}

fn build(layout: &Layout, root: &Path) -> PathBuf {
    for dir in DIRS {
        std::fs::create_dir_all(root.join(dir)).unwrap();
    }
    std::os::unix::fs::symlink(DIR_LINK_TARGET, root.join(DIR_LINK)).unwrap();
    let empty = root.join("empty.c");
    std::fs::write(&empty, "int ssmusl_stub;\n").unwrap();
    for alias in layout.aliases.iter().flatten() {
        let at = root.join("stub/libc").join(alias);
        if !at.exists() {
            stub(&at, alias, &empty);
        }
    }
    // Children before parents: a child always has a higher index than its library parent.
    for lib in layout.libs.iter().rev() {
        let object = lib.index + 1;
        let src = root.join(format!("f{}.c", lib.index));
        std::fs::write(&src, source(layout, object)).unwrap();
        let mut args = vec!["-shared".to_string(), "-fPIC".to_string()];
        match lib.soname {
            Soname::Match => args.push(format!("-Wl,-soname,{}", lib.needed())),
            Soname::Absent => {}
            Soname::Differs => args.push(format!("-Wl,-soname,libssmother{}.so.9", lib.index)),
        }
        args.extend(["-o".to_string(), s(&root.join(lib.file())), s(&src)]);
        args.extend(link_args(layout, object, root));
        musl_gcc(&args);
        let link = root.join(lib.dir).join(lib.needed());
        match lib.name {
            Name::LinkChain => {
                std::os::unix::fs::symlink(format!("{}.so.1.0.0", lib.stem()), &link).unwrap();
            }
            Name::LinkElsewhere => {
                let up = "../".repeat(lib.dir.split('/').count());
                std::os::unix::fs::symlink(format!("{up}{}", lib.file()), &link).unwrap();
            }
            _ => {}
        }
        if matches!(lib.soname, Soname::Differs) {
            let at = root
                .join("stub")
                .join(lib.index.to_string())
                .join(lib.needed());
            stub(&at, &lib.needed(), &src);
        }
    }
    let src = root.join("main.c");
    std::fs::write(&src, source(layout, 0)).unwrap();
    let app = root.join("bin/app");
    let mut args = vec![
        "-Wl,--allow-shlib-undefined".to_string(),
        "-o".to_string(),
        s(&app),
        s(&src),
    ];
    args.extend(link_args(layout, 0, root));
    musl_gcc(&args);
    app
}

fn real(path: &str) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| PathBuf::from(path))
}

// The real files musl's loader maps for the program, the loader included. Its first line
// names the loader alone; every other line is `name => path (address)`.
fn listed(list: &Output) -> BTreeSet<PathBuf> {
    String::from_utf8_lossy(&list.stdout)
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            let path = match line.split_once(" => ") {
                Some((_, rest)) => rest,
                None => line,
            };
            path.rsplit_once(" (").map(|(p, _)| real(p))
        })
        .collect()
}

// The same set from `graph --format json`: every node but the root, plus the loader.
fn graphed(graph: &Output) -> BTreeSet<PathBuf> {
    let json: serde_json::Value = serde_json::from_slice(&graph.stdout).unwrap_or_default();
    let nodes = json["nodes"].as_array().map_or(&[][..], |n| &n[..]);
    nodes
        .iter()
        .skip(1)
        .filter_map(|n| n["id"].as_str())
        .chain(json["interpreter"].as_str())
        .map(real)
        .collect()
}

// One case. Returns whether pack succeeded, or a description of the broken invariant.
fn check(seed: u64) -> Result<bool, String> {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().canonicalize().unwrap().join("case");
    let mut rng = Rng::new(seed);
    let layout = generate(&mut rng, &root);
    let app = build(&layout, &root);
    let bin = env!("CARGO_BIN_EXE_scratchsmith");
    let rootfs = tmp.path().join("rootfs");

    let host = run(Command::new(&app).current_dir("/"));
    let list = run(Command::new(LOADER).arg("--list").arg(&app));
    let graph = run(Command::new(bin)
        .args(["graph", "--format", "json"])
        .arg(&app));
    let pack = run(Command::new(bin)
        .args(["pack", "-n", "-o"])
        .arg(&rootfs)
        .arg(&app));
    let report = |why: &str, extra: &Output| {
        format!(
            "seed {seed:#x}: {why}\nlayout: {layout:#?}\nhost: {}\nmusl --list: {}\ngraph: {}\n\
             pack: {}\n{}",
            text(&host),
            text(&list),
            text(&graph),
            text(&pack),
            text(extra)
        )
    };

    if !matches!(pack.status.code(), Some(0 | 1)) {
        return Err(report("pack crashed instead of exit 0 or 1", &pack));
    }
    if graph.status.success() != pack.status.success() {
        return Err(report("graph and pack disagree", &pack));
    }
    match (host.status.success(), pack.status.success()) {
        (true, false) => return Err(report("musl runs it but pack refuses", &pack)),
        (false, true) => return Err(report("pack exited 0 but musl cannot run it", &host)),
        (false, false) => return Ok(false),
        (true, true) => {}
    }
    let (want, got) = (listed(&list), graphed(&graph));
    if want != got {
        return Err(report(
            &format!("graph resolved {got:?}, but musl --list mapped {want:?}"),
            &graph,
        ));
    }
    std::fs::create_dir_all(rootfs.join("proc")).unwrap();
    let image = run(&mut in_rootfs(&rootfs, &app));
    if !image.status.success() {
        return Err(report("pack exited 0 but the packed image fails", &image));
    }
    Ok(true)
}

#[test]
fn every_packed_musl_image_runs_like_the_musl_loader_says() {
    // ci.yml installs musl-tools, which puts musl's loader at /lib, and allows unprivileged
    // user namespaces, in both jobs that run the suite. So none of these may skip there.
    if !common::tool_available("musl-gcc") {
        skip_required("no musl-gcc");
        return;
    }
    if !Path::new(LOADER).exists() {
        skip_required("no musl loader at /lib/ld-musl-x86_64.so.1");
        return;
    }
    if !chroot_available() {
        skip_required("no unprivileged user namespace for `unshare -r chroot`");
        return;
    }
    let first = env_u64("SCRATCHSMITH_DIFF_SEED", DEFAULT_SEED);
    let cases = env_u64("SCRATCHSMITH_DIFF_CASES", DEFAULT_CASES);
    let mut failures = Vec::new();
    let mut packed = 0;
    for seed in first..first + cases {
        match check(seed) {
            Ok(true) => packed += 1,
            Ok(false) => {}
            Err(e) => failures.push(e),
        }
    }
    eprintln!(
        "{cases} musl cases from seed {first:#x}: {packed} packed and ran, {} refused, {} failed",
        cases - packed - failures.len() as u64,
        failures.len()
    );
    assert!(
        failures.is_empty(),
        "{} of {cases} musl cases broke an invariant. Repeat one with \
         SCRATCHSMITH_DIFF_SEED=<seed> SCRATCHSMITH_DIFF_CASES=1.\n\n{}",
        failures.len(),
        failures.join("\n\n")
    );
    assert!(
        cases < 8 || packed > 0,
        "no case packed: the generator is broken"
    );
}
