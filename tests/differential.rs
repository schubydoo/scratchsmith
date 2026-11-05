//! Differential pack-and-run test: real glibc is the oracle for every packed image.
//!
//! The resolver tests and the fuzzers check scratchsmith against what its authors believe ld.so
//! does. That belief was wrong several times in 2.0 (PRs 428, 437, 441), and each time `pack`
//! exited 0 and the image exited 127 at start. A fuzzer that asserts "no panic" cannot see a
//! wrong answer, so this test asks the real loader instead.
//!
//! Each case is a random but valid library layout, compiled with `cc`: lib and non-lib names,
//! a soname that matches the file, is absent or differs, RPATH or RUNPATH, `$ORIGIN`, absolute
//! entries, directories with ':' in the name, and chained dependencies. For every case:
//!
//! - if `pack` exits 0, the packed rootfs must run the program with exit 0 (in a chroot inside
//!   an unprivileged user namespace, so neither Docker nor root is needed);
//! - `graph` and `pack` must agree on success or failure;
//! - a failing `pack` must exit 1, not crash;
//! - if the host loader runs the program, `pack` must succeed.
//!
//! `SCRATCHSMITH_DIFF_SEED` picks the first seed and `SCRATCHSMITH_DIFF_CASES` the number of
//! cases. A failure prints the seed of its case, which repeats it alone with CASES=1.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

mod common;
use common::{cc_available, skip_required};

const DEFAULT_SEED: u64 = 0x5eed_2000;
// About 85 ms a case. The nightly `differential` workflow runs thousands from a fresh seed.
const DEFAULT_CASES: u64 = 64;

// xorshift64*: enough randomness for layouts, and no dev-dependency.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        // A zero state never leaves zero.
        Rng(seed ^ 0x9e37_79b9_7f4a_7c15)
    }
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    fn chance(&mut self, percent: u64) -> bool {
        self.next() % 100 < percent
    }
    fn pick<T: Copy>(&mut self, items: &[T]) -> T {
        items[self.below(items.len())]
    }
}

#[derive(Clone, Copy, Debug)]
enum Name {
    // libX.so.1, the usual shape.
    LibVersioned,
    // libX.so
    LibPlain,
    // X.so: ldconfig does not cache a name without the lib prefix.
    Bare,
    // X.so.1
    BareVersioned,
    // libX.so.1.0.0 with the soname link libX.so.1 beside it.
    LinkChain,
}

#[derive(Clone, Copy, Debug)]
enum Soname {
    // DT_SONAME is the NEEDED name.
    Match,
    // No DT_SONAME: ldconfig keys the cache by the file name.
    Absent,
    // DT_SONAME differs from the NEEDED name. The needer links against a stub to get that.
    Differs,
}

// Directories under the case root. `bin` holds the program.
const DIRS: &[&str] = &["bin", "lib", "lib/sub", "x:y", "deps/a:b/c", "opt/lib64"];

#[derive(Debug)]
struct Lib {
    index: usize,
    name: Name,
    soname: Soname,
    dir: &'static str,
    // None: the program needs it. Some(j): library j needs it.
    parent: Option<usize>,
}

impl Lib {
    fn stem(&self) -> String {
        match self.name {
            Name::Bare | Name::BareVersioned => format!("ssdiff{}", self.index),
            _ => format!("libssdiff{}", self.index),
        }
    }
    // The NEEDED name the parent records.
    fn needed(&self) -> String {
        match self.name {
            Name::LibVersioned | Name::BareVersioned | Name::LinkChain => {
                format!("{}.so.1", self.stem())
            }
            Name::LibPlain | Name::Bare => format!("{}.so", self.stem()),
        }
    }
    // The real file on disk.
    fn file(&self) -> String {
        match self.name {
            Name::LinkChain => format!("{}.so.1.0.0", self.stem()),
            _ => self.needed(),
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
}

// The directory an object sits in, relative to the case root.
fn dir_of(layout: &Layout, object: usize) -> &'static str {
    if object == 0 {
        "bin"
    } else {
        layout.libs[object - 1].dir
    }
}

// A search-path entry from `from` (an object's directory) to `to`, both under `root`.
fn entry(rng: &mut Rng, root: &Path, from: &str, to: &str) -> String {
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
        Name::BareVersioned,
        Name::LinkChain,
    ];
    let mut libs = Vec::new();
    for index in 0..count {
        let soname = match rng.below(10) {
            0..=5 => Soname::Match,
            6 | 7 => Soname::Absent,
            _ => Soname::Differs,
        };
        let name = rng.pick(&names);
        libs.push(Lib {
            index,
            // A link chain is defined by its soname link, so it always has a soname.
            soname: if matches!(name, Name::LinkChain) && !matches!(soname, Soname::Match) {
                Soname::Match
            } else {
                soname
            },
            name,
            dir: rng.pick(&DIRS[1..]),
            parent: if index == 0 || rng.chance(40) {
                None
            } else {
                Some(rng.below(index))
            },
        });
    }
    let objects = count + 1;
    let tags: Vec<Tags> = (0..objects)
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
    };
    for i in 0..count {
        let needer = layout.libs[i].parent.map_or(0, |p| p + 1);
        // Usually the needer names the directory. Sometimes the program does instead, which
        // reaches the library only through an inherited RPATH; sometimes nobody does.
        let holder = match rng.below(10) {
            0..=6 => needer,
            7 | 8 => 0,
            _ => continue,
        };
        let from = dir_of(&layout, holder);
        let e = entry(rng, root, from, layout.libs[i].dir);
        layout.paths[holder].push(e);
    }
    for paths in &mut layout.paths {
        if rng.chance(25) {
            let at = rng.below(paths.len() + 1);
            paths.insert(at, "/opt/ssdiff-none".to_string());
        }
    }
    layout
}

fn cc(args: &[String]) {
    let out = Command::new("cc").args(args).output().expect("run cc");
    assert!(
        out.status.success(),
        "cc {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn s(p: &Path) -> String {
    p.display().to_string()
}

// The C source of one object: its own value plus the values of what it needs.
fn source(layout: &Layout, object: usize) -> String {
    let children: Vec<&Lib> = layout
        .libs
        .iter()
        .filter(|l| l.parent.map_or(0, |p| p + 1) == object)
        .collect();
    let mut src = String::new();
    for c in &children {
        writeln!(src, "extern int f{}(void);", c.index).unwrap();
    }
    let sum: String = children
        .iter()
        .map(|c| format!(" + f{}()", c.index))
        .collect();
    if object == 0 {
        let expect: u64 = layout.libs.iter().map(|l| l.value()).sum();
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

// Link flags for the children of `object`: each one through its own directory, or through
// the stub that carries the NEEDED name when the real file's soname differs.
fn link_args(layout: &Layout, object: usize, root: &Path) -> Vec<String> {
    let mut args = Vec::new();
    for c in &layout.libs {
        if c.parent.map_or(0, |p| p + 1) != object {
            continue;
        }
        let dir = match c.soname {
            Soname::Differs => root.join("stub").join(c.index.to_string()),
            _ => root.join(c.dir),
        };
        args.push(format!("-L{}", s(&dir)));
        args.push(format!("-l:{}", c.needed()));
    }
    let tags = layout.tags[object];
    args.push(tags.flag().to_string());
    for e in &layout.paths[object] {
        args.push(format!("-Wl,-rpath,{e}"));
    }
    args
}

// Compile the layout under `root` and return the program path.
fn build(layout: &Layout, root: &Path) -> PathBuf {
    for dir in DIRS {
        std::fs::create_dir_all(root.join(dir)).unwrap();
    }
    // Children before parents: a child always has a higher index than its library parent.
    for lib in layout.libs.iter().rev() {
        let object = lib.index + 1;
        let src = root.join(format!("f{}.c", lib.index));
        std::fs::write(&src, source(layout, object)).unwrap();
        let dir = root.join(lib.dir);
        let mut args = vec!["-shared".to_string(), "-fPIC".to_string()];
        match lib.soname {
            Soname::Match => args.push(format!("-Wl,-soname,{}", lib.needed())),
            Soname::Absent => {}
            Soname::Differs => args.push(format!("-Wl,-soname,libssdother{}.so.9", lib.index)),
        }
        args.extend(["-o".to_string(), s(&dir.join(lib.file())), s(&src)]);
        args.extend(link_args(layout, object, root));
        cc(&args);
        if matches!(lib.name, Name::LinkChain) {
            std::os::unix::fs::symlink(lib.file(), dir.join(lib.needed())).unwrap();
        }
        if matches!(lib.soname, Soname::Differs) {
            let stub = root.join("stub").join(lib.index.to_string());
            std::fs::create_dir_all(&stub).unwrap();
            cc(&[
                "-shared".to_string(),
                "-fPIC".to_string(),
                format!("-Wl,-soname,{}", lib.needed()),
                "-o".to_string(),
                s(&stub.join(lib.needed())),
                s(&src),
            ]);
        }
    }
    let src = root.join("main.c");
    std::fs::write(&src, source(layout, 0)).unwrap();
    let app = root.join("bin/app");
    // ld looks for a library's own dependencies at link time. `-rpath-link` would split the
    // ':' directories, so let the loader be the only one that has to find them.
    let mut args = vec![
        "-Wl,--allow-shlib-undefined".to_string(),
        "-o".to_string(),
        s(&app),
        s(&src),
    ];
    args.extend(link_args(layout, 0, root));
    cc(&args);
    app
}

fn run(cmd: &mut Command) -> Output {
    cmd.env_remove("LD_LIBRARY_PATH")
        .env_remove("LD_PRELOAD")
        .output()
        .expect("spawn")
}

fn text(out: &Output) -> String {
    format!(
        "exit {:?}\nstdout: {}\nstderr: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

// Run `program` inside `rootfs` as an unprivileged root, with a fresh /proc as every container
// engine gives an image. Without /proc, ld.so cannot read /proc/self/exe, so it drops each
// `$ORIGIN` entry of the main program and the run fails for a reason no image has.
fn in_rootfs(rootfs: &Path, program: &Path) -> Command {
    let mut cmd = Command::new("unshare");
    cmd.args(["-r", "-m", "-p", "-f"])
        .arg(format!("--mount-proc={}", rootfs.join("proc").display()))
        .arg("chroot")
        .arg(rootfs)
        .arg(program);
    cmd
}

// Can this host run `in_rootfs`?
fn chroot_available() -> bool {
    run(&mut in_rootfs(Path::new("/"), Path::new("/bin/true")))
        .status
        .success()
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
    let graph = run(Command::new(bin).arg("graph").arg(&app));
    let pack = run(Command::new(bin)
        .args(["pack", "-n", "-o"])
        .arg(&rootfs)
        .arg(&app));
    let report = |why: &str, extra: &Output| {
        format!(
            "seed {seed:#x}: {why}\nlayout: {layout:#?}\nhost: {}\ngraph: {}\npack: {}\n{}",
            text(&host),
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
    if pack.status.success() {
        std::fs::create_dir_all(rootfs.join("proc")).unwrap();
        let image = run(&mut in_rootfs(&rootfs, &app));
        if !image.status.success() {
            return Err(report("pack exited 0 but the packed image fails", &image));
        }
    } else if host.status.success() {
        return Err(report("the host loader runs it but pack refuses", &pack));
    }
    Ok(pack.status.success())
}

fn env_u64(name: &str, default: u64) -> u64 {
    match std::env::var(name) {
        Ok(v) => {
            let v = v.trim();
            let parsed = match v.strip_prefix("0x") {
                Some(hex) => u64::from_str_radix(hex, 16),
                None => v.parse(),
            };
            parsed.unwrap_or_else(|_| panic!("{name}={v:?} is not a number"))
        }
        Err(_) => default,
    }
}

#[test]
fn every_packed_image_runs_like_the_real_loader_says() {
    if !cc_available() {
        skip_required("no C compiler");
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
        "{cases} cases from seed {first:#x}: {packed} packed and ran, {} refused, {} failed",
        cases - packed - failures.len() as u64,
        failures.len()
    );
    assert!(
        failures.is_empty(),
        "{} of {cases} cases broke an invariant. Repeat one with \
         SCRATCHSMITH_DIFF_SEED=<seed> SCRATCHSMITH_DIFF_CASES=1.\n\n{}",
        failures.len(),
        failures.join("\n\n")
    );
    // Without a packed case, the run proved nothing about the images.
    assert!(
        cases < 8 || packed > 0,
        "no case packed: the generator is broken"
    );
}
