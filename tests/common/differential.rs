//! Helpers shared by the differential pack-and-run tests, `tests/differential.rs` (glibc) and
//! `tests/differential_musl.rs` (musl), so a fix to the seed parsing or the chroot run reaches
//! both.

use std::path::Path;
use std::process::{Command, Output};

/// xorshift64*: enough randomness for layouts, and no dev-dependency.
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        // A zero state never leaves zero.
        Rng(seed ^ 0x9e37_79b9_7f4a_7c15)
    }
    pub fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    pub fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    pub fn chance(&mut self, percent: u64) -> bool {
        self.next() % 100 < percent
    }
    pub fn pick<T: Copy>(&mut self, items: &[T]) -> T {
        items[self.below(items.len())]
    }
}

/// Run `cmd` with the loader's environment overrides cleared, so the host's own settings
/// cannot change what a case finds.
pub fn run(cmd: &mut Command) -> Output {
    cmd.env_remove("LD_LIBRARY_PATH")
        .env_remove("LD_PRELOAD")
        .output()
        .expect("spawn")
}

pub fn text(out: &Output) -> String {
    format!(
        "exit {:?}\nstdout: {}\nstderr: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// Run `program` inside `rootfs` as an unprivileged root, with a fresh /proc as every container
/// engine gives an image. Without /proc, glibc's ld.so cannot read /proc/self/exe and drops each
/// `$ORIGIN` entry of the main program, and musl cannot expand the program's `$ORIGIN`. The run
/// would then fail for a reason no image has.
pub fn in_rootfs(rootfs: &Path, program: &Path) -> Command {
    let mut cmd = Command::new("unshare");
    cmd.args(["-r", "-m", "-p", "-f"])
        .arg(format!("--mount-proc={}", rootfs.join("proc").display()))
        .arg("chroot")
        .arg(rootfs)
        .arg(program);
    cmd
}

/// Can this host run `in_rootfs`?
pub fn chroot_available() -> bool {
    run(&mut in_rootfs(Path::new("/"), Path::new("/bin/true")))
        .status
        .success()
}

/// `name` from the environment as decimal or `0x` hex, or `default` when unset.
pub fn env_u64(name: &str, default: u64) -> u64 {
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
