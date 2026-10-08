//! `pack --watch`: pack again each time the binary changes, for the inner loop of whoever is
//! building the thing being packed. Polls the file's metadata, so it needs no notify backend
//! and works the same on every filesystem.

use anyhow::Result;
use std::path::Path;
use std::time::{Duration, SystemTime};

const POLL: Duration = Duration::from_millis(500);
/// Polls with the file absent before saying so: five seconds, well past a normal relink.
const ABSENT_NOTICE_POLLS: u32 = 10;

/// What identifies one version of the file: its mtime and length. `None` while the file is
/// absent, which is normal in the middle of a rebuild (a linker unlinks, then writes).
type Stamp = Option<(SystemTime, u64)>;

fn stamp(path: &Path) -> Stamp {
    let meta = std::fs::metadata(path).ok()?;
    Some((meta.modified().ok()?, meta.len()))
}

/// Run `pack` once, then again after every change to `binary`, until the process is
/// interrupted. The first pack fails like a plain `pack`, so a wrong path or flag is not left
/// spinning. A later failure is printed and the watch goes on: a half-written binary or a
/// broken build is what the next save fixes.
pub fn run(binary: &Path, mut pack: impl FnMut() -> Result<()>) -> Result<()> {
    let (mut packed, first) = pack_current(binary, &mut pack);
    first?;
    loop {
        // stderr, like every other status line: stdout is the report.
        eprintln!(
            "watching {} for changes; press Ctrl-C to stop",
            binary.display()
        );
        wait_for_change(binary, packed, &mut || std::thread::sleep(POLL));
        let (stamped, result) = pack_current(binary, &mut pack);
        packed = stamped;
        if let Err(err) = result {
            eprintln!("error: {err:#}");
        }
    }
}

// Pack the binary as it is now, and say which version that was. The stamp is taken BEFORE
// the pack: a change that lands while the pack runs then differs from the stamp and
// triggers the next pack, instead of being mistaken for the version just packed.
fn pack_current(binary: &Path, pack: &mut impl FnMut() -> Result<()>) -> (Stamp, Result<()>) {
    let stamped = stamp(binary);
    (stamped, pack())
}

// Block until the file differs from `packed` and has held still for one poll. The second
// condition is the debounce: a linker writes for longer than one poll on a large binary, and
// packing a half-written file only produces an error to scroll past.
//
// Absence never triggers a pack, because a linker unlinks before it writes. A file that
// stays gone gets one stderr line: a watch on a path no build writes any more (a renamed
// output, a `cargo clean`) must not look the same as a watch that is working.
fn wait_for_change(path: &Path, packed: Stamp, sleep: &mut dyn FnMut()) -> Stamp {
    let mut last = stamp(path);
    let mut absent_polls = 0;
    loop {
        sleep();
        let now = stamp(path);
        if now.is_some() && now != packed && now == last {
            return now;
        }
        absent_polls = if now.is_none() { absent_polls + 1 } else { 0 };
        if absent_polls == ABSENT_NOTICE_POLLS {
            eprintln!(
                "{} is gone; still watching for it to come back",
                path.display()
            );
        }
        last = now;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    // Give the file a distinct mtime without sleeping: length alone would do, but a rebuild
    // that keeps the size is the case the mtime half of the stamp exists for.
    fn write_at(path: &Path, bytes: &[u8], secs: u64) {
        fs::write(path, bytes).unwrap();
        let t = SystemTime::UNIX_EPOCH + Duration::from_secs(secs);
        fs::File::options()
            .write(true)
            .open(path)
            .unwrap()
            .set_modified(t)
            .unwrap();
    }

    #[test]
    fn a_change_is_reported_only_after_it_holds_still() {
        let tmp = tempfile::tempdir().unwrap();
        let bin = tmp.path().join("app");
        write_at(&bin, b"v1", 1_000);
        let packed = stamp(&bin);

        // The "linker": each poll advances the file one step. Same length throughout, so
        // only the mtime tells the versions apart.
        let mut polls = 0;
        let mut sleep = || {
            polls += 1;
            match polls {
                1 => {}                              // unchanged: keep waiting
                2 => fs::remove_file(&bin).unwrap(), // unlinked mid-rebuild
                3 => write_at(&bin, b"v2", 2_000),   // first write
                4 => write_at(&bin, b"v3", 3_000),   // still being written
                5 => {}                              // held still for one poll
                n => panic!("poll {n}: the change was already stable at poll 5"),
            }
        };
        let seen = wait_for_change(&bin, packed, &mut sleep);
        assert_eq!(polls, 5, "must wait out the absence and the two writes");
        assert_eq!(seen, stamp(&bin));
        assert_ne!(seen, packed);
    }

    #[test]
    fn a_change_during_the_pack_is_not_lost() {
        let tmp = tempfile::tempdir().unwrap();
        let bin = tmp.path().join("app");
        write_at(&bin, b"v1", 1_000);
        let v1 = stamp(&bin);

        // The binary is replaced while the pack runs. The stamp handed back must be the
        // version the pack started from, so the new one still counts as a change.
        let mut pack = || {
            write_at(&bin, b"v2", 2_000);
            Ok(())
        };
        let (packed, result) = pack_current(&bin, &mut pack);
        assert!(result.is_ok());
        assert_eq!(packed, v1, "stamped before the pack, not after");

        // Budgeted: with the stamp taken after the pack, no state of the file ever differs
        // from `packed`, and an unbounded wait would hang the suite instead of failing it.
        let mut polls = 0;
        let seen = wait_for_change(&bin, packed, &mut || {
            polls += 1;
            assert!(
                polls <= 2,
                "poll {polls}: the new version was there from the first"
            );
        });
        assert_eq!(polls, 1);
        assert_eq!(seen, stamp(&bin));
    }

    #[test]
    fn a_file_that_stays_gone_is_waited_for_and_then_packed() {
        let tmp = tempfile::tempdir().unwrap();
        let bin = tmp.path().join("app");
        write_at(&bin, b"v1", 1_000);
        let packed = stamp(&bin);
        fs::remove_file(&bin).unwrap();

        // Gone for longer than the notice threshold, then rebuilt. Absence alone must
        // never return, and the wait must survive the notice.
        let back_at = ABSENT_NOTICE_POLLS + 3;
        let mut polls = 0;
        let seen = wait_for_change(&bin, packed, &mut || {
            polls += 1;
            if polls == back_at {
                write_at(&bin, b"v2", 2_000);
            }
            assert!(polls <= back_at + 2, "poll {polls}: v2 was stable by then");
        });
        assert_eq!(polls, back_at + 1, "one more poll to see it hold still");
        assert_eq!(seen, stamp(&bin));
    }
}
