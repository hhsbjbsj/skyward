//! Keeping this recovery in the recovery partitions an install writes
//! over: this recovery as its partition holds it, what each slot's
//! partition held before the install, and which slots get it back after.

use crate::image;
use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use skyward_vab::Slot;
use std::fs::File;
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};

const PARTITION: &str = "recovery";

/// What a slot's recovery partition holds: a digest of all of it, and
/// whether that is Skyward, any build of it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Held {
    pub digest: [u8; 32],
    pub skyward: bool,
}

#[derive(Clone, Copy)]
enum Before {
    Ab([Held; 2]),
    Static,
}

/// This recovery, held from the current slot's (or single static) recovery
/// partition before an install, and what each slot's partition held then,
/// slot A first on A/B devices.
pub struct Kept {
    dir: PathBuf,
    image: Vec<u8>,
    own: [u8; 32],
    before: Before,
}

impl Kept {
    /// Hold this recovery from the recovery partitions among the links in
    /// `dir`, before an install; none when the partition of the `current`
    /// slot (or single static recovery partition when `current` is `None`)
    /// does not hold Skyward, as when it was started without being flashed.
    pub fn hold(dir: &Path, current: Option<Slot>) -> Result<Option<Kept>> {
        match current {
            Some(current) => {
                let (a, image_a) = read(&image::device(dir, PARTITION, Some(Slot::A)))?;
                let (b, image_b) = read(&image::device(dir, PARTITION, Some(Slot::B)))?;
                let (held, image) = match current {
                    Slot::A => (a, image_a),
                    Slot::B => (b, image_b),
                };
                Ok(held.skyward.then(|| Kept { dir: dir.to_path_buf(), image, own: held.digest, before: Before::Ab([a, b]) }))
            }
            None => {
                let (held, image) = read(&image::device(dir, PARTITION, None))?;
                Ok(held.skyward.then(|| Kept { dir: dir.to_path_buf(), image, own: held.digest, before: Before::Static }))
            }
        }
    }

    /// Which recovery partitions get this recovery back once an install is
    /// done: `None` when nothing needs rewriting, `Some(slots)` on A/B
    /// (`next` is the slot that starts next), or `Some(vec![])` for the
    /// single static recovery partition on non-A/B phones.
    pub fn wanted(&self, next: Option<Slot>) -> Result<Option<Vec<Slot>>> {
        match (self.before, next) {
            (Before::Ab(before), Some(next)) => {
                let (a, _) = read(&image::device(&self.dir, PARTITION, Some(Slot::A)))?;
                let (b, _) = read(&image::device(&self.dir, PARTITION, Some(Slot::B)))?;
                let slots = restore(before, [a, b], self.own, next);
                Ok((!slots.is_empty()).then_some(slots))
            }
            (Before::Static, None) => {
                let (now, _) = read(&image::device(&self.dir, PARTITION, None))?;
                Ok((now.digest != self.own).then_some(Vec::new()))
            }
            _ => bail!("slot expectation changed between hold and restore"),
        }
    }

    /// Write this recovery into the recovery partitions of `slots` (or the
    /// single static recovery partition when `slots` is empty) and read
    /// each back; `progress` hears the bytes so far, of all.
    pub fn write(&self, slots: &[Slot], progress: &mut dyn FnMut(u64, u64)) -> Result<()> {
        let devices: Vec<PathBuf> = if slots.is_empty() {
            vec![image::device(&self.dir, PARTITION, None)]
        } else {
            slots.iter().map(|&slot| image::device(&self.dir, PARTITION, Some(slot))).collect()
        };
        image::flash(&mut Cursor::new(&self.image), self.image.len() as u64, &devices, progress)
    }
}

/// What the partition at `path` holds, read past any pages cached of it,
/// and all of it.
fn read(path: &Path) -> Result<(Held, Vec<u8>)> {
    let mut file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    image::drop_cache(&file).with_context(|| format!("drop the cached pages of {}", path.display()))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).with_context(|| format!("read {}", path.display()))?;
    let skyward = image::is_skyward(&mut Cursor::new(&bytes)).with_context(|| format!("look into {}", path.display()))?;
    Ok((Held { digest: Sha256::digest(&bytes).into(), skyward }, bytes))
}

/// The slots whose recovery partition gets this recovery back once an
/// install is done, by what each held `before` and `after` it, slot A
/// first: the slot that starts next, `next`, unless it holds this build,
/// whose digest is `own`; and any other the install wrote over with
/// something that is not Skyward.
pub fn restore(before: [Held; 2], after: [Held; 2], own: [u8; 32], next: Slot) -> Vec<Slot> {
    [Slot::A, Slot::B]
        .into_iter()
        .filter(|&slot| {
            let k = slot.number() as usize;
            match slot == next {
                true => after[k].digest != own,
                false => after[k].digest != before[k].digest && !after[k].skyward,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::image::samples::recovery;

    const SKYWARD: Held = Held { digest: [1; 32], skyward: true };
    const OWN: [u8; 32] = SKYWARD.digest;
    /// Another build of Skyward.
    const OTHER_BUILD: Held = Held { digest: [4; 32], skyward: true };
    const STOCK: Held = Held { digest: [2; 32], skyward: false };
    const OLD: Held = Held { digest: [3; 32], skyward: false };

    #[test]
    fn the_slot_that_starts_next_gets_this_build() {
        assert_eq!(restore([SKYWARD, OLD], [SKYWARD, STOCK], OWN, Slot::B), [Slot::B], "an update or a package that went to slot B");
        assert_eq!(restore([SKYWARD, OLD], [SKYWARD, OLD], OWN, Slot::B), [Slot::B], "an older recovery there, left alone by the install");
        assert_eq!(restore([SKYWARD, OTHER_BUILD], [SKYWARD, OTHER_BUILD], OWN, Slot::B), [Slot::B], "another build of Skyward there");
        assert!(restore([SKYWARD, SKYWARD], [SKYWARD, SKYWARD], OWN, Slot::A).is_empty(), "this recovery is there already");
    }

    #[test]
    fn elsewhere_it_goes_back_only_where_the_install_wrote_something_else() {
        assert!(restore([SKYWARD, OLD], [SKYWARD, OLD], OWN, Slot::A).is_empty(), "a package that left recovery alone, such as a root installer");
        assert_eq!(restore([SKYWARD, OLD], [SKYWARD, STOCK], OWN, Slot::A), [Slot::B]);
        assert_eq!(restore([SKYWARD, OLD], [STOCK, STOCK], OWN, Slot::A), [Slot::A, Slot::B]);
        assert!(restore([SKYWARD, OLD], [SKYWARD, OTHER_BUILD], OWN, Slot::A).is_empty(), "a package that put another build of Skyward in");
    }

    /// Recovery partitions of `size` bytes holding `a` and `b`.
    fn partitions(a: &[u8], b: &[u8], size: usize) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        for (name, image) in [("recovery_a", a), ("recovery_b", b)] {
            let mut bytes = image.to_vec();
            bytes.resize(size, 0);
            std::fs::write(dir.path().join(name), bytes).unwrap();
        }
        dir
    }

    #[test]
    fn this_recovery_goes_back_where_an_install_wrote_over_it() {
        let (skyward, stock) = (recovery(true), recovery(false));
        let size = skyward.len().max(stock.len()) + 4096;
        let dir = partitions(&skyward, &stock, size);
        let kept = Kept::hold(dir.path(), Some(Slot::A)).unwrap().expect("slot A's partition holds Skyward");
        assert!(kept.wanted(Some(Slot::A)).unwrap().is_none(), "nothing written over");
        // A package puts the stock recovery in both slots.
        let mut written = stock.clone();
        written.resize(size, 0);
        std::fs::write(dir.path().join("recovery_a"), &written).unwrap();
        assert_eq!(kept.wanted(Some(Slot::A)).unwrap(), Some(vec![Slot::A]), "slot B held the stock recovery already");
        let mut told = Vec::new();
        kept.write(&[Slot::A], &mut |done, total| told.push((done, total))).unwrap();
        assert_eq!(told.last(), Some(&(2 * size as u64, 2 * size as u64)), "written and read back");
        let mut whole = skyward.clone();
        whole.resize(size, 0);
        assert_eq!(std::fs::read(dir.path().join("recovery_a")).unwrap(), whole);
        assert!(kept.wanted(Some(Slot::A)).unwrap().is_none());
        assert_eq!(kept.wanted(Some(Slot::B)).unwrap(), Some(vec![Slot::B]), "an install that has slot B start next");
    }

    #[test]
    fn nothing_is_kept_when_this_recovery_was_started_without_being_flashed() {
        let dir = partitions(&recovery(false), &recovery(false), 1 << 20);
        assert!(Kept::hold(dir.path(), Some(Slot::B)).unwrap().is_none());
        let erased = partitions(&recovery(true), &[], 1 << 20);
        assert!(Kept::hold(erased.path(), Some(Slot::B)).unwrap().is_none(), "an erased partition");
        assert!(Kept::hold(erased.path(), Some(Slot::A)).unwrap().is_some());
    }

    #[test]
    fn this_recovery_goes_back_to_single_recovery_partition_when_overwritten() {
        let (skyward, stock) = (recovery(true), recovery(false));
        let size = skyward.len().max(stock.len()) + 4096;
        let dir = tempfile::tempdir().unwrap();
        let mut whole = skyward.clone();
        whole.resize(size, 0);
        std::fs::write(dir.path().join("recovery"), &whole).unwrap();
        let kept = Kept::hold(dir.path(), None).unwrap().expect("recovery partition holds Skyward");
        assert_eq!(kept.wanted(None).unwrap(), None);
        let mut written = stock;
        written.resize(size, 0);
        std::fs::write(dir.path().join("recovery"), &written).unwrap();
        assert_eq!(kept.wanted(None).unwrap(), Some(Vec::new()));
        kept.write(&[], &mut |_, _| {}).unwrap();
        assert_eq!(std::fs::read(dir.path().join("recovery")).unwrap(), whole);
        assert_eq!(kept.wanted(None).unwrap(), None);
    }
}
