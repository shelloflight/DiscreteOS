//! DFS host tests: operations, snapshots, corruption detection and a power-cut sweep (every
//! cut point of a multi-transaction workload, with random loss of unflushed writes): after
//! each cut the volume mounts, fsck finds nothing, and the state is exactly one committed one.

use super::*;
use crate::dev::{CutDev, MemDev, SharedCut};
use alloc::rc::Rc;
use core::cell::RefCell;
use std::format;

fn fresh(mib: u64) -> Dfs {
    Dfs::format(Box::new(MemDev::new(mib * 2048)), &FormatOpts { label: b"test", uuid: [9; 16] }).unwrap()
}

fn remount(d: Dfs) -> Dfs {
    match Dfs::mount(d.into_dev()) {
        Ok(d) => d,
        Err((e, _)) => panic!("mount failed: {:?}", e),
    }
}

fn clean(d: &mut Dfs) {
    let r = d.fsck().unwrap();
    assert_eq!(r.errors, 0, "fsck: {:?}", r);
}

fn pattern(seed: u64, n: usize) -> Vec<u8> {
    (0..n).map(|i| (i as u64).wrapping_mul(31).wrapping_add(seed * 7) as u8).collect()
}

#[test]
fn files_dirs_and_remount() {
    let mut d = fresh(32);
    let r = d.root();
    let dir = d.create(r, b"docs", Kind::Dir).unwrap();
    let f = d.create(dir, b"big.bin", Kind::File).unwrap();
    let data = pattern(1, 1_000_003);
    for (i, c) in data.chunks(32768).enumerate() {
        d.write(f, (i * 32768) as u64, c).unwrap();
    }
    for i in 0..500 {
        d.create(dir, format!("entry-{:04}", i).as_bytes(), Kind::File).unwrap();
    }
    d.sync().unwrap();
    let mut d = remount(d);
    clean(&mut d);
    let r = d.root();
    let dir = d.lookup(r, b"docs").unwrap();
    let f = d.lookup(dir, b"big.bin").unwrap();
    assert_eq!(d.stat(f).unwrap().size, 1_000_003);
    let mut got = vec![0u8; 1_000_003];
    assert_eq!(d.read(f, 0, &mut got).unwrap(), 1_000_003);
    assert!(got == data);
    // Overwrite in the middle, sparse extension, truncate.
    d.write(f, 5000, b"hello").unwrap();
    d.write(f, 3_000_000, b"end").unwrap();
    let mut b = [0u8; 8];
    d.read(f, 2_000_000, &mut b).unwrap();
    assert_eq!(b, [0; 8]);
    d.truncate(f, 5003).unwrap();
    let mut b = [0u8; 10];
    assert_eq!(d.read(f, 4998, &mut b).unwrap(), 5);
    assert_eq!(&b[..5], &[data[4998], data[4999], b'h', b'e', b'l']);
    // Listing in pieces sees every entry once.
    let mut n = 0;
    let mut c = 0;
    loop {
        let (e, next) = d.readdir(dir, c, 37).unwrap();
        n += e.len();
        match next {
            Some(x) => c = x,
            None => break,
        }
    }
    assert_eq!(n, 501);
    for i in 0..500 {
        d.unlink(dir, format!("entry-{:04}", i).as_bytes()).unwrap();
    }
    assert_eq!(d.unlink(r, b"docs"), Err(Error::NotEmpty));
    d.unlink(dir, b"big.bin").unwrap();
    d.unlink(r, b"docs").unwrap();
    d.sync().unwrap();
    let mut d = remount(d);
    clean(&mut d);
    assert_eq!(d.lookup(d.root(), b"docs"), Err(Error::NotFound));
    assert_eq!(d.create(d.root(), b"..", Kind::File), Err(Error::BadName));
    // Everything was freed again (allowing for the trees' own blocks).
    let i = d.info();
    assert!(i.free_blocks + 16 > i.total_blocks - DATA_START, "{:?}", i);
}

#[test]
fn snapshots() {
    let mut d = fresh(16);
    let r = d.root();
    let f = d.create(r, b"state", Kind::File).unwrap();
    d.write(f, 0, &pattern(1, 200_000)).unwrap();
    d.snapshot(b"s1").unwrap();
    let free_snap = d.info().free_blocks;
    d.write(f, 0, &pattern(2, 200_000)).unwrap();
    d.create(r, b"after", Kind::File).unwrap();
    d.sync().unwrap();
    let mut d = remount(d);
    clean(&mut d);
    let s = d.open_snapshot(b"s1").unwrap();
    let sf = d.lookup(s, b"state").unwrap();
    let mut got = vec![0u8; 200_000];
    d.read(sf, 0, &mut got).unwrap();
    assert!(got == pattern(1, 200_000), "the snapshot changed");
    assert_eq!(d.lookup(s, b"after"), Err(Error::NotFound));
    assert_eq!(d.write(sf, 0, b"x"), Err(Error::ReadOnly));
    assert_eq!(d.create(s, b"new", Kind::File), Err(Error::ReadOnly));
    let lf = d.lookup(d.root(), b"state").unwrap();
    d.read(lf, 0, &mut got).unwrap();
    assert!(got == pattern(2, 200_000));
    assert!(d.info().free_blocks < free_snap, "the overwrite did not use new blocks");
    let freed = d.delete_snapshot(b"s1").unwrap();
    assert!(freed >= 48, "deleting the snapshot freed only {} blocks", freed);
    clean(&mut d);
    let mut d = remount(d);
    clean(&mut d);
    assert_eq!(d.open_snapshot(b"s1"), Err(Error::NotFound));
}

#[test]
fn corruption_is_detected() {
    let mut d = fresh(16);
    let r = d.root();
    let f = d.create(r, b"victim", Kind::File).unwrap();
    d.write(f, 0, &pattern(3, 10_000)).unwrap();
    for i in 0..300 {
        d.create(r, format!("filler-{}", i).as_bytes(), Kind::File).unwrap();
    }
    d.sync().unwrap();
    // A data block.
    d.corrupt_data(f).unwrap();
    let mut b = vec![0u8; 10_000];
    assert_eq!(d.read(f, 0, &mut b), Err(Error::Corrupt));
    assert!(d.fsck().unwrap().errors > 0);
    d.write(f, 0, &pattern(3, 10_000)).unwrap(); // copy-on-write: a new, good block
    d.sync().unwrap();
    assert_eq!(d.read(f, 0, &mut b), Ok(10_000));
    clean(&mut d);
    // The newest superblock: mount falls back one generation (one more commit first, so the
    // generation it falls back to no longer has the block corrupted above).
    let x = d.create(r, b"extra", Kind::File).unwrap();
    d.write(x, 0, b"one more generation").unwrap();
    d.sync().unwrap();
    let g = d.info().generation;
    d.corrupt_super().unwrap();
    let mut d = remount(d);
    assert_eq!((d.fallbacks, d.info().generation), (1, g - 1));
    clean(&mut d);
    // A tree node: whatever lives in it is refused, never misread.
    let f = d.lookup(d.root(), b"victim").unwrap();
    d.corrupt_meta(f).unwrap();
    assert_eq!(d.stat(f).map(|_| ()), Err(Error::Corrupt));
    assert!(d.fsck().unwrap().errors > 0);
}

/// One workload step: transaction `t` rewrites `state` with version t, adds f<t>, removes
/// f<t-2> (from t = 3), then commits.
fn step(d: &mut Dfs, t: u64) -> Result<()> {
    let r = d.root();
    let s = match d.lookup(r, b"state") {
        Ok(s) => s,
        Err(Error::NotFound) => d.create(r, b"state", Kind::File)?,
        Err(e) => return Err(e),
    };
    let mut v = pattern(t, 9000 + t as usize * 1000);
    v[..8].copy_from_slice(&t.to_le_bytes());
    d.truncate(s, 0)?;
    d.write(s, 0, &v)?;
    let f = d.create(r, format!("f{}", t).as_bytes(), Kind::File)?;
    d.write(f, 0, &pattern(t + 100, 5000))?;
    if t >= 3 {
        d.unlink(r, format!("f{}", t - 2).as_bytes())?;
    }
    d.sync()
}

/// The state after a power cut must be exactly what transaction `t` committed, for some t.
fn check_state(d: &mut Dfs) -> u64 {
    let r = d.root();
    let Ok(s) = d.lookup(r, b"state") else {
        // Nothing committed yet besides the format.
        let (e, _) = d.readdir(r, 0, 100).unwrap();
        assert!(e.is_empty(), "entries without a state file");
        return 0;
    };
    let mut b = vec![0u8; 64 * 1024];
    let n = d.read(s, 0, &mut b).unwrap();
    let t = u64::from_le_bytes(b[..8].try_into().unwrap());
    let mut want = pattern(t, 9000 + t as usize * 1000);
    want[..8].copy_from_slice(&t.to_le_bytes());
    assert!(n == want.len() && b[..n] == want[..], "state is not version {}", t);
    for k in 1..=t + 3 {
        let exists = d.lookup(r, format!("f{}", k).as_bytes()).is_ok();
        assert_eq!(exists, k + 2 > t && k <= t, "f{} after version {}", k, t);
        if exists {
            let f = d.lookup(r, format!("f{}", k).as_bytes()).unwrap();
            let mut g = vec![0u8; 5000];
            d.read(f, 0, &mut g).unwrap();
            assert!(g == pattern(k + 100, 5000), "f{} content", k);
        }
    }
    t
}

#[test]
fn power_cut_sweep() {
    const STEPS: u64 = 5;
    let cut = Rc::new(RefCell::new(CutDev::new(MemDev::new(8 * 2048))));
    drop(Dfs::format(Box::new(SharedCut(cut.clone())), &FormatOpts { label: b"cut", uuid: [5; 16] }).unwrap());
    let base = cut.borrow().inner.data.clone();
    let mut d = match Dfs::mount(Box::new(SharedCut(cut.clone()))) {
        Ok(d) => d,
        Err(_) => panic!("mount"),
    };
    let w0 = cut.borrow().writes;
    for t in 1..=STEPS {
        step(&mut d, t).unwrap();
    }
    let total = cut.borrow().writes - w0;
    std::println!("power cut sweep: {} cut points (sectors) x 3 seeds", total + 1);
    drop(d);
    let mut seen = std::collections::BTreeSet::new();
    for n in 0..=total {
        for seed in [1u64, 2, 3] {
            {
                let mut c = cut.borrow_mut();
                c.inner.data.copy_from_slice(&base);
                c.restore();
                c.arm(n, seed * 7919 + n);
            }
            let mut d = match Dfs::mount(Box::new(SharedCut(cut.clone()))) {
                Ok(d) => d,
                Err(_) => panic!("mount"),
            };
            for t in 1..=STEPS {
                if step(&mut d, t).is_err() {
                    break;
                }
            }
            drop(d);
            cut.borrow_mut().restore();
            let mut d = match Dfs::mount(Box::new(SharedCut(cut.clone()))) {
                Ok(d) => d,
                Err((e, _)) => panic!("cut after {} writes (seed {}): mount failed: {:?}", n, seed, e),
            };
            let r = d.fsck().unwrap();
            assert_eq!(r.errors, 0, "cut after {} writes (seed {}): {:?}", n, seed, r);
            seen.insert(check_state(&mut d));
        }
    }
    // Every committed version was reachable as a post-cut state.
    assert_eq!(seen.len() as u64, STEPS + 1, "states seen: {:?}", seen);
}
