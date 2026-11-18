//! Filesystem fuzzing (host, `cargo test`).
//!
//! A disk is untrusted input: storaged mounts whatever is plugged in. Each test builds a real
//! image, then, many times over, damages a copy and hands it to the code storaged runs.
//!
//! GPT: partition entries and header fields are mutated, and the CRCs recomputed so the damage
//! gets past the checksums into the parser (plus plain mutations that must fail the CRC).
//!
//! FAT32 and DFS: random bytes are changed in sectors that hold data (metadata and file contents,
//! biased to the first ones), then the image is mounted, every directory walked, every file
//! stat-ed and read, written, truncated, unlinked, synced, and (DFS) checked with fsck.
//! Errors are fine; a panic, an out-of-range result or a hang is a failure. Each case runs in a
//! worker thread with a watchdog (no progress for 20 s = hang), and reports the seed that failed.

use crate::dev::{BlockDev, MemDev, SECTOR, crc32};
use crate::dfs::{Dfs, FormatOpts};
use crate::{FileSystem, Ino, Kind, fat, gpt};
use std::boxed::Box;
use std::format;
use std::string::String;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use std::vec::Vec;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        if n == 0 { 0 } else { (self.next() % n as u64) as usize }
    }
}

fn seed0() -> u64 {
    std::env::var("DOS_FUZZ_SEED").ok().and_then(|s| s.parse().ok()).unwrap_or_else(|| {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos() as u64).unwrap_or(1)
    }) | 1
}

/// Run `body(seed)` for `iters` seeds in a worker thread, with a hang watchdog. Panics (fails the
/// test) naming the seed that panicked or hung.
fn campaign(name: &'static str, iters: u64, body: fn(u64) -> bool) {
    // DOS_FUZZ_SCALE=N runs N times as many (a longer campaign than the test suite's).
    let iters = iters * std::env::var("DOS_FUZZ_SCALE").ok().and_then(|s| s.parse().ok()).unwrap_or(1u64).max(1);
    let base = seed0();
    let progress = Arc::new(AtomicU64::new(0));
    let accepted = Arc::new(AtomicU64::new(0));
    let (p, acc) = (progress.clone(), accepted.clone());
    let worker = std::thread::spawn(move || {
        for i in 0..iters {
            p.store(i + 1, Ordering::SeqCst);
            let seed = base.wrapping_add(i.wrapping_mul(0x9E37_79B9_7F4A_7C15)) | 1;
            match std::panic::catch_unwind(|| body(seed)) {
                Ok(true) => {
                    acc.fetch_add(1, Ordering::Relaxed);
                }
                Ok(false) => {}
                Err(_) => return Err(seed),
            }
        }
        Ok(())
    });
    let (mut last, mut since) = (0, Instant::now());
    while !worker.is_finished() {
        std::thread::sleep(Duration::from_millis(50));
        let now = progress.load(Ordering::SeqCst);
        if now != last {
            (last, since) = (now, Instant::now());
        } else if since.elapsed() > Duration::from_secs(20) {
            panic!("{} fuzz: HANG at iteration {} (DOS_FUZZ_SEED={} reproduces the run)", name, now, base);
        }
    }
    match worker.join().unwrap() {
        Ok(()) => std::println!(
            "{} fuzz: {} damaged images ({} still accepted and fully exercised), no panic, no hang",
            name,
            iters,
            accepted.load(Ordering::Relaxed)
        ),
        Err(seed) => panic!("{} fuzz: PANIC with seed {} (run DOS_FUZZ_SEED={})", name, seed, base),
    }
}

/// Sectors of `d` that are not all zero (where the filesystem put something).
fn used_sectors(d: &MemDev) -> Vec<usize> {
    d.data.chunks(SECTOR).enumerate().filter(|(_, s)| s.iter().any(|&b| b != 0)).map(|(i, _)| i).collect()
}

fn damage(rng: &mut Rng, d: &mut MemDev, used: &[usize]) {
    let n = 1 + rng.below(6);
    for _ in 0..n {
        // Half the time the first used sectors: boot sector, FSInfo, the FATs, superblocks.
        let sec = match rng.below(8) {
            0 => rng.below(d.data.len() / SECTOR),
            1..=4 => used[rng.below(used.len() / 16 + 1)],
            _ => used[rng.below(used.len())],
        };
        let at = sec * SECTOR + rng.below(SECTOR);
        match rng.below(5) {
            0 => d.data[at] ^= 1 << rng.below(8),
            1 => d.data[at] = rng.next() as u8,
            2 => d.data[at] = [0, 0xFF, 0x80, 0x7F, 1][rng.below(5)],
            3 => {
                let w = at & !3;
                let v = [0u32, u32::MAX, 0x0FFF_FFF7, 0x0FFF_FFFF, 2, rng.next() as u32][rng.below(6)];
                d.data[w..w + 4].copy_from_slice(&v.to_le_bytes());
            }
            _ => {
                let w = at & !7;
                let v = [0u64, u64::MAX, 1 << 40, rng.next()][rng.below(4)];
                d.data[w..w + 8].copy_from_slice(&v.to_le_bytes());
            }
        }
    }
}

/// Everything a client can do through storaged, bounded (a corrupted directory may be endless
/// or contain itself).
fn exercise(fs: &mut dyn FileSystem, rng: &mut Rng) {
    let mut budget = 3000u32;
    let mut stack: Vec<(Ino, u32)> = std::vec![(fs.root(), 0)];
    let mut files = Vec::new();
    let mut buf = std::vec![0u8; 65536];
    while let Some((dir, depth)) = stack.pop() {
        let mut cookie = 0;
        for _ in 0..64 {
            if budget == 0 {
                break;
            }
            budget -= 1;
            let Ok((entries, next)) = fs.readdir(dir, cookie, 64) else { break };
            for e in entries {
                budget = budget.saturating_sub(1);
                let _ = fs.lookup(dir, &e.name);
                match fs.stat(e.ino) {
                    Ok(st) if st.kind == Kind::Dir && depth < 8 => stack.push((e.ino, depth + 1)),
                    Ok(st) if st.kind == Kind::File => files.push((e.ino, st.size)),
                    _ => {}
                }
            }
            match next {
                Some(c) => cookie = c,
                None => break,
            }
        }
    }
    for &(ino, size) in files.iter().take(64) {
        let offs = [0, size / 2, size.saturating_sub(100), size, size + 4096, u64::MAX - 10];
        for off in offs {
            let want = 1 + rng.below(buf.len());
            if let Ok(n) = fs.read(ino, off, &mut buf[..want]) {
                assert!(n <= want, "read returned {} bytes for a {}-byte buffer", n, want);
            }
        }
    }
    // Writes on the damaged volume (the copy is ours): must fail cleanly or work.
    let root = fs.root();
    if let Ok(f) = fs.create(root, b"FUZZ.BIN", Kind::File) {
        let _ = fs.write(f, rng.below(100_000) as u64, &buf[..1 + rng.below(20_000)]);
        let _ = fs.truncate(f, rng.below(50_000) as u64);
    }
    if let Some(&(ino, _)) = files.first() {
        let _ = fs.write(ino, 0, b"overwritten");
    }
    let _ = fs.create(root, b"fuzzdir", Kind::Dir);
    let _ = fs.unlink(root, b"FUZZ.BIN");
    let _ = fs.sync();
    let _ = fs.info();
}

fn populate(fs: &mut dyn FileSystem) {
    let r = fs.root();
    let docs = fs.create(r, b"Documents and notes", Kind::Dir).unwrap();
    for i in 0..40 {
        let f = fs.create(docs, format!("a fairly long file name number {:02}.txt", i).as_bytes(), Kind::File).unwrap();
        fs.write(f, 0, format!("file {} ", i).repeat(i * 7 + 1).as_bytes()).unwrap();
    }
    let sub = fs.create(docs, b"SUB", Kind::Dir).unwrap();
    let big = fs.create(sub, b"BIG.BIN", Kind::File).unwrap();
    let data: Vec<u8> = (0..200_000u32).map(|i| (i * 13) as u8).collect();
    fs.write(big, 0, &data).unwrap();
    let f = fs.create(r, b"README.TXT", Kind::File).unwrap();
    fs.write(f, 0, b"hello").unwrap();
    fs.sync().unwrap();
}

// ---- GPT ------------------------------------------------------------------------------------------

fn gpt_base() -> MemDev {
    let mut d = MemDev::new(8 * 2048);
    let parts = [
        gpt::NewPart { type_guid: gpt::TYPE_ESP, name: "boot", sectors: 2048 },
        gpt::NewPart { type_guid: gpt::TYPE_BASIC_DATA, name: "data", sectors: 4096 },
        gpt::NewPart { type_guid: gpt::TYPE_DFS, name: "system", sectors: 0 },
    ];
    gpt::write(&mut d, &parts, [3; 16]).unwrap();
    d
}

/// Recompute the CRCs of the header at `lba` (and of its entry array) after a mutation.
fn gpt_fix_crcs(d: &mut MemDev, lba: usize) {
    let h = lba * SECTOR;
    let hsize = u32::from_le_bytes(d.data[h + 12..h + 16].try_into().unwrap()) as usize;
    let entries_lba = u64::from_le_bytes(d.data[h + 72..h + 80].try_into().unwrap()) as usize;
    let count = u32::from_le_bytes(d.data[h + 80..h + 84].try_into().unwrap()) as usize;
    let esize = u32::from_le_bytes(d.data[h + 84..h + 88].try_into().unwrap()) as usize;
    if let Some(len) = count.checked_mul(esize)
        && let Some(start) = entries_lba.checked_mul(SECTOR)
        && start.checked_add(len).is_some_and(|e| e <= d.data.len())
        && len <= 1 << 20
    {
        let c = crc32(&d.data[start..start + len]);
        d.data[h + 88..h + 92].copy_from_slice(&c.to_le_bytes());
    }
    if (92..=SECTOR).contains(&hsize) {
        d.data[h + 16..h + 20].copy_from_slice(&[0; 4]);
        let c = crc32(&d.data[h..h + hsize]);
        d.data[h + 16..h + 20].copy_from_slice(&c.to_le_bytes());
    }
}

fn gpt_one(seed: u64) -> bool {
    let mut rng = Rng(seed);
    let mut d = gpt_base();
    let disk = d.sectors();
    let n = 1 + rng.below(6);
    for _ in 0..n {
        // The primary header (LBA 1) or its first entries (LBA 2), or the backup header.
        let (sec, span) = match rng.below(4) {
            0 => (1, 92),
            1 | 2 => (2, SECTOR),
            _ => (disk as usize - 1, 92),
        };
        let at = sec * SECTOR + rng.below(span);
        match rng.below(3) {
            0 => d.data[at] ^= 1 << rng.below(8),
            1 => d.data[at] = rng.next() as u8,
            _ => {
                let w = at & !7;
                let v = [0u64, u64::MAX, disk, disk - 1, disk + 1, 1, 34, rng.next()][rng.below(8)];
                d.data[w..w + 8].copy_from_slice(&v.to_le_bytes());
            }
        }
    }
    if rng.below(4) != 0 {
        gpt_fix_crcs(&mut d, 1);
        gpt_fix_crcs(&mut d, disk as usize - 1);
    }
    let Ok((parts, _)) = gpt::read(&mut d) else { return false };
    {
        let mut spans: Vec<(u64, u64)> = Vec::new();
        for p in &parts {
            assert!(p.first <= p.last && p.last < disk, "partition {:?} outside the {}-sector disk", (p.first, p.last), disk);
            for &(f, l) in &spans {
                assert!(p.last < f || p.first > l, "partitions overlap");
            }
            spans.push((p.first, p.last));
            let _: &String = &p.name;
        }
    }
    true
}

#[test]
fn fuzz_gpt() {
    campaign("gpt", 20_000, gpt_one);
}

// ---- FAT32 ----------------------------------------------------------------------------------------

fn fat_base() -> &'static (MemDev, Vec<usize>) {
    static BASE: std::sync::OnceLock<(MemDev, Vec<usize>)> = std::sync::OnceLock::new();
    BASE.get_or_init(|| {
        let mut d = MemDev::new(68 * 1024); // 34 MiB: the smallest FAT32 with 512-byte clusters
        fat::format(&mut d, &fat::Format { label: b"FUZZ", serial: 7, hidden: 0 }).unwrap();
        let mut f = fat::Fat::mount(d).unwrap();
        populate(&mut f);
        let d = f.dev;
        let used = used_sectors(&d);
        (d, used)
    })
}

fn fat_one(seed: u64) -> bool {
    let mut rng = Rng(seed);
    let (base, used) = fat_base();
    let mut d = MemDev { data: base.data.clone() };
    damage(&mut rng, &mut d, used);
    let Ok(mut f) = fat::Fat::mount(d) else { return false };
    exercise(&mut f, &mut rng);
    true
}

#[test]
fn fuzz_fat32() {
    campaign("fat32", 1_500, fat_one);
}

// ---- DFS ------------------------------------------------------------------------------------------

fn dfs_base() -> &'static (MemDev, Vec<usize>) {
    static BASE: std::sync::OnceLock<(MemDev, Vec<usize>)> = std::sync::OnceLock::new();
    BASE.get_or_init(|| {
        let mut fs = Dfs::format(Box::new(MemDev::new(16 * 2048)), &FormatOpts { label: b"fuzz", uuid: [5; 16] }).unwrap();
        populate(&mut fs);
        fs.snapshot(b"before").unwrap();
        let r = fs.root();
        let f = fs.create(r, b"after-snapshot", Kind::File).unwrap();
        fs.write(f, 0, &[0x5A; 9000]).unwrap();
        fs.sync().unwrap();
        let mut dev = fs.into_dev();
        let mut d = MemDev::new(dev.sectors());
        dev.read(0, &mut d.data).unwrap();
        let used = used_sectors(&d);
        (d, used)
    })
}

fn dfs_one(seed: u64) -> bool {
    let mut rng = Rng(seed);
    let (base, used) = dfs_base();
    let mut d = MemDev { data: base.data.clone() };
    damage(&mut rng, &mut d, used);
    let Ok(mut fs) = Dfs::mount(Box::new(d)) else { return false };
    let _ = fs.fsck();
    exercise(&mut fs, &mut rng);
    let _ = fs.open_snapshot(b"before").map(|_| ());
    let _ = fs.fsck();
    true
}

#[test]
fn fuzz_dfs() {
    campaign("dfs", 1_500, dfs_one);
}
