//! FAT32 (read/write, long file names), for boot partitions and data exchange with other
//! systems. Only FAT32 is accepted (65525 clusters or more, 512-byte sectors).
//!
//! The FAT is held in memory (4 bytes per cluster) and written back, to every copy, at the end
//! of each changing operation; directory sectors go through a small write-through cache; file
//! data moves in runs of contiguous clusters. FAT has no crash consistency of its own: an
//! interrupted operation can leave lost clusters (the usual FAT trade-off; DFS is the
//! filesystem for anything that must survive a power cut).
//!
//! Nodes are named by the position of their short directory entry (sector << 4 | index); the
//! root directory is node 0.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec;
use alloc::vec::Vec;

use crate::dev::{BlockDev, SECTOR};
use crate::{Entry, Error, FileSystem, Info, Ino, Kind, Result, Stat};

const EOC: u32 = 0x0FFF_FFF8;
const MASK: u32 = 0x0FFF_FFFF;
const ATTR_RO: u8 = 0x01;
const ATTR_VOLUME: u8 = 0x08;
const ATTR_DIR: u8 = 0x10;
const ATTR_ARCHIVE: u8 = 0x20;
const ATTR_LFN: u8 = 0x0F;
const MIN_CLUSTERS: u64 = 65525;
const ROOT: Ino = 0;

pub struct Fat<D: BlockDev> {
    pub dev: D,
    spc: u64,
    fat_start: u64,
    fat_sectors: u64,
    nfats: u64,
    data_start: u64,
    clusters: u32,
    root: u32,
    fsinfo: u64,
    fat: Vec<u32>,
    dirty: BTreeSet<u64>,
    free: u32,
    hint: u32,
    dcache: BTreeMap<u64, [u8; SECTOR]>,
    /// The wall-clock time (D-OS time) new and written entries get; 0: unknown (FAT date 0).
    now: i64,
}

fn le16(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
fn le32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

/// The checksum of a short name that long-name entries carry.
fn lfn_sum(short: &[u8]) -> u8 {
    short[..11].iter().fold(0u8, |s, &c| s.rotate_right(1).wrapping_add(c))
}

fn upper(c: u16) -> u16 {
    if (b'a' as u16..=b'z' as u16).contains(&c) { c - 32 } else { c }
}

/// The display form of a short name ("README.TXT"; lower case where NT flags say so).
fn short_display(e: &[u8]) -> Vec<u8> {
    let (lower_base, lower_ext) = (e[12] & 0x08 != 0, e[12] & 0x10 != 0);
    let conv = |c: u8, low: bool| -> u8 {
        let c = if c >= 0x80 { b'_' } else { c };
        if low { c.to_ascii_lowercase() } else { c }
    };
    let mut first = e[0];
    if first == 0x05 {
        first = 0xE5;
    }
    let mut base: Vec<u8> = core::iter::once(first).chain(e[1..8].iter().copied()).collect();
    while base.last() == Some(&b' ') {
        base.pop();
    }
    let mut out: Vec<u8> = base.iter().map(|&c| conv(c, lower_base)).collect();
    let ext: Vec<u8> = e[8..11].iter().copied().filter(|&c| c != b' ').collect();
    if !ext.is_empty() {
        out.push(b'.');
        out.extend(ext.iter().map(|&c| conv(c, lower_ext)));
    }
    out
}

const SHORT_OK: &[u8] = b"!#$%&'()-@^_`{}~";

fn short_char(c: u8) -> bool {
    c.is_ascii_uppercase() || c.is_ascii_digit() || SHORT_OK.contains(&c)
}

/// `name` as an exact 8.3 short name (upper case, valid characters), if it is one.
fn exact_short(name: &[u8]) -> Option<[u8; 11]> {
    let (base, ext) = match name.iter().position(|&c| c == b'.') {
        Some(i) => (&name[..i], &name[i + 1..]),
        None => (name, &[][..]),
    };
    if base.is_empty() || base.len() > 8 || ext.len() > 3 || !base.iter().chain(ext).all(|&c| short_char(c)) {
        return None;
    }
    let mut s = [b' '; 11];
    s[..base.len()].copy_from_slice(base);
    s[8..8 + ext.len()].copy_from_slice(ext);
    Some(s)
}

/// A short name for a long one: BASE~N.EXT.
fn basis(name: &[u8], n: u32) -> [u8; 11] {
    let clean = |c: u8| -> Option<u8> {
        let u = c.to_ascii_uppercase();
        if u == b' ' || u == b'.' {
            None
        } else if short_char(u) {
            Some(u)
        } else {
            Some(b'_')
        }
    };
    let dot = name.iter().rposition(|&c| c == b'.');
    let (b, e) = match dot {
        Some(i) if i > 0 => (&name[..i], &name[i + 1..]),
        _ => (name, &[][..]),
    };
    let base: Vec<u8> = b.iter().filter_map(|&c| clean(c)).collect();
    let ext: Vec<u8> = e.iter().filter_map(|&c| clean(c)).take(3).collect();
    let tail = alloc::format!("~{}", n);
    let keep = (8 - tail.len()).min(base.len());
    let mut s = [b' '; 11];
    s[..keep].copy_from_slice(&base[..keep]);
    s[keep..keep + tail.len()].copy_from_slice(tail.as_bytes());
    s[8..8 + ext.len()].copy_from_slice(&ext);
    if s[0] == b' ' {
        s[0] = b'_';
    }
    s
}

/// A name FAT can store: UTF-8, at most 255 UTF-16 units, no `"*/:<>?\|`, no trailing dot or
/// space.
fn fat_name(name: &[u8]) -> Result<Vec<u16>> {
    let s = core::str::from_utf8(name).map_err(|_| Error::BadName)?;
    if s.is_empty() || s.ends_with('.') || s.ends_with(' ') || s.chars().any(|c| (c as u32) < 0x20 || "\"*/:<>?\\|".contains(c)) {
        return Err(Error::BadName);
    }
    let u: Vec<u16> = s.encode_utf16().collect();
    if u.len() > 255 {
        return Err(Error::BadName);
    }
    Ok(u)
}

fn eq_fold(a: &[u16], b: &[u16]) -> bool {
    a.len() == b.len() && a.iter().zip(b).all(|(&x, &y)| upper(x) == upper(y))
}

/// One live directory entry found by `scan`.
struct Found {
    slot: usize,
    first_slot: usize,
    name: Vec<u16>,
    short: [u8; 32],
}

impl Found {
    fn kind(&self) -> Kind {
        if self.short[11] & ATTR_DIR != 0 { Kind::Dir } else { Kind::File }
    }
}

/// Format parameters: label (11 bytes) and serial number.
pub struct Format<'a> {
    pub label: &'a [u8],
    pub serial: u32,
    /// Sectors before this partition on its disk (the BPB's hidden sectors).
    pub hidden: u32,
}

/// Create an empty FAT32 filesystem on `dev`.
pub fn format(dev: &mut dyn BlockDev, f: &Format<'_>) -> Result<()> {
    let total = dev.sectors();
    let spc: u64 = match total * SECTOR as u64 {
        b if b < 260 << 20 => 1,
        b if b < 8 << 30 => 8,
        b if b < 16 << 30 => 16,
        b if b < 32 << 30 => 32,
        _ => 64,
    };
    let reserved = 32u64;
    let nfats = 2u64;
    let tmp2 = (256 * spc + nfats) / 2;
    let fatsz = (total - reserved).div_ceil(tmp2);
    let clusters = (total - reserved - nfats * fatsz) / spc;
    if clusters < MIN_CLUSTERS || total > 0xFFFF_FFFF {
        return Err(Error::NoSpace);
    }
    let mut bs = [0u8; SECTOR];
    bs[0..3].copy_from_slice(&[0xEB, 0x58, 0x90]);
    bs[3..11].copy_from_slice(b"D-OS    ");
    bs[11..13].copy_from_slice(&(SECTOR as u16).to_le_bytes());
    bs[13] = spc as u8;
    bs[14..16].copy_from_slice(&(reserved as u16).to_le_bytes());
    bs[16] = nfats as u8;
    bs[21] = 0xF8;
    bs[24..26].copy_from_slice(&32u16.to_le_bytes());
    bs[26..28].copy_from_slice(&64u16.to_le_bytes());
    bs[28..32].copy_from_slice(&f.hidden.to_le_bytes());
    bs[32..36].copy_from_slice(&(total as u32).to_le_bytes());
    bs[36..40].copy_from_slice(&(fatsz as u32).to_le_bytes());
    bs[44..48].copy_from_slice(&2u32.to_le_bytes());
    bs[48..50].copy_from_slice(&1u16.to_le_bytes());
    bs[50..52].copy_from_slice(&6u16.to_le_bytes());
    bs[64] = 0x80;
    bs[66] = 0x29;
    bs[67..71].copy_from_slice(&f.serial.to_le_bytes());
    let mut label = [b' '; 11];
    label[..f.label.len().min(11)].copy_from_slice(&f.label[..f.label.len().min(11)]);
    bs[71..82].copy_from_slice(&label);
    bs[82..90].copy_from_slice(b"FAT32   ");
    bs[510] = 0x55;
    bs[511] = 0xAA;
    let mut fsi = [0u8; SECTOR];
    fsi[0..4].copy_from_slice(&0x4161_5252u32.to_le_bytes());
    fsi[484..488].copy_from_slice(&0x6141_7272u32.to_le_bytes());
    fsi[488..492].copy_from_slice(&((clusters - 1) as u32).to_le_bytes());
    fsi[492..496].copy_from_slice(&3u32.to_le_bytes());
    fsi[508..512].copy_from_slice(&0xAA55_0000u32.to_le_bytes());
    let zero = vec![0u8; 32 * SECTOR];
    dev.write(0, &zero)?; // reserved area
    for copy in [0u64, 6] {
        dev.write(copy, &bs)?;
        dev.write(copy + 1, &fsi)?;
    }
    for i in 0..nfats {
        let start = reserved + i * fatsz;
        let mut s = 0;
        while s < fatsz {
            let n = (fatsz - s).min(32);
            dev.write(start + s, &zero[..n as usize * SECTOR])?;
            s += n;
        }
        let mut first = [0u8; SECTOR];
        first[0..4].copy_from_slice(&0x0FFF_FFF8u32.to_le_bytes());
        first[4..8].copy_from_slice(&0x0FFF_FFFFu32.to_le_bytes());
        first[8..12].copy_from_slice(&0x0FFF_FFFFu32.to_le_bytes()); // root directory: one cluster
        dev.write(start, &first)?;
    }
    let data = reserved + nfats * fatsz;
    let mut root = vec![0u8; spc as usize * SECTOR];
    root[0..11].copy_from_slice(&label);
    root[11] = ATTR_VOLUME;
    dev.write(data, &root)?;
    dev.flush()
}

impl<D: BlockDev> Fat<D> {
    pub fn mount(mut dev: D) -> Result<Fat<D>> {
        let mut bs = [0u8; SECTOR];
        dev.read(0, &mut bs)?;
        if bs[510] != 0x55 || bs[511] != 0xAA || le16(&bs, 11) as usize != SECTOR {
            return Err(Error::Unsupported);
        }
        let spc = u64::from(bs[13]);
        let reserved = u64::from(le16(&bs, 14));
        let nfats = u64::from(bs[16]);
        let fatsz = u64::from(le32(&bs, 36));
        let total = if le16(&bs, 19) != 0 { u64::from(le16(&bs, 19)) } else { u64::from(le32(&bs, 32)) };
        if !spc.is_power_of_two() || reserved == 0 || !(1..=2).contains(&nfats) || le16(&bs, 17) != 0 || le16(&bs, 22) != 0 || fatsz == 0 {
            return Err(Error::Unsupported); // not FAT32 (FAT12/16 have root entries and a 16-bit FAT size)
        }
        let data_start = reserved + nfats * fatsz;
        if total > dev.sectors() || data_start >= total {
            return Err(Error::Corrupt);
        }
        let clusters = (total - data_start) / spc;
        if clusters < MIN_CLUSTERS || fatsz * 128 < clusters + 2 || clusters > u64::from(MASK) - 16 {
            return Err(Error::Unsupported);
        }
        let root = le32(&bs, 44);
        if root < 2 || u64::from(root) >= clusters + 2 {
            return Err(Error::Corrupt);
        }
        let mut raw = vec![0u8; fatsz as usize * SECTOR];
        for (i, c) in raw.chunks_mut(64 * SECTOR).enumerate() {
            dev.read(reserved + (i * 64) as u64, c)?;
        }
        let n = clusters as usize + 2;
        let fat: Vec<u32> = (0..n).map(|i| le32(&raw, 4 * i) & MASK).collect();
        let free = fat[2..].iter().filter(|&&v| v == 0).count() as u32;
        let fsinfo = u64::from(le16(&bs, 48));
        Ok(Fat {
            dev,
            spc,
            fat_start: reserved,
            fat_sectors: fatsz,
            nfats,
            data_start,
            clusters: clusters as u32,
            root,
            fsinfo,
            fat,
            dirty: BTreeSet::new(),
            free,
            hint: 2,
            dcache: BTreeMap::new(),
            now: 0,
        })
    }

    fn cluster_bytes(&self) -> u64 {
        self.spc * SECTOR as u64
    }
    fn lba(&self, c: u32) -> u64 {
        self.data_start + u64::from(c - 2) * self.spc
    }
    fn valid(&self, c: u32) -> bool {
        c >= 2 && c < self.clusters + 2
    }

    fn next(&self, c: u32) -> Result<Option<u32>> {
        let v = self.fat[c as usize];
        if v >= EOC {
            return Ok(None);
        }
        if !self.valid(v) {
            return Err(Error::Corrupt); // free, bad or out-of-range cluster inside a chain
        }
        Ok(Some(v))
    }

    /// The clusters of the chain starting at `first` (0 = empty).
    fn chain(&self, first: u32) -> Result<Vec<u32>> {
        let mut out = Vec::new();
        if first == 0 {
            return Ok(out);
        }
        if !self.valid(first) {
            return Err(Error::Corrupt);
        }
        let mut c = first;
        loop {
            out.push(c);
            if out.len() > self.clusters as usize {
                return Err(Error::Corrupt); // a loop
            }
            match self.next(c)? {
                Some(n) => c = n,
                None => return Ok(out),
            }
        }
    }

    fn set(&mut self, c: u32, v: u32) {
        let old = self.fat[c as usize];
        if old == 0 && v != 0 {
            self.free -= 1;
        } else if old != 0 && v == 0 {
            self.free += 1;
        }
        self.fat[c as usize] = v;
        self.dirty.insert(u64::from(c) / 128);
    }

    fn alloc(&mut self) -> Result<u32> {
        let n = self.clusters + 2;
        for i in 0..self.clusters {
            let c = 2 + (self.hint - 2 + i) % self.clusters;
            if self.fat[c as usize] == 0 {
                self.set(c, MASK);
                self.hint = if c + 1 < n { c + 1 } else { 2 };
                return Ok(c);
            }
        }
        Err(Error::NoSpace)
    }

    fn free_chain(&mut self, first: u32) -> Result<()> {
        for c in self.chain(first)? {
            self.set(c, 0);
            let l = self.lba(c);
            for s in 0..self.spc {
                self.dcache.remove(&(l + s));
            }
        }
        Ok(())
    }

    fn flush_fat(&mut self) -> Result<()> {
        let dirty = core::mem::take(&mut self.dirty);
        for s in dirty {
            let mut b = [0u8; SECTOR];
            for i in 0..128 {
                let c = s as usize * 128 + i;
                let mut v = if c < self.fat.len() { self.fat[c] } else { 0 };
                if c == 0 {
                    v = 0x0FFF_FFF8;
                } else if c == 1 {
                    v = MASK;
                }
                b[4 * i..4 * i + 4].copy_from_slice(&v.to_le_bytes());
            }
            for k in 0..self.nfats {
                self.dev.write(self.fat_start + k * self.fat_sectors + s, &b)?;
            }
        }
        Ok(())
    }

    fn sector(&mut self, lba: u64) -> Result<[u8; SECTOR]> {
        if let Some(s) = self.dcache.get(&lba) {
            return Ok(*s);
        }
        let mut s = [0u8; SECTOR];
        self.dev.read(lba, &mut s)?;
        if self.dcache.len() >= 512 {
            self.dcache.clear();
        }
        self.dcache.insert(lba, s);
        Ok(s)
    }

    fn put_sector(&mut self, lba: u64, s: &[u8; SECTOR]) -> Result<()> {
        self.dev.write(lba, s)?;
        self.dcache.insert(lba, *s);
        Ok(())
    }

    fn first_cluster(e: &[u8]) -> u32 {
        (u32::from(le16(e, 20)) << 16 | u32::from(le16(e, 26))) & MASK
    }

    fn dirent(&mut self, ino: Ino) -> Result<[u8; 32]> {
        let (lba, i) = (ino >> 4, (ino & 15) as usize);
        if lba < self.data_start || lba >= self.data_start + u64::from(self.clusters) * self.spc {
            return Err(Error::NotFound);
        }
        let s = self.sector(lba)?;
        let mut e = [0u8; 32];
        e.copy_from_slice(&s[32 * i..32 * i + 32]);
        if e[0] == 0 || e[0] == 0xE5 || e[11] == ATTR_LFN {
            return Err(Error::NotFound); // deleted since it was opened
        }
        Ok(e)
    }

    fn put_dirent(&mut self, ino: Ino, e: &[u8; 32]) -> Result<()> {
        let (lba, i) = (ino >> 4, (ino & 15) as usize);
        let mut s = self.sector(lba)?;
        s[32 * i..32 * i + 32].copy_from_slice(e);
        self.put_sector(lba, &s)
    }

    /// (kind, first cluster, size) of a node.
    fn node(&mut self, ino: Ino) -> Result<(Kind, u32, u64)> {
        if ino == ROOT {
            return Ok((Kind::Dir, self.root, 0));
        }
        let e = self.dirent(ino)?;
        let kind = if e[11] & ATTR_DIR != 0 { Kind::Dir } else { Kind::File };
        Ok((kind, Self::first_cluster(&e), u64::from(le32(&e, 28))))
    }

    fn dir_cluster(&mut self, dir: Ino) -> Result<u32> {
        match self.node(dir)? {
            (Kind::Dir, c, _) => Ok(if c == 0 { self.root } else { c }),
            _ => Err(Error::NotDir),
        }
    }

    /// The sectors of a directory, in order.
    fn dir_sectors(&mut self, first: u32) -> Result<Vec<u64>> {
        let chain = self.chain(first)?;
        if chain.len() * self.spc as usize > 65536 * 32 / SECTOR {
            return Err(Error::Corrupt); // more than 65536 entries: not a valid FAT directory
        }
        Ok(chain.iter().flat_map(|&c| (0..self.spc).map(move |s| (c, s))).map(|(c, s)| self.lba(c) + s).collect())
    }

    fn slot(&mut self, secs: &[u64], slot: usize) -> Result<[u8; 32]> {
        let s = self.sector(secs[slot / 16])?;
        let mut e = [0u8; 32];
        e.copy_from_slice(&s[32 * (slot % 16)..32 * (slot % 16) + 32]);
        Ok(e)
    }

    fn slot_ino(secs: &[u64], slot: usize) -> Ino {
        secs[slot / 16] << 4 | (slot % 16) as u64
    }

    /// Live entries from `from` on (`.` and `..` and volume labels skipped); `f` returns false to
    /// stop. Returns the slot where scanning ended (the end of the directory if it was reached).
    fn scan(&mut self, secs: &[u64], from: usize, mut f: impl FnMut(&Found) -> bool) -> Result<usize> {
        let mut lfn: Vec<u16> = Vec::new();
        let (mut want, mut sum, mut start) = (0u8, 0u8, 0usize);
        let total = secs.len() * 16;
        let mut s = from;
        while s < total {
            let e = self.slot(secs, s)?;
            if e[0] == 0 {
                return Ok(total);
            }
            if e[0] == 0xE5 {
                want = 0;
                s += 1;
                continue;
            }
            if e[11] == ATTR_LFN {
                let ord = e[0] & 0x3F;
                if e[0] & 0x40 != 0 && (1..=20).contains(&ord) {
                    lfn = vec![0xFFFF; usize::from(ord) * 13];
                    sum = e[13];
                    start = s;
                    want = ord;
                }
                if ord == want && want > 0 && e[13] == sum {
                    let at = usize::from(ord - 1) * 13;
                    for (k, o) in [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30].iter().enumerate() {
                        lfn[at + k] = le16(&e, *o);
                    }
                    want -= 1;
                    if want == 0 {
                        want = 0xFF; // complete: waiting for its short entry
                    }
                } else {
                    want = 0;
                }
                s += 1;
                continue;
            }
            let long_ok = want == 0xFF && sum == lfn_sum(&e);
            want = 0;
            if e[11] & ATTR_VOLUME != 0 || e[0] == b'.' {
                s += 1;
                continue;
            }
            let name: Vec<u16> = if long_ok {
                lfn.iter().copied().take_while(|&c| c != 0 && c != 0xFFFF).collect()
            } else {
                short_display(&e).iter().map(|&c| u16::from(c)).collect()
            };
            let mut short = [0u8; 32];
            short.copy_from_slice(&e);
            let found = Found { slot: s, first_slot: if long_ok { start } else { s }, name, short };
            if !f(&found) {
                return Ok(found.first_slot); // resume here: its long name comes first
            }
            s += 1;
        }
        Ok(total)
    }

    fn find(&mut self, dir: Ino, name: &[u8]) -> Result<(Vec<u64>, Found)> {
        let u = fat_name(name)?;
        let first = self.dir_cluster(dir)?;
        let secs = self.dir_sectors(first)?;
        let mut hit = None;
        self.scan(&secs, 0, |f| {
            let short: Vec<u16> = short_display(&f.short).iter().map(|&c| u16::from(c)).collect();
            if eq_fold(&f.name, &u) || eq_fold(&short, &u) {
                hit = Some(Found { slot: f.slot, first_slot: f.first_slot, name: f.name.clone(), short: f.short });
                return false;
            }
            true
        })?;
        hit.map(|h| (secs, h)).ok_or(Error::NotFound)
    }

    fn zero_cluster(&mut self, c: u32) -> Result<()> {
        let z = vec![0u8; self.cluster_bytes() as usize];
        let l = self.lba(c);
        for s in 0..self.spc {
            self.dcache.remove(&(l + s));
        }
        self.dev.write(l, &z)
    }

    fn short_entry(name: &[u8; 11], attr: u8, cluster: u32, size: u32, now: i64) -> [u8; 32] {
        let mut e = [0u8; 32];
        e[..11].copy_from_slice(name);
        e[11] = attr;
        if let Some((date, time)) = crate::time::to_fat(now) {
            e[14..16].copy_from_slice(&time.to_le_bytes()); // created
            e[16..18].copy_from_slice(&date.to_le_bytes());
            e[18..20].copy_from_slice(&date.to_le_bytes()); // last access (date only)
            e[22..24].copy_from_slice(&time.to_le_bytes()); // last write
            e[24..26].copy_from_slice(&date.to_le_bytes());
        }
        e[20..22].copy_from_slice(&((cluster >> 16) as u16).to_le_bytes());
        e[26..28].copy_from_slice(&(cluster as u16).to_le_bytes());
        e[28..32].copy_from_slice(&size.to_le_bytes());
        e
    }

    fn write_slot(&mut self, secs: &[u64], slot: usize, e: &[u8; 32]) -> Result<()> {
        let lba = secs[slot / 16];
        let mut s = self.sector(lba)?;
        s[32 * (slot % 16)..32 * (slot % 16) + 32].copy_from_slice(e);
        self.put_sector(lba, &s)
    }

    /// Read `buf.len()` bytes at byte `off` of the cluster chain `chain` (whole sectors move
    /// directly; partial ones through a bounce sector).
    fn chain_io(&mut self, chain: &[u32], off: u64, buf: &mut [u8], write: Option<&[u8]>) -> Result<()> {
        let cb = self.cluster_bytes();
        let mut done = 0usize;
        let len = write.map_or(buf.len(), |w| w.len());
        while done < len {
            let pos = off + done as u64;
            let ci = (pos / cb) as usize;
            let in_c = pos % cb;
            // Extend over physically contiguous clusters (at most 32 KiB per transfer).
            let mut run = 1;
            while ci + run < chain.len() && chain[ci + run] == chain[ci] + run as u32 && (run as u64 * cb) < 32768 {
                run += 1;
            }
            let lba = self.lba(chain[ci]) + in_c / SECTOR as u64;
            let sec_off = (in_c % SECTOR as u64) as usize;
            let avail = (run as u64 * cb - in_c) as usize;
            let n = (len - done).min(avail).min(32768);
            if sec_off == 0 && n >= SECTOR {
                let whole = n / SECTOR * SECTOR;
                match write {
                    Some(w) => self.dev.write(lba, &w[done..done + whole])?,
                    None => self.dev.read(lba, &mut buf[done..done + whole])?,
                }
                done += whole;
            } else {
                let n = n.min(SECTOR - sec_off);
                let mut s = [0u8; SECTOR];
                self.dev.read(lba, &mut s)?;
                match write {
                    Some(w) => {
                        s[sec_off..sec_off + n].copy_from_slice(&w[done..done + n]);
                        self.dev.write(lba, &s)?;
                    }
                    None => buf[done..done + n].copy_from_slice(&s[sec_off..sec_off + n]),
                }
                done += n;
            }
        }
        Ok(())
    }

    fn zero_range(&mut self, chain: &[u32], from: u64, to: u64) -> Result<()> {
        let z = vec![0u8; 32768];
        let mut at = from;
        while at < to {
            let n = (to - at).min(32768) as usize;
            self.chain_io(chain, at, &mut [], Some(&z[..n]))?;
            at += n as u64;
        }
        Ok(())
    }

    /// Grow `ino`'s chain to at least `bytes`; newly added clusters are zeroed.
    fn grow(&mut self, ino: Ino, e: &mut [u8; 32], bytes: u64) -> Result<Vec<u32>> {
        let mut chain = self.chain(Self::first_cluster(e))?;
        let need = bytes.div_ceil(self.cluster_bytes()) as usize;
        while chain.len() < need {
            let c = self.alloc()?;
            self.zero_cluster(c)?;
            match chain.last() {
                Some(&p) => self.set(p, c),
                None => {
                    e[20..22].copy_from_slice(&((c >> 16) as u16).to_le_bytes());
                    e[26..28].copy_from_slice(&(c as u16).to_le_bytes());
                    self.put_dirent(ino, e)?;
                }
            }
            chain.push(c);
        }
        Ok(chain)
    }

    fn label(&mut self) -> Vec<u8> {
        let mut bs = [0u8; SECTOR];
        if self.dev.read(0, &mut bs).is_err() {
            return Vec::new();
        }
        let mut l: Vec<u8> = bs[71..82].to_vec();
        while l.last() == Some(&b' ') {
            l.pop();
        }
        l
    }

    /// The volume label from the boot sector.
    pub fn volume_label(&mut self) -> Vec<u8> {
        self.label()
    }
}

impl<D: BlockDev> Fat<D> {
    /// Record the current time as an entry's last write (and access) time. False if unknown.
    fn stamp(&self, e: &mut [u8; 32]) -> bool {
        let Some((date, time)) = crate::time::to_fat(self.now) else { return false };
        e[18..20].copy_from_slice(&date.to_le_bytes());
        e[22..24].copy_from_slice(&time.to_le_bytes());
        e[24..26].copy_from_slice(&date.to_le_bytes());
        true
    }

    fn remove_slots(&mut self, secs: &[u64], first: usize, last: usize) -> Result<()> {
        for s in first..=last {
            let mut e = self.slot(secs, s)?;
            e[0] = 0xE5;
            self.write_slot(secs, s, &e)?;
        }
        Ok(())
    }

    /// Write a new directory entry named `name` (`u`: its UTF-16 form) in the directory whose
    /// first cluster is `first`: long-name entries if needed and the short entry, which is
    /// `tmpl` with the short name filled in. Returns the new entry's node.
    fn insert_entry(&mut self, first: u32, name: &[u8], u: &[u16], tmpl: &[u8; 32]) -> Result<Ino> {
        let mut secs = self.dir_sectors(first)?;
        // Short names in use, to pick a unique one.
        let mut shorts = BTreeSet::new();
        self.scan(&secs, 0, |f| {
            let mut s = [0u8; 11];
            s.copy_from_slice(&f.short[..11]);
            shorts.insert(s);
            true
        })?;
        let (short, lfn) = match exact_short(name) {
            Some(s) if !shorts.contains(&s) => (s, false),
            _ => {
                let mut n = 1;
                loop {
                    let s = basis(name, n);
                    if !shorts.contains(&s) {
                        break (s, true);
                    }
                    n += 1;
                    if n > 999_999 {
                        return Err(Error::TooBig);
                    }
                }
            }
        };
        let nlfn = if lfn { u.len().div_ceil(13) } else { 0 };
        let need = nlfn + 1;
        // A run of `need` free slots (deleted, or past the end marker); else grow the directory.
        let at = loop {
            let mut run = 0;
            let mut found = None;
            for s in 0..secs.len() * 16 {
                let e = self.slot(&secs, s)?;
                if e[0] == 0 || e[0] == 0xE5 {
                    run += 1;
                    if run == need {
                        found = Some(s + 1 - need);
                        break;
                    }
                } else {
                    run = 0;
                }
            }
            if let Some(s) = found {
                break s;
            }
            if secs.len() * 16 + 16 > 65536 {
                return Err(Error::TooBig);
            }
            let c = self.alloc()?;
            self.zero_cluster(c)?;
            let last = *self.chain(first)?.last().ok_or(Error::Corrupt)?;
            self.set(last, c);
            secs = self.dir_sectors(first)?;
        };
        let sum = lfn_sum(&short);
        for i in 0..nlfn {
            let ord = (nlfn - i) as u8;
            let mut e = [0u8; 32];
            e[0] = ord | if i == 0 { 0x40 } else { 0 };
            e[11] = ATTR_LFN;
            e[13] = sum;
            let base = usize::from(ord - 1) * 13;
            for (k, o) in [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30].iter().enumerate() {
                let c = match base + k {
                    j if j < u.len() => u[j],
                    j if j == u.len() => 0,
                    _ => 0xFFFF,
                };
                e[*o..*o + 2].copy_from_slice(&c.to_le_bytes());
            }
            self.write_slot(&secs, at + i, &e)?;
        }
        let mut e = *tmpl;
        e[..11].copy_from_slice(&short);
        self.write_slot(&secs, at + nlfn, &e)?;
        Ok(Self::slot_ino(&secs, at + nlfn))
    }
}

impl<D: BlockDev> FileSystem for Fat<D> {
    fn root(&self) -> Ino {
        ROOT
    }

    fn lookup(&mut self, dir: Ino, name: &[u8]) -> Result<Ino> {
        let (secs, f) = self.find(dir, name)?;
        Ok(Self::slot_ino(&secs, f.slot))
    }

    fn create(&mut self, dir: Ino, name: &[u8], kind: Kind) -> Result<Ino> {
        let u = fat_name(name)?;
        match self.find(dir, name) {
            Ok(_) => return Err(Error::Exists),
            Err(Error::NotFound) => {}
            Err(e) => return Err(e),
        }
        let first = self.dir_cluster(dir)?;
        let cluster = match kind {
            Kind::Dir => {
                let c = self.alloc()?;
                self.zero_cluster(c)?;
                let mut s = [0u8; SECTOR];
                let dot = Self::short_entry(b".          ", ATTR_DIR, c, 0, self.now);
                let parent = if dir == ROOT { 0 } else { first };
                let dotdot = Self::short_entry(b"..         ", ATTR_DIR, parent, 0, self.now);
                s[..32].copy_from_slice(&dot);
                s[32..64].copy_from_slice(&dotdot);
                let l = self.lba(c);
                self.put_sector(l, &s)?;
                c
            }
            Kind::File => 0,
        };
        let attr = if kind == Kind::Dir { ATTR_DIR } else { ATTR_ARCHIVE };
        let tmpl = Self::short_entry(&[b' '; 11], attr, cluster, 0, self.now);
        match self.insert_entry(first, name, &u, &tmpl) {
            Ok(ino) => {
                self.flush_fat()?;
                Ok(ino)
            }
            Err(e) => {
                if cluster != 0 {
                    self.free_chain(cluster)?;
                }
                Err(e)
            }
        }
    }

    fn stat(&mut self, ino: Ino) -> Result<Stat> {
        let (kind, _, size) = self.node(ino)?;
        let (created, modified) = if ino == ROOT {
            (0, 0)
        } else {
            let e = self.dirent(ino)?;
            (crate::time::from_fat(le16(&e, 16), le16(&e, 14)), crate::time::from_fat(le16(&e, 24), le16(&e, 22)))
        };
        Ok(Stat { kind, size, created, modified })
    }

    fn set_time(&mut self, now: i64) {
        self.now = now;
    }

    /// The new name's entries are written before the old ones are removed: after a power cut
    /// in between, both names lead to the same data (never neither); a replaced file's clusters
    /// are freed last.
    fn rename(&mut self, from_dir: Ino, from: &[u8], to_dir: Ino, to: &[u8], replace: bool) -> Result<()> {
        let u = fat_name(to)?;
        let (src_secs, src) = self.find(from_dir, from)?;
        let src_ino = Self::slot_ino(&src_secs, src.slot);
        let to_first = self.dir_cluster(to_dir)?;
        let from_first = self.dir_cluster(from_dir)?;
        let mut replaced: Option<u32> = None;
        let mut case_only = false;
        match self.find(to_dir, to) {
            // The same entry (a change of case, or the same name): rewrite it under the new name.
            Ok((secs, d)) if Self::slot_ino(&secs, d.slot) == src_ino => case_only = true,
            Ok((secs, d)) => {
                if !replace {
                    return Err(Error::Exists);
                }
                if d.kind() == Kind::Dir || src.kind() == Kind::Dir {
                    return Err(if d.kind() == Kind::Dir { Error::IsDir } else { Error::NotDir });
                }
                // Take the old target's name away (its clusters are freed at the end).
                for s in d.first_slot..=d.slot {
                    let mut e = self.slot(&secs, s)?;
                    e[0] = 0xE5;
                    self.write_slot(&secs, s, &e)?;
                }
                replaced = Some(Self::first_cluster(&d.short));
            }
            Err(Error::NotFound) => {}
            Err(e) => return Err(e),
        }
        let mut tmpl = src.short;
        tmpl[12] = 0; // case flags belonged to the old short name
        if let Some((date, _)) = crate::time::to_fat(self.now) {
            tmpl[18..20].copy_from_slice(&date.to_le_bytes());
        }
        if case_only {
            // Only the case changes: the old entries go first (their short name may be reused).
            self.remove_slots(&src_secs, src.first_slot, src.slot)?;
            self.insert_entry(to_first, to, &u, &tmpl)?;
        } else {
            self.insert_entry(to_first, to, &u, &tmpl)?;
            let (secs, now_src) = self.find(from_dir, from)?;
            self.remove_slots(&secs, now_src.first_slot, now_src.slot)?;
        }
        // A directory that moved: its .. names the new parent.
        let first = Self::first_cluster(&src.short);
        if src.kind() == Kind::Dir && from_first != to_first && first != 0 {
            let l = self.lba(first);
            let mut s = self.sector(l)?;
            if &s[32..43] == b"..         " {
                let p = if to_dir == ROOT { 0 } else { to_first };
                s[32 + 20..32 + 22].copy_from_slice(&((p >> 16) as u16).to_le_bytes());
                s[32 + 26..32 + 28].copy_from_slice(&(p as u16).to_le_bytes());
                self.put_sector(l, &s)?;
            }
        }
        if let Some(c) = replaced
            && c != 0
        {
            self.free_chain(c)?;
        }
        self.flush_fat()
    }

    fn read(&mut self, ino: Ino, off: u64, buf: &mut [u8]) -> Result<usize> {
        let (kind, first, size) = self.node(ino)?;
        if kind == Kind::Dir {
            return Err(Error::IsDir);
        }
        if off >= size {
            return Ok(0);
        }
        let n = (size - off).min(buf.len() as u64) as usize;
        let chain = self.chain(first)?;
        if (chain.len() as u64) * self.cluster_bytes() < size {
            return Err(Error::Corrupt); // the chain is shorter than the file
        }
        self.chain_io(&chain, off, &mut buf[..n], None)?;
        Ok(n)
    }

    fn write(&mut self, ino: Ino, off: u64, data: &[u8]) -> Result<usize> {
        if ino == ROOT {
            return Err(Error::IsDir);
        }
        let mut e = self.dirent(ino)?;
        if e[11] & ATTR_DIR != 0 {
            return Err(Error::IsDir);
        }
        if e[11] & ATTR_RO != 0 {
            return Err(Error::ReadOnly);
        }
        let size = u64::from(le32(&e, 28));
        let end = off.checked_add(data.len() as u64).ok_or(Error::TooBig)?;
        if end > 0xFFFF_FFFF {
            return Err(Error::TooBig);
        }
        let chain = self.grow(ino, &mut e, end.max(size))?;
        if off > size {
            // The gap reads as zeros: clear the old tail of the last cluster that held data.
            self.zero_range(&chain, size, off)?;
        }
        self.chain_io(&chain, off, &mut [], Some(data))?;
        let stamped = self.stamp(&mut e);
        if end > size {
            e[28..32].copy_from_slice(&(end as u32).to_le_bytes());
        }
        if end > size || stamped {
            self.put_dirent(ino, &e)?;
        }
        self.flush_fat()?;
        Ok(data.len())
    }

    fn truncate(&mut self, ino: Ino, size: u64) -> Result<()> {
        if ino == ROOT {
            return Err(Error::IsDir);
        }
        let mut e = self.dirent(ino)?;
        if e[11] & ATTR_DIR != 0 {
            return Err(Error::IsDir);
        }
        let old = u64::from(le32(&e, 28));
        self.stamp(&mut e);
        if size > old {
            if size > 0xFFFF_FFFF {
                return Err(Error::TooBig);
            }
            let chain = self.grow(ino, &mut e, size)?;
            self.zero_range(&chain, old, size)?;
            e[28..32].copy_from_slice(&(size as u32).to_le_bytes());
            self.put_dirent(ino, &e)?;
            return self.flush_fat();
        }
        let chain = self.chain(Self::first_cluster(&e))?;
        let keep = size.div_ceil(self.cluster_bytes()) as usize;
        if keep < chain.len() {
            if keep == 0 {
                e[20..22].fill(0);
                e[26..28].fill(0);
            } else {
                self.set(chain[keep - 1], MASK);
            }
            self.free_chain(chain[keep])?;
        }
        e[28..32].copy_from_slice(&(size as u32).to_le_bytes());
        self.put_dirent(ino, &e)?;
        self.flush_fat()
    }

    fn readdir(&mut self, dir: Ino, cookie: u64, max: usize) -> Result<(Vec<Entry>, Option<u64>)> {
        let first = self.dir_cluster(dir)?;
        let secs = self.dir_sectors(first)?;
        let mut out = Vec::new();
        let mut last = 0;
        let end = self.scan(&secs, cookie as usize, |f| {
            if out.len() == max {
                return false;
            }
            let name = alloc::string::String::from_utf16_lossy(&f.name).into_bytes();
            out.push(Entry { name, kind: f.kind(), ino: Self::slot_ino(&secs, f.slot) });
            last = f.slot;
            true
        })?;
        let total = secs.len() * 16;
        let _ = last;
        Ok((out, if end >= total { None } else { Some(end as u64) }))
    }

    fn unlink(&mut self, dir: Ino, name: &[u8]) -> Result<()> {
        let (secs, f) = self.find(dir, name)?;
        let first = Self::first_cluster(&f.short);
        if f.kind() == Kind::Dir {
            let sub = self.dir_sectors(first)?;
            let mut any = false;
            self.scan(&sub, 0, |_| {
                any = true;
                false
            })?;
            if any {
                return Err(Error::NotEmpty);
            }
        }
        for s in f.first_slot..=f.slot {
            let mut e = self.slot(&secs, s)?;
            e[0] = 0xE5;
            self.write_slot(&secs, s, &e)?;
        }
        if first != 0 {
            self.free_chain(first)?;
        }
        self.flush_fat()
    }

    fn sync(&mut self) -> Result<()> {
        self.flush_fat()?;
        if self.fsinfo != 0 && self.fsinfo < self.fat_start {
            let mut s = [0u8; SECTOR];
            self.dev.read(self.fsinfo, &mut s)?;
            if le32(&s, 0) == 0x4161_5252 && le32(&s, 484) == 0x6141_7272 {
                s[488..492].copy_from_slice(&self.free.to_le_bytes());
                s[492..496].copy_from_slice(&self.hint.to_le_bytes());
                self.dev.write(self.fsinfo, &s)?;
            }
        }
        self.dev.flush()
    }

    fn info(&mut self) -> Info {
        Info { total_blocks: u64::from(self.clusters), free_blocks: u64::from(self.free), block_size: self.cluster_bytes(), generation: 0 }
    }

    fn read_only(&self, _ino: Ino) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dev::MemDev;

    fn fresh() -> Fat<MemDev> {
        let mut d = MemDev::new(80 * 2048); // 40 MiB
        format(&mut d, &Format { label: b"TEST", serial: 1, hidden: 0 }).unwrap();
        Fat::mount(d).unwrap()
    }

    #[test]
    fn rename_and_times() {
        let mut f = fresh();
        let r = f.root();
        let t = crate::time::from_civil(2026, 11, 18, 10, 20, 30);
        f.set_time(t);
        let a = f.create(r, b"Docs", Kind::Dir).unwrap();
        let b = f.create(r, b"Archive", Kind::Dir).unwrap();
        let x = f.create(a, b"report draft.txt", Kind::File).unwrap();
        f.write(x, 0, b"contents").unwrap();
        let st = f.stat(x).unwrap();
        assert_eq!((st.created, st.modified), (t, t));
        f.set_time(t + 60_000_000_000);
        f.write(x, 8, b"!").unwrap();
        assert_eq!(f.stat(x).unwrap().modified, t + 60_000_000_000);
        // Across directories, with a long name; the old name is gone.
        f.rename(a, b"report draft.txt", b, b"Final report.txt", false).unwrap();
        assert_eq!(f.lookup(a, b"report draft.txt"), Err(Error::NotFound));
        let y = f.lookup(b, b"final REPORT.txt").unwrap();
        let mut buf = [0u8; 9];
        f.read(y, 0, &mut buf).unwrap();
        assert_eq!(&buf, b"contents!");
        assert_eq!(f.stat(y).unwrap().created, t);
        // A change of case only.
        f.rename(b, b"final report.txt", b, b"FINAL REPORT.TXT", false).unwrap();
        let (names, _) = f.readdir(b, 0, 10).unwrap();
        assert_eq!(names.iter().map(|e| e.name.as_slice()).collect::<Vec<_>>(), [&b"FINAL REPORT.TXT"[..]]);
        // Existing names: refused unless replacing a file.
        let z = f.create(b, b"old.txt", Kind::File).unwrap();
        f.write(z, 0, &[7u8; 20000]).unwrap();
        let free = f.info().free_blocks;
        assert_eq!(f.rename(b, b"FINAL REPORT.TXT", b, b"old.txt", false), Err(Error::Exists));
        f.rename(b, b"FINAL REPORT.TXT", b, b"old.txt", true).unwrap();
        assert!(f.info().free_blocks > free); // the replaced file's clusters are free
        let o = f.lookup(b, b"old.txt").unwrap();
        f.read(o, 0, &mut buf).unwrap();
        assert_eq!(&buf, b"contents!");
        // A directory moved into another: its .. follows.
        f.rename(r, b"Archive", a, b"Archive", false).unwrap();
        f.sync().unwrap();
        let mut f = Fat::mount(f.dev).unwrap();
        let r = f.root();
        let a = f.lookup(r, b"Docs").unwrap();
        let b = f.lookup(a, b"Archive").unwrap();
        assert!(f.lookup(b, b"old.txt").is_ok());
        let bc = f.dir_cluster(b).unwrap();
        let s = f.sector(f.lba(bc)).unwrap();
        assert_eq!(Fat::<MemDev>::first_cluster(&s[32..64]), f.dir_cluster(a).unwrap());
    }

    /// A rename cut at every sector: the file keeps at least one of its names, intact, and the
    /// tables stay readable (FAT has no transactions: both names may survive, pointing at the same
    /// clusters, never neither).
    #[test]
    fn rename_power_cut_sweep() {
        use crate::dev::{CutDev, SharedCut};
        use alloc::rc::Rc;
        use core::cell::RefCell;
        let cut = Rc::new(RefCell::new(CutDev::new(MemDev::new(80 * 2048))));
        {
            let mut d = SharedCut(cut.clone());
            format(&mut d, &Format { label: b"CUT", serial: 2, hidden: 0 }).unwrap();
            let mut f = Fat::mount(SharedCut(cut.clone())).unwrap();
            let r = f.root();
            let a = f.create(r, b"from", Kind::Dir).unwrap();
            f.create(r, b"to", Kind::Dir).unwrap();
            let x = f.create(a, b"a long document name.txt", Kind::File).unwrap();
            f.write(x, 0, &[0x5A; 6000]).unwrap();
            f.sync().unwrap();
        }
        let base = cut.borrow().inner.data.clone();
        let w0 = cut.borrow().writes;
        {
            let mut f = Fat::mount(SharedCut(cut.clone())).unwrap();
            let r = f.root();
            let (a, b) = (f.lookup(r, b"from").unwrap(), f.lookup(r, b"to").unwrap());
            f.rename(a, b"a long document name.txt", b, b"renamed document.txt", false).unwrap();
            f.sync().unwrap();
        }
        let total = cut.borrow().writes - w0;
        let mut both = 0;
        for n in 0..=total {
            {
                let mut c = cut.borrow_mut();
                c.inner.data.copy_from_slice(&base);
                c.restore();
                c.arm(n, 77 + n);
            }
            if let Ok(mut f) = Fat::mount(SharedCut(cut.clone())) {
                let r = f.root();
                let (a, b) = (f.lookup(r, b"from").unwrap(), f.lookup(r, b"to").unwrap());
                let _ = f.rename(a, b"a long document name.txt", b, b"renamed document.txt", false).and_then(|_| f.sync());
            }
            cut.borrow_mut().restore();
            let mut f = Fat::mount(SharedCut(cut.clone())).unwrap();
            let r = f.root();
            let (a, b) = (f.lookup(r, b"from").unwrap(), f.lookup(r, b"to").unwrap());
            let old = f.lookup(a, b"a long document name.txt").ok();
            let new = f.lookup(b, b"renamed document.txt").ok();
            assert!(old.is_some() || new.is_some(), "cut after {} writes: the file has no name", n);
            both += usize::from(old.is_some() && new.is_some());
            for x in [old, new].into_iter().flatten() {
                let mut g = vec![0u8; 6000];
                assert_eq!(f.read(x, 0, &mut g).unwrap(), 6000);
                assert!(g.iter().all(|&c| c == 0x5A), "cut after {} writes: content", n);
            }
        }
        std::println!("fat rename power cut sweep: {} cut points, never nameless ({} left both names)", total + 1, both);
    }

    #[test]
    fn files_and_long_names() {
        let mut f = fresh();
        let r = f.root();
        let a = f.create(r, b"README.TXT", Kind::File).unwrap();
        f.write(a, 0, b"hello").unwrap();
        let b = f.create(r, b"A rather long file name.text", Kind::File).unwrap();
        let data: Vec<u8> = (0..100_000u32).map(|i| (i * 7) as u8).collect();
        f.write(b, 0, &data).unwrap();
        let d = f.create(r, b"Sub dir", Kind::Dir).unwrap();
        let c = f.create(d, b"inner.bin", Kind::File).unwrap();
        f.write(c, 5000, b"x").unwrap();
        f.sync().unwrap();
        let mut f = Fat::mount(f.dev).unwrap();
        let r = f.root();
        let b = f.lookup(r, b"a RATHER long FILE name.text").unwrap();
        let mut got = vec![0u8; 100_000];
        assert_eq!(f.read(b, 0, &mut got).unwrap(), 100_000);
        assert_eq!(got, data);
        assert_eq!(f.lookup(r, b"readme.txt").unwrap(), f.lookup(r, b"README.TXT").unwrap());
        let d = f.lookup(r, b"Sub dir").unwrap();
        let c = f.lookup(d, b"inner.bin").unwrap();
        let mut g = vec![1u8; 5001];
        assert_eq!(f.read(c, 0, &mut g).unwrap(), 5001);
        assert!(g[..5000].iter().all(|&x| x == 0) && g[5000] == b'x');
        let (names, end) = f.readdir(r, 0, 100).unwrap();
        assert!(end.is_none());
        let n: Vec<&[u8]> = names.iter().map(|e| e.name.as_slice()).collect();
        assert_eq!(n, [&b"README.TXT"[..], b"A rather long file name.text", b"Sub dir"]);
        assert_eq!(f.unlink(r, b"Sub dir"), Err(Error::NotEmpty));
        let free0 = f.info().free_blocks;
        f.unlink(d, b"inner.bin").unwrap();
        f.unlink(r, b"Sub dir").unwrap();
        f.truncate(b, 10).unwrap();
        assert!(f.info().free_blocks > free0 + 150);
        assert_eq!(f.lookup(r, b"Sub dir"), Err(Error::NotFound));
        assert_eq!(f.create(r, b"bad:name", Kind::File), Err(Error::BadName));
        // Many entries: the root directory grows.
        for i in 0..300 {
            f.create(r, alloc::format!("file number {}", i).as_bytes(), Kind::File).unwrap();
        }
        let mut count = 0;
        let mut cookie = 0;
        loop {
            let (e, next) = f.readdir(r, cookie, 7).unwrap();
            count += e.len();
            match next {
                Some(c) => cookie = c,
                None => break,
            }
        }
        assert_eq!(count, 302);
    }
}
