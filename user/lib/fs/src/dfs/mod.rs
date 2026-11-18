//! DFS, the D-OS native filesystem (v1). Design (decided with the project owner, 14/11/26):
//! a copy-on-write B+tree, BLAKE3 Merkle checksums, atomic commits through a superblock ring,
//! snapshots as saved read-only roots. Full on-disk format: docs/storage.md.
//!
//! - Blocks are 4 KiB. Block 0 is reserved; blocks 1-4 are the superblock ring (generation g
//!   goes to slot g % 4); everything else is allocated from a bitmap.
//! - Every block pointer is (address, birth generation, BLAKE3 hash). A node or data block is
//!   only ever trusted if its hash matches the pointer that led to it; the superblock hashes
//!   itself. Corruption anywhere is detected, never followed.
//! - Nothing reachable from the last commit is ever overwritten. A commit writes the new data
//!   and nodes, flushes the device, writes the next superblock slot and flushes again: after a
//!   power cut, a volume mounts at its last complete commit. If the newest superblock (or the
//!   root it names) is damaged, the previous generation is used: freed blocks are held back for
//!   one extra commit so that generation is still intact.
//! - The FS tree holds inodes (obj, 1, 0), directory entries (dir, 2, name hash) and extents
//!   (obj, 3, block index) -> data block pointer. The allocation tree holds the bitmap in
//!   2 KiB chunks, so it is copy-on-write and checksummed like everything else.
//! - Snapshots save a committed FS tree root. A block dropped by the live tree is freed only if
//!   it was born after the newest snapshot (otherwise a snapshot still holds it); deleting a
//!   snapshot frees what no root reaches any more (mark and sweep).

pub mod tree;

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;

use crate::dev::{BlockDev, SECTOR};
use crate::{Entry, Error, FileSystem, Info, Ino, Kind, Result, Stat};
use tree::{Key, Tree, Visit};

pub const BS: usize = 4096;
const SPB: u64 = (BS / SECTOR) as u64;
pub const PTR: usize = 48;
const SLOTS: u64 = 4;
const DATA_START: u64 = 1 + SLOTS;
const CHUNK_BLOCKS: u64 = 16384; // bits per bitmap item (2 KiB)
const SUPER_MAGIC: &[u8; 8] = b"DFS1SUPR";
const SNAP_MAGIC: &[u8; 4] = b"DFSS";
const VERSION: u32 = 1;
pub const MAX_SNAPS: usize = 40;
const SNAP_ENTRY: usize = 32 + 8 + PTR;

const TREE_FS: u8 = 1;
const TREE_ALLOC: u8 = 2;
const K_INODE: u8 = 1;
const K_DIRENT: u8 = 2;
const K_EXTENT: u8 = 3;
const K_BITMAP: u8 = 10;
const ROOT_OBJ: u64 = 1;
const VIEW_SHIFT: u32 = 48;
/// Dirty file data kept in memory before a commit is forced.
const DIRTY_LIMIT: usize = 4 << 20;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Ptr {
    pub addr: u64,
    pub generation: u64,
    pub hash: [u8; 32],
}

impl Ptr {
    pub const NONE: Ptr = Ptr { addr: 0, generation: 0, hash: [0; 32] };
    pub fn put(&self, b: &mut [u8]) {
        b[0..8].copy_from_slice(&self.addr.to_le_bytes());
        b[8..16].copy_from_slice(&self.generation.to_le_bytes());
        b[16..48].copy_from_slice(&self.hash);
    }
    pub fn get(b: &[u8]) -> Ptr {
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&b[16..48]);
        Ptr { addr: u64::from_le_bytes(b[0..8].try_into().unwrap_or_default()), generation: u64::from_le_bytes(b[8..16].try_into().unwrap_or_default()), hash }
    }
    fn bytes(&self) -> Vec<u8> {
        let mut v = vec![0u8; PTR];
        self.put(&mut v);
        v
    }
}

/// Block I/O for the trees: reads (checked against pointers) and a queue of writes, sent in
/// runs of contiguous blocks at commit.
pub struct Io {
    pub dev: Box<dyn BlockDev>,
    pub uuid: [u8; 16],
    pub total: u64,
    pending: BTreeMap<u64, Box<[u8; BS]>>,
    pub loaded: u64,
}

impl Io {
    fn read_raw(&mut self, addr: u64) -> Result<Box<[u8; BS]>> {
        if addr == 0 || addr >= self.total {
            return Err(Error::Corrupt); // a pointer outside the volume
        }
        if let Some(b) = self.pending.get(&addr) {
            return Ok(b.clone());
        }
        let mut b = Box::new([0u8; BS]);
        self.dev.read(addr * SPB, &mut b[..])?;
        Ok(b)
    }

    pub fn read_verified(&mut self, p: &Ptr) -> Result<Box<[u8; BS]>> {
        let b = self.read_raw(p.addr)?;
        if crate::blake3::hash(&b[..]) != p.hash {
            return Err(Error::Corrupt);
        }
        Ok(b)
    }

    pub fn queue(&mut self, addr: u64, b: Box<[u8; BS]>) {
        self.pending.insert(addr, b);
    }

    fn write_queued(&mut self) -> Result<()> {
        let pending = core::mem::take(&mut self.pending);
        let mut run: Vec<u8> = Vec::new();
        let mut start = 0;
        for (a, b) in pending {
            if !run.is_empty() && (start + (run.len() / BS) as u64 != a || run.len() >= 8 * BS) {
                self.dev.write(start * SPB, &run)?;
                run.clear();
            }
            if run.is_empty() {
                start = a;
            }
            run.extend_from_slice(&b[..]);
        }
        if !run.is_empty() {
            self.dev.write(start * SPB, &run)?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Default, Debug)]
pub struct Super {
    pub generation: u64,
    pub total: u64,
    pub uuid: [u8; 16],
    pub next_obj: u64,
    pub used: u64,
    pub fs_root: Ptr,
    pub alloc_root: Ptr,
    pub snap_ptr: Ptr,
    pub snap_gen: u64,
    pub label: [u8; 32],
}

impl Super {
    fn serialize(&self) -> Box<[u8; BS]> {
        let mut b = Box::new([0u8; BS]);
        b[0..8].copy_from_slice(SUPER_MAGIC);
        b[8..12].copy_from_slice(&VERSION.to_le_bytes());
        b[12..16].copy_from_slice(&(BS as u32).to_le_bytes());
        b[16..24].copy_from_slice(&self.total.to_le_bytes());
        b[24..32].copy_from_slice(&self.generation.to_le_bytes());
        b[32..48].copy_from_slice(&self.uuid);
        b[48..56].copy_from_slice(&self.next_obj.to_le_bytes());
        b[56..64].copy_from_slice(&self.used.to_le_bytes());
        self.fs_root.put(&mut b[64..112]);
        self.alloc_root.put(&mut b[112..160]);
        self.snap_ptr.put(&mut b[160..208]);
        b[208..216].copy_from_slice(&self.snap_gen.to_le_bytes());
        b[216..248].copy_from_slice(&self.label);
        let h = crate::blake3::hash(&b[..BS - 32]);
        b[BS - 32..].copy_from_slice(&h);
        b
    }

    fn parse(b: &[u8; BS]) -> Option<Super> {
        if &b[0..8] != SUPER_MAGIC || crate::blake3::hash(&b[..BS - 32])[..] != b[BS - 32..] {
            return None;
        }
        if u32::from_le_bytes(b[8..12].try_into().ok()?) != VERSION || u32::from_le_bytes(b[12..16].try_into().ok()?) as usize != BS {
            return None;
        }
        let u = |o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap_or_default());
        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&b[32..48]);
        let mut label = [0u8; 32];
        label.copy_from_slice(&b[216..248]);
        Some(Super {
            total: u(16),
            generation: u(24),
            uuid,
            next_obj: u(48),
            used: u(56),
            fs_root: Ptr::get(&b[64..112]),
            alloc_root: Ptr::get(&b[112..160]),
            snap_ptr: Ptr::get(&b[160..208]),
            snap_gen: u(208),
            label,
        })
    }
}

#[derive(Clone, Debug)]
pub struct Snap {
    pub name: Vec<u8>,
    pub generation: u64,
    pub root: Ptr,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Fsck {
    pub errors: u64,
    /// The first problem found: what, and the block (or object) it concerns.
    pub first: Option<(&'static str, u64)>,
    pub nodes: u64,
    pub data_blocks: u64,
    pub files: u64,
    pub dirs: u64,
    pub leaked: u64,
}

/// The block allocator: the bitmap (as it will be committed), blocks held back after being
/// freed, and the newest snapshot's generation (the birth rule).
pub struct Alloc {
    total: u64,
    bitmap: Vec<u64>,
    chunk_dirty: alloc::collections::BTreeSet<u64>,
    /// Freed blocks held back: freed in this transaction / in the previous one.
    hold: Vec<u64>,
    held_cur: Vec<u64>,
    held_prev: Vec<u64>,
    cursor: u64,
    free: u64,
    snap_gen: u64,
}

impl Alloc {
    fn new(total: u64, snap_gen: u64) -> Alloc {
        let words = total.div_ceil(64) as usize;
        Alloc {
            total,
            bitmap: vec![0; words],
            chunk_dirty: alloc::collections::BTreeSet::new(),
            hold: vec![0; words],
            held_cur: Vec::new(),
            held_prev: Vec::new(),
            cursor: DATA_START,
            free: 0,
            snap_gen,
        }
    }

    fn bit(&self, b: u64) -> bool {
        self.bitmap[(b / 64) as usize] & 1 << (b % 64) != 0
    }

    fn set(&mut self, b: u64) {
        self.bitmap[(b / 64) as usize] |= 1 << (b % 64);
    }

    /// Set bits (bits past the end of the volume are never set).
    fn count_used(&self) -> u64 {
        self.bitmap.iter().map(|w| u64::from(w.count_ones())).sum()
    }

    fn alloc(&mut self) -> Result<u64> {
        let span = self.total - DATA_START;
        let mut i = 0;
        while i < span {
            let b = DATA_START + (self.cursor - DATA_START + i) % span;
            let w = (b / 64) as usize;
            if b.is_multiple_of(64) && b + 64 <= self.total && (self.bitmap[w] | self.hold[w]) == !0 {
                i += 64; // a full word
                continue;
            }
            if (self.bitmap[w] | self.hold[w]) & 1 << (b % 64) == 0 {
                self.bitmap[w] |= 1 << (b % 64);
                self.chunk_dirty.insert(b / CHUNK_BLOCKS);
                self.free -= 1;
                self.cursor = if b + 1 < self.total { b + 1 } else { DATA_START };
                return Ok(b);
            }
            i += 1;
        }
        Err(Error::NoSpace)
    }

    /// Free a block now; it stays held back until the commit after the next one.
    fn free_now(&mut self, addr: u64) {
        if addr < DATA_START || addr >= self.total || !self.bit(addr) {
            return; // never ours to free (a corrupt pointer shows up in fsck)
        }
        let w = (addr / 64) as usize;
        self.bitmap[w] &= !(1 << (addr % 64));
        self.hold[w] |= 1 << (addr % 64);
        self.held_cur.push(addr);
        self.chunk_dirty.insert(addr / CHUNK_BLOCKS);
        self.free += 1;
    }

    /// The live FS tree dropped `p`: free it unless a snapshot still holds it.
    fn release(&mut self, p: &Ptr) {
        if p.addr != 0 && p.generation > self.snap_gen {
            self.free_now(p.addr);
        }
    }

    /// A commit completed: blocks freed in the previous generation may be reused now.
    fn committed(&mut self) {
        for a in core::mem::take(&mut self.held_prev) {
            self.hold[(a / 64) as usize] &= !(1 << (a % 64));
        }
        self.held_prev = core::mem::take(&mut self.held_cur);
    }

    fn chunk_bytes(&self, c: u64) -> Vec<u8> {
        let words = (CHUNK_BLOCKS / 64) as usize;
        let start = c as usize * words;
        let mut v = vec![0u8; words * 8];
        for i in 0..words {
            if let Some(w) = self.bitmap.get(start + i) {
                v[8 * i..8 * i + 8].copy_from_slice(&w.to_le_bytes());
            }
        }
        v
    }
}

/// Directory entries sharing one name hash: (object, kind, name).
type EntryList = Vec<(u64, Kind, Vec<u8>)>;

pub struct Dfs {
    pub io: Io,
    pub sb: Super,
    /// Generation of the transaction in progress (sb.generation + 1).
    generation: u64,
    fs: Tree,
    alloc: Tree,
    snaps: Vec<Snap>,
    snaps_dirty: bool,
    next_obj: u64,
    al: Alloc,
    data: BTreeMap<(u64, u64), Box<[u8; BS]>>,
    views: Vec<Option<Tree>>,
    broken: bool,
    /// Mount: how many superblocks were skipped because they (or the roots they name) were
    /// damaged.
    pub fallbacks: u32,
}

#[derive(Clone, Copy)]
struct Inode {
    kind: Kind,
    size: u64,
    cgen: u64,
    mgen: u64,
}

impl Fsck {
    fn err(&mut self, what: &'static str, at: u64) {
        self.errors += 1;
        if self.first.is_none() {
            self.first = Some((what, at));
        }
    }
}

impl Inode {
    fn bytes(&self) -> Vec<u8> {
        let mut v = vec![0u8; 32];
        v[0] = if self.kind == Kind::Dir { 2 } else { 1 };
        v[8..16].copy_from_slice(&self.size.to_le_bytes());
        v[16..24].copy_from_slice(&self.cgen.to_le_bytes());
        v[24..32].copy_from_slice(&self.mgen.to_le_bytes());
        v
    }
    fn parse(v: &[u8]) -> Result<Inode> {
        if v.len() != 32 {
            return Err(Error::Corrupt);
        }
        let kind = match v[0] {
            1 => Kind::File,
            2 => Kind::Dir,
            _ => return Err(Error::Corrupt),
        };
        let u = |o: usize| u64::from_le_bytes(v[o..o + 8].try_into().unwrap_or_default());
        Ok(Inode { kind, size: u(8), cgen: u(16), mgen: u(24) })
    }
}

/// FNV-1a, 63 bits (directory entry keys; collisions share an item).
fn name_hash(n: &[u8]) -> u64 {
    let mut h = 0xCBF2_9CE4_8422_2325u64;
    for &c in n {
        h = (h ^ u64::from(c)).wrapping_mul(0x100_0000_01B3);
    }
    h >> 1
}

/// A directory item's entries: (obj, kind, name).
fn parse_group(v: &[u8]) -> Result<Vec<(u64, Kind, Vec<u8>)>> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < v.len() {
        if i + 10 > v.len() {
            return Err(Error::Corrupt);
        }
        let obj = u64::from_le_bytes(v[i..i + 8].try_into().unwrap_or_default());
        let kind = match v[i + 8] {
            1 => Kind::File,
            2 => Kind::Dir,
            _ => return Err(Error::Corrupt),
        };
        let n = usize::from(v[i + 9]);
        if n == 0 || i + 10 + n > v.len() {
            return Err(Error::Corrupt);
        }
        out.push((obj, kind, v[i + 10..i + 10 + n].to_vec()));
        i += 10 + n;
    }
    Ok(out)
}

fn group_bytes(g: &[(u64, Kind, Vec<u8>)]) -> Vec<u8> {
    let mut v = Vec::new();
    for (obj, kind, name) in g {
        v.extend_from_slice(&obj.to_le_bytes());
        v.push(if *kind == Kind::Dir { 2 } else { 1 });
        v.push(name.len() as u8);
        v.extend_from_slice(name);
    }
    v
}

fn valid_name(n: &[u8]) -> bool {
    !n.is_empty() && n.len() <= 255 && n != b"." && n != b".." && !n.iter().any(|&c| c == b'/' || c == 0)
}

pub struct FormatOpts<'a> {
    pub label: &'a [u8],
    pub uuid: [u8; 16],
}

impl Dfs {
    fn view(ino: Ino) -> usize {
        (ino >> VIEW_SHIFT) as usize
    }
    fn obj(ino: Ino) -> u64 {
        ino & ((1 << VIEW_SHIFT) - 1)
    }

    fn get(&mut self, view: usize, k: &Key) -> Result<Option<Vec<u8>>> {
        tree_of(&mut self.fs, &mut self.views, view)?.get(&mut self.io, k)
    }

    fn next(&mut self, view: usize, k: &Key) -> Result<Option<(Key, Vec<u8>)>> {
        tree_of(&mut self.fs, &mut self.views, view)?.next(&mut self.io, k)
    }

    fn inode(&mut self, ino: Ino) -> Result<Inode> {
        let v = self.get(Self::view(ino), &Key::new(Self::obj(ino), K_INODE, 0))?.ok_or(Error::NotFound)?;
        Inode::parse(&v)
    }

    fn put_inode(&mut self, obj: u64, i: &Inode) -> Result<()> {
        self.fs.insert(&mut self.io, Key::new(obj, K_INODE, 0), i.bytes())?;
        Ok(())
    }

    fn writable(&self, ino: Ino) -> Result<()> {
        if self.broken {
            return Err(Error::Io);
        }
        if Self::view(ino) != 0 {
            return Err(Error::ReadOnly);
        }
        Ok(())
    }

    // ---- format / mount -----------------------------------------------------------------

    pub fn format(dev: Box<dyn BlockDev>, o: &FormatOpts<'_>) -> Result<Dfs> {
        let total = dev.sectors() / SPB;
        if total < 64 {
            return Err(Error::NoSpace);
        }
        let mut label = [0u8; 32];
        label[..o.label.len().min(32)].copy_from_slice(&o.label[..o.label.len().min(32)]);
        let sb = Super { generation: 0, total, uuid: o.uuid, next_obj: 2, used: 0, label, ..Super::default() };
        let mut d = Dfs::empty(dev, sb);
        for b in 0..DATA_START {
            d.al.set(b);
        }
        d.al.free = total - DATA_START;
        for c in 0..total.div_ceil(CHUNK_BLOCKS) {
            d.al.chunk_dirty.insert(c);
        }
        d.fs = Tree::new(TREE_FS);
        d.alloc = Tree::new(TREE_ALLOC);
        d.put_inode(ROOT_OBJ, &Inode { kind: Kind::Dir, size: 0, cgen: 1, mgen: 1 })?;
        let z = [0u8; BS];
        for s in 0..=SLOTS {
            d.io.dev.write(s * SPB, &z)?; // no stale superblocks from an earlier filesystem
        }
        d.commit()?;
        Ok(d)
    }

    fn empty(dev: Box<dyn BlockDev>, sb: Super) -> Dfs {
        Dfs {
            io: Io { dev, uuid: sb.uuid, total: sb.total, pending: BTreeMap::new(), loaded: 0 },
            generation: sb.generation + 1,
            fs: Tree::open(TREE_FS, sb.fs_root),
            alloc: Tree::open(TREE_ALLOC, sb.alloc_root),
            snaps: Vec::new(),
            snaps_dirty: false,
            next_obj: sb.next_obj,
            al: Alloc::new(sb.total, sb.snap_gen),
            data: BTreeMap::new(),
            views: Vec::new(),
            broken: false,
            fallbacks: 0,
            sb,
        }
    }

    /// Whether `dev` holds a DFS volume (any valid superblock).
    pub fn probe(dev: &mut dyn BlockDev) -> bool {
        let mut b = Box::new([0u8; BS]);
        (1..=SLOTS).any(|s| dev.read(s * SPB, &mut b[..]).is_ok() && Super::parse(&b).is_some())
    }

    pub fn mount(mut dev: Box<dyn BlockDev>) -> core::result::Result<Dfs, (Error, Box<dyn BlockDev>)> {
        let total = dev.sectors() / SPB;
        let mut cands = Vec::new();
        let mut damaged = 0;
        let mut b = Box::new([0u8; BS]);
        for s in 1..=SLOTS {
            if dev.read(s * SPB, &mut b[..]).is_err() {
                damaged += 1;
                continue;
            }
            match Super::parse(&b) {
                Some(sb) if sb.total == total && sb.generation % SLOTS + 1 == s => cands.push(sb),
                // Slots are zeroed at format: anything else in one is a damaged superblock.
                _ if b.iter().any(|&x| x != 0) => damaged += 1,
                _ => {}
            }
        }
        if cands.is_empty() {
            return Err((if damaged > 0 { Error::Corrupt } else { Error::NotFound }, dev));
        }
        cands.sort_by_key(|sb| core::cmp::Reverse(sb.generation));
        let mut fallbacks = damaged;
        for sb in cands {
            let mut d = Dfs::empty(dev, sb);
            match d.load() {
                Ok(()) => {
                    d.fallbacks = fallbacks;
                    return Ok(d);
                }
                Err(_) => {
                    fallbacks += 1;
                    dev = d.io.dev;
                }
            }
        }
        Err((Error::Corrupt, dev))
    }

    /// Mount, step 2: the allocation bitmap, the snapshot table, the FS root.
    fn load(&mut self) -> Result<()> {
        let chunks = self.sb.total.div_ceil(CHUNK_BLOCKS);
        let mut got = 0;
        let ptr = self.sb.alloc_root;
        let words = (CHUNK_BLOCKS / 64) as usize;
        let mut bitmap = core::mem::take(&mut self.al.bitmap);
        tree::walk(&mut self.io, &ptr, TREE_ALLOC, &mut |_| false, &mut |v| {
            if let Visit::Item(k, val) = v {
                if k.obj != 0 || k.kind != K_BITMAP || k.off >= chunks || val.len() != words * 8 {
                    return Err(Error::Corrupt);
                }
                for i in 0..words {
                    let w = k.off as usize * words + i;
                    if w < bitmap.len() {
                        bitmap[w] = u64::from_le_bytes(val[8 * i..8 * i + 8].try_into().unwrap_or_default());
                    }
                }
                got += 1;
            }
            Ok(())
        })?;
        self.al.bitmap = bitmap;
        if got != chunks {
            return Err(Error::Corrupt);
        }
        let total = self.sb.total;
        if !total.is_multiple_of(64) && self.al.bitmap.last().is_some_and(|w| w >> (total % 64) != 0) {
            return Err(Error::Corrupt); // bits past the end of the volume
        }
        let used = self.al.count_used();
        if (0..DATA_START).any(|b| !self.al.bit(b)) || used > total {
            return Err(Error::Corrupt);
        }
        self.al.free = total - used;
        if self.sb.snap_ptr.addr != 0 {
            let b = self.io.read_verified(&self.sb.snap_ptr)?;
            self.snaps = parse_snaps(&b)?;
        }
        self.fs.get(&mut self.io, &Key::new(ROOT_OBJ, K_INODE, 0))?.ok_or(Error::Corrupt)?;
        Ok(())
    }

    /// Give the device back (remount, tests).
    pub fn into_dev(self) -> Box<dyn BlockDev> {
        self.io.dev
    }

    // ---- commit ---------------------------------------------------------------------------

    fn dirty(&self) -> bool {
        !self.data.is_empty() || self.fs.dirty() || self.alloc.dirty() || self.snaps_dirty || !self.al.chunk_dirty.is_empty() || self.next_obj != self.sb.next_obj
    }

    /// Make everything durable as one new generation.
    pub fn commit(&mut self) -> Result<()> {
        if self.broken {
            return Err(Error::Io);
        }
        if !self.dirty() {
            return Ok(());
        }
        let r = self.commit_inner();
        if r.is_err() {
            self.broken = true; // memory and disk disagree now: read-only until remounted
        }
        r
    }

    fn commit_inner(&mut self) -> Result<()> {
        let generation = self.generation;
        // 1. File data: new blocks, extents pointing at them.
        let data = core::mem::take(&mut self.data);
        for ((obj, blk), b) in data {
            let addr = self.al.alloc()?;
            let hash = crate::blake3::hash(&b[..]);
            self.io.queue(addr, b);
            let p = Ptr { addr, generation, hash };
            if let Some(old) = self.fs.insert(&mut self.io, Key::new(obj, K_EXTENT, blk), p.bytes())? {
                self.al.release(&Ptr::get(&old));
            }
        }
        for p in core::mem::take(&mut self.fs.dropped) {
            self.al.release(&p);
        }
        for p in core::mem::take(&mut self.alloc.dropped) {
            self.al.free_now(p.addr); // allocation-tree nodes are never in a snapshot
        }
        // 2. New blocks for every dirty node, until allocating changes nothing more (the
        //    bitmap lives in the allocation tree, which allocation itself changes).
        let mut snap_addr = None;
        loop {
            let al = &mut self.al;
            let mut n = self.fs.assign(&mut |old| {
                al.release(old);
                al.alloc()
            })?;
            if self.snaps_dirty && snap_addr.is_none() {
                if self.sb.snap_ptr.addr != 0 {
                    self.al.free_now(self.sb.snap_ptr.addr);
                }
                snap_addr = Some(self.al.alloc()?);
                n += 1;
            }
            for c in core::mem::take(&mut self.al.chunk_dirty) {
                let v = self.al.chunk_bytes(c);
                self.alloc.insert(&mut self.io, Key::new(0, K_BITMAP, c), v)?;
            }
            let al = &mut self.al;
            n += self.alloc.assign(&mut |old| {
                al.free_now(old.addr);
                al.alloc()
            })?;
            if n == 0 && self.al.chunk_dirty.is_empty() {
                break;
            }
        }
        // 3. Write the nodes (children first) and the snapshot table.
        let fs_root = self.fs.write(&mut self.io, generation)?;
        let alloc_root = self.alloc.write(&mut self.io, generation)?;
        let mut snap_ptr = self.sb.snap_ptr;
        if let Some(addr) = snap_addr {
            let b = snaps_block(&self.snaps);
            let hash = crate::blake3::hash(&b[..]);
            self.io.queue(addr, b);
            snap_ptr = Ptr { addr, generation, hash };
        }
        self.io.write_queued()?;
        self.io.dev.flush()?;
        // 4. The superblock, then a barrier: the generation is durable.
        let sb = Super {
            generation,
            fs_root,
            alloc_root,
            snap_ptr,
            snap_gen: self.al.snap_gen,
            next_obj: self.next_obj,
            used: self.sb.total - self.al.free,
            ..self.sb
        };
        let b = sb.serialize();
        self.io.dev.write((generation % SLOTS + 1) * SPB, &b[..])?;
        self.io.dev.flush()?;
        // 5. Blocks freed in the previous generation may be reused now.
        self.al.committed();
        self.sb = sb;
        self.generation = generation + 1;
        self.snaps_dirty = false;
        if self.io.loaded > 4096 {
            self.fs.shrink();
            self.alloc.shrink();
            self.io.loaded = 0;
        }
        Ok(())
    }

    // ---- snapshots ------------------------------------------------------------------------

    pub fn snapshots(&self) -> &[Snap] {
        &self.snaps
    }

    /// Snapshot what is committed after committing everything written so far.
    pub fn snapshot(&mut self, name: &[u8]) -> Result<()> {
        if name.is_empty() || name.len() > 32 || !valid_name(name) {
            return Err(Error::BadName);
        }
        if self.snaps.iter().any(|s| s.name == name) {
            return Err(Error::Exists);
        }
        if self.snaps.len() >= MAX_SNAPS {
            return Err(Error::NoSpace);
        }
        self.commit()?;
        self.snaps.push(Snap { name: name.to_vec(), generation: self.sb.generation, root: self.sb.fs_root });
        self.al.snap_gen = self.sb.generation;
        self.snaps_dirty = true;
        self.commit()
    }

    /// A read-only view of a snapshot: the node of its root directory.
    pub fn open_snapshot(&mut self, name: &[u8]) -> Result<Ino> {
        let s = self.snaps.iter().find(|s| s.name == name).ok_or(Error::NotFound)?;
        let t = Tree::open(TREE_FS, s.root);
        let slot = match self.views.iter().position(|v| v.is_none()) {
            Some(i) => i,
            None => {
                self.views.push(None);
                self.views.len() - 1
            }
        };
        if slot + 1 >= 1 << 15 {
            return Err(Error::NoSpace);
        }
        self.views[slot] = Some(t);
        Ok(((slot as u64 + 1) << VIEW_SHIFT) | ROOT_OBJ)
    }

    /// Delete a snapshot and free the blocks nothing else reaches. Returns blocks freed.
    pub fn delete_snapshot(&mut self, name: &[u8]) -> Result<u64> {
        let i = self.snaps.iter().position(|s| s.name == name).ok_or(Error::NotFound)?;
        self.commit()?;
        let s = self.snaps.remove(i);
        for v in self.views.iter_mut() {
            if v.as_ref().is_some_and(|t| t.root.ptr == s.root) {
                *v = None;
            }
        }
        self.al.snap_gen = self.snaps.iter().map(|s| s.generation).max().unwrap_or(0);
        self.snaps_dirty = true;
        self.commit()?;
        let freed = self.gc()?;
        self.commit()?;
        Ok(freed)
    }

    /// Mark everything reachable from a committed root; free allocated blocks nothing reaches.
    fn gc(&mut self) -> Result<u64> {
        let marks = self.mark(&mut Fsck::default(), false)?;
        let mut freed = 0;
        for b in DATA_START..self.sb.total {
            if self.al.bit(b) && marks[(b / 64) as usize] & 1 << (b % 64) == 0 {
                self.al.free_now(b);
                freed += 1;
            }
        }
        Ok(freed)
    }

    /// Walk every root (allocation tree, snapshot table, live tree, snapshots) from disk.
    /// Returns the reachable-block bitmap; counts into `r`. With `deep`, data blocks are read
    /// and checked too, and the live tree's structure is checked.
    fn mark(&mut self, r: &mut Fsck, deep: bool) -> Result<Vec<u64>> {
        let words = self.sb.total.div_ceil(64) as usize;
        let mut marks = vec![0u64; words];
        let total = self.sb.total;
        for b in 0..DATA_START {
            marks[(b / 64) as usize] |= 1 << (b % 64);
        }
        fn set(m: &mut [u64], b: u64) -> bool {
            let was = m[(b / 64) as usize] & 1 << (b % 64) != 0;
            m[(b / 64) as usize] |= 1 << (b % 64);
            was
        }
        let ap = self.sb.alloc_root;
        tree::walk(&mut self.io, &ap, TREE_ALLOC, &mut |_| false, &mut |v| {
            if let Visit::Node(a, _) = v
                && (a >= total || set(&mut marks, a)) {
                    return Err(Error::Corrupt);
                }
            Ok(())
        })?;
        if self.sb.snap_ptr.addr != 0 {
            set(&mut marks, self.sb.snap_ptr.addr);
        }
        let mut roots = vec![self.sb.fs_root];
        roots.extend(self.snaps.iter().map(|s| s.root));
        let mut data = Vec::new();
        for (ri, root) in roots.iter().enumerate() {
            // Shared subtrees are walked once; within one tree a block appears only once.
            let mut mine = vec![0u64; if ri == 0 { words } else { 0 }];
            let mut inodes: BTreeMap<u64, Inode> = BTreeMap::new();
            let mut refs: BTreeMap<u64, u32> = BTreeMap::new();
            let mut extents: Vec<(u64, u64)> = Vec::new();
            let marks_ref = &mut marks;
            let mut seen = |a: u64| a < total && ri > 0 && marks_ref[(a / 64) as usize] & 1 << (a % 64) != 0;
            let mut nodes = 0u64;
            let mut visits: Vec<(u64, bool)> = Vec::new();
            let mut bad: Vec<(&'static str, u64)> = Vec::new();
            tree::walk(&mut self.io, root, TREE_FS, &mut seen, &mut |v| {
                match v {
                    Visit::Node(a, _) => {
                        nodes += 1;
                        visits.push((a, true));
                        if ri == 0 && set(&mut mine, a) {
                            bad.push(("node referenced twice", a));
                        }
                    }
                    Visit::Item(k, val) => match k.kind {
                        K_EXTENT => {
                            if val.len() != PTR {
                                return Err(Error::Corrupt);
                            }
                            let p = Ptr::get(val);
                            visits.push((p.addr, false));
                            if ri == 0 {
                                extents.push((k.obj, k.off));
                                if set(&mut mine, p.addr) {
                                    bad.push(("data block referenced twice", p.addr));
                                }
                            }
                            if deep {
                                data.push(p);
                            }
                        }
                        K_INODE if ri == 0 => {
                            inodes.insert(k.obj, Inode::parse(val)?);
                        }
                        K_DIRENT if ri == 0 => {
                            for (obj, kind, name) in parse_group(val)? {
                                if name_hash(&name) != k.off {
                                    bad.push(("entry under the wrong name hash", k.obj));
                                }
                                let _ = kind;
                                *refs.entry(obj).or_default() += 1;
                            }
                        }
                        _ => {}
                    },
                }
                Ok(())
            })?;
            r.nodes += nodes;
            for (what, at) in bad {
                r.err(what, at);
            }
            for (a, _) in visits {
                if a >= total {
                    r.err("pointer outside the volume", a);
                } else {
                    set(&mut marks, a);
                }
            }
            if ri == 0 && deep {
                // Structure: every entry names an inode, every inode but the root has exactly
                // one entry, extents belong to files and lie within their size.
                for (obj, n) in &refs {
                    if !inodes.contains_key(obj) || *n != 1 {
                        r.err("entry without inode, or inode with several entries", *obj);
                    }
                }
                for (obj, i) in &inodes {
                    if *obj != ROOT_OBJ && !refs.contains_key(obj) {
                        r.err("inode without a directory entry", *obj);
                    }
                    match i.kind {
                        Kind::File => r.files += 1,
                        Kind::Dir => r.dirs += 1,
                    }
                }
                for (obj, blk) in &extents {
                    match inodes.get(obj) {
                        Some(i) if i.kind == Kind::File && *blk < i.size.div_ceil(BS as u64) => {}
                        _ => r.err("extent outside its file", *obj),
                    }
                }
            }
        }
        if deep {
            for p in data {
                r.data_blocks += 1;
                if self.io.read_verified(&p).is_err() {
                    r.err("data block fails its checksum", p.addr);
                }
            }
        }
        Ok(marks)
    }

    /// Check the whole volume: every hash, the tree structure, and that the bitmap matches
    /// what is reachable exactly (no leaks, nothing reachable marked free).
    pub fn fsck(&mut self) -> Result<Fsck> {
        self.commit()?;
        let mut r = Fsck::default();
        let marks = match self.mark(&mut r, true) {
            Ok(m) => m,
            Err(_) => {
                r.err("a tree failed its checks (checksum or structure)", 0);
                return Ok(r);
            }
        };
        for b in 0..self.sb.total {
            let m = marks[(b / 64) as usize] & 1 << (b % 64) != 0;
            if m && !self.al.bit(b) {
                r.err("reachable block marked free", b); // it would be overwritten
            } else if !m && self.al.bit(b) {
                r.leaked += 1;
                r.err("allocated block nothing reaches (leak)", b);
            }
        }
        Ok(r)
    }

    // ---- test hooks -------------------------------------------------------------------------

    fn flip(&mut self, addr: u64, at: usize) -> Result<()> {
        let mut b = [0u8; BS];
        self.io.dev.read(addr * SPB, &mut b)?;
        b[at] ^= 0x5A;
        self.io.dev.write(addr * SPB, &b)?;
        self.io.dev.flush()
    }

    /// Flip a byte in the first data block of `ino` on disk.
    pub fn corrupt_data(&mut self, ino: Ino) -> Result<u64> {
        self.commit()?;
        let obj = Self::obj(ino);
        let (k, v) = self.next(0, &Key::new(obj, K_EXTENT, 0))?.ok_or(Error::NotFound)?;
        if k.obj != obj || k.kind != K_EXTENT {
            return Err(Error::NotFound);
        }
        let p = Ptr::get(&v);
        self.flip(p.addr, 100)?;
        Ok(p.addr)
    }

    /// Flip a byte in the leaf holding `ino`'s inode, then forget the cached tree.
    pub fn corrupt_meta(&mut self, ino: Ino) -> Result<u64> {
        self.commit()?;
        let a = self.fs.leaf_of(&mut self.io, &Key::new(Self::obj(ino), K_INODE, 0))?;
        self.flip(a, tree::HDR + 3)?;
        self.fs = Tree::open(TREE_FS, self.sb.fs_root);
        Ok(a)
    }

    /// Flip a byte in the newest superblock.
    pub fn corrupt_super(&mut self) -> Result<u64> {
        self.commit()?;
        let slot = self.sb.generation % SLOTS + 1;
        self.flip(slot, 300)?;
        Ok(self.sb.generation)
    }

    fn file_block(&mut self, view: usize, obj: u64, blk: u64, out: &mut [u8; BS]) -> Result<()> {
        if view == 0
            && let Some(b) = self.data.get(&(obj, blk))
        {
            out.copy_from_slice(&b[..]);
            return Ok(());
        }
        match self.get(view, &Key::new(obj, K_EXTENT, blk))? {
            Some(v) if v.len() == PTR => {
                let b = self.io.read_verified(&Ptr::get(&v))?;
                out.copy_from_slice(&b[..]);
            }
            Some(_) => return Err(Error::Corrupt),
            None => out.fill(0), // a hole
        }
        Ok(())
    }

    fn find_entry(&mut self, view: usize, dir: u64, name: &[u8]) -> Result<(u64, Kind, EntryList)> {
        let d = self.inode(((view as u64) << VIEW_SHIFT) | dir)?;
        if d.kind != Kind::Dir {
            return Err(Error::NotDir);
        }
        let g = match self.get(view, &Key::new(dir, K_DIRENT, name_hash(name)))? {
            Some(v) => parse_group(&v)?,
            None => return Err(Error::NotFound),
        };
        let (obj, kind) = g.iter().find(|e| e.2 == name).map(|e| (e.0, e.1)).ok_or(Error::NotFound)?;
        Ok((obj, kind, g))
    }

    fn touch(&mut self, obj: u64, f: impl FnOnce(&mut Inode)) -> Result<()> {
        let mut i = self.inode(obj)?;
        f(&mut i);
        i.mgen = self.generation;
        self.put_inode(obj, &i)
    }

    fn drop_extents(&mut self, obj: u64, from: u64) -> Result<()> {
        while let Some((k, v)) = self.fs.next(&mut self.io, &Key::new(obj, K_EXTENT, from))? {
            if k.obj != obj || k.kind != K_EXTENT {
                break;
            }
            self.fs.delete(&mut self.io, &k)?;
            if v.len() == PTR {
                self.al.release(&Ptr::get(&v));
            }
        }
        let keys: Vec<(u64, u64)> = self.data.range((obj, from)..=(obj, u64::MAX)).map(|(k, _)| *k).collect();
        for k in keys {
            self.data.remove(&k);
        }
        Ok(())
    }
}

fn tree_of<'a>(fs: &'a mut Tree, views: &'a mut [Option<Tree>], view: usize) -> Result<&'a mut Tree> {
    if view == 0 {
        return Ok(fs);
    }
    views.get_mut(view - 1).and_then(|v| v.as_mut()).ok_or(Error::NotFound)
}

fn snaps_block(s: &[Snap]) -> Box<[u8; BS]> {
    let mut b = Box::new([0u8; BS]);
    b[0..4].copy_from_slice(SNAP_MAGIC);
    b[4..6].copy_from_slice(&(s.len() as u16).to_le_bytes());
    for (i, e) in s.iter().enumerate() {
        let o = 16 + i * SNAP_ENTRY;
        b[o..o + e.name.len()].copy_from_slice(&e.name);
        b[o + 32..o + 40].copy_from_slice(&e.generation.to_le_bytes());
        e.root.put(&mut b[o + 40..o + 40 + PTR]);
    }
    b
}

fn parse_snaps(b: &[u8; BS]) -> Result<Vec<Snap>> {
    if &b[0..4] != SNAP_MAGIC {
        return Err(Error::Corrupt);
    }
    let n = usize::from(u16::from_le_bytes([b[4], b[5]]));
    if n > MAX_SNAPS {
        return Err(Error::Corrupt);
    }
    let mut out = Vec::new();
    for i in 0..n {
        let o = 16 + i * SNAP_ENTRY;
        let name: Vec<u8> = b[o..o + 32].iter().copied().take_while(|&c| c != 0).collect();
        if name.is_empty() {
            return Err(Error::Corrupt);
        }
        out.push(Snap { name, generation: u64::from_le_bytes(b[o + 32..o + 40].try_into().unwrap_or_default()), root: Ptr::get(&b[o + 40..o + 40 + PTR]) });
    }
    Ok(out)
}

impl FileSystem for Dfs {
    fn root(&self) -> Ino {
        ROOT_OBJ
    }

    fn lookup(&mut self, dir: Ino, name: &[u8]) -> Result<Ino> {
        if !valid_name(name) {
            return Err(Error::BadName);
        }
        let view = Self::view(dir);
        let (obj, _, _) = self.find_entry(view, Self::obj(dir), name)?;
        Ok(((view as u64) << VIEW_SHIFT) | obj)
    }

    fn create(&mut self, dir: Ino, name: &[u8], kind: Kind) -> Result<Ino> {
        self.writable(dir)?;
        if !valid_name(name) {
            return Err(Error::BadName);
        }
        let d = Self::obj(dir);
        let mut g = match self.find_entry(0, d, name) {
            Ok(_) => return Err(Error::Exists),
            Err(Error::NotFound) => match self.get(0, &Key::new(d, K_DIRENT, name_hash(name)))? {
                Some(v) => parse_group(&v)?,
                None => Vec::new(),
            },
            Err(e) => return Err(e),
        };
        let obj = self.next_obj;
        if obj >= 1 << VIEW_SHIFT {
            return Err(Error::NoSpace);
        }
        self.next_obj += 1;
        g.push((obj, kind, name.to_vec()));
        let v = group_bytes(&g);
        if v.len() > tree::MAX_VAL {
            return Err(Error::TooBig);
        }
        let generation = self.generation;
        self.put_inode(obj, &Inode { kind, size: 0, cgen: generation, mgen: generation })?;
        self.fs.insert(&mut self.io, Key::new(d, K_DIRENT, name_hash(name)), v)?;
        self.touch(d, |_| {})?;
        Ok(obj)
    }

    fn stat(&mut self, ino: Ino) -> Result<Stat> {
        let i = self.inode(ino)?;
        Ok(Stat { kind: i.kind, size: i.size })
    }

    fn read(&mut self, ino: Ino, off: u64, buf: &mut [u8]) -> Result<usize> {
        let i = self.inode(ino)?;
        if i.kind == Kind::Dir {
            return Err(Error::IsDir);
        }
        if off >= i.size {
            return Ok(0);
        }
        let n = (i.size - off).min(buf.len() as u64) as usize;
        let (view, obj) = (Self::view(ino), Self::obj(ino));
        let mut done = 0;
        let mut blk = [0u8; BS];
        while done < n {
            let pos = off + done as u64;
            let (b, in_b) = (pos / BS as u64, (pos % BS as u64) as usize);
            self.file_block(view, obj, b, &mut blk)?;
            let k = (BS - in_b).min(n - done);
            buf[done..done + k].copy_from_slice(&blk[in_b..in_b + k]);
            done += k;
        }
        Ok(n)
    }

    fn write(&mut self, ino: Ino, off: u64, data: &[u8]) -> Result<usize> {
        self.writable(ino)?;
        let obj = Self::obj(ino);
        let i = self.inode(ino)?;
        if i.kind == Kind::Dir {
            return Err(Error::IsDir);
        }
        let end = off.checked_add(data.len() as u64).ok_or(Error::TooBig)?;
        if end > 1 << 44 {
            return Err(Error::TooBig);
        }
        let mut done = 0;
        while done < data.len() {
            let pos = off + done as u64;
            let (b, in_b) = (pos / BS as u64, (pos % BS as u64) as usize);
            let k = (BS - in_b).min(data.len() - done);
            if !self.data.contains_key(&(obj, b)) {
                let mut blk = Box::new([0u8; BS]);
                if k < BS && b * (BS as u64) < i.size {
                    self.file_block(0, obj, b, &mut blk)?;
                }
                self.data.insert((obj, b), blk);
            }
            if let Some(blk) = self.data.get_mut(&(obj, b)) {
                blk[in_b..in_b + k].copy_from_slice(&data[done..done + k]);
            }
            done += k;
        }
        self.touch(obj, |n| n.size = n.size.max(end))?;
        if self.data.len() * BS > DIRTY_LIMIT {
            self.commit()?;
        }
        Ok(data.len())
    }

    fn truncate(&mut self, ino: Ino, size: u64) -> Result<()> {
        self.writable(ino)?;
        let obj = Self::obj(ino);
        let i = self.inode(ino)?;
        if i.kind == Kind::Dir {
            return Err(Error::IsDir);
        }
        if size > 1 << 44 {
            return Err(Error::TooBig);
        }
        if size < i.size {
            self.drop_extents(obj, size.div_ceil(BS as u64))?;
            if !size.is_multiple_of(BS as u64) {
                // Zero the tail of the last block (it reads as zeros if the file grows again).
                let b = size / BS as u64;
                let mut blk = Box::new([0u8; BS]);
                self.file_block(0, obj, b, &mut blk)?;
                blk[(size % BS as u64) as usize..].fill(0);
                self.data.insert((obj, b), blk);
            }
        }
        self.touch(obj, |n| n.size = size)
    }

    fn readdir(&mut self, dir: Ino, cookie: u64, max: usize) -> Result<(Vec<Entry>, Option<u64>)> {
        let view = Self::view(dir);
        let d = Self::obj(dir);
        if self.inode(dir)?.kind != Kind::Dir {
            return Err(Error::NotDir);
        }
        let mut out = Vec::new();
        let mut at = cookie;
        loop {
            let Some((k, v)) = self.next(view, &Key::new(d, K_DIRENT, at))? else { return Ok((out, None)) };
            if k.obj != d || k.kind != K_DIRENT {
                return Ok((out, None));
            }
            let g = parse_group(&v)?;
            if !out.is_empty() && out.len() + g.len() > max {
                return Ok((out, Some(k.off)));
            }
            for (obj, kind, name) in g {
                out.push(Entry { name, kind, ino: ((view as u64) << VIEW_SHIFT) | obj });
            }
            at = k.off + 1;
        }
    }

    fn unlink(&mut self, dir: Ino, name: &[u8]) -> Result<()> {
        self.writable(dir)?;
        if !valid_name(name) {
            return Err(Error::BadName);
        }
        let d = Self::obj(dir);
        let (obj, kind, mut g) = self.find_entry(0, d, name)?;
        if kind == Kind::Dir
            && let Some((k, _)) = self.fs.next(&mut self.io, &Key::new(obj, K_DIRENT, 0))?
            && k.obj == obj
            && k.kind == K_DIRENT
        {
            return Err(Error::NotEmpty);
        }
        g.retain(|e| e.2 != name);
        let key = Key::new(d, K_DIRENT, name_hash(name));
        if g.is_empty() {
            self.fs.delete(&mut self.io, &key)?;
        } else {
            self.fs.insert(&mut self.io, key, group_bytes(&g))?;
        }
        self.drop_extents(obj, 0)?;
        self.fs.delete(&mut self.io, &Key::new(obj, K_INODE, 0))?;
        self.touch(d, |_| {})
    }

    fn sync(&mut self) -> Result<()> {
        self.commit()
    }

    fn info(&mut self) -> Info {
        Info { total_blocks: self.sb.total, free_blocks: self.al.free, block_size: BS as u64, generation: self.sb.generation }
    }

    fn read_only(&self, ino: Ino) -> bool {
        Self::view(ino) != 0 || self.broken
    }
}

#[cfg(test)]
mod tests;
