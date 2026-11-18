//! Virtual memory address region (VMAR): a range of a process's address space, holding VMO
//! mappings and child regions. Every process gets a root VMAR covering the user half.
//!
//! Enforced here: ranges are page-aligned, inside the region and never overlap; a mapping is
//! never writable and executable at once (W^X); a mapping keeps its VMO alive; a writable mapping
//! counts as a writer of its VMO (so a VMO mapped writable anywhere cannot be sealed and made
//! executable, and a sealed one cannot be mapped writable); an executable mapping needs an
//! executable (sealed) VMO.
//! Enforced by the caller (`Process`): mapping permissions are a subset of both the VMAR
//! handle's and the VMO handle's rights.
//!
//! Every mapping is backed by the process's page tables (`AddressSpace`): installed when it is
//! made, and removed (with a TLB shootdown on every CPU) before its VMO reference is dropped, so
//! no CPU can reach a VMO's pages after they are freed.
//!
//! Placement without a fixed offset is randomized (user ASLR): a random page-aligned spot that
//! fits; first fit only if a few random tries all collide.

use alloc::vec::Vec;

use super::aspace::AddressSpace;
use super::quota::Account;
use super::vmo::WriteRef;
use super::{Header, KRef, KResult, ObjType, Rights, Status, Vmo};
use crate::ffi::{self, rank};
use crate::sync::SpinLock;

/// User half: everything below the canonical hole, minus the first 2 MiB (NULL stays unmapped).
pub const USER_BASE: u64 = ffi::USER_BASE;
pub const USER_TOP: u64 = ffi::USER_TOP;
const PAGE: u64 = 4096;
const ASLR_TRIES: u32 = 16;

pub const PERM_MASK: Rights = Rights(Rights::READ.0 | Rights::WRITE.0 | Rights::EXECUTE.0);

enum Kind {
    Mapping {
        #[allow(dead_code)] // keeps the VMO (and its frames) alive while mapped
        vmo: KRef<Vmo>,
        perms: Rights,
        #[allow(dead_code)] // writable mappings: a writer of the VMO while mapped
        writer: Option<WriteRef>,
    },
    Child(KRef<Vmar>),
}

struct Entry {
    start: u64,
    len: u64,
    /// Mappings: offset of `start` in the VMO.
    vmo_off: u64,
    kind: Kind,
}

struct Inner {
    dead: bool,
    entries: Vec<Entry>, // sorted by start, non-overlapping
}

/// Where a new mapping or child region goes.
#[derive(Clone, Copy)]
pub enum Placement {
    /// At this offset from the region's base.
    At(u64),
    /// Anywhere: first fit, starting at the region's random hint (packed: page tables stay dense).
    Any,
    /// A random spot of its own (program images and stacks; falls back to `Any` if crowded).
    Random,
}

impl From<Option<u64>> for Placement {
    fn from(o: Option<u64>) -> Self {
        o.map_or(Placement::Any, Placement::At)
    }
}

pub struct Vmar {
    pub header: Header,
    base: u64,
    size: u64,
    hint: u64, // offset where `Any` placements start (random for root regions, else 0)
    aspace: KRef<AddressSpace>,
    inner: SpinLock<Inner>,
}

fn aligned(v: u64) -> bool {
    v.is_multiple_of(PAGE)
}

fn vmm_flags(perms: Rights) -> u32 {
    let mut f = 0;
    if perms.contains(Rights::WRITE) {
        f |= ffi::VMM_W;
    }
    if perms.contains(Rights::EXECUTE) {
        f |= ffi::VMM_X;
    }
    f
}

fn random() -> u64 {
    // SAFETY: plain call.
    unsafe { ffi::cpu_random64() }
}

impl Vmar {
    /// The root region of a new address space, whose page tables are charged to `acct`. Its
    /// placement hint (where `Any` placements start packing) is random: per-process ASLR.
    pub fn new_root(acct: &KRef<Account>) -> KResult<KRef<Vmar>> {
        let aspace = AddressSpace::new(acct)?;
        let size = USER_TOP - USER_BASE;
        // A 2 MiB-aligned hint that leaves at least 1 TiB above it before wrapping around.
        let slots = (size - (1 << 40)) / (2 << 20);
        let hint = (random() % slots) * (2 << 20);
        Self::create(USER_BASE, size, hint, aspace)
    }

    fn create(base: u64, size: u64, hint: u64, aspace: KRef<AddressSpace>) -> KResult<KRef<Vmar>> {
        KRef::try_new(Vmar {
            header: Header::new(ObjType::Vmar),
            base,
            size,
            hint,
            aspace,
            inner: SpinLock::new(
                c"vmar",
                rank::OBJECT,
                Inner {
                    dead: false,
                    entries: Vec::new(),
                },
            ),
        })
        .map_err(|_| Status::NoMemory)
    }

    pub fn base(&self) -> u64 {
        self.base
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    pub fn aspace(&self) -> &KRef<AddressSpace> {
        &self.aspace
    }

    /// Does [start, start+len) fit (absolute address)? Returns the insert position.
    fn fits(inner: &Inner, start: u64, len: u64) -> Option<usize> {
        let pos = inner.entries.partition_point(|e| e.start < start);
        let prev_ok = pos == 0 || {
            let p = &inner.entries[pos - 1];
            p.start + p.len <= start
        };
        let next_ok = pos == inner.entries.len() || inner.entries[pos].start >= start + len;
        (prev_ok && next_ok).then_some(pos)
    }

    /// First gap of `len` inside [lo, hi).
    fn first_fit(inner: &Inner, lo: u64, hi: u64, len: u64) -> Option<(u64, usize)> {
        let mut cursor = lo;
        let first = inner.entries.partition_point(|e| e.start + e.len <= lo);
        for (i, e) in inner.entries.iter().enumerate().skip(first) {
            if e.start >= cursor && e.start - cursor >= len {
                return (cursor + len <= hi).then_some((cursor, i));
            }
            cursor = cursor.max(e.start + e.len);
            if cursor >= hi {
                return None;
            }
        }
        (hi - cursor >= len).then_some((cursor, inner.entries.len()))
    }

    /// Where a range of `len` goes (see `Placement`).
    fn place(&self, inner: &Inner, at: Placement, len: u64) -> KResult<(u64, usize)> {
        if len == 0 || !aligned(len) || len > self.size {
            return Err(Status::InvalidArgs);
        }
        let end = self.base + self.size;
        match at {
            Placement::At(off) => {
                if !aligned(off) {
                    return Err(Status::InvalidArgs);
                }
                let stop = off.checked_add(len).ok_or(Status::OutOfRange)?;
                if stop > self.size {
                    return Err(Status::OutOfRange);
                }
                let start = self.base + off;
                Self::fits(inner, start, len)
                    .map(|p| (start, p))
                    .ok_or(Status::NoSpace)
            }
            Placement::Random => {
                let slots = (self.size - len) / PAGE + 1;
                for _ in 0..ASLR_TRIES {
                    let start = self.base + (random() % slots) * PAGE;
                    if let Some(p) = Self::fits(inner, start, len) {
                        return Ok((start, p));
                    }
                }
                self.place(inner, Placement::Any, len)
            }
            Placement::Any => {
                let from = self.base + self.hint;
                Self::first_fit(inner, from, end, len)
                    .or_else(|| Self::first_fit(inner, self.base, end, len))
                    .ok_or(Status::NoSpace)
            }
        }
    }

    /// Map `len` bytes of `vmo` from `vmo_off` with `perms` (READ/WRITE/EXECUTE). Returns the address.
    pub fn map(
        &self,
        offset: Option<u64>,
        vmo: KRef<Vmo>,
        vmo_off: u64,
        len: u64,
        perms: Rights,
    ) -> KResult<u64> {
        if perms == Rights::NONE || !PERM_MASK.contains(perms) {
            return Err(Status::InvalidArgs);
        }
        if perms.contains(Rights::WRITE | Rights::EXECUTE) {
            return Err(Status::InvalidArgs); // W^X
        }
        if !aligned(vmo_off) {
            return Err(Status::InvalidArgs);
        }
        let vmo_end = vmo_off.checked_add(len).ok_or(Status::OutOfRange)?;
        if vmo_end > vmo.size() {
            return Err(Status::OutOfRange);
        }
        if perms.contains(Rights::EXECUTE) && !vmo.executable() {
            return Err(Status::AccessDenied);
        }
        // Taken before the lock: a sealed VMO cannot be mapped writable.
        let writer = if perms.contains(Rights::WRITE) { Some(Vmo::write_ref(&vmo)?) } else { None };
        let mut g = self.inner.lock();
        if g.dead {
            return Err(Status::BadState);
        }
        let (start, pos) = self.place(&g, offset.into(), len)?;
        g.entries.try_reserve(1).map_err(|_| Status::NoMemory)?;
        let first = (vmo_off / PAGE) as usize;
        let frames = &vmo.frames()[first..first + (len / PAGE) as usize];
        let uc = match (vmo.is_device(), vmo.is_write_combining()) {
            (true, true) => ffi::VMM_WC,
            (true, false) => ffi::VMM_UC,
            _ => 0,
        };
        self.aspace.map(start, frames, vmm_flags(perms) | uc)?;
        g.entries.insert(
            pos,
            Entry {
                start,
                len,
                vmo_off,
                kind: Kind::Mapping { vmo, perms, writer },
            },
        );
        Ok(start)
        // On an error path `vmo` and `writer` are dropped while the lock is held. That is fine:
        // the caller still holds its own reference (it passed a clone), so neither is the last one.
    }

    /// Carve out a child region of `len` bytes (at `offset` if given). Returns it.
    pub fn allocate(&self, offset: Option<u64>, len: u64) -> KResult<KRef<Vmar>> {
        self.allocate_at(offset.into(), len)
    }

    pub fn allocate_at(&self, at: Placement, len: u64) -> KResult<KRef<Vmar>> {
        // Find a place, then allocate the child without holding the lock (never drop it under it).
        let g = self.inner.lock();
        if g.dead {
            return Err(Status::BadState);
        }
        let (start, _) = self.place(&g, at, len)?;
        drop(g);
        let child = Vmar::create(start, len, 0, self.aspace.clone())?;
        let mut g = self.inner.lock();
        // Re-check: the range may have been taken meanwhile.
        let fits = !g.dead && Self::fits(&g, start, len).is_some();
        if !fits || g.entries.try_reserve(1).is_err() {
            let e = if !fits { Status::NoSpace } else { Status::NoMemory };
            drop(g);
            drop(child);
            return Err(e);
        }
        let pos = g.entries.partition_point(|e| e.start < start);
        g.entries.insert(
            pos,
            Entry {
                start,
                len,
                vmo_off: 0,
                kind: Kind::Child(child.clone()),
            },
        );
        Ok(child)
    }

    /// Remove the mappings that lie completely inside [addr, addr+len). A mapping that only
    /// partly overlaps the range is an error (`InvalidArgs`) and nothing is removed.
    /// Child regions are not touched (destroy them through their own handle).
    pub fn unmap(&self, addr: u64, len: u64) -> KResult<u32> {
        if len == 0 || !aligned(addr) || !aligned(len) {
            return Err(Status::InvalidArgs);
        }
        let end = addr.checked_add(len).ok_or(Status::OutOfRange)?;
        {
            let g = self.inner.lock();
            if g.dead {
                return Err(Status::BadState);
            }
            for e in &g.entries {
                let overlaps = e.start < end && addr < e.start + e.len;
                let inside = e.start >= addr && e.start + e.len <= end;
                if overlaps && !inside && matches!(e.kind, Kind::Mapping { .. }) {
                    return Err(Status::InvalidArgs);
                }
            }
        }
        // One mapping per lock hold. Its pages leave the page tables (and every TLB) first; the
        // entry, and with it possibly the VMO's last reference, is dropped after unlocking.
        // Each search starts after the mapping removed last: between two lock holds another
        // thread of the process may map something new into the part already freed (the heap
        // reuses addresses at once), and that mapping is not ours to remove.
        let mut removed = 0;
        let mut cursor = addr;
        loop {
            let mut g = self.inner.lock();
            let i = g.entries.iter().position(|e| {
                e.start >= cursor && e.start + e.len <= end && matches!(e.kind, Kind::Mapping { .. })
            });
            let Some(i) = i else { break };
            let e = g.entries.remove(i);
            cursor = e.start + e.len;
            self.aspace.unmap(e.start, e.len);
            drop(g);
            drop(e);
            removed += 1;
        }
        Ok(removed)
    }

    /// Remove the child region starting at `base` (after it was destroyed).
    pub fn remove_child(&self, base: u64) {
        let mut g = self.inner.lock();
        let i = g
            .entries
            .iter()
            .position(|e| e.start == base && matches!(e.kind, Kind::Child(_)));
        let e = i.map(|i| g.entries.remove(i));
        drop(g);
        drop(e);
    }

    fn vmo_offset(&self, e: &Entry) -> u64 {
        e.vmo_off
    }

    fn release(&self, entries: Vec<Entry>) {
        for e in &entries {
            match &e.kind {
                Kind::Mapping { .. } => self.aspace.unmap(e.start, e.len),
                Kind::Child(c) => c.destroy(),
            }
        }
        drop(entries);
    }

    /// Remove everything (recursively) and refuse further changes (process kill / region destroy).
    pub fn destroy(&self) {
        let entries = {
            let mut g = self.inner.lock();
            g.dead = true;
            core::mem::take(&mut g.entries)
        };
        self.release(entries);
    }

    /// (mappings, child regions) directly in this region.
    pub fn counts(&self) -> (usize, usize) {
        let g = self.inner.lock();
        let maps = g
            .entries
            .iter()
            .filter(|e| matches!(e.kind, Kind::Mapping { .. }))
            .count();
        (maps, g.entries.len() - maps)
    }

    /// The mapping containing `addr` (searching child regions too): its VMO, the offset of
    /// `addr` in it, the mapping's permissions and how many bytes of the mapping follow `addr`.
    pub fn lookup(&self, addr: u64) -> Option<(KRef<Vmo>, u64, Rights, u64)> {
        let child = {
            let g = self.inner.lock();
            let e = g.entries.iter().find(|e| addr >= e.start && addr < e.start + e.len)?;
            match &e.kind {
                Kind::Mapping { vmo, perms, .. } => {
                    let off = addr - e.start;
                    let vmo_off = self.vmo_offset(e) + off;
                    return Some((vmo.clone(), vmo_off, *perms, e.len - off));
                }
                Kind::Child(c) => c.clone(),
            }
        };
        child.lookup(addr) // outside the lock (never nested)
    }

    /// Permissions of the mapping containing `addr`, if any (inspection, tests).
    pub fn perms_at(&self, addr: u64) -> Option<Rights> {
        let g = self.inner.lock();
        g.entries.iter().find_map(|e| match &e.kind {
            Kind::Mapping { perms, .. } if addr >= e.start && addr < e.start + e.len => Some(*perms),
            _ => None,
        })
    }
}

impl Drop for Vmar {
    /// A region dropped without being destroyed (its last handle closed): its mappings still
    /// leave the page tables before their VMOs can go.
    fn drop(&mut self) {
        let entries = core::mem::take(&mut self.inner.lock().entries);
        self.release(entries);
    }
}
