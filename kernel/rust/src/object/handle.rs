//! Per-process handle tables.
//!
//! A handle value is a scrambled (slot index, generation) pair:
//! - **not a guessable index**: the pair goes through a per-table bijection keyed with random bits,
//!   so values look random and differ between processes;
//! - **closed handles stay invalid**: closing bumps the slot's generation, so the old value no
//!   longer decodes to a live entry, and a slot only produces the same value again after 65535
//!   reuses;
//! - **0 is never a valid handle** (`Handle::INVALID`).
//!
//! The table only stores entries; rights checks and quota charging are done by `Process`.
//! Lookups are O(1): decode, index, compare the generation.

use alloc::vec::Vec;

use super::kref::KRef;
use super::quota::{Account, Res};
use super::{KResult, Object, Rights, Status};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct Handle(pub u32);

impl Handle {
    pub const INVALID: Handle = Handle(0);
}

/// Slots per table (16-bit index).
pub const MAX_SLOTS: usize = 1 << 16;
const NO_SLOT: u32 = u32::MAX;

enum Slot {
    Free { generation: u16, next: u32 },
    Used { generation: u16, rights: Rights, obj: Object },
}

pub struct HandleTable {
    slots: Vec<Slot>,
    free_head: u32,
    count: u32,
    key: [u32; 2],
    dead: bool,
    acct: KRef<Account>,
}

// Invertible 32-bit mixing: xor with a key, multiply by an odd constant (invertible mod 2^32),
// xor-shift by 16 (its own inverse), multiply, xor with a second key.
const M1: u32 = 0x7FEB_352D;
const M2: u32 = 0x846C_A68B;
const fn mod_inverse(m: u32) -> u32 {
    let mut inv = m; // Newton's iteration: correct bits double each step (3 -> 6 -> ... -> 48)
    let mut i = 0;
    while i < 5 {
        inv = inv.wrapping_mul(2u32.wrapping_sub(m.wrapping_mul(inv)));
        i += 1;
    }
    inv
}
const M1_INV: u32 = mod_inverse(M1);
const M2_INV: u32 = mod_inverse(M2);
const _: () = assert!(M1.wrapping_mul(M1_INV) == 1 && M2.wrapping_mul(M2_INV) == 1);

impl HandleTable {
    pub fn new(acct: KRef<Account>, random: u64) -> HandleTable {
        HandleTable {
            slots: Vec::new(),
            free_head: NO_SLOT,
            count: 0,
            key: [random as u32, (random >> 32) as u32],
            dead: false,
            acct,
        }
    }

    fn encode(&self, idx: u32, generation: u16) -> u32 {
        let mut x = ((generation as u32) << 16 | idx) ^ self.key[0];
        x = x.wrapping_mul(M1);
        x ^= x >> 16;
        x = x.wrapping_mul(M2);
        x ^ self.key[1]
    }

    fn decode(&self, h: Handle) -> (u32, u16) {
        let mut x = h.0 ^ self.key[1];
        x = x.wrapping_mul(M2_INV);
        x ^= x >> 16;
        x = x.wrapping_mul(M1_INV);
        x ^= self.key[0];
        (x & 0xFFFF, (x >> 16) as u16)
    }

    /// Next generation for a slot: never 0 (so the raw pair is never 0), and skipping the one
    /// generation whose encoded value would be 0.
    fn next_gen(&self, idx: u32, generation: u16) -> u16 {
        let mut g = generation;
        loop {
            g = if g == u16::MAX { 1 } else { g + 1 };
            if self.encode(idx, g) != 0 {
                return g;
            }
        }
    }

    pub fn count(&self) -> u32 {
        self.count
    }

    pub fn is_dead(&self) -> bool {
        self.dead
    }

    /// Add an entry. On failure the object comes back so the caller can drop it after unlocking.
    pub fn insert(&mut self, obj: Object, rights: Rights) -> Result<Handle, (Status, Object)> {
        if self.dead {
            return Err((Status::BadState, obj));
        }
        if let Err(e) = self.acct.charge(Res::Handles, 1) {
            return Err((e, obj));
        }
        let idx = if self.free_head != NO_SLOT {
            self.free_head
        } else {
            let full = self.slots.len() >= MAX_SLOTS;
            if full || self.slots.try_reserve(1).is_err() {
                self.acct.uncharge(Res::Handles, 1);
                let e = if full { Status::NoResources } else { Status::NoMemory };
                return Err((e, obj));
            }
            self.slots.push(Slot::Free {
                generation: 0,
                next: NO_SLOT,
            });
            (self.slots.len() - 1) as u32
        };
        let Slot::Free { generation, next } = self.slots[idx as usize] else {
            unreachable!()
        };
        if self.free_head == idx {
            self.free_head = next;
        }
        let generation = self.next_gen(idx, generation);
        self.slots[idx as usize] = Slot::Used { generation, rights, obj };
        self.count += 1;
        Ok(Handle(self.encode(idx, generation)))
    }

    fn find(&self, h: Handle) -> Option<u32> {
        if h == Handle::INVALID {
            return None;
        }
        let (idx, generation) = self.decode(h);
        let len = self.slots.len();
        if idx as usize >= len {
            return None;
        }
        // Spectre v1: the slot index comes from a user-supplied handle value.
        let i = crate::nospec::index(idx as usize, len);
        match &self.slots[i] {
            Slot::Used { generation: g, .. } if *g == generation => Some(i as u32),
            _ => None,
        }
    }

    /// The entry's object (a new reference) and rights.
    pub fn get(&self, h: Handle) -> KResult<(Object, Rights)> {
        let idx = self.find(h).ok_or(Status::BadHandle)?;
        match &self.slots[idx as usize] {
            Slot::Used { rights, obj, .. } => Ok((obj.clone(), *rights)),
            Slot::Free { .. } => Err(Status::BadHandle),
        }
    }

    pub fn rights(&self, h: Handle) -> KResult<Rights> {
        let idx = self.find(h).ok_or(Status::BadHandle)?;
        match &self.slots[idx as usize] {
            Slot::Used { rights, .. } => Ok(*rights),
            Slot::Free { .. } => Err(Status::BadHandle),
        }
    }

    /// Visit every entry (type, koid, rights, name) in slot order, at most `max`; returns how
    /// many entries the table holds. No allocation, no other lock.
    pub fn list(&self, max: usize, mut f: impl FnMut(&Object, Rights)) -> u32 {
        let mut seen = 0;
        for s in &self.slots {
            if let Slot::Used { rights, obj, .. } = s {
                if seen < max {
                    f(obj, *rights);
                }
                seen += 1;
            }
        }
        self.count
    }

    /// Remove an entry; the caller drops the object after unlocking.
    pub fn remove(&mut self, h: Handle) -> KResult<(Object, Rights)> {
        let idx = self.find(h).ok_or(Status::BadHandle)?;
        let generation = match &self.slots[idx as usize] {
            Slot::Used { generation, .. } => *generation,
            Slot::Free { .. } => return Err(Status::BadHandle),
        };
        let old = core::mem::replace(
            &mut self.slots[idx as usize],
            Slot::Free {
                generation,
                next: self.free_head,
            },
        );
        self.free_head = idx;
        self.count -= 1;
        self.acct.uncharge(Res::Handles, 1);
        match old {
            Slot::Used { obj, rights, .. } => Ok((obj, rights)),
            Slot::Free { .. } => unreachable!(),
        }
    }

    /// Close everything and refuse new entries (process kill). Returns the entries so the caller
    /// can drop them after unlocking; no allocation.
    pub fn close_all(&mut self) -> SlotsDrop {
        self.dead = true;
        self.acct.uncharge(Res::Handles, u64::from(self.count));
        self.count = 0;
        self.free_head = NO_SLOT;
        SlotsDrop(core::mem::take(&mut self.slots))
    }
}

impl Drop for HandleTable {
    /// A process dropped without being killed still gives its handle quota back.
    fn drop(&mut self) {
        self.acct.uncharge(Res::Handles, u64::from(self.count));
    }
}

/// Closed entries, to be dropped outside the table lock.
pub struct SlotsDrop(#[allow(dead_code)] Vec<Slot>);
