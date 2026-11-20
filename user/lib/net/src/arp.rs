//! Bounded ARP neighbor cache and pending transmit queue.

use alloc::vec::Vec;

use crate::{Ipv4Addr, MacAddr};

const MAX_ENTRIES: usize = 32;
const MAX_PENDING: usize = 16;
const ARP_TTL_MS: u64 = 120_000;

#[derive(Clone, Copy)]
struct Entry {
    ip: Ipv4Addr,
    mac: MacAddr,
    expires_ms: u64,
}

struct Pending {
    next_hop: Ipv4Addr,
    ipv4_pkt: Vec<u8>,
    queued_ms: u64,
}

pub struct ArpTable {
    entries: [Option<Entry>; MAX_ENTRIES],
    pending: Vec<Pending>,
}

impl Default for ArpTable {
    fn default() -> Self {
        Self::new()
    }
}

impl ArpTable {
    pub const fn new() -> Self {
        Self {
            entries: [None; MAX_ENTRIES],
            pending: Vec::new(),
        }
    }

    pub fn lookup(&self, ip: Ipv4Addr, now_ms: u64) -> Option<MacAddr> {
        self.entries
            .iter()
            .flatten()
            .find(|e| e.ip == ip && e.expires_ms > now_ms)
            .map(|e| e.mac)
    }

    /// Record `(ip, mac)` and return any queued IPv4 packets waiting for `ip`.
    pub fn insert(&mut self, ip: Ipv4Addr, mac: MacAddr, now_ms: u64) -> Vec<Vec<u8>> {
        let expires_ms = now_ms.saturating_add(ARP_TTL_MS);
        if let Some(e) = self.entries.iter_mut().flatten().find(|e| e.ip == ip) {
            e.mac = mac;
            e.expires_ms = expires_ms;
        } else {
            let slot = self
                .entries
                .iter()
                .position(|e| e.is_none() || e.is_some_and(|x| x.expires_ms <= now_ms))
                .unwrap_or(0);
            self.entries[slot] = Some(Entry { ip, mac, expires_ms });
        }
        let mut ready = Vec::new();
        let mut i = 0;
        while i < self.pending.len() {
            if self.pending[i].next_hop == ip {
                ready.push(self.pending.swap_remove(i).ipv4_pkt);
            } else {
                i += 1;
            }
        }
        ready
    }

    pub fn queue_pending(&mut self, next_hop: Ipv4Addr, ipv4_pkt: Vec<u8>, now_ms: u64) {
        if self.pending.len() >= MAX_PENDING {
            self.pending.remove(0);
        }
        self.pending.push(Pending { next_hop, ipv4_pkt, queued_ms: now_ms });
    }

    pub fn prune(&mut self, now_ms: u64) {
        for slot in &mut self.entries {
            if slot.is_some_and(|e| e.expires_ms <= now_ms) {
                *slot = None;
            }
        }
        self.pending.retain(|p| now_ms.saturating_sub(p.queued_ms) < 5_000);
    }
}
