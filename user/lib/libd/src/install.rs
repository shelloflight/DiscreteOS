//! Installer & disk partitioning client protocol (`storaged.admin` endpoint).
//!
//! Capability-gated to `shell` and `installer.dapp` (`Permission::StorageAdmin`, Operator-only).

use crate::proto::{HEADER, Header};
use crate::sys::{self, Handle};

pub fn admin_endpoint() -> Handle {
    crate::svc::endpoint(b"storaged.admin")
}

/// List all attached disks, existing partitions, detected filesystems, and unallocated GPT space.
pub const OP_LIST_DISKS: u32 = 260;
/// Dry-run install plan for `disk_name`; `a = mode | (confirm_wipe << 8)`. Reply payload = UTF-8 summary.
pub const OP_PLAN: u32 = 261;
/// Delete a single GPT partition; `a = part_index | (confirm << 32)`, payload = `disk_name`.
pub const OP_DELETE_PART: u32 = 262;
/// Execute installation on `disk_name`; `a = mode | (confirm_wipe << 8)`. Reply payload = UTF-8 summary.
pub const OP_INSTALL: u32 = 263;

pub const MODE_DUAL_BOOT: u8 = 1;
pub const MODE_WHOLE_DISK: u8 = 2;
pub const MODE_WIPE_DISK: u8 = 3;

pub const DISK_FLAG_LIVE_BOOT: u32 = 1 << 0;
pub const DISK_FLAG_OPTICAL: u32 = 1 << 1;
pub const DISK_FLAG_HAS_GPT: u32 = 1 << 2;
pub const DISK_FLAG_HAS_MBR: u32 = 1 << 3;
pub const DISK_FLAG_HAS_ESP: u32 = 1 << 4;

pub const MAX_DISKS: usize = 8;
pub const MAX_PARTS_PER_DISK: usize = 16;

/// Wire size of one `PartSummary` (64 bytes).
pub const PART_WIRE_BYTES: usize = 64;
/// Wire size of one `DiskHeaderWire` (104 bytes).
pub const DISK_HEADER_WIRE_BYTES: usize = 104;

#[derive(Clone, Copy, Debug, Default)]
pub struct PartSummary {
    pub index: u32,
    pub first: u64,
    pub last: u64,
    pub size_mib: u32,
    pub fs_label: [u8; 12],
    pub fs_len: u8,
    pub name: [u8; 24],
    pub name_len: u8,
}

impl PartSummary {
    pub fn fs_str(&self) -> &str {
        core::str::from_utf8(&self.fs_label[..usize::from(self.fs_len).min(12)]).unwrap_or("?")
    }
    pub fn name_str(&self) -> &str {
        core::str::from_utf8(&self.name[..usize::from(self.name_len).min(24)]).unwrap_or("")
    }

    pub fn encode(&self, dst: &mut [u8; PART_WIRE_BYTES]) {
        dst.fill(0);
        dst[0..4].copy_from_slice(&self.index.to_le_bytes());
        dst[4..8].copy_from_slice(&self.size_mib.to_le_bytes());
        dst[8..16].copy_from_slice(&self.first.to_le_bytes());
        dst[16..24].copy_from_slice(&self.last.to_le_bytes());
        dst[24] = self.fs_len.min(12);
        dst[25] = self.name_len.min(24);
        dst[26..38].copy_from_slice(&self.fs_label);
        dst[38..62].copy_from_slice(&self.name);
    }

    pub fn decode(src: &[u8]) -> Option<Self> {
        if src.len() < PART_WIRE_BYTES {
            return None;
        }
        let u32_at = |i: usize| u32::from_le_bytes([src[i], src[i + 1], src[i + 2], src[i + 3]]);
        let u64_at = |i: usize| u64::from(u32_at(i)) | (u64::from(u32_at(i + 4)) << 32);
        let mut p = Self {
            index: u32_at(0),
            size_mib: u32_at(4),
            first: u64_at(8),
            last: u64_at(16),
            fs_len: src[24].min(12),
            name_len: src[25].min(24),
            fs_label: [0; 12],
            name: [0; 24],
        };
        p.fs_label.copy_from_slice(&src[26..38]);
        p.name.copy_from_slice(&src[38..62]);
        Some(p)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct DiskSummary {
    pub name: [u8; 32],
    pub name_len: u8,
    pub model: [u8; 40],
    pub model_len: u8,
    pub sectors: u64,
    pub flags: u32,
    pub largest_free_mib: u32,
    pub total_free_mib: u32,
    pub part_count: u8,
    pub parts: [PartSummary; MAX_PARTS_PER_DISK],
}

impl Default for DiskSummary {
    fn default() -> Self {
        Self {
            name: [0; 32],
            name_len: 0,
            model: [0; 40],
            model_len: 0,
            sectors: 0,
            flags: 0,
            largest_free_mib: 0,
            total_free_mib: 0,
            part_count: 0,
            parts: [PartSummary::default(); MAX_PARTS_PER_DISK],
        }
    }
}

impl DiskSummary {
    pub fn name_str(&self) -> &str {
        core::str::from_utf8(&self.name[..usize::from(self.name_len).min(32)]).unwrap_or("?")
    }
    pub fn model_str(&self) -> &str {
        core::str::from_utf8(&self.model[..usize::from(self.model_len).min(40)]).unwrap_or("")
    }
    pub fn size_mib(&self) -> u64 {
        self.sectors / 2048
    }
    pub fn is_live_boot(&self) -> bool {
        (self.flags & DISK_FLAG_LIVE_BOOT) != 0
    }
    pub fn is_optical(&self) -> bool {
        (self.flags & DISK_FLAG_OPTICAL) != 0
    }
    pub fn has_gpt(&self) -> bool {
        (self.flags & DISK_FLAG_HAS_GPT) != 0
    }
    pub fn has_mbr(&self) -> bool {
        (self.flags & DISK_FLAG_HAS_MBR) != 0
    }
    pub fn has_esp(&self) -> bool {
        (self.flags & DISK_FLAG_HAS_ESP) != 0
    }
    pub fn is_blank(&self) -> bool {
        !self.has_gpt() && !self.has_mbr() && self.part_count == 0
    }
    pub fn parts_slice(&self) -> &[PartSummary] {
        &self.parts[..usize::from(self.part_count).min(MAX_PARTS_PER_DISK)]
    }

    pub fn encode_header(&self, dst: &mut [u8; DISK_HEADER_WIRE_BYTES]) {
        dst.fill(0);
        dst[0..8].copy_from_slice(&self.sectors.to_le_bytes());
        dst[8..12].copy_from_slice(&self.flags.to_le_bytes());
        dst[12..16].copy_from_slice(&self.largest_free_mib.to_le_bytes());
        dst[16..20].copy_from_slice(&self.total_free_mib.to_le_bytes());
        dst[20] = self.name_len.min(32);
        dst[21] = self.model_len.min(40);
        dst[22] = self.part_count.min(MAX_PARTS_PER_DISK as u8);
        dst[24..56].copy_from_slice(&self.name);
        dst[56..96].copy_from_slice(&self.model);
    }

    pub fn decode_from(src: &[u8]) -> Option<(Self, usize)> {
        if src.len() < DISK_HEADER_WIRE_BYTES {
            return None;
        }
        let u32_at = |i: usize| u32::from_le_bytes([src[i], src[i + 1], src[i + 2], src[i + 3]]);
        let u64_at = |i: usize| u64::from(u32_at(i)) | (u64::from(u32_at(i + 4)) << 32);
        let mut d = Self {
            sectors: u64_at(0),
            flags: u32_at(8),
            largest_free_mib: u32_at(12),
            total_free_mib: u32_at(16),
            name_len: src[20].min(32),
            model_len: src[21].min(40),
            part_count: src[22].min(MAX_PARTS_PER_DISK as u8),
            ..Self::default()
        };
        d.name.copy_from_slice(&src[24..56]);
        d.model.copy_from_slice(&src[56..96]);
        let mut off = DISK_HEADER_WIRE_BYTES;
        for i in 0..usize::from(d.part_count) {
            if off + PART_WIRE_BYTES > src.len() {
                return None;
            }
            d.parts[i] = PartSummary::decode(&src[off..off + PART_WIRE_BYTES])?;
            off += PART_WIRE_BYTES;
        }
        Some((d, off))
    }
}

const CALL_TIMEOUT_NS: u64 = 180_000_000_000; // 180s for full DFS copy + fsck

pub fn list_disks(ch: Handle, out: &mut [DiskSummary]) -> Result<usize, i64> {
    if ch == 0 {
        return Err(sys::ERR_ACCESS_DENIED);
    }
    let mut req = [0u8; HEADER];
    Header { txid: 0, op: OP_LIST_DISKS, status: 0, a: 0, b: 0 }.put(&mut req);
    let mut rep = [0u8; HEADER + 12 * 1024];
    let n = sys::channel_call(ch, &req, &mut rep, 30_000_000_000)? as usize;
    let h = Header::get(&rep[..n]).ok_or(sys::ERR_INVALID_ARGS)?;
    if h.status != 0 {
        return Err(i64::from(h.status));
    }
    let body = &rep[HEADER..n];
    let mut off = 0usize;
    let mut cnt = 0usize;
    let want = (h.a as usize).min(out.len());
    while cnt < want && off < body.len() {
        let Some((d, used)) = DiskSummary::decode_from(&body[off..]) else { break };
        out[cnt] = d;
        cnt += 1;
        off += used;
    }
    Ok(cnt)
}

fn call_text(ch: Handle, op: u32, a: u64, disk: &str, out: &mut [u8]) -> Result<usize, (i64, usize)> {
    if ch == 0 {
        return Err((sys::ERR_ACCESS_DENIED, 0));
    }
    let db = disk.as_bytes();
    if db.is_empty() || db.len() > 64 {
        return Err((sys::ERR_INVALID_ARGS, 0));
    }
    let mut req = [0u8; HEADER + 64];
    Header { txid: 0, op, status: 0, a, b: 0 }.put(&mut req);
    req[HEADER..HEADER + db.len()].copy_from_slice(db);
    let mut rep = [0u8; HEADER + 4096];
    let n = match sys::channel_call(ch, &req[..HEADER + db.len()], &mut rep, CALL_TIMEOUT_NS) {
        Ok(n) => n as usize,
        Err(e) => return Err((e, 0)),
    };
    let Some(h) = Header::get(&rep[..n]) else {
        return Err((sys::ERR_INVALID_ARGS, 0));
    };
    let body = &rep[HEADER..n];
    let copy = body.len().min(out.len());
    out[..copy].copy_from_slice(&body[..copy]);
    if h.status != 0 {
        Err((i64::from(h.status), copy))
    } else {
        Ok(copy)
    }
}

pub fn plan(ch: Handle, disk: &str, mode: u8, confirm_wipe: bool, out: &mut [u8]) -> Result<usize, (i64, usize)> {
    let a = u64::from(mode) | (u64::from(confirm_wipe) << 8);
    call_text(ch, OP_PLAN, a, disk, out)
}

pub fn delete_part(ch: Handle, disk: &str, part_index: u32, confirm: bool, out: &mut [u8]) -> Result<usize, (i64, usize)> {
    let a = u64::from(part_index) | (u64::from(confirm) << 32);
    call_text(ch, OP_DELETE_PART, a, disk, out)
}

pub fn execute(ch: Handle, disk: &str, mode: u8, confirm_wipe: bool, out: &mut [u8]) -> Result<usize, (i64, usize)> {
    let a = u64::from(mode) | (u64::from(confirm_wipe) << 8);
    call_text(ch, OP_INSTALL, a, disk, out)
}
