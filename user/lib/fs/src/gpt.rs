//! GUID Partition Table (UEFI spec, chapter 5): reading, with both header and entry-array
//! CRCs checked and the backup table used when the primary is damaged; writing (with a
//! protective MBR) for the host image tool.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use crate::dev::{BlockDev, SECTOR, crc32};
use crate::{Error, Result};

pub type Guid = [u8; 16];

/// GUIDs in their on-disk byte order (the first three fields little-endian).
pub const fn guid(a: u32, b: u16, c: u16, d: [u8; 8]) -> Guid {
    let a = a.to_le_bytes();
    let (b, c) = (b.to_le_bytes(), c.to_le_bytes());
    [a[0], a[1], a[2], a[3], b[0], b[1], c[0], c[1], d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]]
}

/// EFI System Partition (FAT32).
pub const TYPE_ESP: Guid = guid(0xC12A7328, 0xF81F, 0x11D2, [0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B]);
/// Microsoft basic data (FAT32 for data exchange).
pub const TYPE_BASIC_DATA: Guid = guid(0xEBD0A0A2, 0xB9E5, 0x4433, [0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26, 0x99, 0xC7]);
/// BIOS boot partition: raw sectors for a BIOS boot loader (D-OS: stage 2 + the kernel).
pub const TYPE_BIOS_BOOT: Guid = guid(0x21686148, 0x6449, 0x6E6F, [0x74, 0x4E, 0x65, 0x65, 0x64, 0x45, 0x46, 0x49]);
/// D-OS native filesystem (DFS), our own type GUID.
pub const TYPE_DFS: Guid = guid(0xD05F5D05, 0x0012, 0x4D0F, [0x9A, 0x5E, 0x44, 0x46, 0x53, 0x31, 0x00, 0x01]);
/// Linux filesystem data.
pub const TYPE_LINUX_FS: Guid = guid(0x0FC63DAF, 0x8483, 0x4772, [0x8E, 0x79, 0x3D, 0x69, 0xD8, 0x47, 0x7D, 0xE4]);
/// Microsoft Reserved Partition (MSR).
pub const TYPE_MSR: Guid = guid(0xE3C9E316, 0x0B5C, 0x4DB8, [0x81, 0x7D, 0xF9, 0x2D, 0xF0, 0x02, 0x15, 0xAE]);
/// Windows Recovery Environment.
pub const TYPE_WIN_RE: Guid = guid(0xDE94BBA4, 0x06D1, 0x4D40, [0xA1, 0x6A, 0xBF, 0xD5, 0x01, 0x79, 0xD6, 0xAC]);

const SIG: &[u8; 8] = b"EFI PART";
const ENTRY: usize = 128;
const ENTRIES: usize = 128;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Partition {
    pub index: usize,
    pub type_guid: Guid,
    pub guid: Guid,
    pub first: u64,
    pub last: u64,
    pub attributes: u64,
    pub name: String,
}

/// Full parsed GPT table metadata + partitions.
#[derive(Clone, Debug)]
pub struct GptInfo {
    pub disk_guid: Guid,
    pub first_usable: u64,
    pub last_usable: u64,
    pub entry_count: u32,
    pub entry_size: u32,
    pub parts: Vec<Partition>,
    pub primary_ok: bool,
}

/// An unallocated contiguous 1 MiB-aligned sector range `[first, last]` inside the GPT usable area.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FreeExtent {
    pub first: u64,
    pub last: u64,
}

impl FreeExtent {
    pub fn sectors(&self) -> u64 {
        self.last - self.first + 1
    }
}

/// A partition entry specification for `write_preserving`.
#[derive(Clone, Debug)]
pub struct RawPart {
    /// Original 1-based GPT slot to preserve (`None` = allocate first free slot).
    pub slot: Option<usize>,
    pub type_guid: Guid,
    pub guid: Guid,
    pub first: u64,
    pub last: u64,
    pub attributes: u64,
    pub name: String,
}

impl Partition {
    pub fn sectors(&self) -> u64 {
        self.last - self.first + 1
    }
}

fn u32_at(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}
fn u64_at(b: &[u8], o: usize) -> u64 {
    u64::from(u32_at(b, o)) | u64::from(u32_at(b, o + 4)) << 32
}

/// The partition table, or `NotFound` if the disk has no (valid) GPT. `primary_ok` reports
/// whether the primary table was intact (false: read from the backup).
pub fn read(dev: &mut dyn BlockDev) -> Result<(Vec<Partition>, bool)> {
    let info = read_full(dev)?;
    Ok((info.parts, info.primary_ok))
}

/// Read the full GPT table (disk GUID, usable LBA bounds, and all partitions).
pub fn read_full(dev: &mut dyn BlockDev) -> Result<GptInfo> {
    let n = dev.sectors();
    if n < 68 {
        return Err(Error::NotFound);
    }
    match table_full(dev, 1, n, true) {
        Ok(info) => Ok(info),
        Err(_) => table_full(dev, n - 1, n, false),
    }
}

fn table_full(dev: &mut dyn BlockDev, lba: u64, n: u64, primary_ok: bool) -> Result<GptInfo> {
    let mut h = [0u8; SECTOR];
    dev.read(lba, &mut h)?;
    if &h[0..8] != SIG {
        return Err(Error::NotFound);
    }
    let hsize = u32_at(&h, 12) as usize;
    if !(92..=SECTOR).contains(&hsize) || u64_at(&h, 24) != lba {
        return Err(Error::Corrupt);
    }
    let want = u32_at(&h, 16);
    let mut c = h;
    c[16..20].fill(0);
    if crc32(&c[..hsize]) != want {
        return Err(Error::Corrupt);
    }
    let (first_usable, last_usable) = (u64_at(&h, 40), u64_at(&h, 48));
    let mut disk_guid = [0u8; 16];
    disk_guid.copy_from_slice(&h[56..72]);
    let entries_lba = u64_at(&h, 72);
    let count = u32_at(&h, 80) as usize;
    let esize = u32_at(&h, 84) as usize;
    if esize < ENTRY || !esize.is_multiple_of(8) || esize > 1024 || count > 1024 || last_usable >= n || first_usable > last_usable {
        return Err(Error::Corrupt);
    }
    let bytes = (count * esize).div_ceil(SECTOR) * SECTOR;
    if entries_lba.checked_add((bytes / SECTOR) as u64).is_none_or(|e| e > n) {
        return Err(Error::Corrupt);
    }
    let mut arr = vec![0u8; bytes];
    for (i, s) in arr.chunks_mut(32 * SECTOR).enumerate() {
        dev.read(entries_lba + (i * 32) as u64, s)?;
    }
    if crc32(&arr[..count * esize]) != u32_at(&h, 88) {
        return Err(Error::Corrupt);
    }
    let mut parts = Vec::new();
    for i in 0..count {
        let e = &arr[i * esize..i * esize + esize];
        let mut t = [0u8; 16];
        t.copy_from_slice(&e[0..16]);
        if t == [0; 16] {
            continue;
        }
        let mut g = [0u8; 16];
        g.copy_from_slice(&e[16..32]);
        let (first, last) = (u64_at(e, 32), u64_at(e, 40));
        let attributes = u64_at(e, 48);
        if first < first_usable || last > last_usable || first > last {
            return Err(Error::Corrupt); // a partition outside the usable area is never trusted
        }
        let name: String = char::decode_utf16((0..36).map(|j| u16::from_le_bytes([e[56 + 2 * j], e[57 + 2 * j]])).take_while(|&c| c != 0))
            .map(|r| r.unwrap_or('?'))
            .collect();
        parts.push(Partition { index: i + 1, type_guid: t, guid: g, first, last, attributes, name });
    }
    // Overlapping partitions would let two filesystems write the same sectors: refused.
    for a in &parts {
        for b in &parts {
            if a.index < b.index && a.first <= b.last && b.first <= a.last {
                return Err(Error::Corrupt);
            }
        }
    }
    Ok(GptInfo {
        disk_guid,
        first_usable,
        last_usable,
        entry_count: count as u32,
        entry_size: esize as u32,
        parts,
        primary_ok,
    })
}

/// Compute all 1 MiB-aligned unallocated free extents within the GPT usable area.
pub fn free_extents(info: &GptInfo) -> Vec<FreeExtent> {
    let mut used: Vec<(u64, u64)> = info.parts.iter().map(|p| (p.first, p.last)).collect();
    used.sort_by_key(|&(f, _)| f);
    let align_up = |x: u64| x.div_ceil(2048) * 2048;
    let mut cur = align_up(info.first_usable.max(2048));
    let mut out = Vec::new();
    for (first, last) in used {
        if first > cur {
            let end = first - 1;
            if end >= cur && end <= info.last_usable {
                out.push(FreeExtent { first: cur, last: end });
            }
        }
        if last >= cur {
            cur = align_up(last.saturating_add(1));
        }
    }
    if cur <= info.last_usable {
        out.push(FreeExtent { first: cur, last: info.last_usable });
    }
    out
}

/// True if the disk contains a valid GPT OR a non-empty legacy MBR partition table.
pub fn has_any_partition_table(dev: &mut dyn BlockDev) -> Result<bool> {
    if read(dev).is_ok() {
        return Ok(true);
    }
    if dev.sectors() == 0 {
        return Ok(false);
    }
    let mut mbr = [0u8; SECTOR];
    dev.read(0, &mut mbr)?;
    if mbr[510] == 0x55 && mbr[511] == 0xAA {
        for i in 0..4 {
            let e = &mbr[446 + i * 16..446 + (i + 1) * 16];
            let ptype = e[4];
            let len = u32::from_le_bytes([e[12], e[13], e[14], e[15]]);
            if ptype != 0 && len > 0 {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// A partition to create: type, name, size in sectors (0 = the rest of the disk).
pub struct NewPart<'a> {
    pub type_guid: Guid,
    pub name: &'a str,
    pub sectors: u64,
}

/// Write a protective MBR and a GPT (primary and backup) with `parts`, 1 MiB aligned.
/// `disk_guid` seeds the disk and partition GUIDs (deterministic images).
pub fn write(dev: &mut dyn BlockDev, parts: &[NewPart<'_>], disk_guid: Guid) -> Result<Vec<Partition>> {
    let n = dev.sectors();
    let array_sectors = (ENTRIES * ENTRY / SECTOR) as u64; // 32
    let first_usable = 2 + array_sectors;
    let last_usable = n - 2 - array_sectors;
    let mut arr = vec![0u8; ENTRIES * ENTRY];
    let mut out = Vec::new();
    let mut at = 2048u64;
    for (i, p) in parts.iter().enumerate() {
        let len = if p.sectors == 0 { last_usable + 1 - at } else { p.sectors };
        let last = at + len - 1;
        if last > last_usable || len == 0 {
            return Err(Error::NoSpace);
        }
        let mut g = disk_guid;
        g[15] = g[15].wrapping_add(i as u8 + 1);
        let e = &mut arr[i * ENTRY..(i + 1) * ENTRY];
        e[0..16].copy_from_slice(&p.type_guid);
        e[16..32].copy_from_slice(&g);
        e[32..40].copy_from_slice(&at.to_le_bytes());
        e[40..48].copy_from_slice(&last.to_le_bytes());
        for (j, c) in p.name.encode_utf16().take(36).enumerate() {
            e[56 + 2 * j..58 + 2 * j].copy_from_slice(&c.to_le_bytes());
        }
        out.push(Partition { index: i + 1, type_guid: p.type_guid, guid: g, first: at, last, attributes: 0, name: p.name.into() });
        at = (last + 1).div_ceil(2048) * 2048;
    }
    let arr_crc = crc32(&arr);
    // Protective MBR: one partition of type 0xEE over the whole disk.
    let mut mbr = [0u8; SECTOR];
    mbr[446 + 4] = 0xEE;
    mbr[446 + 1..446 + 4].copy_from_slice(&[0, 2, 0]);
    mbr[446 + 5..446 + 8].copy_from_slice(&[0xFF, 0xFF, 0xFF]);
    mbr[446 + 8..446 + 12].copy_from_slice(&1u32.to_le_bytes());
    mbr[446 + 12..446 + 16].copy_from_slice(&((n - 1).min(0xFFFF_FFFF) as u32).to_le_bytes());
    mbr[510] = 0x55;
    mbr[511] = 0xAA;
    dev.write(0, &mbr)?;
    write_gpt_tables(dev, n, first_usable, last_usable, disk_guid, &arr, arr_crc)?;
    Ok(out)
}

fn write_gpt_tables(
    dev: &mut dyn BlockDev,
    n: u64,
    first_usable: u64,
    last_usable: u64,
    disk_guid: Guid,
    arr: &[u8],
    arr_crc: u32,
) -> Result<()> {
    let array_sectors = (ENTRIES * ENTRY / SECTOR) as u64; // 32
    for (me, other, entries) in [(1, n - 1, 2), (n - 1, 1, n - 1 - array_sectors)] {
        let mut h = [0u8; SECTOR];
        h[0..8].copy_from_slice(SIG);
        h[8..12].copy_from_slice(&0x0001_0000u32.to_le_bytes());
        h[12..16].copy_from_slice(&92u32.to_le_bytes());
        h[24..32].copy_from_slice(&me.to_le_bytes());
        h[32..40].copy_from_slice(&other.to_le_bytes());
        h[40..48].copy_from_slice(&first_usable.to_le_bytes());
        h[48..56].copy_from_slice(&last_usable.to_le_bytes());
        h[56..72].copy_from_slice(&disk_guid);
        h[72..80].copy_from_slice(&entries.to_le_bytes());
        h[80..84].copy_from_slice(&(ENTRIES as u32).to_le_bytes());
        h[84..88].copy_from_slice(&(ENTRY as u32).to_le_bytes());
        h[88..92].copy_from_slice(&arr_crc.to_le_bytes());
        let c = crc32(&h[..92]);
        h[16..20].copy_from_slice(&c.to_le_bytes());
        dev.write(entries, arr)?;
        dev.write(me, &h)?;
    }
    dev.flush()?;
    Ok(())
}

/// Write an updated GPT preserving exact slots, GUIDs, LBA ranges, and attributes for existing
/// partitions while placing new entries (`slot: None`) into unused slots. Refuses overlaps or
/// out-of-range LBAs before writing a single sector.
pub fn write_preserving(
    dev: &mut dyn BlockDev,
    disk_guid: Guid,
    parts: &[RawPart],
    keep_mbr_boot_code: bool,
) -> Result<Vec<Partition>> {
    let n = dev.sectors();
    let array_sectors = (ENTRIES * ENTRY / SECTOR) as u64;
    if n < 2 * (2 + array_sectors) {
        return Err(Error::NoSpace);
    }
    let first_usable = 2 + array_sectors;
    let last_usable = n - 2 - array_sectors;

    // Validate bounds and zero overlaps before touching disk.
    for (i, a) in parts.iter().enumerate() {
        if a.type_guid == [0; 16] || a.first < first_usable || a.last > last_usable || a.first > a.last {
            return Err(Error::Corrupt);
        }
        for b in &parts[i + 1..] {
            if a.first <= b.last && b.first <= a.last {
                return Err(Error::Corrupt);
            }
        }
    }

    let mut used_slots = [false; ENTRIES];
    for p in parts {
        if let Some(slot) = p.slot {
            if slot == 0 || slot > ENTRIES || used_slots[slot - 1] {
                return Err(Error::Corrupt);
            }
            used_slots[slot - 1] = true;
        }
    }

    let mut arr = vec![0u8; ENTRIES * ENTRY];
    let mut out = Vec::with_capacity(parts.len());
    for p in parts {
        let idx0 = match p.slot {
            Some(s) => s - 1,
            None => {
                let free = used_slots.iter().position(|&u| !u).ok_or(Error::NoSpace)?;
                used_slots[free] = true;
                free
            }
        };
        let e = &mut arr[idx0 * ENTRY..(idx0 + 1) * ENTRY];
        e[0..16].copy_from_slice(&p.type_guid);
        e[16..32].copy_from_slice(&p.guid);
        e[32..40].copy_from_slice(&p.first.to_le_bytes());
        e[40..48].copy_from_slice(&p.last.to_le_bytes());
        e[48..56].copy_from_slice(&p.attributes.to_le_bytes());
        for (j, c) in p.name.encode_utf16().take(36).enumerate() {
            e[56 + 2 * j..58 + 2 * j].copy_from_slice(&c.to_le_bytes());
        }
        out.push(Partition {
            index: idx0 + 1,
            type_guid: p.type_guid,
            guid: p.guid,
            first: p.first,
            last: p.last,
            attributes: p.attributes,
            name: p.name.clone(),
        });
    }
    out.sort_by_key(|p| p.index);

    let mut mbr = [0u8; SECTOR];
    if keep_mbr_boot_code {
        let mut cur = [0u8; SECTOR];
        if dev.read(0, &mut cur).is_ok() {
            mbr[..440].copy_from_slice(&cur[..440]);
        }
    }
    mbr[446 + 4] = 0xEE;
    mbr[446 + 1..446 + 4].copy_from_slice(&[0, 2, 0]);
    mbr[446 + 5..446 + 8].copy_from_slice(&[0xFF, 0xFF, 0xFF]);
    mbr[446 + 8..446 + 12].copy_from_slice(&1u32.to_le_bytes());
    mbr[446 + 12..446 + 16].copy_from_slice(&((n - 1).min(0xFFFF_FFFF) as u32).to_le_bytes());
    mbr[510] = 0x55;
    mbr[511] = 0xAA;
    dev.write(0, &mbr)?;

    let arr_crc = crc32(&arr);
    write_gpt_tables(dev, n, first_usable, last_usable, disk_guid, &arr, arr_crc)?;
    Ok(out)
}

/// Remove a single partition by 1-based GPT slot index, leaving every other partition untouched.
pub fn delete_partition(dev: &mut dyn BlockDev, part_index: usize) -> Result<Vec<Partition>> {
    let info = read_full(dev)?;
    if !info.parts.iter().any(|p| p.index == part_index) {
        return Err(Error::NotFound);
    }
    let kept: Vec<RawPart> = info
        .parts
        .into_iter()
        .filter(|p| p.index != part_index)
        .map(|p| RawPart {
            slot: Some(p.index),
            type_guid: p.type_guid,
            guid: p.guid,
            first: p.first,
            last: p.last,
            attributes: p.attributes,
            name: p.name,
        })
        .collect();
    write_preserving(dev, info.disk_guid, &kept, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dev::MemDev;

    #[test]
    fn round_trip_and_backup() {
        let mut d = MemDev::new(16 * 2048);
        let parts = [NewPart { type_guid: TYPE_ESP, name: "boot", sectors: 4096 }, NewPart { type_guid: TYPE_DFS, name: "system", sectors: 0 }];
        write(&mut d, &parts, [7; 16]).unwrap();
        let (p, ok) = read(&mut d).unwrap();
        assert!(ok);
        assert_eq!(p.len(), 2);
        assert_eq!((p[0].first, p[0].sectors(), p[0].name.as_str()), (2048, 4096, "boot"));
        assert_eq!(p[1].type_guid, TYPE_DFS);
        assert_eq!(p[1].first, 6144);
        // A damaged primary header: the backup is used.
        d.data[SECTOR + 30] ^= 1;
        let (p2, ok) = read(&mut d).unwrap();
        assert!(!ok);
        assert_eq!(p2.len(), 2);
        // Both damaged: no table.
        let last = d.data.len() - SECTOR;
        d.data[last + 30] ^= 1;
        assert!(read(&mut d).is_err());
    }
}
