//! Deterministic ISO 9660 + El Torito (BIOS + UEFI) + hybrid MBR/GPT image builder.
//!
//! Takes the built `discrete.img` (which already contains a Protective MBR at LBA 0, Primary GPT
//! at LBA 1..33, Backup GPT at the end of the image, `bios-boot` at LBA 2048, FAT32 `esp`, and
//! immutable DFS `sys`) and populates the unused 17 KiB..1 MiB gap (ISO blocks 16..31) with:
//! - ISO 9660 Primary Volume Descriptor (block 16)
//! - El Torito Boot Record Volume Descriptor (block 17)
//! - ISO 9660 Volume Descriptor Set Terminator (block 18)
//! - El Torito Boot Catalog (block 19) with BOTH:
//!   - BIOS No-Emulation boot entry (`isoboot.bin` at block 24)
//!   - UEFI EFI System Partition boot entry (Platform ID `0xEF`, pointing directly at the FAT32 ESP)
//! - ISO 9660 L/M Path Tables (blocks 20..21), Root Directory (block 22), and `README.TXT` (block 25)
//!
//! Because LBA 0..33 fit entirely inside the 32 KiB ISO 9660 System Area and every GPT partition
//! starts at >= 1 MiB (block 512), the resulting `discrete.iso` boots cleanly as:
//! - A virtual/physical CD-ROM under UEFI (VirtualBox, VMware, QEMU OVMF)
//! - A virtual/physical CD-ROM under Legacy BIOS (VirtualBox, VMware, QEMU SeaBIOS)
//! - A hybrid raw disk / USB stick (`dd`) under both UEFI and BIOS.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use dosfs::dev::{BlockDev, SECTOR};
use dosfs::gpt;

const ISO_BLOCK: usize = 2048;
const PVD_LBA: u32 = 16;
const BOOT_REC_LBA: u32 = 17;
const TERM_LBA: u32 = 18;
const CATALOG_LBA: u32 = 19;
const LPATH_LBA: u32 = 20;
const MPATH_LBA: u32 = 21;
const ROOT_DIR_LBA: u32 = 22;
const ISOBOOT_LBA: u32 = 24;
const README_LBA: u32 = 25;

const ISO_README: &[u8] = b"DiscreteOS Hybrid Live/Installer ISO (UEFI + BIOS)\r\n\
\r\n\
This ISO image is bootable as an optical disc (VirtualBox, VMware, QEMU, or\r\n\
burned media) and as a hybrid raw image written directly to a USB drive.\r\n\
\r\n\
Both UEFI (El Torito EFI System Partition) and Legacy BIOS (El Torito\r\n\
no-emulation) boot paths are included with Ed25519 verified boot.\r\n\
";

struct RoFileDev {
    f: File,
    sectors: u64,
}

impl BlockDev for RoFileDev {
    fn sectors(&self) -> u64 {
        self.sectors
    }
    fn read(&mut self, lba: u64, buf: &mut [u8]) -> dosfs::Result<()> {
        self.f
            .seek(SeekFrom::Start(lba * SECTOR as u64))
            .map_err(|_| dosfs::Error::Io)?;
        self.f.read_exact(buf).map_err(|_| dosfs::Error::Io)
    }
    fn write(&mut self, _lba: u64, _buf: &[u8]) -> dosfs::Result<()> {
        Err(dosfs::Error::ReadOnly)
    }
    fn flush(&mut self) -> dosfs::Result<()> {
        Ok(())
    }
}

fn put_both16(dst: &mut [u8], v: u16) {
    dst[0..2].copy_from_slice(&v.to_le_bytes());
    dst[2..4].copy_from_slice(&v.to_be_bytes());
}

fn put_both32(dst: &mut [u8], v: u32) {
    dst[0..4].copy_from_slice(&v.to_le_bytes());
    dst[4..8].copy_from_slice(&v.to_be_bytes());
}

fn put_str_pad(dst: &mut [u8], s: &[u8], pad: u8) {
    dst.fill(pad);
    let n = s.len().min(dst.len());
    dst[..n].copy_from_slice(&s[..n]);
}

/// Encode an ISO 9660 directory record with deterministic timestamp (2026-01-01 00:00:00 UTC).
fn dir_record(extent_lba: u32, data_len: u32, flags: u8, name: &[u8]) -> Vec<u8> {
    let mut len = 33 + name.len();
    if !len.is_multiple_of(2) {
        len += 1;
    }
    let mut r = vec![0u8; len];
    r[0] = len as u8;
    r[1] = 0; // extended attribute record length
    put_both32(&mut r[2..10], extent_lba);
    put_both32(&mut r[10..18], data_len);
    // Recording date and time: years since 1900 (126 = 2026), month 1, day 1, 00:00:00 UTC.
    r[18..25].copy_from_slice(&[126, 1, 1, 0, 0, 0, 0]);
    r[25] = flags;
    r[26] = 0; // file unit size
    r[27] = 0; // interleave gap size
    put_both16(&mut r[28..32], 1); // volume sequence number
    r[32] = name.len() as u8;
    r[33..33 + name.len()].copy_from_slice(name);
    r
}

fn build_pvd(total_blocks: u32) -> [u8; ISO_BLOCK] {
    let mut b = [0u8; ISO_BLOCK];
    b[0] = 1; // Primary Volume Descriptor
    b[1..6].copy_from_slice(b"CD001");
    b[6] = 1; // Version
    put_str_pad(&mut b[8..40], b"D-OS", b' ');
    put_str_pad(&mut b[40..72], b"DISCRETE_OS", b' ');
    put_both32(&mut b[80..88], total_blocks);
    put_both16(&mut b[120..124], 1); // Volume Set Size
    put_both16(&mut b[124..128], 1); // Volume Sequence Number
    put_both16(&mut b[128..132], ISO_BLOCK as u16); // Logical Block Size
    put_both32(&mut b[132..140], 10); // Path Table Size (root entry = 10 bytes)
    b[140..144].copy_from_slice(&LPATH_LBA.to_le_bytes());
    b[148..152].copy_from_slice(&MPATH_LBA.to_be_bytes());

    let root = dir_record(ROOT_DIR_LBA, ISO_BLOCK as u32, 0x02, &[0x00]);
    debug_assert_eq!(root.len(), 34);
    b[156..190].copy_from_slice(&root);

    put_str_pad(&mut b[190..318], b"DISCRETE_OS", b' '); // Volume Set Identifier
    put_str_pad(&mut b[318..446], b"DISCRETE OS PROJECT", b' '); // Publisher Identifier
    put_str_pad(&mut b[446..574], b"DBUILD", b' '); // Data Preparer Identifier
    put_str_pad(&mut b[574..702], b"DISCRETE OS HYBRID ISO", b' '); // Application Identifier
    put_str_pad(&mut b[702..739], b"", b' ');
    put_str_pad(&mut b[739..776], b"", b' ');
    put_str_pad(&mut b[776..813], b"", b' ');
    // Deterministic 17-byte DEC-datetime stamps.
    b[813..830].copy_from_slice(b"2026010100000000\0");
    b[830..847].copy_from_slice(b"2026010100000000\0");
    b[847..864].copy_from_slice(b"0000000000000000\0");
    b[864..881].copy_from_slice(b"0000000000000000\0");
    b[881] = 1; // File Structure Version
    b
}

fn build_boot_record() -> [u8; ISO_BLOCK] {
    let mut b = [0u8; ISO_BLOCK];
    b[0] = 0; // Boot Record
    b[1..6].copy_from_slice(b"CD001");
    b[6] = 1;
    put_str_pad(&mut b[7..39], b"EL TORITO SPECIFICATION", 0);
    b[71..75].copy_from_slice(&CATALOG_LBA.to_le_bytes());
    b
}

fn build_terminator() -> [u8; ISO_BLOCK] {
    let mut b = [0u8; ISO_BLOCK];
    b[0] = 0xFF;
    b[1..6].copy_from_slice(b"CD001");
    b[6] = 1;
    b
}

fn build_boot_catalog(esp_iso_lba: u32) -> [u8; ISO_BLOCK] {
    let mut b = [0u8; ISO_BLOCK];

    // 1. Validation Entry (bytes 0..32): Platform ID 0x00 (x86 BIOS).
    let val = &mut b[0..32];
    val[0] = 0x01; // Header ID
    val[1] = 0x00; // Platform ID: 80x86
    put_str_pad(&mut val[4..28], b"DiscreteOS", 0);
    val[30] = 0x55;
    val[31] = 0xAA;
    let mut sum: u16 = 0;
    for chunk in val.as_chunks::<2>().0 {
        sum = sum.wrapping_add(u16::from_le_bytes(*chunk));
    }
    let checksum = 0u16.wrapping_sub(sum);
    val[28..30].copy_from_slice(&checksum.to_le_bytes());

    // 2. Initial / Default Entry (bytes 32..64): BIOS No-Emulation (`isoboot.bin`).
    let bios = &mut b[32..64];
    bios[0] = 0x88; // Bootable
    bios[1] = 0x00; // No Emulation
    bios[2..4].copy_from_slice(&0u16.to_le_bytes()); // Default load segment (0x07C0)
    bios[4] = 0x00; // System type
    bios[6..8].copy_from_slice(&4u16.to_le_bytes()); // 4 virtual 512-byte sectors = 2048 bytes
    bios[8..12].copy_from_slice(&ISOBOOT_LBA.to_le_bytes());

    // 3. Section Header Entry (bytes 64..96): Final section, Platform ID 0xEF (EFI).
    let hdr = &mut b[64..96];
    hdr[0] = 0x91; // Final Section Header
    hdr[1] = 0xEF; // Platform ID: EFI
    hdr[2..4].copy_from_slice(&1u16.to_le_bytes()); // 1 entry follows
    put_str_pad(&mut hdr[4..32], b"UEFI", 0);

    // 4. Section Entry (bytes 96..128): EFI System Partition (FAT32 ESP).
    // Sector count 0 instructs UEFI (UEFI 2.10 §13.3.2.1 / EDK2 PartitionDxe) to use the FAT BPB
    // length, which is required for FAT32 partitions larger than 32 MiB (>65535 512-byte sectors).
    let uefi = &mut b[96..128];
    uefi[0] = 0x88; // Bootable
    uefi[1] = 0x00; // No Emulation
    uefi[2..4].copy_from_slice(&0u16.to_le_bytes());
    uefi[4] = 0x00;
    uefi[6..8].copy_from_slice(&0u16.to_le_bytes());
    uefi[8..12].copy_from_slice(&esp_iso_lba.to_le_bytes());

    b
}

fn build_path_table(big_endian: bool) -> [u8; ISO_BLOCK] {
    let mut b = [0u8; ISO_BLOCK];
    b[0] = 1; // Length of Directory Identifier (root = 1 byte 0x00)
    b[1] = 0; // Extended Attribute Record Length
    if big_endian {
        b[2..6].copy_from_slice(&ROOT_DIR_LBA.to_be_bytes());
        b[6..8].copy_from_slice(&1u16.to_be_bytes());
    } else {
        b[2..6].copy_from_slice(&ROOT_DIR_LBA.to_le_bytes());
        b[6..8].copy_from_slice(&1u16.to_le_bytes());
    }
    b[8] = 0x00;
    b[9] = 0x00; // padding to even length
    b
}

fn build_root_dir() -> [u8; ISO_BLOCK] {
    let mut b = [0u8; ISO_BLOCK];
    let mut off = 0usize;
    for rec in [
        dir_record(ROOT_DIR_LBA, ISO_BLOCK as u32, 0x02, &[0x00]),
        dir_record(ROOT_DIR_LBA, ISO_BLOCK as u32, 0x02, &[0x01]),
        dir_record(README_LBA, ISO_README.len() as u32, 0x00, b"README.TXT;1"),
    ] {
        b[off..off + rec.len()].copy_from_slice(&rec);
        off += rec.len();
    }
    b
}

/// Build `out_iso` by copying `src_img` and injecting deterministic ISO 9660 + El Torito
/// (BIOS + UEFI) boot structures into the unused gap between the Primary GPT and Partition 1.
pub fn make_hybrid_iso(src_img: &Path, isoboot_bin: &Path, out_iso: &Path) -> Result<(), String> {
    let isoboot = std::fs::read(isoboot_bin)
        .map_err(|e| format!("{}: {e}", isoboot_bin.display()))?;
    if isoboot.len() != ISO_BLOCK {
        return Err(format!(
            "isoboot.bin must be exactly {ISO_BLOCK} bytes (got {})",
            isoboot.len()
        ));
    }

    // Validate GPT in `src_img` and locate the ESP partition.
    let img_len = std::fs::metadata(src_img)
        .map_err(|e| format!("{}: {e}", src_img.display()))?
        .len();
    if img_len == 0 || !img_len.is_multiple_of(ISO_BLOCK as u64) {
        return Err(format!(
            "{}: image size ({img_len}) must be a non-zero multiple of {ISO_BLOCK}",
            src_img.display()
        ));
    }
    let esp_first_lba = {
        let f = File::open(src_img).map_err(|e| format!("{}: {e}", src_img.display()))?;
        let mut dev = RoFileDev { f, sectors: img_len / SECTOR as u64 };
        let (parts, ok) = gpt::read(&mut dev).map_err(|e| format!("read GPT: {e:?}"))?;
        if !ok {
            return Err("source image primary GPT is damaged".into());
        }
        let min_first = parts.iter().map(|p| p.first).min().unwrap_or(0);
        if min_first < 2048 {
            return Err(format!(
                "first partition starts at LBA {min_first}; need >= 2048 for ISO 9660 headers"
            ));
        }
        let esp = parts
            .iter()
            .find(|p| p.type_guid == gpt::TYPE_ESP)
            .ok_or_else(|| "source image has no EFI System Partition".to_string())?;
        if !esp.first.is_multiple_of(4) {
            return Err(format!("ESP LBA {} is not 2048-byte aligned", esp.first));
        }
        esp.first
    };

    std::fs::copy(src_img, out_iso)
        .map_err(|e| format!("copy {} -> {}: {e}", src_img.display(), out_iso.display()))?;

    let mut f = OpenOptions::new()
        .read(true)
        .write(true)
        .open(out_iso)
        .map_err(|e| format!("open {}: {e}", out_iso.display()))?;

    let total_blocks = (img_len / ISO_BLOCK as u64) as u32;
    let esp_iso_lba = (esp_first_lba / 4) as u32;

    let mut write_block = |lba: u32, data: &[u8; ISO_BLOCK]| -> Result<(), String> {
        f.seek(SeekFrom::Start(u64::from(lba) * ISO_BLOCK as u64))
            .map_err(|e| format!("seek ISO block {lba}: {e}"))?;
        f.write_all(data)
            .map_err(|e| format!("write ISO block {lba}: {e}"))
    };

    write_block(PVD_LBA, &build_pvd(total_blocks))?;
    write_block(BOOT_REC_LBA, &build_boot_record())?;
    write_block(TERM_LBA, &build_terminator())?;
    write_block(CATALOG_LBA, &build_boot_catalog(esp_iso_lba))?;
    write_block(LPATH_LBA, &build_path_table(false))?;
    write_block(MPATH_LBA, &build_path_table(true))?;
    write_block(ROOT_DIR_LBA, &build_root_dir())?;

    let mut ib_block = [0u8; ISO_BLOCK];
    ib_block.copy_from_slice(&isoboot);
    write_block(ISOBOOT_LBA, &ib_block)?;

    let mut readme_block = [0u8; ISO_BLOCK];
    readme_block[..ISO_README.len()].copy_from_slice(ISO_README);
    write_block(README_LBA, &readme_block)?;

    f.flush().map_err(|e| format!("flush {}: {e}", out_iso.display()))?;
    Ok(())
}
