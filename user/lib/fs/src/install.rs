//! Disk installation planner & GPT partition engine (`dosfs::install`).
//!
//! Pure `#![no_std]` + `alloc` logic shared by `storaged`, the installer CLI/GUI, and host tests.
//! Supports:
//! - **Dual-boot (`DualBoot`)**: non-destructively installs D-OS into unallocated GPT free space
//!   without modifying any existing OS partitions; reuses an existing ESP (adding `\EFI\DOS\BOOTX64.EFI`
//!   without overwriting an existing `\EFI\BOOT\BOOTX64.EFI`) or creates an ESP in free space if absent.
//! - **Use Entire Disk (`WholeDisk`)**: formats a blank/unpartitioned disk with a full GPT layout
//!   (`bios-boot`, `esp`, immutable `sys`, writable `home`). Refuses non-empty disks.
//! - **Wipe & Repartition (`WipeDisk`)**: explicitly confirmed destructive replacement of existing
//!   partitions on a target disk with a clean full-disk D-OS GPT layout.

use alloc::string::String;
use alloc::vec::Vec;

use crate::dev::{BlockDev, SECTOR};
use crate::gpt::{self, FreeExtent, Guid, NewPart, Partition, RawPart};
use crate::{Error, Result};

/// 1 MiB in 512-byte sectors.
pub const SECTORS_PER_MIB: u64 = 2048;
/// BIOS boot partition size (8 MiB, matches `dbuild` layout so installed disks boot BIOS + UEFI).
pub const BIOS_BOOT_SECTORS: u64 = 8 * SECTORS_PER_MIB;
/// Minimum EFI System Partition size (36 MiB FAT32 — fallback for tiny virtual disks < 256 MiB).
pub const ESP_SECTORS: u64 = 36 * SECTORS_PER_MIB;
/// Medium EFI System Partition size (100 MiB FAT32 — Windows 512e minimum for 256..512 MiB targets).
pub const MED_ESP_SECTORS: u64 = 100 * SECTORS_PER_MIB;
/// Standard EFI System Partition size on real drives >= 512 MiB (260 MiB FAT32 with 4 KiB clusters).
pub const STD_ESP_SECTORS: u64 = 260 * SECTORS_PER_MIB;
/// Immutable `sys` DFS system partition size (44 MiB — holds signed services, apps, firmware).
pub const SYS_SECTORS: u64 = 44 * SECTORS_PER_MIB;
/// Minimum writable `home` DFS partition size (16 MiB).
pub const MIN_HOME_SECTORS: u64 = 16 * SECTORS_PER_MIB;

/// Choose an EFI System Partition size suited to `avail_sectors`:
/// - >= 512 MiB available (real SSDs/HDDs/USB drives): 260 MiB (formats FAT32 with 4 KiB clusters)
/// - 256..512 MiB available: 100 MiB FAT32
/// - < 256 MiB (small virtual test images): 36 MiB FAT32
pub const fn esp_sectors_for(avail_sectors: u64) -> u64 {
    if avail_sectors >= 512 * SECTORS_PER_MIB {
        STD_ESP_SECTORS
    } else if avail_sectors >= 256 * SECTORS_PER_MIB {
        MED_ESP_SECTORS
    } else {
        ESP_SECTORS
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum InstallMode {
    /// Non-destructive dual-boot into unallocated GPT free space.
    DualBoot = 1,
    /// Full-disk install onto a blank/unpartitioned drive (refuses disks with existing partitions).
    WholeDisk = 2,
    /// Destructive wipe & repartition of an existing drive (requires explicit `confirm_wipe`).
    WipeDisk = 3,
}

impl InstallMode {
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::DualBoot),
            2 => Some(Self::WholeDisk),
            3 => Some(Self::WipeDisk),
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DualBoot => "dual-boot",
            Self::WholeDisk => "whole-disk",
            Self::WipeDisk => "wipe-disk",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InstallError {
    Io,
    ConfirmWipeRequired,
    DiskNotEmpty,
    NoGptForDualBoot,
    InsufficientFreeSpace { needed_mib: u64, largest_mib: u64 },
    DiskTooSmall { needed_mib: u64, disk_mib: u64 },
    TooManyPartitions,
}

#[derive(Clone, Debug)]
pub struct InstallPlan {
    pub mode: InstallMode,
    pub disk_sectors: u64,
    pub disk_guid: Guid,
    pub preserved: Vec<Partition>,
    pub wiped: Vec<Partition>,
    pub existing_esp: Option<Partition>,
    pub new_bios_boot: Option<(u64, u64)>,
    pub new_esp: Option<(u64, u64)>,
    pub new_sys: (u64, u64),
    pub new_home: (u64, u64),
}

/// Resulting partition layout on disk after applying an `InstallPlan`.
#[derive(Clone, Debug)]
pub struct AppliedLayout {
    pub bios_boot: Option<Partition>,
    pub esp: Partition,
    pub esp_created: bool,
    pub sys: Partition,
    pub home: Partition,
    pub preserved_count: usize,
}

/// Identify a human-readable filesystem / partition type label without mounting it.
pub fn detect_fs_label(dev: &mut dyn BlockDev, p: &Partition) -> &'static str {
    if p.type_guid == gpt::TYPE_BIOS_BOOT {
        return "BIOS-Boot";
    }
    if p.type_guid == gpt::TYPE_MSR {
        return "MSR";
    }
    if p.type_guid == gpt::TYPE_WIN_RE {
        return "WinRE";
    }
    if p.type_guid == gpt::TYPE_DFS {
        return "DFS";
    }
    let mut bs = [0u8; SECTOR];
    if dev.read(p.first, &mut bs).is_ok() {
        match &bs[3..11] {
            b"NTFS    " => return "NTFS",
            b"EXFAT   " => return "exFAT",
            _ => {}
        }
        if &bs[82..90] == b"FAT32   " {
            return if p.type_guid == gpt::TYPE_ESP { "ESP/FAT32" } else { "FAT32" };
        }
    }
    if p.type_guid == gpt::TYPE_ESP {
        return "ESP";
    }
    if p.type_guid == gpt::TYPE_LINUX_FS {
        return "Linux";
    }
    if p.type_guid == gpt::TYPE_BASIC_DATA {
        return "Data";
    }
    "Unknown"
}

fn align_up_mib(lba: u64) -> u64 {
    lba.div_ceil(SECTORS_PER_MIB) * SECTORS_PER_MIB
}

/// Build and strictly validate a partition plan for `dev` without writing a single sector.
pub fn plan_install(
    dev: &mut dyn BlockDev,
    mode: InstallMode,
    confirm_wipe: bool,
    default_disk_guid: Guid,
) -> core::result::Result<InstallPlan, InstallError> {
    let total_sectors = dev.sectors();
    let disk_mib = total_sectors / SECTORS_PER_MIB;

    match mode {
        InstallMode::DualBoot => {
            let info = gpt::read_full(dev).map_err(|_| InstallError::NoGptForDualBoot)?;
            let existing_esp = info.parts.iter().find(|p| p.type_guid == gpt::TYPE_ESP).cloned();
            let need_esp = existing_esp.is_none();
            let extra_slots = 2 + usize::from(need_esp);
            if info.parts.len() + extra_slots > 128 {
                return Err(InstallError::TooManyPartitions);
            }
            let min_needed = (if need_esp { ESP_SECTORS } else { 0 }) + SYS_SECTORS + MIN_HOME_SECTORS;
            let extents: Vec<FreeExtent> = gpt::free_extents(&info);
            let best = extents.iter().copied().max_by_key(FreeExtent::sectors);
            let largest = best.map_or(0, |e| e.sectors());
            let Some(ext) = best.filter(|e| e.sectors() >= min_needed) else {
                return Err(InstallError::InsufficientFreeSpace {
                    needed_mib: min_needed.div_ceil(SECTORS_PER_MIB),
                    largest_mib: largest / SECTORS_PER_MIB,
                });
            };
            let mut cur = ext.first;
            let new_esp = if need_esp {
                let esp_sz = esp_sectors_for(ext.sectors());
                let r = (cur, cur + esp_sz - 1);
                cur = align_up_mib(r.1 + 1);
                Some(r)
            } else {
                None
            };
            let sys_range = (cur, cur + SYS_SECTORS - 1);
            cur = align_up_mib(sys_range.1 + 1);
            if cur > ext.last || ext.last - cur + 1 < MIN_HOME_SECTORS {
                return Err(InstallError::InsufficientFreeSpace {
                    needed_mib: min_needed.div_ceil(SECTORS_PER_MIB),
                    largest_mib: largest / SECTORS_PER_MIB,
                });
            }
            let home_range = (cur, ext.last);
            Ok(InstallPlan {
                mode,
                disk_sectors: total_sectors,
                disk_guid: info.disk_guid,
                preserved: info.parts,
                wiped: Vec::new(),
                existing_esp,
                new_bios_boot: None,
                new_esp,
                new_sys: sys_range,
                new_home: home_range,
            })
        }
        InstallMode::WholeDisk | InstallMode::WipeDisk => {
            let has_table = gpt::has_any_partition_table(dev).map_err(|_| InstallError::Io)?;
            if mode == InstallMode::WholeDisk && has_table {
                return Err(InstallError::DiskNotEmpty);
            }
            if mode == InstallMode::WipeDisk && !confirm_wipe {
                return Err(InstallError::ConfirmWipeRequired);
            }
            let wiped = gpt::read(dev).map_or_else(|_| Vec::new(), |(p, _)| p);
            let min_usable = SECTORS_PER_MIB + BIOS_BOOT_SECTORS + ESP_SECTORS + SYS_SECTORS + MIN_HOME_SECTORS + 64;
            if total_sectors < min_usable {
                return Err(InstallError::DiskTooSmall {
                    needed_mib: min_usable.div_ceil(SECTORS_PER_MIB),
                    disk_mib,
                });
            }
            let last_usable = total_sectors - 34;
            let esp_sz = esp_sectors_for(total_sectors);
            let bios_first = SECTORS_PER_MIB;
            let bios_last = bios_first + BIOS_BOOT_SECTORS - 1;
            let esp_first = align_up_mib(bios_last + 1);
            let esp_last = esp_first + esp_sz - 1;
            let sys_first = align_up_mib(esp_last + 1);
            let sys_last = sys_first + SYS_SECTORS - 1;
            let home_first = align_up_mib(sys_last + 1);
            let home_last = last_usable;
            Ok(InstallPlan {
                mode,
                disk_sectors: total_sectors,
                disk_guid: default_disk_guid,
                preserved: Vec::new(),
                wiped,
                existing_esp: None,
                new_bios_boot: Some((bios_first, bios_last)),
                new_esp: Some((esp_first, esp_last)),
                new_sys: (sys_first, sys_last),
                new_home: (home_first, home_last),
            })
        }
    }
}

fn derived_guid(base: Guid, salt: u8) -> Guid {
    let mut g = base;
    g[14] = g[14].wrapping_add(salt.wrapping_mul(17));
    g[15] = g[15].wrapping_add(salt);
    g
}

/// Apply a validated `InstallPlan` to `dev`'s GPT partition table.
pub fn apply_plan(dev: &mut dyn BlockDev, plan: &InstallPlan) -> Result<AppliedLayout> {
    match plan.mode {
        InstallMode::DualBoot => {
            let mut raw: Vec<RawPart> = plan
                .preserved
                .iter()
                .map(|p| RawPart {
                    slot: Some(p.index),
                    type_guid: p.type_guid,
                    guid: p.guid,
                    first: p.first,
                    last: p.last,
                    attributes: p.attributes,
                    name: p.name.clone(),
                })
                .collect();
            let base = plan.disk_guid;
            let esp_guid = derived_guid(base, 0xD1);
            let sys_guid = derived_guid(base, 0xD2);
            let home_guid = derived_guid(base, 0xD3);
            if let Some((f, l)) = plan.new_esp {
                raw.push(RawPart {
                    slot: None,
                    type_guid: gpt::TYPE_ESP,
                    guid: esp_guid,
                    first: f,
                    last: l,
                    attributes: 0,
                    name: String::from("esp"),
                });
            }
            raw.push(RawPart {
                slot: None,
                type_guid: gpt::TYPE_DFS,
                guid: sys_guid,
                first: plan.new_sys.0,
                last: plan.new_sys.1,
                attributes: 0,
                name: String::from("sys"),
            });
            raw.push(RawPart {
                slot: None,
                type_guid: gpt::TYPE_DFS,
                guid: home_guid,
                first: plan.new_home.0,
                last: plan.new_home.1,
                attributes: 0,
                name: String::from("home"),
            });
            let written = gpt::write_preserving(dev, plan.disk_guid, &raw, true)?;
            let esp = if let Some(ref e) = plan.existing_esp {
                written
                    .iter()
                    .find(|p| p.index == e.index && p.first == e.first)
                    .cloned()
                    .ok_or(Error::Corrupt)?
            } else {
                written
                    .iter()
                    .find(|p| p.guid == esp_guid)
                    .cloned()
                    .ok_or(Error::Corrupt)?
            };
            let sys = written.iter().find(|p| p.guid == sys_guid).cloned().ok_or(Error::Corrupt)?;
            let home = written.iter().find(|p| p.guid == home_guid).cloned().ok_or(Error::Corrupt)?;
            Ok(AppliedLayout {
                bios_boot: None,
                esp,
                esp_created: plan.new_esp.is_some(),
                sys,
                home,
                preserved_count: plan.preserved.len(),
            })
        }
        InstallMode::WholeDisk | InstallMode::WipeDisk => {
            let esp_sz = plan.new_esp.map_or(ESP_SECTORS, |(f, l)| l - f + 1);
            let parts = [
                NewPart { type_guid: gpt::TYPE_BIOS_BOOT, name: "bios-boot", sectors: BIOS_BOOT_SECTORS },
                NewPart { type_guid: gpt::TYPE_ESP, name: "esp", sectors: esp_sz },
                NewPart { type_guid: gpt::TYPE_DFS, name: "sys", sectors: SYS_SECTORS },
                NewPart { type_guid: gpt::TYPE_DFS, name: "home", sectors: 0 },
            ];
            let made = gpt::write(dev, &parts, plan.disk_guid)?;
            if made.len() != 4 {
                return Err(Error::Corrupt);
            }
            Ok(AppliedLayout {
                bios_boot: Some(made[0].clone()),
                esp: made[1].clone(),
                esp_created: true,
                sys: made[2].clone(),
                home: made[3].clone(),
                preserved_count: 0,
            })
        }
    }
}

/// Build a spec-compliant UEFI 2.10 `EFI_LOAD_OPTION` binary descriptor pointing at
/// `(esp_part_index, esp_first_lba, esp_sectors, esp_guid)` + `efi_path` (e.g. `\EFI\DOS\BOOTX64.EFI`).
pub fn build_uefi_load_option(
    esp_part_index: u32,
    esp_first_lba: u64,
    esp_sectors: u64,
    esp_guid: &Guid,
    label: &str,
    efi_path: &str,
) -> Vec<u8> {
    // 1. MEDIA_HARDDRIVE_DP (42 bytes): type 4, sub 1, len 42, part_num, start, size, sig[16], fmt=2 (GPT), sig_type=2 (GUID).
    let mut dp = Vec::with_capacity(128);
    dp.push(0x04);
    dp.push(0x01);
    dp.extend_from_slice(&42u16.to_le_bytes());
    dp.extend_from_slice(&esp_part_index.to_le_bytes());
    dp.extend_from_slice(&esp_first_lba.to_le_bytes());
    dp.extend_from_slice(&esp_sectors.to_le_bytes());
    dp.extend_from_slice(esp_guid);
    dp.push(0x02); // GPT partition format
    dp.push(0x02); // GUID signature type

    // 2. MEDIA_FILEPATH_DP: type 4, sub 4, len = 4 + (chars + 1) * 2, UTF-16LE NUL-terminated path.
    let mut path_u16: Vec<u16> = efi_path.encode_utf16().collect();
    path_u16.push(0);
    let fp_len = (4 + path_u16.len() * 2) as u16;
    dp.push(0x04);
    dp.push(0x04);
    dp.extend_from_slice(&fp_len.to_le_bytes());
    for u in path_u16 {
        dp.extend_from_slice(&u.to_le_bytes());
    }

    // 3. END_ENTIRE_DEVICE_PATH: type 0x7F, sub 0xFF, len 4.
    dp.extend_from_slice(&[0x7F, 0xFF, 0x04, 0x00]);

    // EFI_LOAD_OPTION header: Attributes (LOAD_OPTION_ACTIVE = 1), FilePathListLength, Description (UTF-16LE NUL), FilePathList.
    let mut out = Vec::with_capacity(6 + (label.len() + 1) * 2 + dp.len());
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&(dp.len() as u16).to_le_bytes());
    for u in label.encode_utf16() {
        out.extend_from_slice(&u.to_le_bytes());
    }
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&dp);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dev::MemDev;

    #[test]
    fn dual_boot_preserves_existing_os_partitions() {
        // 160 MiB disk: 36 MiB ESP + 20 MiB simulated Windows NTFS + 102 MiB unallocated free space.
        let mut dev = MemDev::new(160 * SECTORS_PER_MIB);
        let init_parts = [
            NewPart { type_guid: gpt::TYPE_ESP, name: "EFI system partition", sectors: 36 * SECTORS_PER_MIB },
            NewPart { type_guid: gpt::TYPE_BASIC_DATA, name: "Windows", sectors: 20 * SECTORS_PER_MIB },
        ];
        let orig = gpt::write(&mut dev, &init_parts, *b"WIN11-DUAL-BOOT0").unwrap();
        // Stamp NTFS boot sector and unique sentinel pattern across the Windows partition.
        let mut ntfs = [0u8; SECTOR];
        ntfs[0..3].copy_from_slice(&[0xEB, 0x52, 0x90]);
        ntfs[3..11].copy_from_slice(b"NTFS    ");
        ntfs[510] = 0x55;
        ntfs[511] = 0xAA;
        dev.write(orig[1].first, &ntfs).unwrap();
        let mut sentinel = [0u8; SECTOR];
        for (i, b) in sentinel.iter_mut().enumerate() {
            *b = ((i * 37) ^ 0xA5) as u8;
        }
        dev.write(orig[1].last, &sentinel).unwrap();
        assert_eq!(detect_fs_label(&mut dev, &orig[1]), "NTFS");

        // WholeDisk must refuse a non-empty disk; WipeDisk must refuse without confirm_wipe.
        assert_eq!(plan_install(&mut dev, InstallMode::WholeDisk, false, [1; 16]).unwrap_err(), InstallError::DiskNotEmpty);
        assert_eq!(plan_install(&mut dev, InstallMode::WipeDisk, false, [1; 16]).unwrap_err(), InstallError::ConfirmWipeRequired);

        // DualBoot plans cleanly into the 102 MiB free gap, reusing existing ESP.
        let plan = plan_install(&mut dev, InstallMode::DualBoot, false, [1; 16]).unwrap();
        assert!(plan.existing_esp.is_some());
        assert!(plan.new_esp.is_none());
        assert_eq!(plan.preserved.len(), 2);

        let applied = apply_plan(&mut dev, &plan).unwrap();
        assert!(!applied.esp_created);
        assert_eq!(applied.esp.index, orig[0].index);
        assert_eq!(applied.preserved_count, 2);

        // Re-read GPT and verify Windows partition entry & data are 100% untouched.
        let (after, ok) = gpt::read(&mut dev).unwrap();
        assert!(ok);
        assert_eq!(after.len(), 4);
        assert_eq!(after[0], orig[0]);
        assert_eq!(after[1], orig[1]);
        assert_eq!(after[2].name, "sys");
        assert_eq!(after[3].name, "home");

        let mut check_ntfs = [0u8; SECTOR];
        dev.read(orig[1].first, &mut check_ntfs).unwrap();
        assert_eq!(check_ntfs, ntfs);
        let mut check_sent = [0u8; SECTOR];
        dev.read(orig[1].last, &mut check_sent).unwrap();
        assert_eq!(check_sent, sentinel);
    }

    #[test]
    fn whole_disk_and_wipe_and_delete_partition() {
        // 128 MiB blank disk -> WholeDisk succeeds.
        let mut blank = MemDev::new(128 * SECTORS_PER_MIB);
        assert!(!gpt::has_any_partition_table(&mut blank).unwrap());
        let plan = plan_install(&mut blank, InstallMode::WholeDisk, false, *b"DOS-BLANK-DISK-0").unwrap();
        let applied = apply_plan(&mut blank, &plan).unwrap();
        assert!(applied.bios_boot.is_some());
        assert!(applied.esp_created);
        let (parts, ok) = gpt::read(&mut blank).unwrap();
        assert!(ok);
        assert_eq!(parts.len(), 4);
        assert_eq!(parts[0].name, "bios-boot");
        assert_eq!(parts[1].name, "esp");
        assert_eq!(parts[2].name, "sys");
        assert_eq!(parts[3].name, "home");

        // Deleting partition 3 (sys) frees its space while keeping partitions 1, 2, 4 intact.
        let after_del = gpt::delete_partition(&mut blank, 3).unwrap();
        assert_eq!(after_del.len(), 3);
        assert_eq!(after_del[0].index, 1);
        assert_eq!(after_del[1].index, 2);
        assert_eq!(after_del[2].index, 4);

        // WipeDisk with confirm_wipe=true cleanly rebuilds the entire 4-partition layout.
        let wipe_plan = plan_install(&mut blank, InstallMode::WipeDisk, true, *b"DOS-WIPED-DISK-0").unwrap();
        assert_eq!(wipe_plan.wiped.len(), 3);
        let wiped_applied = apply_plan(&mut blank, &wipe_plan).unwrap();
        assert!(wiped_applied.bios_boot.is_some());
        let (final_parts, ok2) = gpt::read(&mut blank).unwrap();
        assert!(ok2);
        assert_eq!(final_parts.len(), 4);

        // UEFI load option encoding smoke check.
        let opt = build_uefi_load_option(
            wiped_applied.esp.index as u32,
            wiped_applied.esp.first,
            wiped_applied.esp.sectors(),
            &wiped_applied.esp.guid,
            "DiscreteOS",
            "\\EFI\\DOS\\BOOTX64.EFI",
        );
        assert!(opt.len() > 60);
        assert_eq!(u32::from_le_bytes([opt[0], opt[1], opt[2], opt[3]]), 1);
        assert_eq!(&opt[opt.len() - 4..], &[0x7F, 0xFF, 0x04, 0x00]);
    }

    #[test]
    fn large_disk_selects_260_mib_4k_cluster_esp() {
        assert_eq!(esp_sectors_for(128 * SECTORS_PER_MIB), ESP_SECTORS);
        assert_eq!(esp_sectors_for(300 * SECTORS_PER_MIB), MED_ESP_SECTORS);
        assert_eq!(esp_sectors_for(512 * SECTORS_PER_MIB), STD_ESP_SECTORS);
        assert_eq!(esp_sectors_for(1024 * SECTORS_PER_MIB), STD_ESP_SECTORS);

        // Format a 260 MiB ESP and verify FAT32 mounts with 4 KiB clusters (`block_size == 4096`).
        let mut esp_dev = MemDev::new(STD_ESP_SECTORS);
        crate::fat::format(
            &mut esp_dev,
            &crate::fat::Format { label: b"D-OS ESP", serial: 0x0D05_2026, hidden: 18432 },
        )
        .unwrap();
        let mut fat = crate::fat::Fat::mount(esp_dev).unwrap();
        let info = crate::FileSystem::info(&mut fat);
        assert_eq!(info.block_size, 4096);
        assert!(info.total_blocks >= 65_525);
    }
}
