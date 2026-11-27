//! Disk inspection, GPT partitioning, non-destructive dual-boot, whole-disk, wipe & repartition,
//! and DFS/FAT32 installation execution inside `storaged` (`storaged.admin`).

use alloc::boxed::Box;
use alloc::format;
use alloc::rc::Rc;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::cell::RefCell;

use dosfs::dev::{BlockDev, CacheDev, Part, SECTOR};
use dosfs::dfs::{Dfs, FormatOpts};
use dosfs::fat::{self, Fat};
use dosfs::install::{
    self, BIOS_BOOT_SECTORS, InstallError, InstallMode, SECTORS_PER_MIB, apply_plan,
    build_uefi_load_option, detect_fs_label, plan_install,
};
use dosfs::{FileSystem, Ino, Kind, gpt};
use libd::install as wire;
use libd::proto::Header;
use libd::{println, sys};

use crate::{CACHE_BYTES, RemoteDev, Svc, VolFs};

fn mkdirs(fs: &mut dyn FileSystem, path: &str) -> dosfs::Result<Ino> {
    let mut at = fs.root();
    for c in path.split('/').filter(|c| !c.is_empty()) {
        at = match fs.lookup(at, c.as_bytes()) {
            Ok(i) => i,
            Err(_) => fs.create(at, c.as_bytes(), Kind::Dir)?,
        };
    }
    Ok(at)
}

fn put_file(fs: &mut dyn FileSystem, path: &str, data: &[u8]) -> dosfs::Result<()> {
    let (dir, name) = path.rsplit_once('/').unwrap_or(("", path));
    let d = mkdirs(fs, dir)?;
    let f = match fs.lookup(d, name.as_bytes()) {
        Ok(existing) => {
            fs.truncate(existing, 0)?;
            existing
        }
        Err(_) => fs.create(d, name.as_bytes(), Kind::File)?,
    };
    if !data.is_empty() {
        fs.write(f, 0, data)?;
    }
    Ok(())
}

fn file_exists(fs: &mut dyn FileSystem, path: &str) -> bool {
    let mut at = fs.root();
    for c in path.split('/').filter(|c| !c.is_empty()) {
        match fs.lookup(at, c.as_bytes()) {
            Ok(i) => at = i,
            Err(_) => return false,
        }
    }
    true
}

fn read_vol_file(fs: &mut dyn FileSystem, path: &str) -> Result<Vec<u8>, String> {
    let mut at = fs.root();
    for c in path.split('/').filter(|c| !c.is_empty()) {
        at = fs
            .lookup(at, c.as_bytes())
            .map_err(|e| format!("live esp missing {}: {:?}", path, e))?;
    }
    let st = fs.stat(at).map_err(|e| format!("stat {}: {:?}", path, e))?;
    let mut buf = vec![0u8; st.size as usize];
    let mut off = 0u64;
    while (off as usize) < buf.len() {
        let got = fs
            .read(at, off, &mut buf[off as usize..])
            .map_err(|e| format!("read {}: {:?}", path, e))?;
        if got == 0 {
            break;
        }
        off += got as u64;
    }
    buf.truncate(off as usize);
    Ok(buf)
}

/// Recursively copy every directory and file from `src` (rooted at `src_dir`) into `dst` (`dst_dir`).
fn copy_tree(src: &mut dyn FileSystem, src_dir: Ino, dst: &mut dyn FileSystem, dst_dir: Ino) -> Result<u32, String> {
    let mut entries = Vec::new();
    let mut cookie = 0u64;
    loop {
        let (batch, next) = src
            .readdir(src_dir, cookie, 64)
            .map_err(|e| format!("readdir live sys: {:?}", e))?;
        entries.extend(batch);
        match next {
            Some(c) => cookie = c,
            None => break,
        }
    }
    let mut files = 0u32;
    let mut chunk = vec![0u8; 64 * 1024];
    for e in entries {
        if e.kind == Kind::Dir {
            let child_dst = match dst.lookup(dst_dir, &e.name) {
                Ok(i) => i,
                Err(_) => dst
                    .create(dst_dir, &e.name, Kind::Dir)
                    .map_err(|er| format!("mkdir {:?}: {:?}", core::str::from_utf8(&e.name), er))?,
            };
            files += copy_tree(src, e.ino, dst, child_dst)?;
        } else {
            let st = src
                .stat(e.ino)
                .map_err(|er| format!("stat file: {:?}", er))?;
            let child_dst = dst
                .create(dst_dir, &e.name, Kind::File)
                .map_err(|er| format!("create file: {:?}", er))?;
            let mut off = 0u64;
            while off < st.size {
                let want = ((st.size - off) as usize).min(chunk.len());
                let got = src
                    .read(e.ino, off, &mut chunk[..want])
                    .map_err(|er| format!("read live sys file: {:?}", er))?;
                if got == 0 {
                    break;
                }
                dst.write(child_dst, off, &chunk[..got])
                    .map_err(|er| format!("write target sys file: {:?}", er))?;
                off += got as u64;
            }
            files += 1;
        }
    }
    Ok(files)
}

fn fmt_install_err(e: InstallError) -> String {
    match e {
        InstallError::Io => String::from("disk I/O error reading partition table"),
        InstallError::ConfirmWipeRequired => {
            String::from("refused: wiping an existing disk requires explicit wipe confirmation (--confirm)")
        }
        InstallError::DiskNotEmpty => {
            String::from("refused: disk already has partitions (use dual-boot, delete partitions, or wipe --confirm)")
        }
        InstallError::NoGptForDualBoot => {
            String::from("refused: dual-boot requires an existing GPT partition table (blank/MBR disks require whole-disk or wipe)")
        }
        InstallError::InsufficientFreeSpace { needed_mib, largest_mib } => format!(
            "insufficient unallocated GPT free space: need at least {} MiB contiguous, largest gap is {} MiB (free space or delete a partition first)",
            needed_mib, largest_mib
        ),
        InstallError::DiskTooSmall { needed_mib, disk_mib } => {
            format!("disk too small ({} MiB); need at least {} MiB", disk_mib, needed_mib)
        }
        InstallError::TooManyPartitions => String::from("GPT has no free partition slots"),
    }
}

fn format_plan_text(disk_name: &str, plan: &install::InstallPlan) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "Target: {} ({} MiB)  Mode: {}\n",
        disk_name,
        plan.disk_sectors / SECTORS_PER_MIB,
        plan.mode.as_str()
    ));
    if !plan.preserved.is_empty() {
        out.push_str(&format!("Preserved partitions ({}, untouched):\n", plan.preserved.len()));
        for p in &plan.preserved {
            out.push_str(&format!(
                "  #{} '{}' ({} MiB, LBA {}..{})\n",
                p.index,
                p.name,
                p.sectors() / SECTORS_PER_MIB,
                p.first,
                p.last
            ));
        }
    }
    if !plan.wiped.is_empty() {
        out.push_str(&format!("WIPED partitions ({} will be DESTROYED):\n", plan.wiped.len()));
        for p in &plan.wiped {
            out.push_str(&format!("  #{} '{}' ({} MiB)\n", p.index, p.name, p.sectors() / SECTORS_PER_MIB));
        }
    }
    if let Some((f, l)) = plan.new_bios_boot {
        out.push_str(&format!("Create BIOS Boot: {} MiB (LBA {}..{})\n", (l - f + 1) / SECTORS_PER_MIB, f, l));
    }
    if let Some(ref esp) = plan.existing_esp {
        out.push_str(&format!(
            "Reuse existing ESP #{} '{}': add \\EFI\\DOS\\BOOTX64.EFI + \\DOS\\KERNEL.BIN (existing OS bootloaders preserved)\n",
            esp.index, esp.name
        ));
    } else if let Some((f, l)) = plan.new_esp {
        out.push_str(&format!(
            "Create FAT32 ESP: {} MiB (LBA {}..{}) with \\EFI\\BOOT\\BOOTX64.EFI & \\EFI\\DOS\\BOOTX64.EFI\n",
            (l - f + 1) / SECTORS_PER_MIB,
            f,
            l
        ));
    }
    out.push_str(&format!(
        "Create immutable sys (DFS): {} MiB (LBA {}..{})\n",
        (plan.new_sys.1 - plan.new_sys.0 + 1) / SECTORS_PER_MIB,
        plan.new_sys.0,
        plan.new_sys.1
    ));
    out.push_str(&format!(
        "Create writable home (DFS): {} MiB (LBA {}..{})",
        (plan.new_home.1 - plan.new_home.0 + 1) / SECTORS_PER_MIB,
        plan.new_home.0,
        plan.new_home.1
    ));
    out
}

impl Svc {
    pub(crate) fn handle_admin(&mut self, h: &Header, payload: &[u8]) -> (i64, u64, u64, Vec<u8>) {
        match h.op {
            wire::OP_LIST_DISKS => self.admin_list_disks(),
            wire::OP_PLAN => self.admin_plan(h.a, payload),
            wire::OP_DELETE_PART => self.admin_delete_part(h.a, payload),
            wire::OP_INSTALL => self.admin_install(h.a, payload),
            _ => (sys::ERR_NOT_SUPPORTED, 0, 0, Vec::new()),
        }
    }

    fn find_disk_by_name(&self, name: &str) -> Option<usize> {
        if let Some(i) = self.disks.iter().position(|d| d.remote.borrow().name == name) {
            return Some(i);
        }
        // Friendly deterministic short aliases (`nvme0`, `nvme1`, `sata0`, `ahci0`, `virtio0`, `usb0`),
        // ordered lexicographically by full device path so concurrent driver startup never swaps them.
        let (prefix, rest) = if let Some(r) = name.strip_prefix("nvme") {
            ("nvme:", r)
        } else if let Some(r) = name.strip_prefix("sata").or_else(|| name.strip_prefix("ahci")) {
            ("ahci:", r)
        } else if let Some(r) = name.strip_prefix("usb").or_else(|| name.strip_prefix("xhci")) {
            ("xhci:", r)
        } else {
            let r = name.strip_prefix("virtio")?;
            ("virtio-blk:", r)
        };
        let want: usize = rest.parse().ok()?;
        let mut matches: Vec<(String, usize)> = self
            .disks
            .iter()
            .enumerate()
            .filter_map(|(i, d)| {
                let n = d.remote.borrow().name.clone();
                n.starts_with(prefix).then_some((n, i))
            })
            .collect();
        matches.sort_by(|a, b| a.0.cmp(&b.0));
        matches.get(want).map(|&(_, idx)| idx)
    }

    fn unmount_disk_volumes(&mut self, disk_idx: usize) {
        for v in &mut self.vols {
            if v.disk_idx == disk_idx {
                v.fs = None;
                v.dirty = false;
            }
        }
    }

    fn reset_disk_cache(&mut self, disk_idx: usize) {
        if let Some(d) = self.disks.get_mut(disk_idx) {
            d.cache = Rc::new(RefCell::new(CacheDev::new(RemoteDev(d.remote.clone()), CACHE_BYTES)));
        }
    }

    fn admin_list_disks(&mut self) -> (i64, u64, u64, Vec<u8>) {
        let mut out = Vec::new();
        let mut count = 0u64;
        for d in self.disks.iter().take(wire::MAX_DISKS) {
            let (name, model, sectors, is_live, is_opt) = {
                let r = d.remote.borrow();
                (r.name.clone(), d.model.clone(), r.sectors, d.is_live_boot, d.is_optical)
            };
            let mut sum = wire::DiskSummary {
                sectors,
                flags: if is_live { wire::DISK_FLAG_LIVE_BOOT } else { 0 }
                    | if is_opt { wire::DISK_FLAG_OPTICAL } else { 0 },
                ..wire::DiskSummary::default()
            };
            let nb = name.as_bytes();
            sum.name_len = nb.len().min(32) as u8;
            sum.name[..usize::from(sum.name_len)].copy_from_slice(&nb[..usize::from(sum.name_len)]);
            let mb = model.as_bytes();
            sum.model_len = mb.len().min(40) as u8;
            sum.model[..usize::from(sum.model_len)].copy_from_slice(&mb[..usize::from(sum.model_len)]);

            let mut dev = RemoteDev(d.remote.clone());
            match gpt::read_full(&mut dev) {
                Ok(info) => {
                    sum.flags |= wire::DISK_FLAG_HAS_GPT;
                    if info.parts.iter().any(|p| p.type_guid == gpt::TYPE_ESP) {
                        sum.flags |= wire::DISK_FLAG_HAS_ESP;
                    }
                    let exts = gpt::free_extents(&info);
                    let largest = exts.iter().map(|e| e.sectors()).max().unwrap_or(0);
                    let total: u64 = exts.iter().map(|e| e.sectors()).sum();
                    sum.largest_free_mib = (largest / SECTORS_PER_MIB) as u32;
                    sum.total_free_mib = (total / SECTORS_PER_MIB) as u32;
                    let nparts = info.parts.len().min(wire::MAX_PARTS_PER_DISK);
                    sum.part_count = nparts as u8;
                    for (pi, p) in info.parts.iter().take(nparts).enumerate() {
                        let fs_lbl = detect_fs_label(&mut dev, p);
                        let mut ps = wire::PartSummary {
                            index: p.index as u32,
                            first: p.first,
                            last: p.last,
                            size_mib: (p.sectors() / SECTORS_PER_MIB) as u32,
                            ..wire::PartSummary::default()
                        };
                        let fb = fs_lbl.as_bytes();
                        ps.fs_len = fb.len().min(12) as u8;
                        ps.fs_label[..usize::from(ps.fs_len)].copy_from_slice(&fb[..usize::from(ps.fs_len)]);
                        let pnb = p.name.as_bytes();
                        ps.name_len = pnb.len().min(24) as u8;
                        ps.name[..usize::from(ps.name_len)].copy_from_slice(&pnb[..usize::from(ps.name_len)]);
                        sum.parts[pi] = ps;
                    }
                }
                Err(_) => {
                    if gpt::has_any_partition_table(&mut dev).unwrap_or(false) {
                        sum.flags |= wire::DISK_FLAG_HAS_MBR;
                    } else {
                        sum.largest_free_mib = (sectors / SECTORS_PER_MIB) as u32;
                        sum.total_free_mib = sum.largest_free_mib;
                    }
                }
            }

            let mut hdr = [0u8; wire::DISK_HEADER_WIRE_BYTES];
            sum.encode_header(&mut hdr);
            out.extend_from_slice(&hdr);
            for p in sum.parts_slice() {
                let mut pb = [0u8; wire::PART_WIRE_BYTES];
                p.encode(&mut pb);
                out.extend_from_slice(&pb);
            }
            count += 1;
        }
        (0, count, 0, out)
    }

    fn admin_plan(&mut self, a: u64, payload: &[u8]) -> (i64, u64, u64, Vec<u8>) {
        let Ok(disk_name) = core::str::from_utf8(payload) else {
            return (sys::ERR_INVALID_ARGS, 0, 0, b"invalid disk name".to_vec());
        };
        let Some(mode) = InstallMode::from_u8((a & 0xFF) as u8) else {
            return (sys::ERR_INVALID_ARGS, 0, 0, b"invalid install mode".to_vec());
        };
        let confirm_wipe = ((a >> 8) & 1) != 0;
        let Some(di) = self.find_disk_by_name(disk_name) else {
            return (libd::fs::ERR_NOT_FOUND, 0, 0, b"disk not found".to_vec());
        };
        if self.disks[di].is_live_boot {
            return (sys::ERR_ACCESS_DENIED, 0, 0, b"refused: cannot install onto the live boot disk".to_vec());
        }
        if self.disks[di].is_optical {
            return (sys::ERR_ACCESS_DENIED, 0, 0, b"refused: optical drive is read-only".to_vec());
        }
        let mut dev = RemoteDev(self.disks[di].remote.clone());
        let mut guid = *b"D-OS-INST-DISK-0";
        let _ = sys::get_random(&mut guid, 0);
        match plan_install(&mut dev, mode, confirm_wipe, guid) {
            Ok(plan) => {
                let text = format_plan_text(disk_name, &plan);
                (0, plan.preserved.len() as u64, plan.wiped.len() as u64, text.into_bytes())
            }
            Err(e) => (sys::ERR_INVALID_ARGS, 0, 0, fmt_install_err(e).into_bytes()),
        }
    }

    fn admin_delete_part(&mut self, a: u64, payload: &[u8]) -> (i64, u64, u64, Vec<u8>) {
        let part_index = (a & 0xFFFF_FFFF) as usize;
        let confirm = ((a >> 32) & 1) != 0;
        if !confirm {
            return (
                sys::ERR_ACCESS_DENIED,
                0,
                0,
                b"refused: deleting a partition requires explicit confirmation (--confirm)".to_vec(),
            );
        }
        let Ok(disk_name) = core::str::from_utf8(payload) else {
            return (sys::ERR_INVALID_ARGS, 0, 0, b"invalid disk name".to_vec());
        };
        let Some(di) = self.find_disk_by_name(disk_name) else {
            return (libd::fs::ERR_NOT_FOUND, 0, 0, b"disk not found".to_vec());
        };
        if self.disks[di].is_live_boot || self.disks[di].is_optical {
            return (sys::ERR_ACCESS_DENIED, 0, 0, b"refused: cannot modify live boot or optical disk".to_vec());
        }
        if let Err(e) = self.enable_disk_rw(di, true) {
            return (e, 0, 0, b"failed to enable write access on target disk".to_vec());
        }
        self.unmount_disk_volumes(di);
        let mut dev = RemoteDev(self.disks[di].remote.clone());
        let res = gpt::delete_partition(&mut dev, part_index);
        self.reset_disk_cache(di);
        match res {
            Ok(kept) => {
                let msg = format!(
                    "Deleted partition #{} on {} ({} partition(s) remain; space is now unallocated)",
                    part_index,
                    disk_name,
                    kept.len()
                );
                println!("storaged: install: {}", msg);
                (0, kept.len() as u64, 0, msg.into_bytes())
            }
            Err(e) => (sys::ERR_INVALID_ARGS, 0, 0, format!("delete partition failed: {:?}", e).into_bytes()),
        }
    }

    fn admin_install(&mut self, a: u64, payload: &[u8]) -> (i64, u64, u64, Vec<u8>) {
        let Ok(disk_name) = core::str::from_utf8(payload) else {
            return (sys::ERR_INVALID_ARGS, 0, 0, b"invalid disk name".to_vec());
        };
        let Some(mode) = InstallMode::from_u8((a & 0xFF) as u8) else {
            return (sys::ERR_INVALID_ARGS, 0, 0, b"invalid install mode".to_vec());
        };
        let confirm_wipe = ((a >> 8) & 1) != 0;
        let Some(di) = self.find_disk_by_name(disk_name) else {
            return (libd::fs::ERR_NOT_FOUND, 0, 0, b"disk not found".to_vec());
        };
        if self.disks[di].is_live_boot {
            return (sys::ERR_ACCESS_DENIED, 0, 0, b"refused: cannot install onto the live boot disk".to_vec());
        }
        if self.disks[di].is_optical {
            return (sys::ERR_ACCESS_DENIED, 0, 0, b"refused: optical drive is read-only".to_vec());
        }

        // 1. Validate plan before touching target disk or enabling writes.
        let mut guid = *b"D-OS-INST-DISK-0";
        let _ = sys::get_random(&mut guid, 0);
        // Set RFC 4122 UUID v4 version/variant bits for strict UEFI GPT compatibility.
        guid[6] = (guid[6] & 0x0F) | 0x40;
        guid[8] = (guid[8] & 0x3F) | 0x80;
        let plan = {
            let mut dev = RemoteDev(self.disks[di].remote.clone());
            match plan_install(&mut dev, mode, confirm_wipe, guid) {
                Ok(p) => p,
                Err(e) => return (sys::ERR_INVALID_ARGS, 0, 0, fmt_install_err(e).into_bytes()),
            }
        };

        // 2. Read live boot artifacts from the running `esp` volume (preferring the live boot disk).
        let live_disk_idx = self.disks.iter().position(|d| d.is_live_boot);
        let esp_vi = live_disk_idx
            .and_then(|ldi| {
                self.vols
                    .iter()
                    .position(|v| v.disk_idx == ldi && v.kind == libd::fs::KIND_FAT32 && v.fs.is_some())
            })
            .or_else(|| self.vols.iter().position(|v| v.name == "esp" && v.fs.is_some()));
        let Some(esp_vi) = esp_vi else {
            return (sys::ERR_BAD_STATE, 0, 0, b"live esp volume is not mounted".to_vec());
        };
        let sys_vi = live_disk_idx
            .and_then(|ldi| {
                self.vols
                    .iter()
                    .position(|v| v.disk_idx == ldi && v.kind == libd::fs::KIND_DFS && v.fs.is_some())
            })
            .or_else(|| self.vols.iter().position(|v| v.name == "sys" && v.fs.is_some()));
        let Some(sys_vi) = sys_vi else {
            return (sys::ERR_BAD_STATE, 0, 0, b"live sys volume is not mounted".to_vec());
        };
        let (efi_bin, kernel_bin, kernel_dsig) = {
            let Some(esp_fs) = self.vols[esp_vi].fs.as_mut() else {
                return (sys::ERR_BAD_STATE, 0, 0, b"live esp unavailable".to_vec());
            };
            let fs = esp_fs.fs();
            let efi = match read_vol_file(fs, "EFI/BOOT/BOOTX64.EFI")
                .or_else(|_| read_vol_file(fs, "EFI/DOS/BOOTX64.EFI"))
            {
                Ok(b) => b,
                Err(e) => return (sys::ERR_BAD_STATE, 0, 0, e.into_bytes()),
            };
            let kbin = match read_vol_file(fs, "DOS/KERNEL.BIN") {
                Ok(b) => b,
                Err(e) => return (sys::ERR_BAD_STATE, 0, 0, e.into_bytes()),
            };
            let ksig = match read_vol_file(fs, "DOS/KERNEL.DSIG") {
                Ok(b) => b,
                Err(e) => return (sys::ERR_BAD_STATE, 0, 0, e.into_bytes()),
            };
            (efi, kbin, ksig)
        };

        // 3. Enable writes exclusively on target disk `di` and unmount stale mounts on `di`.
        if let Err(e) = self.enable_disk_rw(di, true) {
            return (e, 0, 0, b"failed to enable write access on target disk".to_vec());
        }
        self.unmount_disk_volumes(di);

        println!("storaged: install: starting {} install on {}", mode.as_str(), disk_name);

        // 4. Write GPT partition layout.
        let target_remote = self.disks[di].remote.clone();
        let layout = {
            let mut raw = RemoteDev(target_remote.clone());
            match apply_plan(&mut raw, &plan) {
                Ok(l) => l,
                Err(e) => {
                    self.reset_disk_cache(di);
                    return (libd::fs::ERR_IO, 0, 0, format!("GPT write failed: {:?}", e).into_bytes());
                }
            }
        };

        // 5. Copy BIOS boot code & bios-boot partition (WholeDisk / WipeDisk) so Legacy BIOS boots too.
        let mut bios_copied = false;
        if let (Some(bb), Some(ldi)) = (&layout.bios_boot, live_disk_idx) {
            let mut src_dev = RemoteDev(self.disks[ldi].remote.clone());
            let mut dst_dev = RemoteDev(target_remote.clone());
            let mut src_mbr = [0u8; SECTOR];
            let mut dst_mbr = [0u8; SECTOR];
            if src_dev.read(0, &mut src_mbr).is_ok()
                && dst_dev.read(0, &mut dst_mbr).is_ok()
                && src_mbr[510] == 0x55
                && src_mbr[511] == 0xAA
            {
                dst_mbr[..440].copy_from_slice(&src_mbr[..440]);
                let _ = dst_dev.write(0, &dst_mbr);
                let mut buf = vec![0u8; 64 * SECTOR];
                let mut copied_ok = true;
                let mut off = 0u64;
                while off < BIOS_BOOT_SECTORS {
                    let n = (BIOS_BOOT_SECTORS - off).min(64);
                    let slice = &mut buf[..n as usize * SECTOR];
                    if src_dev.read(2048 + off, slice).is_err() || dst_dev.write(bb.first + off, slice).is_err() {
                        copied_ok = false;
                        break;
                    }
                    off += n;
                }
                bios_copied = copied_ok;
            }
        }

        // 6. Populate ESP (format if created, otherwise mount existing ESP non-destructively).
        let target_shared: dosfs::dev::Shared = Rc::new(RefCell::new(RemoteDev(target_remote.clone())));
        let mut esp_part = Part {
            disk: target_shared.clone(),
            start: layout.esp.first,
            len: layout.esp.sectors(),
        };
        if layout.esp_created
            && let Err(e) = fat::format(
                &mut esp_part,
                &fat::Format { label: b"D-OS ESP", serial: 0x0D05_2026, hidden: layout.esp.first as u32 },
            )
        {
            self.reset_disk_cache(di);
            return (libd::fs::ERR_IO, 0, 0, format!("ESP FAT32 format failed: {:?}", e).into_bytes());
        }
        let mut esp_fs = match Fat::mount(esp_part) {
            Ok(f) => f,
            Err(e) => {
                self.reset_disk_cache(di);
                return (libd::fs::ERR_IO, 0, 0, format!("mount target ESP failed: {:?}", e).into_bytes());
            }
        };
        let fallback_written = if layout.esp_created || !file_exists(&mut esp_fs, "EFI/BOOT/BOOTX64.EFI") {
            if let Err(e) = put_file(&mut esp_fs, "EFI/BOOT/BOOTX64.EFI", &efi_bin) {
                self.reset_disk_cache(di);
                return (libd::fs::ERR_IO, 0, 0, format!("write EFI/BOOT/BOOTX64.EFI: {:?}", e).into_bytes());
            }
            true
        } else {
            false
        };
        let boot_entry = build_uefi_load_option(
            layout.esp.index as u32,
            layout.esp.first,
            layout.esp.sectors(),
            &layout.esp.guid,
            "DiscreteOS",
            "\\EFI\\DOS\\BOOTX64.EFI",
        );
        let boot_cfg = b"# D-OS installed disk boot configuration\ninstalled = true\noobe = pending\n";
        let efi_readme = b"DiscreteOS UEFI boot files: \\EFI\\DOS\\BOOTX64.EFI verifies \\DOS\\KERNEL.BIN via \\DOS\\KERNEL.DSIG.\r\n";
        for (path, data) in [
            ("EFI/DOS/BOOTX64.EFI", efi_bin.as_slice()),
            ("EFI/DOS/BOOTENTRY.BIN", boot_entry.as_slice()),
            ("EFI/DOS/README.TXT", efi_readme.as_slice()),
            ("DOS/KERNEL.BIN", kernel_bin.as_slice()),
            ("DOS/KERNEL.DSIG", kernel_dsig.as_slice()),
            ("DOS/BOOT.CFG", boot_cfg.as_slice()),
        ] {
            if let Err(e) = put_file(&mut esp_fs, path, data) {
                self.reset_disk_cache(di);
                return (libd::fs::ERR_IO, 0, 0, format!("write ESP {}: {:?}", path, e).into_bytes());
            }
        }
        if let Err(e) = esp_fs.sync() {
            self.reset_disk_cache(di);
            return (libd::fs::ERR_IO, 0, 0, format!("sync target ESP: {:?}", e).into_bytes());
        }
        drop(esp_fs);

        // 6b. Read back GPT & remount target ESP directly from disk to verify BIOS/UEFI visibility.
        {
            let mut raw_check = RemoteDev(target_remote.clone());
            let Ok(gpt_check) = gpt::read_full(&mut raw_check) else {
                self.reset_disk_cache(di);
                return (libd::fs::ERR_CORRUPT, 0, 0, b"post-write GPT verification failed".to_vec());
            };
            let Some(esp_chk) = gpt_check
                .parts
                .iter()
                .find(|p| p.type_guid == gpt::TYPE_ESP && p.first == layout.esp.first && p.last == layout.esp.last)
            else {
                self.reset_disk_cache(di);
                return (libd::fs::ERR_CORRUPT, 0, 0, b"post-write GPT is missing the EFI System Partition".to_vec());
            };
            let verify_part = Part {
                disk: target_shared.clone(),
                start: esp_chk.first,
                len: esp_chk.sectors(),
            };
            let mut verify_esp = match Fat::mount(verify_part) {
                Ok(f) => f,
                Err(e) => {
                    self.reset_disk_cache(di);
                    return (
                        libd::fs::ERR_CORRUPT,
                        0,
                        0,
                        format!("post-write ESP FAT32 verification failed: {:?}", e).into_bytes(),
                    );
                }
            };
            for req in [
                "EFI/DOS/BOOTX64.EFI",
                "EFI/DOS/BOOTENTRY.BIN",
                "DOS/KERNEL.BIN",
                "DOS/KERNEL.DSIG",
                "DOS/BOOT.CFG",
            ] {
                if !file_exists(&mut verify_esp, req) {
                    self.reset_disk_cache(di);
                    return (
                        libd::fs::ERR_CORRUPT,
                        0,
                        0,
                        format!("post-write ESP missing required file {}", req).into_bytes(),
                    );
                }
            }
            if fallback_written && !file_exists(&mut verify_esp, "EFI/BOOT/BOOTX64.EFI") {
                self.reset_disk_cache(di);
                return (
                    libd::fs::ERR_CORRUPT,
                    0,
                    0,
                    b"post-write ESP missing fallback EFI/BOOT/BOOTX64.EFI".to_vec(),
                );
            }
        }

        // 7. Format `sys` DFS volume, recursively copy live `/sys`, sync, and verify via `fsck`.
        let mut sys_uuid = *b"D-OS-DFS-SYS-INS";
        let _ = sys::get_random(&mut sys_uuid, 0);
        let sys_part = Part { disk: target_shared.clone(), start: layout.sys.first, len: layout.sys.sectors() };
        let now = libd::time::now().0;
        let mut target_sys = match Dfs::format(Box::new(sys_part), &FormatOpts { label: b"sys", uuid: sys_uuid, time: now }) {
            Ok(d) => d,
            Err(e) => {
                self.reset_disk_cache(di);
                return (libd::fs::ERR_IO, 0, 0, format!("format target sys DFS: {:?}", e).into_bytes());
            }
        };
        let sys_files_copied = {
            let Some(VolFs::Dfs(ref mut live_sys)) = self.vols[sys_vi].fs else {
                self.reset_disk_cache(di);
                return (sys::ERR_BAD_STATE, 0, 0, b"live sys DFS unavailable".to_vec());
            };
            let src_root = live_sys.root();
            let dst_root = target_sys.root();
            match copy_tree(live_sys, src_root, &mut target_sys, dst_root) {
                Ok(n) => n,
                Err(e) => {
                    self.reset_disk_cache(di);
                    return (libd::fs::ERR_IO, 0, 0, e.into_bytes());
                }
            }
        };
        if let Err(e) = target_sys.sync() {
            self.reset_disk_cache(di);
            return (libd::fs::ERR_IO, 0, 0, format!("sync target sys DFS: {:?}", e).into_bytes());
        }
        let sys_fsck = match target_sys.fsck() {
            Ok(r) if r.errors == 0 => r,
            Ok(r) => {
                self.reset_disk_cache(di);
                return (libd::fs::ERR_CORRUPT, 0, 0, format!("target sys fsck found {} error(s)", r.errors).into_bytes());
            }
            Err(e) => {
                self.reset_disk_cache(di);
                return (libd::fs::ERR_IO, 0, 0, format!("target sys fsck failed: {:?}", e).into_bytes());
            }
        };
        drop(target_sys);

        // 8. Format writable `home` DFS volume, seed `.dos/oobe.toml` & `user/`, sync, and `fsck`.
        let mut home_uuid = *b"D-OS-DFS-HOME-00";
        let _ = sys::get_random(&mut home_uuid, 0);
        let home_part = Part { disk: target_shared.clone(), start: layout.home.first, len: layout.home.sectors() };
        let mut target_home = match Dfs::format(Box::new(home_part), &FormatOpts { label: b"home", uuid: home_uuid, time: now }) {
            Ok(d) => d,
            Err(e) => {
                self.reset_disk_cache(di);
                return (libd::fs::ERR_IO, 0, 0, format!("format target home DFS: {:?}", e).into_bytes());
            }
        };
        let init_oobe = b"# D-OS first-boot setup state\nversion = 1\ncompleted = false\nlanguage = \"en-US\"\nkeyboard = \"us\"\ntimezone = \"UTC\"\nnet-mode = \"dhcp\"\n";
        if let Err(e) = put_file(&mut target_home, ".dos/oobe.toml", init_oobe)
            .and_then(|()| mkdirs(&mut target_home, "user").map(|_| ()))
            .and_then(|()| target_home.sync())
        {
            self.reset_disk_cache(di);
            return (libd::fs::ERR_IO, 0, 0, format!("init target home DFS: {:?}", e).into_bytes());
        }
        let home_fsck = match target_home.fsck() {
            Ok(r) if r.errors == 0 => r,
            Ok(r) => {
                self.reset_disk_cache(di);
                return (libd::fs::ERR_CORRUPT, 0, 0, format!("target home fsck found {} error(s)", r.errors).into_bytes());
            }
            Err(e) => {
                self.reset_disk_cache(di);
                return (libd::fs::ERR_IO, 0, 0, format!("target home fsck failed: {:?}", e).into_bytes());
            }
        };
        drop(target_home);

        let _ = target_remote.borrow_mut().flush();
        self.reset_disk_cache(di);

        let boot_hint = if fallback_written {
            "\n  UEFI boot: select this drive in BIOS (or reboot once with live media attached to register 'DiscreteOS' in UEFI NVRAM)"
        } else {
            "\n  UEFI boot: reboot once with live media attached so the UEFI loader registers 'DiscreteOS' (Boot00D0) in BIOS NVRAM, then remove live media"
        };
        let summary = format!(
            "Installed D-OS ({}) on {}:\n  ESP #{} ({} MiB FAT32, verified): \\EFI\\DOS\\BOOTX64.EFI{} ({})\n  sys (DFS): {} MiB, {} files copied, fsck 0 errors ({} blocks)\n  home (DFS): {} MiB, initialized for OOBE, fsck 0 errors\n  preserved partitions: {}{}{}",
            mode.as_str(),
            disk_name,
            layout.esp.index,
            layout.esp.sectors() / SECTORS_PER_MIB,
            if fallback_written { " + \\EFI\\BOOT\\BOOTX64.EFI" } else { " (existing \\EFI\\BOOT preserved)" },
            if layout.esp_created { "created" } else { "reused" },
            layout.sys.sectors() / SECTORS_PER_MIB,
            sys_files_copied,
            sys_fsck.nodes + sys_fsck.data_blocks,
            layout.home.sectors() / SECTORS_PER_MIB,
            layout.preserved_count,
            if bios_copied { "\n  BIOS boot: installed" } else { "" },
            boot_hint,
        );
        let _ = home_fsck;
        println!("storaged: install: complete on {} ({}, {} sys files, {} preserved, fsck OK)", disk_name, mode.as_str(), sys_files_copied, layout.preserved_count);
        (0, u64::from(sys_files_copied), layout.preserved_count as u64, summary.into_bytes())
    }
}
