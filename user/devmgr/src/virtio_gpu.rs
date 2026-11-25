//! Modern VirtIO 1.2 GPU Atomic KMS, GEM/GPU-VM/Syncobj, Blob/UUID, and 3D VirGL/Venus driver
//! (`virtio-gpu.ddrv`, PCI `1AF4:1050`, loaded from verified `sys:/bin/virtio-gpu.ddrv`).

use core::sync::atomic::{Ordering, fence};

use dosdrm::edid::{self, EdidInfo};
use dosdrm::gem::{GemTable, GpuVmTable, SyncobjTable};
use dosdrm::kms::{self, AtomicCommit, ConnectorKind, KmsMode, KmsState, PlaneKind};
use dosdrm::shim::{self, FirmwareDir, SgPin};
use dosdrm::virtio as vg;
use dosdrm::{DamageRect, MAX_DIM, PixelFormat};
use libd::gpu::{self, KmsResourcesWire, ModeEntry};
use libd::proto;
use libd::sys::{self, Handle};
use libd::{Dma, Mapping, Port, Startup, println};

use crate::gpu_drv::{self, DrmDriver, GpuAnnounce, KEY_IRQ0, KEY_IRQ1, kms_err_to_sys, mem_err_to_sys};
use crate::virtio::{DESC_NEXT, DESC_WRITE, Queue, Virtio};

const SEC: u64 = 1_000_000_000;
const CMD_BUF_OFF: usize = 0;
const CMD_BUF_MAX: usize = 8192;
const RESP_BUF_OFF: usize = 8192;
const RESP_BUF_MAX: usize = 4096;
const CURSOR_CMD_OFF: usize = 12288;
const DMA_BYTES: u64 = 16384;
const MAX_VIRTIO_BOS: usize = 16;

struct BoBacking {
    gem_handle: u32,
    pin: SgPin,
    res_id: u32,
    res_width: u32,
    res_height: u32,
    res_format: u32,
    is_blob: bool,
}

struct VirtioGpu {
    dev: Handle,
    v: Virtio,
    ctrlq: Queue,
    cursorq: Queue,
    dma: Dma,
    scratch: Mapping,
    virgl: bool,
    has_uuid: bool,
    has_blob: bool,
    has_ctx_init: bool,
    venus_capset_id: u32,
    fw_loaded: bool,
    shim_abi: u32,
    edid: Option<EdidInfo>,
    edid_blocks: u8,
    boot_mode: KmsMode,
    kms: KmsState,
    gem: GemTable,
    vms: GpuVmTable,
    syncobjs: SyncobjTable,
    backings: [Option<BoBacking>; MAX_VIRTIO_BOS],
    scanout_res: u32,
    cursor_res: u32,
    next_res_id: u32,
    next_blob_id: u64,
    next_ctx_id: u32,
    frames: u64,
    fences: u64,
    irqs: u64,
}

impl VirtioGpu {
    fn exec_ctrl(&mut self, cmd_len: usize, resp_len: usize) -> Result<u32, i64> {
        if cmd_len > CMD_BUF_MAX || resp_len > RESP_BUF_MAX {
            return Err(sys::ERR_INVALID_ARGS);
        }
        let rbytes = &mut self.dma.map.bytes_mut()[RESP_BUF_OFF..RESP_BUF_OFF + 24.min(resp_len)];
        rbytes.fill(0);
        fence(Ordering::Release);

        let mut d = 0u16;
        let mut rem = cmd_len;
        let mut off = CMD_BUF_OFF;
        while rem > 0 {
            let chunk = rem.min(4096 - (off % 4096));
            self.ctrlq.desc(d, self.dma.dev_addr(off as u64), chunk as u32, DESC_NEXT, d + 1);
            d += 1;
            off += chunk;
            rem -= chunk;
        }
        let resp_desc = d;
        self.ctrlq.desc(
            resp_desc,
            self.dma.dev_addr(RESP_BUF_OFF as u64),
            resp_len as u32,
            DESC_WRITE,
            0,
        );
        self.ctrlq.push(0);
        self.v.notify(&self.ctrlq);
        let Some(_) = self.ctrlq.wait(3 * SEC) else {
            return Err(sys::ERR_TIMED_OUT);
        };
        self.irqs += 1;
        fence(Ordering::Acquire);
        let hdr = vg::CtrlHdr::decode(&self.dma.map.bytes()[RESP_BUF_OFF..RESP_BUF_OFF + resp_len])
            .ok_or(sys::ERR_BAD_STATE)?;
        Ok(hdr.ty)
    }

    fn exec_cursor(&mut self, cmd_len: usize) -> Result<(), i64> {
        if cmd_len > 256 {
            return Err(sys::ERR_INVALID_ARGS);
        }
        fence(Ordering::Release);
        self.cursorq.desc(0, self.dma.dev_addr(CURSOR_CMD_OFF as u64), cmd_len as u32, 0, 0);
        self.cursorq.push(0);
        self.v.notify(&self.cursorq);
        let Some(_) = self.cursorq.wait(2 * SEC) else {
            return Err(sys::ERR_TIMED_OUT);
        };
        self.irqs += 1;
        Ok(())
    }

    fn query_display_info(&mut self) -> Result<(u32, u32, usize), i64> {
        let n = vg::encode_get_display_info(&mut self.dma.map.bytes_mut()[CMD_BUF_OFF..])
            .ok_or(sys::ERR_INVALID_ARGS)?;
        let ty = self.exec_ctrl(n, vg::RESP_DISPLAY_INFO_SIZE)?;
        if ty != vg::RESP_OK_DISPLAY_INFO {
            return Err(i64::from(proto::ERR_IO));
        }
        let info = vg::decode_display_info(
            &self.dma.map.bytes()[RESP_BUF_OFF..RESP_BUF_OFF + vg::RESP_DISPLAY_INFO_SIZE],
        )
        .ok_or(sys::ERR_BAD_STATE)?;
        let enabled = info.pmodes.iter().filter(|p| p.enabled).count();
        let p0 = info.pmodes[0];
        let w = if (320..=MAX_DIM).contains(&p0.width) { p0.width } else { 1024 };
        let h = if (200..=MAX_DIM).contains(&p0.height) { p0.height } else { 768 };
        Ok((w, h, enabled.max(1)))
    }

    fn query_edid(&mut self) -> Option<(EdidInfo, u8)> {
        let n = vg::encode_get_edid(&mut self.dma.map.bytes_mut()[CMD_BUF_OFF..], 0)?;
        let ty = self.exec_ctrl(n, 32 + 1024).ok()?;
        if ty != vg::RESP_OK_EDID {
            return None;
        }
        let slice = vg::decode_edid_resp(&self.dma.map.bytes()[RESP_BUF_OFF..RESP_BUF_OFF + 32 + 1024])?;
        let blocks = (slice.len() / 128).min(8) as u8;
        let parsed = edid::parse_edid(slice).ok()?;
        Some((parsed, blocks.max(1)))
    }

    fn unref_resource(&mut self, res_id: u32, is_blob: bool) {
        if res_id == 0 {
            return;
        }
        if !is_blob
            && let Some(n) = vg::encode_resource_detach_backing(&mut self.dma.map.bytes_mut()[CMD_BUF_OFF..], res_id)
        {
            let _ = self.exec_ctrl(n, vg::CTRL_HDR_SIZE);
        }
        if let Some(n) = vg::encode_resource_unref(&mut self.dma.map.bytes_mut()[CMD_BUF_OFF..], res_id) {
            let _ = self.exec_ctrl(n, vg::CTRL_HDR_SIZE);
        }
    }

    fn synth_uuid(&self, gem_handle: u32, res_id: u32) -> [u8; 16] {
        let mut u = [0u8; 16];
        u[0..4].copy_from_slice(b"DOSG");
        u[4..8].copy_from_slice(&gem_handle.to_le_bytes());
        u[8..12].copy_from_slice(&res_id.to_le_bytes());
        u[12..16].copy_from_slice(&0x1AF4_1050u32.to_le_bytes());
        u
    }

    fn assign_or_synth_uuid(&mut self, gem_handle: u32, res_id: u32) -> [u8; 16] {
        if self.has_uuid
            && res_id != 0
            && let Some(n) = vg::encode_resource_assign_uuid(&mut self.dma.map.bytes_mut()[CMD_BUF_OFF..], res_id)
            && self.exec_ctrl(n, 40) == Ok(vg::RESP_OK_RESOURCE_UUID)
            && let Some(u) = vg::decode_resource_uuid(&self.dma.map.bytes()[RESP_BUF_OFF..RESP_BUF_OFF + 40])
        {
            return u;
        }
        self.synth_uuid(gem_handle, res_id)
    }

    fn ensure_2d_resource(&mut self, gem_handle: u32, width: u32, height: u32, format: u32) -> Result<u32, i64> {
        let Some(b_idx) = self.backings.iter().position(|b| b.as_ref().is_some_and(|x| x.gem_handle == gem_handle)) else {
            return Err(sys::ERR_OUT_OF_RANGE);
        };
        let fmt = PixelFormat::from_u32(format).ok_or(sys::ERR_NOT_SUPPORTED)?;
        let vfmt = match fmt {
            PixelFormat::Argb8888 => vg::FORMAT_B8G8R8A8_UNORM,
            PixelFormat::Xbgr8888 => vg::FORMAT_R8G8B8X8_UNORM,
            PixelFormat::Xrgb8888 | PixelFormat::Argb2101010 => vg::FORMAT_B8G8R8X8_UNORM,
        };
        if let Some(existing) = self.backings[b_idx].as_ref()
            && existing.res_id != 0
            && !existing.is_blob
            && existing.res_width == width
            && existing.res_height == height
            && existing.res_format == vfmt
        {
            return Ok(existing.res_id);
        }

        // Replace any previous 2D resource on this BO if dimensions changed.
        if let Some(old_res) = self.backings[b_idx].as_ref().filter(|x| x.res_id != 0 && !x.is_blob).map(|x| x.res_id) {
            if self.scanout_res == old_res {
                let _ = self.bind_scanout(0, 0, 0);
            }
            self.unref_resource(old_res, false);
            if let Some(b) = self.backings[b_idx].as_mut() {
                b.res_id = 0;
            }
        }

        let res_id = self.next_res_id;
        self.next_res_id += 1;
        let n = vg::encode_resource_create_2d(
            &mut self.dma.map.bytes_mut()[CMD_BUF_OFF..],
            res_id,
            vfmt,
            width,
            height,
        )
        .ok_or(sys::ERR_INVALID_ARGS)?;
        if self.exec_ctrl(n, vg::CTRL_HDR_SIZE)? != vg::RESP_OK_NODATA {
            return Err(i64::from(proto::ERR_IO));
        }

        let mut runs_copy = [(0u64, 0u32); shim::MAX_SG_RUNS];
        let run_cnt = match self.backings[b_idx].as_ref() {
            Some(b) => {
                runs_copy[..b.pin.run_count].copy_from_slice(b.pin.runs());
                b.pin.run_count
            }
            None => return Err(sys::ERR_BAD_STATE),
        };
        let n = vg::encode_resource_attach_backing(
            &mut self.dma.map.bytes_mut()[CMD_BUF_OFF..],
            res_id,
            &runs_copy[..run_cnt],
        )
        .ok_or(sys::ERR_NO_RESOURCES)?;
        if self.exec_ctrl(n, vg::CTRL_HDR_SIZE)? != vg::RESP_OK_NODATA {
            self.unref_resource(res_id, false);
            return Err(i64::from(proto::ERR_IO));
        }

        if let Some(b) = self.backings[b_idx].as_mut() {
            b.res_id = res_id;
            b.res_width = width;
            b.res_height = height;
            b.res_format = vfmt;
            b.is_blob = false;
        }
        Ok(res_id)
    }

    fn bind_scanout(&mut self, res_id: u32, width: u32, height: u32) -> Result<(), i64> {
        let n = vg::encode_set_scanout(
            &mut self.dma.map.bytes_mut()[CMD_BUF_OFF..],
            0,
            0,
            width,
            height,
            0,
            res_id,
        )
        .ok_or(sys::ERR_INVALID_ARGS)?;
        if self.exec_ctrl(n, vg::CTRL_HDR_SIZE)? != vg::RESP_OK_NODATA {
            return Err(i64::from(proto::ERR_IO));
        }
        self.scanout_res = res_id;
        Ok(())
    }

    fn res_id_for_fb(&self, fb_id: u32) -> Option<(u32, kms::KmsFb)> {
        let fb = self.kms.get_fb(fb_id)?;
        let res_id = self
            .backings
            .iter()
            .flatten()
            .find(|b| b.gem_handle == fb.gem_handle)
            .map(|b| b.res_id)?;
        (res_id != 0).then_some((res_id, fb))
    }

    fn flush_primary_damage(&mut self, fb_id: u32, damage: &[DamageRect]) -> Result<(), i64> {
        let Some((res_id, fb)) = self.res_id_for_fb(fb_id) else {
            return Err(sys::ERR_OUT_OF_RANGE);
        };
        if self.scanout_res != res_id {
            self.bind_scanout(res_id, fb.width, fb.height)?;
        }
        let full = [DamageRect::full(fb.width, fb.height)];
        let list = if damage.is_empty() { &full[..] } else { damage };
        let mut union = DamageRect::EMPTY;
        for &r in list {
            let dmg = if r.w == 0 || r.h == 0 {
                DamageRect::full(fb.width, fb.height)
            } else {
                match r.clip(fb.width, fb.height) {
                    Some(c) => c,
                    None => continue,
                }
            };
            let byte_off = u64::from(dmg.y) * u64::from(fb.pitch) + u64::from(dmg.x) * 4;
            let n = vg::encode_transfer_to_host_2d(
                &mut self.dma.map.bytes_mut()[CMD_BUF_OFF..],
                dmg.x,
                dmg.y,
                dmg.w,
                dmg.h,
                byte_off,
                res_id,
            )
            .ok_or(sys::ERR_INVALID_ARGS)?;
            if self.exec_ctrl(n, vg::CTRL_HDR_SIZE)? != vg::RESP_OK_NODATA {
                return Err(i64::from(proto::ERR_IO));
            }
            union = union.union(dmg);
        }
        let flush = if union.is_empty() {
            DamageRect::full(fb.width, fb.height)
        } else {
            union
        };
        let n = vg::encode_resource_flush(
            &mut self.dma.map.bytes_mut()[CMD_BUF_OFF..],
            flush.x,
            flush.y,
            flush.w,
            flush.h,
            res_id,
        )
        .ok_or(sys::ERR_INVALID_ARGS)?;
        if self.exec_ctrl(n, vg::CTRL_HDR_SIZE)? != vg::RESP_OK_NODATA {
            return Err(i64::from(proto::ERR_IO));
        }
        self.frames += 1;
        Ok(())
    }

    fn apply_cursor(&mut self, fb_id: u32, x: i32, y: i32, hot_x: u16, hot_y: u16) -> Result<(), i64> {
        let cx = x.max(0) as u32;
        let cy = y.max(0) as u32;
        if fb_id != 0 {
            let Some((res_id, fb)) = self.res_id_for_fb(fb_id) else {
                return Err(sys::ERR_OUT_OF_RANGE);
            };
            let n = vg::encode_transfer_to_host_2d(
                &mut self.dma.map.bytes_mut()[CMD_BUF_OFF..],
                0,
                0,
                fb.width,
                fb.height,
                0,
                res_id,
            )
            .ok_or(sys::ERR_INVALID_ARGS)?;
            if self.exec_ctrl(n, vg::CTRL_HDR_SIZE)? != vg::RESP_OK_NODATA {
                return Err(i64::from(proto::ERR_IO));
            }
            let cn = vg::encode_cursor(
                &mut self.dma.map.bytes_mut()[CURSOR_CMD_OFF..],
                true,
                0,
                cx,
                cy,
                res_id,
                u32::from(hot_x).min(fb.width.saturating_sub(1)),
                u32::from(hot_y).min(fb.height.saturating_sub(1)),
            )
            .ok_or(sys::ERR_INVALID_ARGS)?;
            self.exec_cursor(cn)?;
            self.cursor_res = res_id;
            Ok(())
        } else {
            if self.cursor_res == 0 {
                return Err(sys::ERR_BAD_STATE);
            }
            let cn = vg::encode_cursor(
                &mut self.dma.map.bytes_mut()[CURSOR_CMD_OFF..],
                false,
                0,
                cx,
                cy,
                self.cursor_res,
                0,
                0,
            )
            .ok_or(sys::ERR_INVALID_ARGS)?;
            self.exec_cursor(cn)
        }
    }
}

impl DrmDriver for VirtioGpu {
    fn kms_get_resources(&self, res_out: &mut KmsResourcesWire, modes_out: &mut [ModeEntry]) -> usize {
        let conn = self.kms.connectors[0].unwrap_or_default();
        let crtc = self.kms.crtcs[0].unwrap_or_default();
        let mut status = gpu::KMS_STATUS_CONNECTED | gpu::KMS_STATUS_CURSOR_PLANE;
        if crtc.active {
            status |= gpu::KMS_STATUS_CRTC_ACTIVE;
        }
        if conn.vrr_capable {
            status |= gpu::KMS_STATUS_VRR_CAPABLE;
        }
        if crtc.vrr_enabled {
            status |= gpu::KMS_STATUS_VRR_ENABLED;
        }
        if conn.hdr_capable {
            status |= gpu::KMS_STATUS_HDR_CAPABLE;
        }
        if crtc.hdr_enabled {
            status |= gpu::KMS_STATUS_HDR_ENABLED;
        }
        if self.fw_loaded {
            status |= gpu::KMS_STATUS_FIRMWARE_LOADED;
        }
        if self.shim_abi != 0 {
            status |= gpu::KMS_STATUS_VENDOR_SHIM_OK;
        }

        *res_out = KmsResourcesWire::empty();
        res_out.connector_id = conn.id.max(1);
        res_out.connector_kind = conn.kind as u8;
        res_out.crtc_id = crtc.id.max(1);
        res_out.pipe = crtc.pipe;
        res_out.plane_count = self.kms.planes.iter().flatten().count() as u8;
        res_out.edid_blocks = self.edid_blocks;
        res_out.status_flags = status;
        res_out.width = crtc.mode.width;
        res_out.height = crtc.mode.height;
        res_out.pitch_bytes = crtc.mode.width.saturating_mul(4);
        res_out.refresh_mhz = crtc.mode.refresh_mhz;
        res_out.htotal = crtc.mode.htotal;
        res_out.vtotal = crtc.mode.vtotal;
        res_out.vrr_min_hz = conn.vrr_min_hz;
        res_out.vrr_max_hz = conn.vrr_max_hz;
        res_out.vblank_seq = crtc.vblank_seq;
        res_out.shim_abi = self.shim_abi;
        res_out.set_monitor(&conn.monitor_name[..usize::from(conn.monitor_len)]);
        res_out.set_note(if self.venus_capset_id != 0 {
            b"VirtIO-GPU Atomic KMS + Venus/VirGL"
        } else if self.virgl {
            b"VirtIO-GPU Atomic KMS + VirGL 3D"
        } else {
            b"VirtIO-GPU Atomic KMS (IOMMU SG)"
        });

        let count = self.kms.mode_count.min(modes_out.len());
        for (i, slot) in modes_out.iter_mut().take(count).enumerate() {
            let m = self.kms.modes[i];
            *slot = ModeEntry {
                width: m.width,
                height: m.height,
                refresh_mhz: m.refresh_mhz,
                pixel_clock_khz: m.pixel_clock_khz,
                htotal: m.htotal,
                vtotal: m.vtotal,
                flags: m.flags,
            };
        }
        count
    }

    fn gem_import(&mut self, vmo: Handle, size: u64, bo_flags: u32) -> Result<(u32, [u8; 16]), i64> {
        let Some(b_slot) = self.backings.iter().position(Option::is_none) else {
            sys::handle_close(vmo);
            return Err(sys::ERR_NO_RESOURCES);
        };
        let dma_flags = if (bo_flags & gpu::BO_RENDER) != 0 {
            sys::DMA_DEVICE_READ | sys::DMA_DEVICE_WRITE
        } else {
            sys::DMA_DEVICE_READ
        };
        let pin = SgPin::pin(self.dev, &mut self.scratch, vmo, size, dma_flags)?;
        let gem_h = match self.gem.insert(size, bo_flags, 0, [0; 16]) {
            Ok(h) => h,
            Err(e) => return Err(mem_err_to_sys(e)),
        };
        let uuid = self.synth_uuid(gem_h, 0);
        self.backings[b_slot] = Some(BoBacking {
            gem_handle: gem_h,
            pin,
            res_id: 0,
            res_width: 0,
            res_height: 0,
            res_format: 0,
            is_blob: false,
        });
        Ok((gem_h, uuid))
    }

    fn gem_create(&mut self, size: u64, bo_flags: u32) -> Result<(u32, Handle, [u8; 16]), i64> {
        if size == 0 || size > dosdrm::MAX_FB_BYTES {
            return Err(sys::ERR_INVALID_ARGS);
        }
        let Some(b_slot) = self.backings.iter().position(Option::is_none) else {
            return Err(sys::ERR_NO_RESOURCES);
        };
        let aligned = size.div_ceil(sys::PAGE) * sys::PAGE;
        let vmo = sys::vmo_create(aligned)?;
        let client_vmo = match sys::handle_duplicate(
            vmo,
            sys::RIGHT_READ | sys::RIGHT_WRITE | sys::RIGHT_MAP | sys::RIGHT_DUPLICATE | sys::RIGHT_TRANSFER,
        ) {
            Ok(d) => d,
            Err(e) => {
                sys::handle_close(vmo);
                return Err(e);
            }
        };
        let pin = match SgPin::pin(
            self.dev,
            &mut self.scratch,
            vmo,
            aligned,
            sys::DMA_DEVICE_READ | sys::DMA_DEVICE_WRITE,
        ) {
            Ok(p) => p,
            Err(e) => {
                sys::handle_close(client_vmo);
                return Err(e);
            }
        };

        let mut res_id = 0u32;
        let mut is_blob = false;
        if self.has_blob && (bo_flags & gpu::BO_RENDER) != 0 {
            let candidate = self.next_res_id;
            let blob_id = self.next_blob_id;
            if let Some(n) = vg::encode_resource_create_blob(
                &mut self.dma.map.bytes_mut()[CMD_BUF_OFF..],
                0,
                candidate,
                vg::BLOB_MEM_GUEST,
                vg::BLOB_FLAG_USE_MAPPABLE | vg::BLOB_FLAG_USE_SHAREABLE,
                blob_id,
                aligned,
                pin.runs(),
            ) && self.exec_ctrl(n, vg::CTRL_HDR_SIZE) == Ok(vg::RESP_OK_NODATA)
            {
                self.next_res_id += 1;
                self.next_blob_id += 1;
                res_id = candidate;
                is_blob = true;
            }
        }

        let gem_h = match self.gem.insert(aligned, bo_flags, res_id, [0; 16]) {
            Ok(h) => h,
            Err(e) => {
                if res_id != 0 {
                    self.unref_resource(res_id, is_blob);
                }
                sys::handle_close(client_vmo);
                return Err(mem_err_to_sys(e));
            }
        };
        let uuid = self.assign_or_synth_uuid(gem_h, res_id);
        self.backings[b_slot] = Some(BoBacking {
            gem_handle: gem_h,
            pin,
            res_id,
            res_width: 0,
            res_height: 0,
            res_format: 0,
            is_blob,
        });
        Ok((gem_h, client_vmo, uuid))
    }

    fn gem_close(&mut self, gem_handle: u32) -> Result<(), i64> {
        let released = self.gem.release(gem_handle).map_err(mem_err_to_sys)?;
        if released.is_some() {
            for slot in &mut self.backings {
                if slot.as_ref().is_some_and(|b| b.gem_handle == gem_handle)
                    && let Some(b) = slot.take()
                {
                    if b.res_id != 0 {
                        if self.scanout_res == b.res_id {
                            let _ = self.bind_scanout(0, 0, 0);
                        }
                        if self.cursor_res == b.res_id {
                            self.cursor_res = 0;
                        }
                        self.unref_resource(b.res_id, b.is_blob);
                    }
                    break;
                }
            }
        }
        Ok(())
    }

    fn kms_create_fb(
        &mut self,
        gem_handle: u32,
        width: u32,
        height: u32,
        pitch: u32,
        format: u32,
        modifier: u64,
    ) -> Result<u32, i64> {
        let Some(bo) = self.gem.get(gem_handle) else {
            return Err(sys::ERR_OUT_OF_RANGE);
        };
        kms::KmsFb::validate(gem_handle, width, height, pitch, format, bo.size).map_err(kms_err_to_sys)?;
        let _res_id = self.ensure_2d_resource(gem_handle, width, height, format)?;
        // Hold an extra GEM ref while the KmsFb exists so scanout cannot outlive its IOMMU pin.
        let _ = self.gem.add_ref(gem_handle);
        match self.kms.add_fb(gem_handle, width, height, pitch, format, modifier, bo.size) {
            Ok(fb_id) => Ok(fb_id),
            Err(e) => {
                let _ = self.gem_close(gem_handle);
                Err(kms_err_to_sys(e))
            }
        }
    }

    fn kms_destroy_fb(&mut self, fb_id: u32) -> Result<(), i64> {
        let Some(fb) = self.kms.remove_fb(fb_id) else {
            return Err(sys::ERR_OUT_OF_RANGE);
        };
        let _ = self.gem_close(fb.gem_handle);
        Ok(())
    }

    fn kms_atomic_commit(&mut self, commit: &AtomicCommit) -> Result<(u64, bool), i64> {
        if commit.in_syncobj != 0 {
            let ready = self
                .syncobjs
                .is_signaled(commit.in_syncobj, commit.in_point)
                .map_err(mem_err_to_sys)?;
            if !ready {
                return Err(sys::ERR_SHOULD_WAIT);
            }
        }

        if (commit.flags & kms::ATOMIC_RESET_BOOT) != 0 {
            if (commit.flags & kms::ATOMIC_TEST_ONLY) == 0 {
                let mut rst = AtomicCommit {
                    flags: kms::ATOMIC_ALLOW_MODESET,
                    mode_changed: true,
                    mode_width: self.boot_mode.width,
                    mode_height: self.boot_mode.height,
                    mode_refresh_mhz: self.boot_mode.refresh_mhz,
                    ..AtomicCommit::default()
                };
                if let Ok(resolved) = self.kms.validate_commit(&rst) {
                    let _ = self.bind_scanout(0, 0, 0);
                    self.kms.apply_commit(&rst, resolved);
                }
                let _ = &mut rst;
            }
            let seq = self.kms.crtcs[0].map_or(0, |c| c.vblank_seq);
            return Ok((seq, false));
        }

        let resolved_mode = self.kms.validate_commit(commit).map_err(kms_err_to_sys)?;
        if (commit.flags & kms::ATOMIC_TEST_ONLY) != 0 {
            let seq = self.kms.crtcs[0].map_or(0, |c| c.vblank_seq);
            return Ok((seq, false));
        }

        if let Some(m) = resolved_mode {
            // If a framebuffer matching the new mode is either in this commit or already on Primary,
            // bind it to scanout 0 at the new dimensions; otherwise clear scanout until next flip.
            let target_fb = if commit.primary_changed && commit.primary_fb_id != 0 {
                Some(commit.primary_fb_id)
            } else {
                self.kms.planes[0]
                    .filter(|p| p.kind == PlaneKind::Primary && p.fb_id != 0)
                    .map(|p| p.fb_id)
            };
            if let Some(fb_id) = target_fb
                && let Some((res_id, fb)) = self.res_id_for_fb(fb_id)
                && fb.width == m.width
                && fb.height == m.height
            {
                self.bind_scanout(res_id, m.width, m.height)?;
            } else if self.scanout_res != 0 {
                let _ = self.bind_scanout(0, 0, 0);
            }
        }

        if commit.primary_changed && commit.primary_fb_id != 0 {
            let cnt = usize::from(commit.damage_count).min(kms::MAX_COMMIT_DAMAGE);
            self.flush_primary_damage(commit.primary_fb_id, &commit.damage[..cnt])?;
        } else if commit.primary_changed && commit.primary_fb_id == 0 && self.scanout_res != 0 {
            self.bind_scanout(0, 0, 0)?;
        }

        if commit.cursor_changed {
            self.apply_cursor(
                commit.cursor_fb_id,
                commit.cursor_x,
                commit.cursor_y,
                commit.cursor_hot_x,
                commit.cursor_hot_y,
            )?;
        }

        self.kms.apply_commit(commit, resolved_mode);
        let seq = self.kms.crtcs[0].map_or(self.frames, |c| c.vblank_seq.max(self.frames));
        if commit.out_syncobj != 0 {
            let pt = if commit.out_point == 0 { seq.max(1) } else { commit.out_point };
            let _ = self.syncobjs.signal(commit.out_syncobj, pt);
        }
        Ok((seq, false))
    }

    fn vm_create(&mut self) -> Result<u32, i64> {
        self.vms.create().map_err(mem_err_to_sys)
    }

    fn vm_destroy(&mut self, vm_id: u32) -> Result<(), i64> {
        self.vms.destroy(vm_id).map_err(mem_err_to_sys)
    }

    fn vm_bind(
        &mut self,
        vm_id: u32,
        gem_handle: u32,
        bo_offset: u64,
        gpu_va: u64,
        size: u64,
        flags: u32,
    ) -> Result<(), i64> {
        let Some(vm) = self.vms.get_mut(vm_id) else {
            return Err(sys::ERR_OUT_OF_RANGE);
        };
        vm.bind(&self.gem, gpu_va, size, gem_handle, bo_offset, flags)
            .map_err(mem_err_to_sys)
    }

    fn vm_unbind(&mut self, vm_id: u32, gpu_va: u64, size: u64) -> Result<(), i64> {
        let Some(vm) = self.vms.get_mut(vm_id) else {
            return Err(sys::ERR_OUT_OF_RANGE);
        };
        vm.unbind(gpu_va, size).map(|_| ()).map_err(mem_err_to_sys)
    }

    fn syncobj_create(&mut self, initial_point: u64) -> Result<u32, i64> {
        self.syncobjs.create(initial_point).map_err(mem_err_to_sys)
    }

    fn syncobj_destroy(&mut self, syncobj: u32) -> Result<(), i64> {
        self.syncobjs.destroy(syncobj).map_err(mem_err_to_sys)
    }

    fn syncobj_signal(&mut self, syncobj: u32, point: u64) -> Result<u64, i64> {
        self.syncobjs.signal(syncobj, point).map_err(mem_err_to_sys)
    }

    fn syncobj_wait(&mut self, syncobj: u32, point: u64) -> Result<u64, i64> {
        if point == 0 {
            return self.syncobjs.query(syncobj).map_err(mem_err_to_sys);
        }
        let ready = self.syncobjs.is_signaled(syncobj, point).map_err(mem_err_to_sys)?;
        if !ready {
            return Err(sys::ERR_SHOULD_WAIT);
        }
        self.syncobjs.query(syncobj).map_err(mem_err_to_sys)
    }

    fn ctx_create(&mut self, engine: u32, _vm_id: u32) -> Result<u32, i64> {
        let id = self.next_ctx_id;
        self.next_ctx_id += 1;
        if self.virgl {
            let capset = if engine == gpu::ENGINE_VENUS_VK && self.has_ctx_init && self.venus_capset_id != 0 {
                self.venus_capset_id
            } else {
                0
            };
            let n = vg::encode_ctx_create_ex(&mut self.dma.map.bytes_mut()[CMD_BUF_OFF..], id, capset, b"d-os-drm")
                .ok_or(sys::ERR_INVALID_ARGS)?;
            if self.exec_ctrl(n, vg::CTRL_HDR_SIZE)? != vg::RESP_OK_NODATA {
                return Err(i64::from(proto::ERR_IO));
            }
        }
        Ok(id)
    }

    fn ctx_destroy(&mut self, ctx_id: u32) -> Result<(), i64> {
        if ctx_id == 0 {
            return Err(sys::ERR_INVALID_ARGS);
        }
        if self.virgl
            && let Some(n) = vg::encode_ctx_destroy(&mut self.dma.map.bytes_mut()[CMD_BUF_OFF..], ctx_id)
        {
            let _ = self.exec_ctrl(n, vg::CTRL_HDR_SIZE);
        }
        Ok(())
    }

    fn submit(
        &mut self,
        ctx_id: u32,
        engine: u32,
        wait_syncobj: u32,
        wait_point: u64,
        signal_syncobj: u32,
        signal_point: u64,
        cmd: &[u8],
    ) -> Result<u64, i64> {
        if ctx_id == 0 || !matches!(engine, gpu::ENGINE_VIRGL_3D | gpu::ENGINE_VENUS_VK) {
            return Err(sys::ERR_INVALID_ARGS);
        }
        if wait_syncobj != 0 {
            let ready = self
                .syncobjs
                .is_signaled(wait_syncobj, wait_point)
                .map_err(mem_err_to_sys)?;
            if !ready {
                return Err(sys::ERR_SHOULD_WAIT);
            }
        }
        if engine == gpu::ENGINE_VIRGL_3D {
            vg::validate_virgl_cs(cmd).map_err(|_| sys::ERR_INVALID_ARGS)?;
        } else if !cmd.len().is_multiple_of(4) || cmd.is_empty() {
            return Err(sys::ERR_INVALID_ARGS);
        }
        if !self.virgl || (engine == gpu::ENGINE_VENUS_VK && self.venus_capset_id == 0) {
            return Err(sys::ERR_NOT_SUPPORTED);
        }
        let n = vg::encode_submit_3d(&mut self.dma.map.bytes_mut()[CMD_BUF_OFF..], ctx_id, cmd)
            .ok_or(sys::ERR_INVALID_ARGS)?;
        if self.exec_ctrl(n, vg::CTRL_HDR_SIZE)? != vg::RESP_OK_NODATA {
            return Err(i64::from(proto::ERR_IO));
        }
        self.fences += 1;
        if signal_syncobj != 0 {
            let pt = if signal_point == 0 { self.fences } else { signal_point };
            let _ = self.syncobjs.signal(signal_syncobj, pt);
        }
        Ok(self.fences)
    }

    fn irqs(&self) -> u64 {
        self.irqs
    }

    fn frames(&self) -> u64 {
        self.frames
    }

    fn on_irq(&mut self, key: u64) {
        if key == KEY_IRQ0 {
            self.irqs += sys::interrupt_ack(self.ctrlq.irq).unwrap_or(0);
        } else if key == KEY_IRQ1 {
            self.irqs += sys::interrupt_ack(self.cursorq.irq).unwrap_or(0);
        }
    }
}

pub fn main(s: *const Startup) -> i32 {
    // SAFETY: `s` is the startup block pointer passed by the kernel.
    if !unsafe { libd::init(s, "virtio-gpu") } {
        return -1;
    }
    let dev = libd::startup_handle(sys::TAG_DEVICE);
    let ctl = libd::startup_handle(proto::TAG_CONTROL);
    let fw = FirmwareDir::from_startup();
    let Ok(info) = sys::device_info(dev) else {
        println!("virtio-gpu: device_info failed");
        return 1;
    };

    let shim_abi = match shim::init_and_verify_vendor_shim(dev, fw.raw()) {
        Ok(ver) => ver,
        Err(rc) => {
            println!("virtio-gpu: vendor C/C++ shim self-test failed ({})", rc);
            return 1;
        }
    };
    let fw_loaded = if let Ok((fw_vmo, fw_len)) = fw.load_vmo(b"manifest.toml") {
        sys::handle_close(fw_vmo);
        fw_len > 0
    } else {
        false
    };

    let want_features =
        vg::F_VIRGL | vg::F_EDID | vg::F_RESOURCE_UUID | vg::F_RESOURCE_BLOB | vg::F_CONTEXT_INIT;
    let (v, features) = match Virtio::open_with(dev, want_features) {
        Ok(x) => x,
        Err(e) => {
            println!("virtio-gpu: {}: {}", info.name(), e);
            return 1;
        }
    };
    let ctrlq = match v.queue(0) {
        Ok(q) => q,
        Err(e) => {
            println!("virtio-gpu: controlq: {}", e);
            return 1;
        }
    };
    let cursorq = match v.queue(1) {
        Ok(q) => q,
        Err(e) => {
            println!("virtio-gpu: cursorq: {}", e);
            return 1;
        }
    };
    let mut dma = match Dma::new(dev, DMA_BYTES, sys::DMA_DEVICE_READ | sys::DMA_DEVICE_WRITE) {
        Ok(d) => d,
        Err(e) => {
            println!("virtio-gpu: dma_map: {}", sys::status(e));
            return 1;
        }
    };
    dma.map.bytes_mut().fill(0);
    let Ok(scratch) = shim::alloc_sg_scratch() else {
        println!("virtio-gpu: scratch mapping failed");
        return 1;
    };
    v.driver_ok();

    let virgl = (features & vg::F_VIRGL) != 0;
    let has_edid = (features & vg::F_EDID) != 0;
    let has_uuid = (features & vg::F_RESOURCE_UUID) != 0;
    let has_blob = (features & vg::F_RESOURCE_BLOB) != 0;
    let has_ctx_init = (features & vg::F_CONTEXT_INIT) != 0;
    let num_capsets = v.devcfg.map_or(0, |c| if c.len >= 16 { v.r32(c, 12) } else { 0 });

    let mut drv = VirtioGpu {
        dev,
        v,
        ctrlq,
        cursorq,
        dma,
        scratch,
        virgl,
        has_uuid,
        has_blob,
        has_ctx_init,
        venus_capset_id: 0,
        fw_loaded,
        shim_abi,
        edid: None,
        edid_blocks: 0,
        boot_mode: KmsMode::simple(1024, 768, 60_000, kms::MODE_FLAG_PREFERRED | kms::MODE_FLAG_CURRENT),
        kms: KmsState::new(),
        gem: GemTable::new(),
        vms: GpuVmTable::new(),
        syncobjs: SyncobjTable::new(),
        backings: [const { None }; MAX_VIRTIO_BOS],
        scanout_res: 0,
        cursor_res: 0,
        next_res_id: 1,
        next_blob_id: 1,
        next_ctx_id: 1,
        frames: 0,
        fences: 0,
        irqs: 0,
    };

    let (w, h, scanouts) = drv.query_display_info().unwrap_or((1024, 768, 1));
    if has_edid && let Some((ed, blks)) = drv.query_edid() {
        drv.edid = Some(ed);
        drv.edid_blocks = blks;
    }

    let mut mon_bytes = [0u8; 24];
    let mon_len = match &drv.edid {
        Some(e) if e.name_len > 0 => {
            let n = usize::from(e.name_len).min(e.name.len());
            mon_bytes[..n].copy_from_slice(&e.name[..n]);
            n
        }
        _ => {
            let s = b"VirtIO Display";
            mon_bytes[..s.len()].copy_from_slice(s);
            s.len()
        }
    };

    drv.kms
        .init_single_pipe(ConnectorKind::Virtual, &mon_bytes[..mon_len], w, h, 60_000, true);
    drv.kms.allow_arbitrary_modeset = true;
    drv.boot_mode = drv.kms.crtcs[0].map_or(drv.boot_mode, |c| c.mode);

    if let Some(ed) = drv.edid {
        if let Some(conn) = drv.kms.connectors[0].as_mut() {
            conn.edid_blocks = drv.edid_blocks;
            conn.vrr_capable = ed.vrr_max_hz > 0;
            conn.vrr_min_hz = ed.vrr_min_hz;
            conn.vrr_max_hz = ed.vrr_max_hz;
            conn.hdr_capable = ed.hdr_supported;
        }
        for t in ed.timings() {
            let is_cur = t.h_active == w && t.v_active == h && t.refresh_mhz.abs_diff(60_000) <= 1_000;
            drv.kms.push_mode(KmsMode::from_timing(t, is_cur));
        }
    }
    for &(mw, mh) in &[(1920, 1080), (1280, 800), (1024, 768), (800, 600), (640, 480)] {
        drv.kms.push_mode(KmsMode::simple(mw, mh, 60_000, 0));
    }

    if virgl {
        for idx in 0..num_capsets.min(8) {
            if let Some(n) = vg::encode_get_capset_info(&mut drv.dma.map.bytes_mut()[CMD_BUF_OFF..], idx)
                && drv.exec_ctrl(n, 40) == Ok(vg::RESP_OK_CAPSET_INFO)
                && let Some(cs) = vg::decode_capset_info(&drv.dma.map.bytes()[RESP_BUF_OFF..RESP_BUF_OFF + 40])
            {
                if cs.capset_id == vg::CAPSET_VENUS {
                    drv.venus_capset_id = cs.capset_id;
                }
                println!(
                    "virtio-gpu: capset[{}] id={} ver={} max_size={}",
                    idx, cs.capset_id, cs.capset_max_version, cs.capset_max_size
                );
            }
        }
    }

    let iommu = (info.flags & sys::DEV_FLAG_IOMMU) != 0;
    let mut caps = gpu::CAP_SCANOUT_2D
        | gpu::CAP_HW_CURSOR
        | gpu::CAP_ATOMIC_KMS
        | gpu::CAP_GEM_VM
        | gpu::CAP_SYNCOBJ_TIMELINE;
    if iommu {
        caps |= gpu::CAP_IOMMU;
    }
    if drv.edid.is_some() {
        caps |= gpu::CAP_EDID;
    }
    if virgl {
        caps |= gpu::CAP_VIRGL_3D | gpu::CAP_CMD_GFX;
    }
    if drv.venus_capset_id != 0 {
        caps |= gpu::CAP_VENUS_VK;
    }
    if fw_loaded {
        caps |= gpu::CAP_SYS_FIRMWARE;
    }
    let mon_str = core::str::from_utf8(&mon_bytes[..mon_len]).unwrap_or("?");
    println!(
        "virtio-gpu: ready on {} {}x{} ({} scanout(s), monitor='{}', virgl={}, edid={}, fw={}, shim={:#x}, IOMMU={})",
        info.name(),
        w,
        h,
        scanouts,
        mon_str,
        virgl,
        drv.edid.is_some(),
        fw_loaded,
        shim_abi,
        iommu
    );

    let Ok(port) = Port::new(32) else { return 1 };
    gpu_drv::announce(
        ctl,
        &GpuAnnounce {
            kind: gpu::KIND_VIRTIO_GPU,
            vendor: info.vendor,
            device: info.device,
            vram_mib: 0,
            width: w as u16,
            height: h as u16,
            caps,
            name: "VirtIO-GPU",
        },
    );
    gpu_drv::serve_loop(ctl, &port, &mut drv)
}
