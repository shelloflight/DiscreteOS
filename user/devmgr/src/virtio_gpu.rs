//! Modern VirtIO 1.x GPU driver (`virtio-gpu.ddrv`, PCI `1AF4:1050`).
//!
//! Runs isolated in user space inside a per-device IOMMU domain with zero-copy VMO framebuffer
//! pinning, 2D scanout & damage-rectangle flushing, EDID parsing, hardware cursor (`cursorq`),
//! and 3D VirGL context / command submission (`VIRTIO_GPU_F_VIRGL`).

use core::sync::atomic::{Ordering, fence};

use dosgpu::edid::{self, EdidInfo};
use dosgpu::virtio as vg;
use dosgpu::{DamageRect, MAX_DIM};
use libd::gpu::{self, MODE_FLAG_CURRENT, MODE_FLAG_PREFERRED, ModeEntry};
use libd::proto;
use libd::sys::{self, Handle};
use libd::{Dma, Mapping, Port, Startup, println};

use crate::gpu_drv::{self, FbPin, GpuAnnounce, GpuDriver, KEY_IRQ0, KEY_IRQ1};
use crate::virtio::{DESC_NEXT, DESC_WRITE, Queue, Virtio};

const SEC: u64 = 1_000_000_000;
const CMD_BUF_OFF: usize = 0;
const CMD_BUF_MAX: usize = 8192;
const RESP_BUF_OFF: usize = 8192;
const RESP_BUF_MAX: usize = 4096;
const CURSOR_CMD_OFF: usize = 12288;
const DMA_BYTES: u64 = 16384; // 4 pages

const MAX_FBS: usize = 4;

struct FbSlot {
    fb_id: u32,
    res_id: u32,
    pin: FbPin,
}

struct VirtioGpu {
    dev: Handle,
    v: Virtio,
    ctrlq: Queue,
    cursorq: Queue,
    dma: Dma,
    scratch: Mapping,
    virgl: bool,
    edid: Option<EdidInfo>,
    width: u32,
    height: u32,
    scanout_res: u32,
    next_res_id: u32,
    next_fb_id: u32,
    next_ctx_id: u32,
    cursor_res: u32,
    cursor_pin: Option<FbPin>,
    fbs: [Option<FbSlot>; MAX_FBS],
    frames: u64,
    fences: u64,
    irqs: u64,
}

impl VirtioGpu {
    /// Execute one synchronous VirtIO-GPU control command on `controlq`.
    fn exec_ctrl(&mut self, cmd_len: usize, resp_len: usize) -> Result<u32, i64> {
        if cmd_len > CMD_BUF_MAX || resp_len > RESP_BUF_MAX {
            return Err(sys::ERR_INVALID_ARGS);
        }
        // Clear response header before sending.
        let rbytes = &mut self.dma.map.bytes_mut()[RESP_BUF_OFF..RESP_BUF_OFF + 24.min(resp_len)];
        rbytes.fill(0);
        fence(Ordering::Release);

        // Descriptor 0: command (device-read), chaining to descriptor 1: response (device-write).
        // Command buffer is up to 8 KiB (2 pages); IOMMU guarantees contiguous IOVA across pages
        // of one Dma pin, and for multi-page commands without IOMMU we split at 4 KiB page boundaries.
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
        let n = vg::encode_get_display_info(&mut self.dma.map.bytes_mut()[CMD_BUF_OFF..]).ok_or(sys::ERR_INVALID_ARGS)?;
        let ty = self.exec_ctrl(n, vg::RESP_DISPLAY_INFO_SIZE)?;
        if ty != vg::RESP_OK_DISPLAY_INFO {
            return Err(i64::from(proto::ERR_IO));
        }
        let info = vg::decode_display_info(&self.dma.map.bytes()[RESP_BUF_OFF..RESP_BUF_OFF + vg::RESP_DISPLAY_INFO_SIZE])
            .ok_or(sys::ERR_BAD_STATE)?;
        let enabled = info.pmodes.iter().filter(|p| p.enabled).count();
        let p0 = info.pmodes[0];
        let w = if p0.width >= 320 && p0.width <= MAX_DIM { p0.width } else { 1024 };
        let h = if p0.height >= 200 && p0.height <= MAX_DIM { p0.height } else { 768 };
        Ok((w, h, enabled.max(1)))
    }

    fn query_edid(&mut self) -> Option<EdidInfo> {
        let n = vg::encode_get_edid(&mut self.dma.map.bytes_mut()[CMD_BUF_OFF..], 0)?;
        let ty = self.exec_ctrl(n, 32 + 1024).ok()?;
        if ty != vg::RESP_OK_EDID {
            return None;
        }
        let slice = vg::decode_edid_resp(&self.dma.map.bytes()[RESP_BUF_OFF..RESP_BUF_OFF + 32 + 1024])?;
        edid::parse_edid(slice).ok()
    }

    fn unref_resource(&mut self, res_id: u32) {
        if res_id == 0 {
            return;
        }
        if let Some(n) = vg::encode_resource_detach_backing(&mut self.dma.map.bytes_mut()[CMD_BUF_OFF..], res_id) {
            let _ = self.exec_ctrl(n, vg::CTRL_HDR_SIZE);
        }
        if let Some(n) = vg::encode_resource_unref(&mut self.dma.map.bytes_mut()[CMD_BUF_OFF..], res_id) {
            let _ = self.exec_ctrl(n, vg::CTRL_HDR_SIZE);
        }
    }

    fn create_and_attach_2d(&mut self, res_id: u32, fmt: u32, pin: &FbPin) -> Result<(), i64> {
        let vfmt = match fmt {
            gpu::FMT_ARGB8888 => vg::FORMAT_B8G8R8A8_UNORM,
            gpu::FMT_XBGR8888 => vg::FORMAT_R8G8B8X8_UNORM,
            _ => vg::FORMAT_B8G8R8X8_UNORM,
        };
        let n = vg::encode_resource_create_2d(
            &mut self.dma.map.bytes_mut()[CMD_BUF_OFF..],
            res_id,
            vfmt,
            pin.width,
            pin.height,
        )
        .ok_or(sys::ERR_INVALID_ARGS)?;
        if self.exec_ctrl(n, vg::CTRL_HDR_SIZE)? != vg::RESP_OK_NODATA {
            return Err(i64::from(proto::ERR_IO));
        }
        let n = vg::encode_resource_attach_backing(
            &mut self.dma.map.bytes_mut()[CMD_BUF_OFF..],
            res_id,
            &pin.runs[..pin.run_count],
        )
        .ok_or(sys::ERR_NO_RESOURCES)?;
        if self.exec_ctrl(n, vg::CTRL_HDR_SIZE)? != vg::RESP_OK_NODATA {
            self.unref_resource(res_id);
            return Err(i64::from(proto::ERR_IO));
        }
        Ok(())
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
        self.width = width;
        self.height = height;
        Ok(())
    }
}

impl GpuDriver for VirtioGpu {
    fn modes(&self, out: &mut [ModeEntry]) -> usize {
        let mut count = 0usize;
        let mut push = |w: u32, h: u32, hz: u32, pref: bool| {
            if count >= out.len() {
                return;
            }
            for e in &out[..count] {
                if e.width == w && e.height == h {
                    return;
                }
            }
            let mut flags = if pref { MODE_FLAG_PREFERRED } else { 0 };
            if w == self.width && h == self.height {
                flags |= MODE_FLAG_CURRENT;
            }
            out[count] = ModeEntry { width: w, height: h, refresh_mhz: hz, flags };
            count += 1;
        };
        push(self.width, self.height, 60_000, true);
        if let Some(ed) = self.edid {
            for m in ed.modes() {
                push(m.width, m.height, m.refresh_mhz, m.preferred);
            }
        }
        for &(w, h) in &[(1920, 1080), (1280, 800), (1024, 768), (800, 600), (640, 480)] {
            push(w, h, 60_000, false);
        }
        count
    }

    fn monitor_name(&self) -> &[u8] {
        match &self.edid {
            Some(e) if e.name_len > 0 => &e.name[..usize::from(e.name_len)],
            _ => b"VirtIO Display",
        }
    }

    fn attach_fb(&mut self, vmo: Handle, width: u32, height: u32, pitch: u32, format: u32) -> Result<u32, i64> {
        let pin = FbPin::pin(self.dev, &mut self.scratch, vmo, width, height, pitch, format)?;
        // Reuse an empty slot or evict the oldest non-scanout slot.
        let slot_idx = self
            .fbs
            .iter()
            .position(|s| s.is_none())
            .or_else(|| self.fbs.iter().position(|s| s.as_ref().is_some_and(|f| f.res_id != self.scanout_res)))
            .unwrap_or(0);
        if let Some(old) = self.fbs[slot_idx].take() {
            if self.scanout_res == old.res_id {
                let _ = self.bind_scanout(0, 0, 0);
            }
            self.unref_resource(old.res_id);
        }
        let res_id = self.next_res_id;
        self.next_res_id += 1;
        let fb_id = self.next_fb_id;
        self.next_fb_id += 1;
        self.create_and_attach_2d(res_id, format, &pin)?;
        self.fbs[slot_idx] = Some(FbSlot { fb_id, res_id, pin });
        Ok(fb_id)
    }

    fn set_mode(&mut self, width: u32, height: u32) -> Result<(), i64> {
        if !(320..=MAX_DIM).contains(&width) || !(200..=MAX_DIM).contains(&height) {
            return Err(sys::ERR_INVALID_ARGS);
        }
        if let Some(res_id) = self
            .fbs
            .iter()
            .flatten()
            .find(|f| f.pin.width == width && f.pin.height == height)
            .map(|f| f.res_id)
        {
            self.bind_scanout(res_id, width, height)?;
        } else {
            // Update requested dimensions; bound on next attach/present of matching FB.
            self.width = width;
            self.height = height;
        }
        Ok(())
    }

    fn present(&mut self, fb_id: u32, rect: DamageRect) -> Result<u64, i64> {
        let Some((res_id, w, h, pitch)) = self
            .fbs
            .iter()
            .flatten()
            .find(|f| f.fb_id == fb_id)
            .map(|f| (f.res_id, f.pin.width, f.pin.height, f.pin.pitch))
        else {
            return Err(sys::ERR_INVALID_ARGS);
        };
        if self.scanout_res != res_id {
            self.bind_scanout(res_id, w, h)?;
        }
        let dmg = if rect.w == 0 || rect.h == 0 {
            DamageRect::full(w, h)
        } else {
            rect.clip(w, h).unwrap_or_else(|| DamageRect::full(w, h))
        };
        let byte_off = u64::from(dmg.y) * u64::from(pitch) + u64::from(dmg.x) * 4;
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
        let n = vg::encode_resource_flush(
            &mut self.dma.map.bytes_mut()[CMD_BUF_OFF..],
            dmg.x,
            dmg.y,
            dmg.w,
            dmg.h,
            res_id,
        )
        .ok_or(sys::ERR_INVALID_ARGS)?;
        if self.exec_ctrl(n, vg::CTRL_HDR_SIZE)? != vg::RESP_OK_NODATA {
            return Err(i64::from(proto::ERR_IO));
        }
        self.frames += 1;
        Ok(self.frames)
    }

    fn set_cursor(&mut self, vmo: Handle, hot_x: u32, hot_y: u32) -> Result<(), i64> {
        let pin = FbPin::pin(self.dev, &mut self.scratch, vmo, 64, 64, 64 * 4, gpu::FMT_ARGB8888)?;
        if self.cursor_res != 0 {
            self.unref_resource(self.cursor_res);
            self.cursor_res = 0;
            self.cursor_pin = None;
        }
        let res_id = self.next_res_id;
        self.next_res_id += 1;
        self.create_and_attach_2d(res_id, gpu::FMT_ARGB8888, &pin)?;
        // Transfer 64x64 cursor pixels to host before updating cursorq.
        let n = vg::encode_transfer_to_host_2d(
            &mut self.dma.map.bytes_mut()[CMD_BUF_OFF..],
            0,
            0,
            64,
            64,
            0,
            res_id,
        )
        .ok_or(sys::ERR_INVALID_ARGS)?;
        if self.exec_ctrl(n, vg::CTRL_HDR_SIZE)? != vg::RESP_OK_NODATA {
            self.unref_resource(res_id);
            return Err(i64::from(proto::ERR_IO));
        }
        let cn = vg::encode_cursor(
            &mut self.dma.map.bytes_mut()[CURSOR_CMD_OFF..],
            true,
            0,
            0,
            0,
            res_id,
            hot_x.min(63),
            hot_y.min(63),
        )
        .ok_or(sys::ERR_INVALID_ARGS)?;
        self.exec_cursor(cn)?;
        self.cursor_res = res_id;
        self.cursor_pin = Some(pin);
        Ok(())
    }

    fn move_cursor(&mut self, x: u32, y: u32) -> Result<(), i64> {
        if self.cursor_res == 0 {
            return Err(sys::ERR_BAD_STATE);
        }
        let cn = vg::encode_cursor(
            &mut self.dma.map.bytes_mut()[CURSOR_CMD_OFF..],
            false,
            0,
            x,
            y,
            self.cursor_res,
            0,
            0,
        )
        .ok_or(sys::ERR_INVALID_ARGS)?;
        self.exec_cursor(cn)
    }

    fn ctx_create(&mut self) -> Result<u32, i64> {
        let id = self.next_ctx_id;
        self.next_ctx_id += 1;
        if self.virgl {
            let n = vg::encode_ctx_create(&mut self.dma.map.bytes_mut()[CMD_BUF_OFF..], id, b"d-os-virgl")
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
        if self.virgl {
            let n = vg::encode_ctx_destroy(&mut self.dma.map.bytes_mut()[CMD_BUF_OFF..], ctx_id)
                .ok_or(sys::ERR_INVALID_ARGS)?;
            let _ = self.exec_ctrl(n, vg::CTRL_HDR_SIZE);
        }
        Ok(())
    }

    fn submit_cmd(&mut self, ctx_id: u32, engine: u32, cmd: &[u8]) -> Result<u64, i64> {
        if engine != gpu::ENGINE_VIRGL_3D {
            return Err(sys::ERR_INVALID_ARGS);
        }
        // Always validate the untrusted VirGL command buffer first.
        vg::validate_virgl_cs(cmd).map_err(|_| sys::ERR_INVALID_ARGS)?;
        if !self.virgl {
            return Err(sys::ERR_NOT_SUPPORTED);
        }
        let n = vg::encode_submit_3d(&mut self.dma.map.bytes_mut()[CMD_BUF_OFF..], ctx_id, cmd)
            .ok_or(sys::ERR_INVALID_ARGS)?;
        if self.exec_ctrl(n, vg::CTRL_HDR_SIZE)? != vg::RESP_OK_NODATA {
            return Err(i64::from(proto::ERR_IO));
        }
        self.fences += 1;
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
    let Ok(info) = sys::device_info(dev) else {
        println!("virtio-gpu: device_info failed");
        return 1;
    };
    let (v, features) = match Virtio::open_with(dev, vg::F_VIRGL | vg::F_EDID) {
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
    let Ok(scratch) = gpu_drv::alloc_pin_scratch() else {
        println!("virtio-gpu: scratch mapping failed");
        return 1;
    };
    v.driver_ok();

    let virgl = (features & vg::F_VIRGL) != 0;
    let has_edid = (features & vg::F_EDID) != 0;
    let num_capsets = v.devcfg.map_or(0, |c| if c.len >= 16 { v.r32(c, 12) } else { 0 });

    let mut drv = VirtioGpu {
        dev,
        v,
        ctrlq,
        cursorq,
        dma,
        scratch,
        virgl,
        edid: None,
        width: 1024,
        height: 768,
        scanout_res: 0,
        next_res_id: 1,
        next_fb_id: 1,
        next_ctx_id: 1,
        cursor_res: 0,
        cursor_pin: None,
        fbs: [const { None }; MAX_FBS],
        frames: 0,
        fences: 0,
        irqs: 0,
    };

    let (w, h, scanouts) = drv.query_display_info().unwrap_or((1024, 768, 1));
    drv.width = w;
    drv.height = h;
    if has_edid {
        drv.edid = drv.query_edid();
    }
    if virgl
        && num_capsets > 0
        && let Some(n) = vg::encode_get_capset_info(&mut drv.dma.map.bytes_mut()[CMD_BUF_OFF..], 0)
        && drv.exec_ctrl(n, 40) == Ok(vg::RESP_OK_CAPSET_INFO)
        && let Some(cs) = vg::decode_capset_info(&drv.dma.map.bytes()[RESP_BUF_OFF..RESP_BUF_OFF + 40])
    {
        println!(
            "virtio-gpu: VirGL 3D capset id={} ver={} max_size={}",
            cs.capset_id, cs.capset_max_version, cs.capset_max_size
        );
    }

    let iommu = (info.flags & sys::DEV_FLAG_IOMMU) != 0;
    let mut caps = gpu::CAP_SCANOUT_2D | gpu::CAP_HW_CURSOR;
    if iommu {
        caps |= gpu::CAP_IOMMU;
    }
    if drv.edid.is_some() {
        caps |= gpu::CAP_EDID;
    }
    if virgl {
        caps |= gpu::CAP_VIRGL_3D | gpu::CAP_CMD_GFX;
    }
    let mon = core::str::from_utf8(drv.monitor_name()).unwrap_or("?");
    println!(
        "virtio-gpu: ready on {} {}x{} ({} scanout(s), monitor='{}', virgl={}, edid={}, IOMMU={})",
        info.name(),
        drv.width,
        drv.height,
        scanouts,
        mon,
        virgl,
        drv.edid.is_some(),
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
            width: drv.width as u16,
            height: drv.height as u16,
            caps,
            name: "VirtIO-GPU",
        },
    );
    gpu_drv::serve_loop(ctl, &port, &mut drv)
}
