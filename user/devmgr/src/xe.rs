//! Intel Xe / i915 isolated user-space GPU driver (`xe.ddrv`, PCI `8086:*` class `03.*`).
//!
//! Targets Intel Gen9/Gen11/Gen12 (Xe-LP), Arc Alchemist (Xe-HPG), and Arc Battlemage / Lunar Lake (Xe2).
//! Maps BAR 0 (`GTTMMADR`, UC) and a bounded 32 MiB WC window of BAR 2 (`GMADR` / `LMEM`),
//! probes `GMD_ID` and active Display Pipes A-D (`TRANS_CONF`, `PIPE_SRCSZ`, `PLANE_SURF_1`),
//! supports WC aperture scanout + atomic `PLANE_SURF` flips, and validates MI/XY Blitter command
//! streams on IOMMU-pinned DMA rings.

use core::sync::atomic::{Ordering, fence};

use dosgpu::intel::{self, IntelGpuInfo};
use dosgpu::{DamageRect, MAX_DIM, PixelFormat, blit_rect_wc};
use libd::gpu::{self, MODE_FLAG_CURRENT, MODE_FLAG_PREFERRED, ModeEntry};
use libd::proto;
use libd::sys::{self, Handle};
use libd::{Dma, Mapping, Port, Startup, println};

use crate::gpu_drv::{self, FbPin, GpuAnnounce, GpuDriver, KEY_IRQ0};

const APERTURE_MAP_MAX: u64 = 32 << 20;
const RING_DMA_BYTES: u64 = 16384;
const MAX_FBS: usize = 2;

struct XeFb {
    fb_id: u32,
    map: Mapping,
    pin: FbPin,
}

struct IntelXe {
    dev: Handle,
    gpu: IntelGpuInfo,
    mmio: Mapping,
    aperture: Option<Mapping>,
    _ring_dma: Dma,
    scratch: Mapping,
    irq: Handle,
    active_pipe: Option<u32>,
    surf_off: u64,
    width: u32,
    height: u32,
    pitch: u32,
    fbs: [Option<XeFb>; MAX_FBS],
    next_fb_id: u32,
    next_ctx_id: u32,
    front_buf: u8,
    frames: u64,
    irqs: u64,
}

impl IntelXe {
    fn r32(&self, off: u64) -> Option<u32> {
        if off + 4 <= self.mmio.len && off.is_multiple_of(4) {
            Some(self.mmio.r32(off))
        } else {
            None
        }
    }

    fn w32(&self, off: u64, val: u32) {
        if off + 4 <= self.mmio.len && off.is_multiple_of(4) {
            self.mmio.w32(off, val);
        }
    }
}

impl GpuDriver for IntelXe {
    fn modes(&self, out: &mut [ModeEntry]) -> usize {
        let list = [
            (self.width, self.height, 60_000, MODE_FLAG_PREFERRED | MODE_FLAG_CURRENT),
            (2560, 1440, 60_000, 0),
            (1920, 1080, 60_000, 0),
            (1280, 800, 60_000, 0),
        ];
        let mut count = 0usize;
        for &(w, h, hz, flags) in &list {
            if count >= out.len() {
                break;
            }
            if out[..count].iter().any(|e| e.width == w && e.height == h) {
                continue;
            }
            out[count] = ModeEntry { width: w, height: h, refresh_mhz: hz, flags };
            count += 1;
        }
        count
    }

    fn monitor_name(&self) -> &[u8] {
        self.gpu.name.as_bytes()
    }

    fn attach_fb(&mut self, vmo: Handle, width: u32, height: u32, pitch: u32, format: u32) -> Result<u32, i64> {
        let map_len = u64::from(pitch).saturating_mul(u64::from(height));
        let map = Mapping::of_ro(vmo, map_len)?;
        let pin = FbPin::pin(self.dev, &mut self.scratch, vmo, width, height, pitch, format)?;
        let slot = self.fbs.iter().position(|s| s.is_none()).unwrap_or(0);
        let fb_id = self.next_fb_id;
        self.next_fb_id += 1;
        self.fbs[slot] = Some(XeFb { fb_id, map, pin });
        Ok(fb_id)
    }

    fn set_mode(&mut self, width: u32, height: u32) -> Result<(), i64> {
        if !(320..=MAX_DIM).contains(&width) || !(200..=MAX_DIM).contains(&height) {
            return Err(sys::ERR_INVALID_ARGS);
        }
        self.width = width;
        self.height = height;
        self.pitch = width.saturating_mul(4);
        Ok(())
    }

    fn present(&mut self, fb_id: u32, rect: DamageRect) -> Result<u64, i64> {
        let Some(ap) = self.aperture.as_ref() else {
            return Err(sys::ERR_NOT_SUPPORTED);
        };
        let Some(fb) = self.fbs.iter().flatten().find(|f| f.fb_id == fb_id) else {
            return Err(sys::ERR_INVALID_ARGS);
        };
        let w = fb.pin.width.min(self.width);
        let h = fb.pin.height.min(self.height);
        let frame_bytes = (u64::from(self.pitch) * u64::from(h)).div_ceil(4096) * 4096;
        let use_flip = self.active_pipe.is_some() && self.surf_off + frame_bytes * 2 <= ap.len;
        let target_off = if use_flip {
            self.surf_off + u64::from(self.front_buf ^ 1) * frame_bytes
        } else {
            self.surf_off
        };
        if target_off.saturating_add(frame_bytes) > ap.len {
            return Err(sys::ERR_OUT_OF_RANGE);
        }
        let dmg = if rect.w == 0 || rect.h == 0 || use_flip {
            DamageRect::full(w, h)
        } else {
            rect.clip(w, h).unwrap_or_else(|| DamageRect::full(w, h))
        };
        let fmt = PixelFormat::from_u32(fb.pin.format).unwrap_or(PixelFormat::Xrgb8888);
        blit_rect_wc(
            fb.map.bytes(),
            fb.pin.pitch,
            fmt,
            self.pitch,
            [16, 8, 0],
            w,
            h,
            dmg,
            |off, px| ap.w32(target_off + off, px),
        );
        fence(Ordering::Release);
        if let Some(pipe) = self.active_pipe
            && use_flip
        {
            self.w32(intel::reg_plane_surf_1(pipe), target_off as u32 & !0xFFF);
            self.front_buf ^= 1;
        }
        self.frames += 1;
        Ok(self.frames)
    }

    fn ctx_create(&mut self) -> Result<u32, i64> {
        let id = self.next_ctx_id;
        self.next_ctx_id += 1;
        Ok(id)
    }

    fn ctx_destroy(&mut self, ctx_id: u32) -> Result<(), i64> {
        if ctx_id == 0 { Err(sys::ERR_INVALID_ARGS) } else { Ok(()) }
    }

    fn submit_cmd(&mut self, ctx_id: u32, engine: u32, cmd: &[u8]) -> Result<u64, i64> {
        if ctx_id == 0 || engine != gpu::ENGINE_INTEL_BLIT {
            return Err(sys::ERR_INVALID_ARGS);
        }
        intel::validate_mi_cs(cmd).map_err(|_| sys::ERR_INVALID_ARGS)?;
        // Strict MI/XY Blitter validation done; GuC/BCS0 ring submission requires GuC firmware load.
        Err(sys::ERR_NOT_SUPPORTED)
    }

    fn irqs(&self) -> u64 {
        self.irqs
    }

    fn frames(&self) -> u64 {
        self.frames
    }

    fn on_irq(&mut self, key: u64) {
        if key == KEY_IRQ0 && self.irq != 0 {
            self.irqs += sys::interrupt_ack(self.irq).unwrap_or(0);
        }
    }
}

pub fn main(s: *const Startup) -> i32 {
    // SAFETY: `s` is the startup block pointer passed by the kernel.
    if !unsafe { libd::init(s, "xe") } {
        return -1;
    }
    let dev = libd::startup_handle(sys::TAG_DEVICE);
    let ctl = libd::startup_handle(proto::TAG_CONTROL);
    let Ok(info) = sys::device_info(dev) else {
        println!("xe: device_info failed");
        return 1;
    };
    let gpu_info = intel::identify_pci(info.device);
    let _ = sys::config_write(dev, 0x04, 2, 0x6);

    if info.bar_kind[0] != 1 || info.bar_size[0] < 0x10_0000 {
        println!("xe: {}: missing GTTMMADR BAR 0", info.name());
        return 1;
    }
    let Ok(mmio_vmo) = sys::device_map_bar(dev, 0) else {
        println!("xe: {}: cannot map BAR 0", info.name());
        return 1;
    };
    let Ok(mmio) = Mapping::of_range(mmio_vmo, 0, info.bar_size[0].min(2 << 20)) else {
        println!("xe: {}: cannot map MMIO window", info.name());
        return 1;
    };
    let aperture = if info.bar_kind[2] == 1 && info.bar_size[2] >= (1 << 20) {
        sys::device_map_bar(dev, 2)
            .ok()
            .and_then(|v| Mapping::of_range(v, 0, info.bar_size[2].min(APERTURE_MAP_MAX)).ok())
    } else {
        None
    };
    let Ok(ring_dma) = Dma::new(dev, RING_DMA_BYTES, sys::DMA_DEVICE_READ | sys::DMA_DEVICE_WRITE) else {
        println!("xe: {}: cannot pin BCS0 ring DMA", info.name());
        return 1;
    };
    let Ok(scratch) = gpu_drv::alloc_pin_scratch() else {
        println!("xe: scratch mapping failed");
        return 1;
    };
    let irq = if info.irqs > 0 { sys::device_interrupt(dev, 0).unwrap_or(0) } else { 0 };

    let mut drv = IntelXe {
        dev,
        gpu: gpu_info,
        mmio,
        aperture,
        _ring_dma: ring_dma,
        scratch,
        irq,
        active_pipe: None,
        surf_off: 0,
        width: 1920,
        height: 1080,
        pitch: 1920 * 4,
        fbs: [const { None }; MAX_FBS],
        next_fb_id: 1,
        next_ctx_id: 1,
        front_buf: 0,
        frames: 0,
        irqs: 0,
    };

    let gmd = intel::decode_gmd_id(drv.r32(intel::REG_GMD_ID).unwrap_or(0));
    for pipe in 0..4u32 {
        let conf = drv.r32(intel::reg_trans_conf(pipe)).unwrap_or(0);
        let pctl = drv.r32(intel::reg_plane_ctl_1(pipe)).unwrap_or(0);
        if (conf & intel::TRANS_CONF_ENABLE) != 0 && (pctl & intel::PLANE_CTL_ENABLE) != 0 {
            let (w, h) = intel::decode_pipe_srcsz(drv.r32(intel::reg_pipe_srcsz(pipe)).unwrap_or(0));
            let surf = u64::from(drv.r32(intel::reg_plane_surf_1(pipe)).unwrap_or(0) & !0xFFF);
            if (320..=MAX_DIM).contains(&w) && (200..=MAX_DIM).contains(&h) {
                drv.active_pipe = Some(pipe);
                drv.width = w;
                drv.height = h;
                drv.pitch = w * 4;
                if surf < drv.aperture.as_ref().map_or(0, |a| a.len) {
                    drv.surf_off = surf;
                }
                break;
            }
        }
    }

    let vram_mib = (info.bar_size[2] >> 20) as u32;
    let iommu = (info.flags & sys::DEV_FLAG_IOMMU) != 0;
    let mut caps = gpu::CAP_SCANOUT_2D | gpu::CAP_CMD_DMA;
    if iommu {
        caps |= gpu::CAP_IOMMU;
    }
    if drv.aperture.is_some() {
        caps |= gpu::CAP_WC;
    }
    if drv.active_pipe.is_some() {
        caps |= gpu::CAP_PAGE_FLIP;
    }
    println!(
        "xe: ready on {} ({:04x}:{:04x} {}, GMD {}.{}.{}, pipe={:?}, {}x{}, IOMMU={})",
        info.name(),
        info.vendor,
        info.device,
        gpu_info.name,
        gmd.arch,
        gmd.release,
        gmd.step,
        drv.active_pipe,
        drv.width,
        drv.height,
        iommu
    );

    let Ok(port) = Port::new(32) else { return 1 };
    if drv.irq != 0 {
        port.arm(drv.irq, sys::SIGNALED, KEY_IRQ0);
    }
    gpu_drv::announce(
        ctl,
        &GpuAnnounce {
            kind: gpu::KIND_INTEL_XE,
            vendor: info.vendor,
            device: info.device,
            vram_mib,
            width: drv.width as u16,
            height: drv.height as u16,
            caps,
            name: gpu_info.name,
        },
    );
    gpu_drv::serve_loop(ctl, &port, &mut drv)
}
