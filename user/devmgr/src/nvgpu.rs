//! NVIDIA Open-GSP isolated user-space GPU driver (`nvgpu.ddrv`, PCI `10DE:*` class `03.*`).
//!
//! Targets NVIDIA's open GPU kernel architecture (Turing TU10x, Ampere GA10x, Ada Lovelace AD10x,
//! Blackwell GB20x): maps BAR 0 (MMIO, UC) and a bounded 32 MiB WC window of BAR 1 (VRAM),
//! identifies architecture & VRAM geometry via `NV_PMC_BOOT_0`/`BOOT_42` and
//! `NV_PFB_PRI_MMU_LOCAL_MEMORY_RANGE`, probes GSP Falcon status, pins Open-GSP RPC DMA queues
//! inside the device's IOMMU domain, and provides BAR 1 WC framebuffer scanout.

use core::sync::atomic::{Ordering, fence};

use dosgpu::nvidia::{self, NvidiaGpuInfo};
use dosgpu::{DamageRect, MAX_DIM, PixelFormat, blit_rect_wc};
use libd::gpu::{self, MODE_FLAG_CURRENT, MODE_FLAG_PREFERRED, ModeEntry};
use libd::proto;
use libd::sys::{self, Handle};
use libd::{Dma, Mapping, Port, Startup, println};

use crate::gpu_drv::{self, FbPin, GpuAnnounce, GpuDriver, KEY_IRQ0};

const VRAM_MAP_MAX: u64 = 32 << 20;
const GSP_QUEUE_DMA_BYTES: u64 = 16384;
const MAX_FBS: usize = 2;

struct NvFb {
    fb_id: u32,
    map: Mapping,
    pin: FbPin,
}

struct NvidiaGpu {
    dev: Handle,
    gpu: NvidiaGpuInfo,
    _mmio: Mapping,
    vram: Option<Mapping>,
    _gsp_dma: Dma,
    scratch: Mapping,
    irq: Handle,
    gsp_running: bool,
    width: u32,
    height: u32,
    pitch: u32,
    fbs: [Option<NvFb>; MAX_FBS],
    next_fb_id: u32,
    next_ctx_id: u32,
    frames: u64,
    irqs: u64,
}

impl GpuDriver for NvidiaGpu {
    fn modes(&self, out: &mut [ModeEntry]) -> usize {
        let list = [
            (self.width, self.height, 60_000, MODE_FLAG_PREFERRED | MODE_FLAG_CURRENT),
            (3840, 2160, 60_000, 0),
            (2560, 1440, 60_000, 0),
            (1920, 1080, 60_000, 0),
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
        self.fbs[slot] = Some(NvFb { fb_id, map, pin });
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
        let Some(vram) = self.vram.as_ref() else {
            return Err(sys::ERR_NOT_SUPPORTED);
        };
        let Some(fb) = self.fbs.iter().flatten().find(|f| f.fb_id == fb_id) else {
            return Err(sys::ERR_INVALID_ARGS);
        };
        let w = fb.pin.width.min(self.width);
        let h = fb.pin.height.min(self.height);
        let frame_bytes = u64::from(self.pitch) * u64::from(h);
        if frame_bytes > vram.len {
            return Err(sys::ERR_OUT_OF_RANGE);
        }
        let dmg = if rect.w == 0 || rect.h == 0 {
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
            |off, px| vram.w32(off, px),
        );
        fence(Ordering::Release);
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
        if ctx_id == 0 || engine != gpu::ENGINE_NVIDIA_GSP {
            return Err(sys::ERR_INVALID_ARGS);
        }
        nvidia::validate_gsp_rpc(cmd).map_err(|_| sys::ERR_INVALID_ARGS)?;
        if !self.gsp_running {
            // RPC framing/checksum validated; full GSP-RM execution requires signed `gsp_*.bin` firmware.
            return Err(sys::ERR_NOT_SUPPORTED);
        }
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
    if !unsafe { libd::init(s, "nvgpu") } {
        return -1;
    }
    let dev = libd::startup_handle(sys::TAG_DEVICE);
    let ctl = libd::startup_handle(proto::TAG_CONTROL);
    let Ok(info) = sys::device_info(dev) else {
        println!("nvgpu: device_info failed");
        return 1;
    };
    let _ = sys::config_write(dev, 0x04, 2, 0x6);

    if info.bar_kind[0] != 1 || info.bar_size[0] < 0x20_0000 {
        println!("nvgpu: {}: missing MMIO BAR 0", info.name());
        return 1;
    }
    let Ok(mmio_vmo) = sys::device_map_bar(dev, 0) else {
        println!("nvgpu: {}: cannot map BAR 0", info.name());
        return 1;
    };
    let Ok(mmio) = Mapping::of_range(mmio_vmo, 0, info.bar_size[0].min(2 << 20)) else {
        println!("nvgpu: {}: cannot map MMIO window", info.name());
        return 1;
    };
    let boot0 = mmio.r32(nvidia::NV_PMC_BOOT_0);
    let boot42 = mmio.r32(nvidia::NV_PMC_BOOT_42);
    let gpu_info = nvidia::decode_boot_regs(boot0, boot42);
    let local_mem = mmio.r32(nvidia::NV_PFB_PRI_MMU_LOCAL_MEMORY_RANGE);
    let vram_mib = match nvidia::decode_local_memory_mib(local_mem) {
        0 => (info.bar_size[1] >> 20) as u32,
        m => m,
    };
    let gsp_cpuctl = mmio.r32(nvidia::NV_PGSP_FALCON_CPUCTL);
    let gsp_running = gpu_info.gsp_capable && gsp_cpuctl != 0 && gsp_cpuctl != 0xFFFF_FFFF && (gsp_cpuctl & (1 << 4)) == 0;

    let vram = if info.bar_kind[1] == 1 && info.bar_size[1] >= (1 << 20) {
        sys::device_map_bar(dev, 1)
            .ok()
            .and_then(|v| Mapping::of_range(v, 0, info.bar_size[1].min(VRAM_MAP_MAX)).ok())
    } else {
        None
    };
    let Ok(gsp_dma) = Dma::new(dev, GSP_QUEUE_DMA_BYTES, sys::DMA_DEVICE_READ | sys::DMA_DEVICE_WRITE) else {
        println!("nvgpu: {}: cannot pin GSP RPC DMA queue", info.name());
        return 1;
    };
    let Ok(scratch) = gpu_drv::alloc_pin_scratch() else {
        println!("nvgpu: scratch mapping failed");
        return 1;
    };
    let irq = if info.irqs > 0 { sys::device_interrupt(dev, 0).unwrap_or(0) } else { 0 };

    let mut drv = NvidiaGpu {
        dev,
        gpu: gpu_info,
        _mmio: mmio,
        vram,
        _gsp_dma: gsp_dma,
        scratch,
        irq,
        gsp_running,
        width: 1920,
        height: 1080,
        pitch: 1920 * 4,
        fbs: [const { None }; MAX_FBS],
        next_fb_id: 1,
        next_ctx_id: 1,
        frames: 0,
        irqs: 0,
    };

    let iommu = (info.flags & sys::DEV_FLAG_IOMMU) != 0;
    let mut caps = gpu::CAP_SCANOUT_2D;
    if iommu {
        caps |= gpu::CAP_IOMMU;
    }
    if drv.vram.is_some() {
        caps |= gpu::CAP_WC;
    }
    if gpu_info.gsp_capable {
        caps |= gpu::CAP_GSP_RPC;
    }
    println!(
        "nvgpu: ready on {} ({:04x}:{:04x} {}, chip {:#x}, VRAM {} MiB, GSP active={}, IOMMU={})",
        info.name(),
        info.vendor,
        info.device,
        gpu_info.name,
        gpu_info.chipset,
        vram_mib,
        gsp_running,
        iommu
    );

    let Ok(port) = Port::new(32) else { return 1 };
    if drv.irq != 0 {
        port.arm(drv.irq, sys::SIGNALED, KEY_IRQ0);
    }
    gpu_drv::announce(
        ctl,
        &GpuAnnounce {
            kind: gpu::KIND_NVIDIA_GSP,
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
