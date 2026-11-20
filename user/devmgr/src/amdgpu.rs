//! AMD RDNA / AMDGPU isolated user-space driver (`amdgpu.ddrv`, PCI `1002:*` class `03.*`).
//!
//! Targets AMD RDNA 4 (Radeon RX 9070 / RX 9070 XT, Navi 48, GFX12 / DCN 4.0.1 / SDMA 7.0),
//! RDNA 3 (Navi 31/32/33), and RDNA 2 (Navi 21/22/23/24 & Ryzen 7000/9000 Granite Ridge iGPU).
//!
//! Runs unprivileged inside a per-device IOMMU domain (AMD-Vi / Intel VT-d):
//! - Maps BAR 5 (RMMIO registers, UC), optional BAR 2 (Doorbell, UC), and a bounded 32 MiB
//!   Write-Combining window of BAR 0 VRAM (works with both 256 MiB and 16 GiB ReBAR).
//! - Reads VRAM geometry (`RCC_CONFIG_MEMSIZE`) and parses the verified AMD IP Discovery table
//!   at `VRAM_SIZE - 64 KiB` via indirect MMIO VRAM access to discover live GC/DCN/SDMA/NBIO bases.
//! - Preserves active UEFI DP/HDMI link training, discovers the live DCN HUBP0 scanout address,
//!   supports WC VRAM presentation and atomic DCN primary surface double-buffered page flips,
//!   and validates PM4 Type-3 / SDMA command streams on IOMMU-pinned DMA rings.

use core::sync::atomic::{Ordering, fence};

use dosgpu::amd::{self, AmdGpuInfo, DiscoverySummary, dcn};
use dosgpu::{DamageRect, MAX_DIM, PixelFormat, blit_rect_wc};
use libd::gpu::{self, MODE_FLAG_CURRENT, MODE_FLAG_PREFERRED, ModeEntry};
use libd::proto;
use libd::sys::{self, Handle};
use libd::{Dma, Mapping, Port, Startup, println};

use crate::gpu_drv::{self, FbPin, GpuAnnounce, GpuDriver, KEY_IRQ0};

/// Bounded CPU-mapped WC window of BAR 0 VRAM (32 MiB — enough for double-buffered 4K scanout
/// without consuming excessive page-table quota on 16 GiB Resizable BAR GPUs like RX 9070).
const VRAM_MAP_MAX: u64 = 32 << 20;
const RING_DMA_BYTES: u64 = 16384; // 4 pages: PM4 ring (4K) + SDMA ring (4K) + writeback/fence (4K) + scratch (4K)
const MAX_FBS: usize = 2;

struct AmdFb {
    fb_id: u32,
    map: Mapping,
    pin: FbPin,
}

struct AmdGpu {
    dev: Handle,
    gpu: AmdGpuInfo,
    mmio: Mapping,
    _doorbell: Option<Mapping>,
    vram: Option<Mapping>,
    _ring_dma: Dma,
    scratch: Mapping,
    irq: Handle,
    vram_mib: u32,
    discovery: Option<DiscoverySummary>,
    dcn_base_bytes: u64,
    active_surf_off: u64,
    dcn_flip_ok: bool,
    cp_ready: bool,
    width: u32,
    height: u32,
    pitch: u32,
    fbs: [Option<AmdFb>; MAX_FBS],
    next_fb_id: u32,
    next_ctx_id: u32,
    front_buf: u8,
    frames: u64,
    fences: u64,
    irqs: u64,
}

impl AmdGpu {
    fn rreg32(&self, byte_off: u64) -> Option<u32> {
        if byte_off + 4 <= self.mmio.len && byte_off.is_multiple_of(4) {
            Some(self.mmio.r32(byte_off))
        } else {
            None
        }
    }

    fn wreg32(&self, byte_off: u64, val: u32) {
        if byte_off + 4 <= self.mmio.len && byte_off.is_multiple_of(4) {
            self.mmio.w32(byte_off, val);
        }
    }

    /// Read a 32-bit word from GPU VRAM via indirect MMIO (`MM_INDEX` / `MM_INDEX_HI` / `MM_DATA`).
    /// Works even when BAR 0 is a non-ReBAR 256 MiB window and IP Discovery sits near top of 16 GiB VRAM.
    fn read_vram_indirect(&self, vram_off: u64) -> u32 {
        let lo = (vram_off as u32 & 0x7FFF_FFFC) | amd::MM_INDEX_VRAM_BIT;
        let hi = (vram_off >> 31) as u32;
        self.wreg32(amd::MM_INDEX, lo);
        self.wreg32(amd::MM_INDEX_HI, hi);
        self.rreg32(amd::MM_DATA).unwrap_or(0xFFFF_FFFF)
    }

    fn probe_ip_discovery(&self, vram_bytes: u64) -> Option<DiscoverySummary> {
        if vram_bytes < amd::IP_DISCOVERY_OFFSET_FROM_TOP * 2 {
            return None;
        }
        let base = vram_bytes - amd::IP_DISCOVERY_OFFSET_FROM_TOP;
        let sig = self.read_vram_indirect(base);
        if sig != amd::IP_DISCOVERY_BINARY_SIG {
            return None;
        }
        let mut raw = [0u8; 4096];
        for i in (0..raw.len()).step_by(4) {
            let w = self.read_vram_indirect(base + i as u64);
            raw[i..i + 4].copy_from_slice(&w.to_le_bytes());
        }
        amd::parse_ip_discovery(&raw).ok()
    }
}

impl GpuDriver for AmdGpu {
    fn modes(&self, out: &mut [ModeEntry]) -> usize {
        let list = [
            (self.width, self.height, 60_000, MODE_FLAG_PREFERRED | MODE_FLAG_CURRENT),
            (3840, 2160, 60_000, 0),
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
        self.fbs[slot] = Some(AmdFb { fb_id, map, pin });
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
        let frame_bytes = (u64::from(self.pitch) * u64::from(h)).div_ceil(256) * 256;
        // Double-buffer in WC VRAM with atomic DCN primary surface flip when HUBP is verified live
        // and both front+back buffers fit inside the mapped WC VRAM window.
        let use_flip = self.dcn_flip_ok && self.active_surf_off + frame_bytes * 2 <= vram.len;
        let target_off = if use_flip {
            let next_buf = self.front_buf ^ 1;
            self.active_surf_off + u64::from(next_buf) * frame_bytes
        } else {
            self.active_surf_off
        };
        if target_off.saturating_add(frame_bytes) > vram.len {
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
            |off, px| vram.w32(target_off + off, px),
        );
        fence(Ordering::Release);
        if use_flip {
            let (lo, hi) = dcn::encode_surface_addr(target_off);
            let base = self.dcn_base_bytes;
            self.wreg32(base + u64::from(dcn::HUBP0_DCSURF_PRIMARY_SURFACE_ADDRESS_HIGH) * 4, hi);
            self.wreg32(base + u64::from(dcn::HUBP0_DCSURF_PRIMARY_SURFACE_ADDRESS) * 4, lo);
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
        if ctx_id == 0 {
            return Err(sys::ERR_INVALID_ARGS);
        }
        match engine {
            gpu::ENGINE_AMD_PM4 => {
                amd::validate_pm4_cs(cmd).map_err(|_| sys::ERR_INVALID_ARGS)?;
            }
            gpu::ENGINE_AMD_SDMA => {
                amd::validate_sdma_cs(cmd).map_err(|_| sys::ERR_INVALID_ARGS)?;
            }
            _ => return Err(sys::ERR_INVALID_ARGS),
        }
        if !self.cp_ready {
            // Command stream passed strict validation, but full GFX/SDMA ring execution requires
            // AMD PSP/MES/ME/SDMA microcode firmware images (`sys:/firmware/amdgpu/`).
            return Err(sys::ERR_NOT_SUPPORTED);
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
        if key == KEY_IRQ0 && self.irq != 0 {
            self.irqs += sys::interrupt_ack(self.irq).unwrap_or(0);
        }
    }
}

pub fn main(s: *const Startup) -> i32 {
    // SAFETY: `s` is the startup block pointer passed by the kernel.
    if !unsafe { libd::init(s, "amdgpu") } {
        return -1;
    }
    let dev = libd::startup_handle(sys::TAG_DEVICE);
    let ctl = libd::startup_handle(proto::TAG_CONTROL);
    let Ok(info) = sys::device_info(dev) else {
        println!("amdgpu: device_info failed");
        return 1;
    };
    let gpu_info = amd::identify_pci(info.device);
    let _ = sys::config_write(dev, 0x04, 2, 0x6); // Memory decode + Bus mastering

    // BAR 5 is the standard AMD RMMIO register block (fallback to BAR 2 on legacy parts).
    let mmio_bar = if info.bar_kind[5] == 1 && info.bar_size[5] >= 0x4000 {
        5
    } else if info.bar_kind[2] == 1 && info.bar_size[2] >= 0x4000 {
        2
    } else {
        println!("amdgpu: {}: no MMIO BAR found", info.name());
        return 1;
    };
    let Ok(mmio_vmo) = sys::device_map_bar(dev, mmio_bar) else {
        println!("amdgpu: {}: cannot map MMIO BAR {}", info.name(), mmio_bar);
        return 1;
    };
    let mmio_len = info.bar_size[mmio_bar as usize].min(2 << 20);
    let Ok(mmio) = Mapping::of_range(mmio_vmo, 0, mmio_len) else {
        println!("amdgpu: {}: cannot map MMIO window", info.name());
        return 1;
    };
    // Optional BAR 2 doorbell aperture (distinct from MMIO BAR).
    let doorbell = if mmio_bar != 2 && info.bar_kind[2] == 1 && info.bar_size[2] >= 4096 {
        sys::device_map_bar(dev, 2)
            .ok()
            .and_then(|v| Mapping::of_range(v, 0, info.bar_size[2].min(2 << 20)).ok())
    } else {
        None
    };
    // BAR 0 VRAM aperture (mapped Write-Combining for a bounded 32 MiB scanout window).
    let vram = if info.bar_kind[0] == 1 && info.bar_size[0] >= (1 << 20) {
        sys::device_map_bar(dev, 0)
            .ok()
            .and_then(|v| Mapping::of_range(v, 0, info.bar_size[0].min(VRAM_MAP_MAX)).ok())
    } else {
        None
    };
    let Ok(ring_dma) = Dma::new(dev, RING_DMA_BYTES, sys::DMA_DEVICE_READ | sys::DMA_DEVICE_WRITE) else {
        println!("amdgpu: {}: cannot pin command ring DMA", info.name());
        return 1;
    };
    let Ok(scratch) = gpu_drv::alloc_pin_scratch() else {
        println!("amdgpu: scratch mapping failed");
        return 1;
    };
    let irq = if info.irqs > 0 { sys::device_interrupt(dev, 0).unwrap_or(0) } else { 0 };

    let mut drv = AmdGpu {
        dev,
        gpu: gpu_info,
        mmio,
        _doorbell: doorbell,
        vram,
        _ring_dma: ring_dma,
        scratch,
        irq,
        vram_mib: (info.bar_size[0] >> 20) as u32,
        discovery: None,
        dcn_base_bytes: 0,
        active_surf_off: 0,
        dcn_flip_ok: false,
        cp_ready: false,
        width: 1920,
        height: 1080,
        pitch: 1920 * 4,
        fbs: [const { None }; MAX_FBS],
        next_fb_id: 1,
        next_ctx_id: 1,
        front_buf: 0,
        frames: 0,
        fences: 0,
        irqs: 0,
    };

    // Query real VRAM size in MiB via RCC_CONFIG_MEMSIZE.
    let mem_reg = drv
        .rreg32(amd::REG_RCC_CONFIG_MEMSIZE)
        .filter(|&v| v > 0 && v != 0xFFFF_FFFF && v <= 65536)
        .or_else(|| {
            drv.rreg32(amd::REG_RCC_CONFIG_MEMSIZE_ALT)
                .filter(|&v| v > 0 && v != 0xFFFF_FFFF && v <= 65536)
        });
    if let Some(mib) = mem_reg {
        drv.vram_mib = mib;
    }

    // Parse AMD IP Discovery table from top of VRAM (`VRAM_SIZE - 64 KiB`).
    drv.discovery = drv.probe_ip_discovery(u64::from(drv.vram_mib) << 20);
    if let Some(disc) = drv.discovery
        && let Some(dcn_blk) = disc.find(amd::HWID_DCE, 0)
    {
        let base = u64::from(dcn_blk.base_dword) * 4;
        if base + u64::from(dcn::HUBP0_DCSURF_SURFACE_CONTROL) * 4 + 4 <= drv.mmio.len {
            drv.dcn_base_bytes = base;
            let lo = drv.rreg32(base + u64::from(dcn::HUBP0_DCSURF_PRIMARY_SURFACE_ADDRESS) * 4).unwrap_or(0);
            let hi = drv.rreg32(base + u64::from(dcn::HUBP0_DCSURF_PRIMARY_SURFACE_ADDRESS_HIGH) * 4).unwrap_or(0);
            let surf = dcn::decode_surface_addr(lo, hi);
            if surf < drv.vram.as_ref().map_or(0, |v| v.len) {
                drv.active_surf_off = surf;
                drv.dcn_flip_ok = true;
            }
        }
        println!(
            "amdgpu: IP Discovery: DCN {}.{}.{} base={:#x}, GC={}, SDMA={}",
            dcn_blk.major,
            dcn_blk.minor,
            dcn_blk.revision,
            dcn_blk.base_dword,
            disc.find(amd::HWID_GC, 0).map_or(gpu_info.gfx_major, |b| b.major),
            disc.find(amd::HWID_SDMA0, 0).map_or(gpu_info.sdma_major, |b| b.major)
        );
    }

    let iommu = (info.flags & sys::DEV_FLAG_IOMMU) != 0;
    let mut caps = gpu::CAP_SCANOUT_2D | gpu::CAP_CMD_GFX | gpu::CAP_CMD_DMA;
    if iommu {
        caps |= gpu::CAP_IOMMU;
    }
    if drv.vram.is_some() {
        caps |= gpu::CAP_WC;
    }
    if drv.dcn_flip_ok {
        caps |= gpu::CAP_PAGE_FLIP;
    }
    println!(
        "amdgpu: ready on {} ({:04x}:{:04x} {}, VRAM {} MiB, BAR0 {} MiB, DCN flip={}, IOMMU={})",
        info.name(),
        info.vendor,
        info.device,
        gpu_info.name,
        drv.vram_mib,
        info.bar_size[0] >> 20,
        drv.dcn_flip_ok,
        iommu
    );

    let Ok(port) = Port::new(32) else { return 1 };
    if drv.irq != 0 {
        port.arm(drv.irq, sys::SIGNALED, KEY_IRQ0);
    }
    gpu_drv::announce(
        ctl,
        &GpuAnnounce {
            kind: gpu::KIND_AMD_RDNA,
            vendor: info.vendor,
            device: info.device,
            vram_mib: drv.vram_mib,
            width: drv.width as u16,
            height: drv.height as u16,
            caps,
            name: gpu_info.name,
        },
    );
    gpu_drv::serve_loop(ctl, &port, &mut drv)
}
