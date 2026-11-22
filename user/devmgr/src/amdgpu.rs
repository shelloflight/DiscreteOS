//! AMD RDNA / AMDGPU isolated user-space driver (`amdgpu.ddrv`, PCI `1002:*` class `03.*`).
//!
//! Targets AMD RDNA 4 (Radeon RX 9070 / RX 9070 XT, Navi 48, DCN 4.0.1 / MMHUB 4.1.0 / OSSSYS 7.0.0),
//! Ryzen 7000/9000 iGPU (Raphael / Granite Ridge, DCN 3.1.5 / MMHUB 3.0.1 / OSSSYS 6.0.0),
//! RDNA 3 (Navi 31/32/33, DCN 3.2 / MMHUB 3.0.0 / OSSSYS 6.0.0), and
//! RDNA 2 (Navi 21/22/23/24, DCN 3.0 / MMHUB 2.0.0 / OSSSYS 5.0.0).
//!
//! Runs unprivileged inside a per-device IOMMU domain (AMD-Vi / Intel VT-d):
//! - Read-only startup probe (zero display writes): reads IP Discovery, resolves version-keyed
//!   DCN/MMHUB/OSSSYS/NBIF register segments, finds all active pipes, decodes active OTG timing
//!   and HUBP pitch/format/MC address, measures live refresh rate from `OTG_STATUS_FRAME_COUNT`,
//!   and reads DPCD + multi-block EDID over DP AUX.
//! - After firmware GOP identity confirmation (`DRV_SET_GOP_INFO`), allocates 3 (or 2) scanout
//!   buffers + 256 KiB hardware cursor in visible VRAM adjacent to the GOP FB, maps only that
//!   exact WC window, recovers if a crashed prior driver left our buffer on screen, and runs a
//!   3-frame self-check showing an identical copy of the live screen before enabling native flips.
//! - Tear-free vsync flipping with buffer-age damage copying, immediate HUBP + DPP hardware cursor,
//!   OSSSYS IH ring vblank/flip interrupts (with predicted-vblank timer fallback), clean GOP hand-back,
//!   guarded mode-setting (OTG + DCCG DTO + MSA + DP link training + DSC 1.2), VRR, HDR10, and
//!   validated PM4/SDMA command streams.

use core::sync::atomic::{Ordering, fence};

use dosgpu::amd::dp_aux::{self as aux, DpAuxProbe, dpcd_rate_label};
use dosgpu::amd::dcn::{
    self, ActivePipe, DcnAccess, FbWindow, GopInfo, RegIo, ScanoutLayout, allocate_scanout_buffers,
    frame_count_diff, measure_refresh_mhz, probe_active_pipes, read_frame_count,
};
use dosgpu::amd::flip::{
    self, CursorSize, FlipEngine, FlipPoll, HwCursor, IhController, IhEvent, ModeBandwidthPlan,
    SelfCheckState, plan_mode_bandwidth, program_mode_regs,
};
use dosgpu::amd::{self, AmdGpuInfo, DiscoverySummary};
use dosgpu::edid::EdidInfo;
use dosgpu::{
    DamageRect, MAX_AGE_RECTS, MAX_DIM, PixelFormat, blit_rect_wc, blit_rect_wc_10bpc,
};
use libd::gpu::{
    self, DisplayProbeInfo, FlipTestResult, GopInfoWire, MODE_FLAG_CURRENT, MODE_FLAG_PREFERRED,
    ModeEntry,
};
use libd::proto;
use libd::sys::{self, Handle};
use libd::{Dma, Mapping, Port, Startup, println};

use crate::gpu_drv::{self, FbPin, GpuAnnounce, GpuDriver, KEY_IRQ0};

/// DMA buffer layout (7 x 4 KiB = 28 KiB, pinned in the device's IOMMU domain):
/// - Page 0 (0x0000): PM4 ring
/// - Page 1 (0x1000): SDMA ring
/// - Page 2 (0x2000): Fence writeback
/// - Page 3 (0x3000): Scratch
/// - Page 4 (0x4000): OSSSYS IH ring (4 KiB = 128 x 32-byte IVs)
/// - Page 5 (0x5000): IH WPTR writeback
/// - Page 6 (0x6000): NBIF dummy read page
const RING_DMA_BYTES: u64 = 7 * 4096;
const IH_RING_OFF: usize = 4 * 4096;
const IH_RING_BYTES: usize = 4096;
const IH_WPTR_OFF: u64 = 5 * 4096;
const IH_DUMMY_OFF: u64 = 6 * 4096;

const FALLBACK_VRAM_MAP_MAX: u64 = 32 << 20;
const MAX_FBS: usize = 4;

/// Borrowed MMIO view implementing `RegIo` so `AmdGpu` can mutate state while performing MMIO.
struct MmioRef<'a>(&'a Mapping);

impl RegIo for MmioRef<'_> {
    #[inline]
    fn r32(&self, byte_off: u64) -> Option<u32> {
        if byte_off + 4 <= self.0.len && byte_off.is_multiple_of(4) {
            Some(self.0.r32(byte_off))
        } else {
            None
        }
    }

    #[inline]
    fn w32(&mut self, byte_off: u64, val: u32) {
        if byte_off + 4 <= self.0.len && byte_off.is_multiple_of(4) {
            self.0.w32(byte_off, val);
        }
    }
}

fn delay_us(us: u32) {
    if us > 0 {
        libd::handle::sleep(u64::from(us) * 1000);
    }
}

struct AmdFb {
    fb_id: u32,
    map: Mapping,
    pin: FbPin,
}

impl Drop for AmdFb {
    fn drop(&mut self) {
        if self.map.len != 0 {
            let _ = sys::vmar_unmap(libd::root_vmar(), self.map.addr, self.map.len);
        }
    }
}

struct AmdGpu {
    dev: Handle,
    gpu: AmdGpuInfo,
    mmio: Mapping,
    _doorbell: Option<Mapping>,
    bar0_vmo: Handle,
    bar0_phys: u64,
    bar0_size: u64,
    vram_map: Option<Mapping>,
    vram_map_off: u64,
    ring_dma: Dma,
    scratch: Mapping,
    irq: Handle,
    iommu: bool,
    vram_mib: u32,
    discovery: Option<DiscoverySummary>,
    dcn: Option<DcnAccess>,
    fb_win: Option<FbWindow>,
    pipes: [ActivePipe; 6],
    pipe_count: usize,
    primary_slot: usize,
    measured_mhz: u32,
    aux_probe: Option<DpAuxProbe>,
    gop: Option<GopInfo>,
    layout: Option<ScanoutLayout>,
    flip: Option<FlipEngine>,
    cursor: HwCursor,
    ih: IhController,
    /// True only once a real FlipDone/Vblank IV has been observed in the IH ring; until then
    /// flips wake on predicted vblank so an unrouted IRQ never cuts refresh rate in half.
    ih_verified: bool,
    ih_missed_streak: u8,
    vrr_enabled: bool,
    hdr_enabled: bool,
    dsc_enabled: bool,
    status_note: [u8; 48],
    status_note_len: usize,
    cp_ready: bool,
    width: u32,
    height: u32,
    pitch: u32,
    fbs: [Option<AmdFb>; MAX_FBS],
    next_fb_id: u32,
    next_ctx_id: u32,
    pending_async_notify: Option<(u64, u64, bool)>,
    flip_deadline_ns: Option<u64>,
    frames: u64,
    fences: u64,
    irqs: u64,
}

impl AmdGpu {
    fn set_note(&mut self, msg: &[u8]) {
        let n = msg.len().min(self.status_note.len());
        self.status_note.fill(0);
        self.status_note[..n].copy_from_slice(&msg[..n]);
        self.status_note_len = n;
    }

    fn rreg32(&self, byte_off: u64) -> Option<u32> {
        MmioRef(&self.mmio).r32(byte_off)
    }

    fn wreg32(&self, byte_off: u64, val: u32) {
        MmioRef(&self.mmio).w32(byte_off, val);
    }

    /// Read a 32-bit word from GPU VRAM via indirect MMIO (`MM_INDEX` / `MM_INDEX_HI` / `MM_DATA`).
    fn read_vram_indirect(&self, vram_off: u64) -> u32 {
        let lo = (vram_off as u32 & 0x7FFF_FFFC) | amd::MM_INDEX_VRAM_BIT;
        let hi = (vram_off >> 31) as u32;
        self.wreg32(amd::MM_INDEX, lo);
        self.wreg32(amd::MM_INDEX_HI, hi);
        self.rreg32(amd::MM_DATA).unwrap_or(0xFFFF_FFFF)
    }

    fn ih_ready(&self) -> bool {
        self.ih.active && self.ih_verified
    }

    fn probe_ip_discovery(&mut self, vram_bytes: u64) -> Option<DiscoverySummary> {
        if vram_bytes < amd::IP_DISCOVERY_OFFSET_FROM_TOP * 2 {
            return None;
        }
        let base = vram_bytes - amd::IP_DISCOVERY_OFFSET_FROM_TOP;
        let max_len = amd::IP_DISCOVERY_MAX_SIZE;
        let mut dir_sig = 0u32;

        // 1. Direct BAR 0 path first when top of VRAM sits inside the visible BAR 0 aperture
        // (Resizable BAR on modern GPUs — matches Linux `amdgpu_device_vram_access` fast path).
        if vram_bytes <= self.bar0_size && self.bar0_size >= (1 << 20) {
            if self.bar0_vmo == 0
                && let Ok(vmo) = sys::device_map_bar(self.dev, 0)
            {
                self.bar0_vmo = vmo;
            }
            if self.bar0_vmo != 0
                && let Ok(tmp) = Mapping::of_range(self.bar0_vmo, base, amd::IP_DISCOVERY_OFFSET_FROM_TOP)
            {
                dir_sig = tmp.r32(0);
                let parsed = if dir_sig == amd::IP_DISCOVERY_BINARY_SIG {
                    let bin_size = ((tmp.r32(8) >> 16) as usize).clamp(48, max_len);
                    let read_len = bin_size.next_multiple_of(4).min(tmp.len as usize);
                    if let Ok(mut buf) = Mapping::new(max_len as u64) {
                        buf.bytes_mut()[..read_len].copy_from_slice(&tmp.bytes()[..read_len]);
                        let res = amd::parse_ip_discovery(&buf.bytes()[..read_len]);
                        let _ = sys::vmar_unmap(libd::root_vmar(), buf.addr, buf.len);
                        sys::handle_close(buf.vmo);
                        if let Err(e) = res {
                            println!("amdgpu: ip-discovery direct parse err {:?} at {} MiB (size={})", e, vram_bytes >> 20, bin_size);
                        }
                        res.ok()
                    } else {
                        None
                    }
                } else {
                    None
                };
                let _ = sys::vmar_unmap(libd::root_vmar(), tmp.addr, tmp.len);
                if parsed.is_some() {
                    return parsed;
                }
            }
        }

        // 2. Fallback: indirect VRAM access via `MM_INDEX` / `MM_INDEX_HI` / `MM_DATA` (small BAR).
        let ind_sig = self.read_vram_indirect(base);
        if ind_sig == amd::IP_DISCOVERY_BINARY_SIG {
            let dw2 = self.read_vram_indirect(base + 8);
            let bin_size = ((dw2 >> 16) as usize).clamp(48, max_len);
            let read_len = bin_size.next_multiple_of(4).min(max_len);
            if let Ok(mut buf) = Mapping::new(max_len as u64) {
                let dst = buf.bytes_mut();
                for i in (0..read_len).step_by(4) {
                    let w = self.read_vram_indirect(base + i as u64);
                    dst[i..i + 4].copy_from_slice(&w.to_le_bytes());
                }
                let res = amd::parse_ip_discovery(&buf.bytes()[..read_len]);
                let _ = sys::vmar_unmap(libd::root_vmar(), buf.addr, buf.len);
                sys::handle_close(buf.vmo);
                if let Ok(disc) = res {
                    return Some(disc);
                }
                if let Err(e) = res {
                    println!("amdgpu: ip-discovery indirect parse err {:?} at {} MiB (size={})", e, vram_bytes >> 20, bin_size);
                }
            }
        }

        println!(
            "amdgpu: ip-discovery miss at {} MiB (bar0={} MiB, dir_sig={:#x}, ind_sig={:#x})",
            vram_bytes >> 20,
            self.bar0_size >> 20,
            dir_sig,
            ind_sig
        );
        None
    }

    fn active_pipe(&self) -> Option<ActivePipe> {
        if self.pipe_count > 0 && self.primary_slot < self.pipe_count {
            Some(self.pipes[self.primary_slot])
        } else {
            None
        }
    }

    fn edid(&self) -> Option<&EdidInfo> {
        self.aux_probe.as_ref().and_then(|p| p.edid.as_ref())
    }

    /// Measure the live refresh rate on `pipe` by sampling `OTG_STATUS_FRAME_COUNT` against `clock_ns`.
    /// Purely read-only; bounded to <= 65 ms so startup never blocks even if OTG is static.
    fn measure_pipe_refresh(&self, dcn: &DcnAccess, pipe: u8) -> Option<u32> {
        let io = MmioRef(&self.mmio);
        let f0 = read_frame_count(&io, dcn, pipe);
        // Wait for first frame edge so our measurement interval starts cleanly on a vblank boundary.
        let edge_deadline = sys::clock_ns() + 25_000_000;
        let mut f_start = f0;
        while sys::clock_ns() < edge_deadline {
            let cur = read_frame_count(&io, dcn, pipe);
            if cur != f0 {
                f_start = cur;
                break;
            }
            libd::handle::sleep(200_000);
        }
        if f_start == f0 {
            return None;
        }
        let t_start = sys::clock_ns();
        let sample_deadline = t_start + 55_000_000;
        let mut f_last = f_start;
        let mut t_last = t_start;
        while sys::clock_ns() < sample_deadline {
            let cur = read_frame_count(&io, dcn, pipe);
            if cur != f_last {
                f_last = cur;
                t_last = sys::clock_ns();
                let df = frame_count_diff(f_last, f_start);
                if df >= 3 && t_last.saturating_sub(t_start) >= 12_000_000 {
                    break;
                }
            }
            libd::handle::sleep(200_000);
        }
        let df = frame_count_diff(f_last, f_start);
        measure_refresh_mhz(df, t_last.saturating_sub(t_start))
    }

    /// Ensure BAR 0 VMO handle is acquired and map `[vram_off, vram_off + len)` Write-Combining.
    fn map_vram_window(&mut self, vram_off: u64, len: u64) -> bool {
        if self.bar0_size < (1 << 20) || len == 0 || vram_off.saturating_add(len) > self.bar0_size {
            return false;
        }
        if self.bar0_vmo == 0 {
            let Ok(vmo) = sys::device_map_bar(self.dev, 0) else {
                return false;
            };
            self.bar0_vmo = vmo;
        }
        if let Some(old) = self.vram_map.take() {
            let _ = sys::vmar_unmap(libd::root_vmar(), old.addr, old.len);
        }
        match Mapping::of_range(self.bar0_vmo, vram_off, len) {
            Ok(m) => {
                self.vram_map = Some(m);
                self.vram_map_off = vram_off;
                true
            }
            Err(_) => false,
        }
    }

    fn current_caps(&self) -> u32 {
        let mut caps = gpu::CAP_SCANOUT_2D | gpu::CAP_CMD_GFX | gpu::CAP_CMD_DMA;
        if self.iommu {
            caps |= gpu::CAP_IOMMU;
        }
        if self.bar0_size >= (1 << 20) {
            caps |= gpu::CAP_WC;
        }
        if self.edid().is_some() {
            caps |= gpu::CAP_EDID;
        }
        if let Some(p) = self.active_pipe()
            && p.gop_matched
            && self.flip.as_ref().is_some_and(FlipEngine::is_verified)
        {
            caps |= gpu::CAP_NATIVE_GOP_MATCH | gpu::CAP_PAGE_FLIP | gpu::CAP_ASYNC_FLIP | gpu::CAP_HW_CURSOR;
        }
        if let Some(ed) = self.edid() {
            if ed.vrr_min_hz >= 24 && ed.vrr_max_hz > ed.vrr_min_hz {
                caps |= gpu::CAP_VRR;
            }
            if ed.hdr_supported {
                caps |= gpu::CAP_HDR;
            }
        }
        if self.aux_probe.as_ref().is_some_and(|p| p.link.dsc_supported) {
            caps |= gpu::CAP_DSC;
        }
        caps
    }

    /// Verify GOP match, map exact WC scanout window, recover from any crashed prior driver,
    /// run the 3-frame identical-image self-check, and initialize OSSSYS IH ring interrupts.
    fn setup_native_scanout(&mut self, gop: GopInfo) {
        self.gop = Some(gop);
        let Some(dcn) = self.dcn else {
            self.set_note(b"no IP Discovery DCN block");
            return;
        };
        let Some(fb_win) = self.fb_win else {
            self.set_note(b"MMHUB FB window unavailable");
            return;
        };

        // Re-check all active pipes against the real GOP physical base, size, and pitch.
        let mut matched_slot: Option<usize> = None;
        for i in 0..self.pipe_count {
            self.pipes[i].gop_matched = self.pipes[i].check_gop_match(self.bar0_phys, &gop);
            if self.pipes[i].gop_matched && matched_slot.is_none() {
                matched_slot = Some(i);
            }
        }
        // Also check crash-recovery: if a prior crashed driver left our scanout buffer on screen,
        // the current scanout offset will lie in the expected post-GOP scanout window even though
        // `vram_off != gop_vram_off`.
        let gop_vram_off = if self.bar0_phys != 0 && gop.phys_base >= self.bar0_phys {
            let off = gop.phys_base - self.bar0_phys;
            (off < self.bar0_size).then_some(off)
        } else {
            None
        };

        let slot = match matched_slot {
            Some(s) => s,
            None => {
                // Attempt crash-recovery check if GOP lives inside our BAR 0 and pipe 0 matches dims/pitch.
                if let (Some(g_off), Some(p0)) = (gop_vram_off, self.pipes.first().filter(|_| self.pipe_count > 0))
                    && p0.width() == gop.width
                    && p0.height() == gop.height
                    && p0.pitch_bytes == gop.pitch
                    && let Some(orig_mc) = fb_win.vram_to_mc(g_off)
                {
                    let res = self.discovery.as_ref().map_or(&[][..], DiscoverySummary::reserved);
                    if let Some(lay) = allocate_scanout_buffers(
                        g_off,
                        gop.size,
                        gop.pitch,
                        gop.height,
                        self.bar0_size,
                        u64::from(self.vram_mib) << 20,
                        res,
                        true,
                    ) {
                        let mut recover = FlipEngine::new(p0.pipe, fb_win, lay, orig_mc, gop.width, gop.height, self.measured_mhz.max(60_000));
                        let mut io = MmioRef(&self.mmio);
                        if recover.recover_if_crashed_own_buffer(&mut io, &dcn) {
                            println!("amdgpu: crash recovery: restored firmware GOP scanout {:#x}", orig_mc);
                            libd::handle::sleep(20_000_000);
                            self.pipes[0].vram_off = Some(g_off);
                            self.pipes[0].mc_addr = orig_mc;
                            self.pipes[0].earliest_inuse_mc = orig_mc;
                            self.pipes[0].gop_matched = true;
                            0
                        } else {
                            println!(
                                "amdgpu: GOP mismatch: gop={:#x} {}x{} p={} vs bar0={:#x} ({} MiB) pipe0={}x{} p={} vram={:?}",
                                gop.phys_base, gop.width, gop.height, gop.pitch, self.bar0_phys, self.bar0_size >> 20,
                                p0.width(), p0.height(), p0.pitch_bytes, p0.vram_off
                            );
                            self.set_note(b"active DCN pipe does not match GOP FB");
                            return;
                        }
                    } else {
                        self.set_note(b"active DCN pipe does not match GOP FB");
                        return;
                    }
                } else {
                    if let Some(p0) = self.pipes.first().filter(|_| self.pipe_count > 0) {
                        println!(
                            "amdgpu: GOP mismatch: gop={:#x} {}x{} p={} vs bar0={:#x} ({} MiB) pipe0={}x{} p={} vram={:?}",
                            gop.phys_base, gop.width, gop.height, gop.pitch, self.bar0_phys, self.bar0_size >> 20,
                            p0.width(), p0.height(), p0.pitch_bytes, p0.vram_off
                        );
                    }
                    self.set_note(b"active DCN pipe does not match GOP FB");
                    return;
                }
            }
        };

        self.primary_slot = slot;
        let ap = self.pipes[slot];
        let Some(gop_off) = ap.vram_off else {
            self.set_note(b"scanout MC addr outside MMHUB window");
            return;
        };
        let Some(orig_mc) = fb_win.vram_to_mc(gop_off) else {
            self.set_note(b"cannot convert GOP VRAM off to MC");
            return;
        };
        let vram_bytes = u64::from(self.vram_mib) << 20;
        let reserved = self.discovery.as_ref().map_or(&[][..], DiscoverySummary::reserved);
        let Some(layout) = allocate_scanout_buffers(
            gop_off,
            gop.size,
            ap.pitch_bytes,
            ap.height(),
            self.bar0_size,
            vram_bytes,
            reserved,
            true,
        ) else {
            self.set_note(b"insufficient BAR0 VRAM for scanout buffers");
            return;
        };
        if !self.map_vram_window(layout.map_vram_off, layout.map_len) {
            self.set_note(b"failed to map WC VRAM scanout window");
            return;
        }

        // Self-check before use: write-only clear of scanout buffer 0 (never read back WC VRAM
        // over PCIe, which takes seconds on 1440p/4K), flip for a single vblank to confirm
        // `EARLIEST_INUSE` latches within 3 frames, then immediately hand back to untouched GOP.
        let clear_len = u64::from(ap.pitch_bytes) * u64::from(ap.height());
        if let (Some(vram), Some(dst_rel)) = (self.vram_map.as_ref(), layout.to_map_off(layout.buffers[0]))
            && dst_rel + clear_len <= vram.len
        {
            const DARK_SLATE_PAIR: u64 = 0x000E_1016_000E_1016;
            let mut off = 0u64;
            while off + 8 <= clear_len {
                vram.w64(dst_rel + off, DARK_SLATE_PAIR);
                off += 8;
            }
            fence(Ordering::Release);
        }

        let refresh_mhz = self.measured_mhz.max(60_000);
        let mut eng = FlipEngine::new(ap.pipe, fb_win, layout, orig_mc, ap.width(), ap.height(), refresh_mhz);
        {
            let mut io = MmioRef(&self.mmio);
            eng.self_check_start(&mut io, &dcn);
        }
        let check_deadline = sys::clock_ns() + 250_000_000;
        let mut state = eng.self_check;
        while matches!(state, SelfCheckState::InProgress { .. }) && sys::clock_ns() < check_deadline {
            libd::handle::sleep(500_000);
            let mut io = MmioRef(&self.mmio);
            state = eng.self_check_poll(&mut io, &dcn);
        }
        if matches!(state, SelfCheckState::InProgress { .. }) {
            let mut io = MmioRef(&self.mmio);
            eng.restore_original(&mut io, &dcn);
            eng.self_check = SelfCheckState::Failed(flip::SelfCheckReason::NotLatchedWithin3Frames);
            state = eng.self_check;
        }

        match state {
            SelfCheckState::Verified => {
                // Hand back to GOP immediately so the text console stays untouched until a GUI session presents!
                let mut io = MmioRef(&self.mmio);
                eng.restore_original(&mut io, &dcn);
                eng.age.mark_all_dirty();

                // Initialize OSSSYS IH ring DMA for zero-polling vblank/flip completion when MSI/MSI-X is bound.
                self.ih_verified = false;
                self.ih_missed_streak = 0;
                if self.irq != 0 {
                    let ring_iova = self.ring_dma.dev_addr(IH_RING_OFF as u64);
                    let wptr_iova = self.ring_dma.dev_addr(IH_WPTR_OFF);
                    let dummy_iova = self.ring_dma.dev_addr(IH_DUMMY_OFF);
                    self.ring_dma.map.w32(IH_WPTR_OFF, 0);
                    if self.ih.enable(&mut io, &dcn, ring_iova, wptr_iova, dummy_iova) {
                        self.ih.enable_pipe_irqs(&mut io, &dcn, ap.pipe, ap.timing.v_blank_start);
                    }
                }
                self.width = ap.width();
                self.height = ap.height();
                self.pitch = ap.pitch_bytes;
                self.cursor = HwCursor::new(ap.pipe);
                self.layout = Some(layout);
                self.flip = Some(eng);
                self.set_note(if self.ih.active {
                    b"native DCN verified (IH IRQ armed)"
                } else {
                    b"native DCN verified (timer pacing)"
                });
                println!(
                    "amdgpu: native DCN {} pipe {} verified: {}x{} @ {}.{:02} Hz ({} bufs @ {:#x}, WC {} MiB, ih_armed={})",
                    dcn.version.name(),
                    ap.pipe,
                    self.width,
                    self.height,
                    refresh_mhz / 1000,
                    (refresh_mhz % 1000) / 10,
                    layout.buf_count,
                    layout.buffers[0],
                    layout.map_len >> 20,
                    self.ih.active,
                );
            }
            SelfCheckState::Failed(reason) => {
                println!("amdgpu: self-check FAILED ({:?}): staying on firmware GOP", reason);
                self.set_note(b"self-check failed: latch timeout (reverted)");
                self.layout = Some(layout);
                self.flip = Some(eng);
            }
            _ => {}
        }
    }

    fn drain_ih_ring(&mut self) {
        let Some(dcn) = self.dcn else { return };
        if !self.ih.active {
            return;
        }
        let wptr_wb = self.ring_dma.map.r32(IH_WPTR_OFF);
        let ring_slice = &self.ring_dma.map.bytes()[IH_RING_OFF..IH_RING_OFF + IH_RING_BYTES];
        let mut io = MmioRef(&self.mmio);
        let mut saw_flip = false;
        let pipe_want = self.active_pipe().map_or(0, |p| p.pipe);
        self.ih.drain(&mut io, &dcn, ring_slice, Some(wptr_wb), |ev| match ev {
            IhEvent::FlipDone { pipe, .. } | IhEvent::Vblank { pipe, .. } if pipe == pipe_want => {
                saw_flip = true;
            }
            _ => {}
        });
        if saw_flip {
            if !self.ih_verified {
                self.ih_verified = true;
                self.set_note(b"native DCN verified (IH IRQ active)");
            }
            self.ih_missed_streak = 0;
            self.check_pending_flip();
        }
    }

    fn check_pending_flip(&mut self) {
        let Some(dcn) = self.dcn else { return };
        let ih_ready = self.ih_ready();
        let Some(flip) = self.flip.as_mut() else { return };
        if flip.pending_buf.is_none() {
            self.flip_deadline_ns = None;
            return;
        }
        let now = sys::clock_ns();
        let io = MmioRef(&self.mmio);
        match flip.poll_flip_complete(&io, &dcn, now) {
            FlipPoll::Completed { frames, late, .. } => {
                self.frames = frames;
                self.flip_deadline_ns = None;
                self.pending_async_notify = Some((frames, now, late));
                if self.ih_verified && late {
                    self.ih_missed_streak = self.ih_missed_streak.saturating_add(1);
                    if self.ih_missed_streak >= 2 {
                        self.ih_verified = false;
                        self.set_note(b"native DCN verified (timer fallback)");
                    }
                }
            }
            FlipPoll::Pending => {
                // Schedule next short poll (200 us) if timer-paced, or safety timeout (1 frame) if IH verified.
                let delta = if ih_ready {
                    flip.frame_interval_ns()
                } else {
                    200_000
                };
                self.flip_deadline_ns = Some(now + delta);
            }
            FlipPoll::Idle => {
                self.flip_deadline_ns = None;
            }
        }
    }

    /// Wait synchronously for an in-flight flip to latch (bounded to 3 frame intervals) so
    /// we NEVER overwrite a buffer that is on screen or pending.
    fn wait_in_flight_flip(&mut self) {
        let Some(dcn) = self.dcn else { return };
        let timeout_ns = self.flip.as_ref().map_or(50_000_000, |f| f.frame_interval_ns() * 3);
        let dl = sys::clock_ns() + timeout_ns;
        while self.flip.as_ref().is_some_and(|f| f.pending_buf.is_some()) && sys::clock_ns() < dl {
            self.check_pending_flip();
            if self.flip.as_ref().is_some_and(|f| f.pending_buf.is_some()) {
                let sleep_ns = match (self.flip.as_ref(), self.active_pipe()) {
                    (Some(f), Some(ap)) if !self.ih_ready() => f.ns_until_vblank(&MmioRef(&self.mmio), &dcn, &ap.timing).min(500_000),
                    _ => 200_000,
                };
                libd::handle::sleep(sleep_ns);
            }
        }
    }

    fn draw_flip_test_pattern(
        vram: &Mapping,
        buf_rel: u64,
        width: u32,
        height: u32,
        pitch: u32,
        frame: u64,
    ) {
        // Two high-contrast alternating tear-detecting patterns + a sliding vertical bar + frame counter.
        let alt = (frame & 1) != 0;
        let bg = if alt { 0x0018_202E } else { 0x0056_6087 }; // Dark Slate vs Discrete Blue
        let bar_x = ((frame * 17) as u32) % width.max(1);
        let bar_w = 24u32;

        // Draw top 96 rows (frame counter + moving tear bar) and a fast-updating central band
        // so even at 540 Hz (1.85 ms/frame) WC writes complete well within a single frame!
        let rows = height.min(256);
        for y in 0..rows {
            let row_off = buf_rel + u64::from(y) * u64::from(pitch);
            for x in 0..width {
                let in_bar = x >= bar_x && x < bar_x.saturating_add(bar_w);
                let px = if in_bar {
                    0x00FF_FFFF
                } else if y < 64 && x < 256 {
                    // Simple binary/striped frame counter blocks in top-left corner.
                    let bit = (x / 16) as u64;
                    let on = ((frame >> bit) & 1) != 0;
                    if on && (x % 16) < 12 && (16..48).contains(&y) { 0x0038_D996 } else { 0x000E_131B }
                } else {
                    bg
                };
                let o = row_off + u64::from(x) * 4;
                if o + 4 <= vram.len {
                    vram.w32(o, px);
                }
            }
        }
        fence(Ordering::Release);
    }
}

impl GpuDriver for AmdGpu {
    fn modes(&self, out: &mut [ModeEntry]) -> usize {
        let mut count = 0usize;
        let cur_hz = self.measured_mhz.max(60_000);
        let cur_w = self.width;
        let cur_h = self.height;
        let push = |out: &mut [ModeEntry], count: &mut usize, w: u32, h: u32, hz: u32, pref: bool| {
            if *count >= out.len() || w == 0 || h == 0 {
                return;
            }
            for e in &out[..*count] {
                if e.width == w && e.height == h && e.refresh_mhz.abs_diff(hz) < 1000 {
                    return;
                }
            }
            let mut flags = if pref { MODE_FLAG_PREFERRED } else { 0 };
            if w == cur_w && h == cur_h && cur_hz.abs_diff(hz) < 2000 {
                flags |= MODE_FLAG_CURRENT;
            }
            out[*count] = ModeEntry { width: w, height: h, refresh_mhz: hz, flags };
            *count += 1;
        };

        // Current live hardware mode first.
        push(out, &mut count, self.width, self.height, cur_hz, true);
        // All EDID modes (including CTA-861 and DisplayID 2.0 240/540 Hz timings).
        if let Some(ed) = self.edid() {
            for m in ed.modes() {
                push(out, &mut count, m.width, m.height, m.refresh_mhz, m.preferred);
            }
        }
        // Standard fallbacks if no EDID was read.
        if count <= 1 {
            for &(w, h) in &[(3840, 2160), (2560, 1440), (1920, 1080), (1280, 800)] {
                push(out, &mut count, w, h, 60_000, false);
            }
        }
        count
    }

    fn monitor_name(&self) -> &[u8] {
        if let Some(ed) = self.edid()
            && ed.name_len > 0
        {
            return &ed.name[..usize::from(ed.name_len)];
        }
        self.gpu.name.as_bytes()
    }

    fn set_active_slot(&mut self, slot: usize) {
        if slot < self.pipe_count {
            self.primary_slot = slot;
        }
    }

    fn set_gop_info(&mut self, gop: GopInfoWire) -> Option<(u32, u32, u32)> {
        let info = GopInfo {
            phys_base: gop.phys_base,
            size: gop.size,
            width: gop.width,
            height: gop.height,
            pitch: gop.pitch,
            red_shift: gop.shifts[0],
            green_shift: gop.shifts[1],
            blue_shift: gop.shifts[2],
        };
        self.setup_native_scanout(info);
        Some((self.current_caps(), self.width, self.height))
    }

    fn display_info(&self, out: &mut DisplayProbeInfo) -> bool {
        *out = DisplayProbeInfo::empty();
        if let Some(dcn) = self.dcn {
            out.dcn_major = dcn.dcn.major;
            out.dcn_minor = dcn.dcn.minor;
            out.dcn_rev = dcn.dcn.revision;
        }
        out.active_pipes = self.pipe_count as u8;
        if let Some(ap) = self.active_pipe() {
            out.pipe = ap.pipe;
            out.width = ap.width();
            out.height = ap.height();
            out.h_total = ap.timing.h_total;
            out.v_total = ap.timing.v_total;
            out.pitch_bytes = ap.pitch_bytes;
            out.raw_format = ap.raw_format;
            out.mc_addr = ap.earliest_inuse_mc;
            out.vram_off = ap.vram_off.unwrap_or(0);
            if ap.gop_matched {
                out.flags |= gpu::PROBE_GOP_MATCHED;
            }
        } else {
            out.width = self.width;
            out.height = self.height;
            out.pitch_bytes = self.pitch;
        }
        out.measured_mhz = self.measured_mhz;
        out.gop_phys_base = self.gop.map_or(0, |g| g.phys_base);

        if let Some(f) = self.flip.as_ref() {
            if f.is_verified() {
                out.flags |= gpu::PROBE_FLIP_VERIFIED;
            } else if matches!(f.self_check, SelfCheckState::Failed(_)) {
                out.flags2 |= gpu::PROBE2_SELF_CHECK_FAILED;
            }
        }
        if self.ih_ready() {
            out.flags |= gpu::PROBE_IH_IRQ_ACTIVE;
        }
        if let Some(ed) = self.edid() {
            out.vrr_min_hz = ed.vrr_min_hz;
            out.vrr_max_hz = ed.vrr_max_hz;
            if ed.vrr_min_hz >= 24 && ed.vrr_max_hz > ed.vrr_min_hz {
                out.flags |= gpu::PROBE_VRR_SUPPORTED;
            }
            if ed.hdr_supported {
                out.flags |= gpu::PROBE_HDR_SUPPORTED;
            }
        }
        if self.vrr_enabled {
            out.flags |= gpu::PROBE_VRR_ENABLED;
        }
        if self.hdr_enabled {
            out.flags |= gpu::PROBE_HDR_ENABLED;
        }
        if let Some(aux) = self.aux_probe.as_ref() {
            out.edid_blocks = aux.edid_blocks_read;
            out.dp_lanes = aux.link.active_lanes;
            out.dp_max_lanes = aux.link.max_lanes;
            out.dp_rate_mbps = aux.link.active_link_rate_mbps;
            out.dp_max_rate_mbps = aux.link.max_link_rate_mbps;
            out.dpcd_000 = aux.link.dpcd_000;
            out.dpcd_060 = aux.link.dpcd_060;
            out.dpcd_100 = aux.link.dpcd_100;
            out.dpcd_202 = aux.link.dpcd_202;
            if aux.link.dsc_supported {
                out.flags |= gpu::PROBE_DSC_SUPPORTED;
            }
            if aux.link.dsc_enabled || self.dsc_enabled {
                out.flags2 |= gpu::PROBE2_DSC_ENABLED;
            }
            if aux.link.is_uhbr {
                out.flags2 |= gpu::PROBE2_IS_UHBR;
            }
            if aux.link.cr_done {
                out.flags2 |= gpu::PROBE2_CR_DONE;
            }
            if aux.link.eq_done {
                out.flags2 |= gpu::PROBE2_EQ_DONE;
            }
        }
        let mon = self.monitor_name();
        let ml = mon.len().min(24);
        out.monitor_name[..ml].copy_from_slice(&mon[..ml]);
        out.monitor_len = ml as u8;
        out.set_note(&self.status_note[..self.status_note_len]);
        true
    }

    fn attach_fb(&mut self, vmo: Handle, width: u32, height: u32, pitch: u32, format: u32) -> Result<u32, i64> {
        let map_len = u64::from(pitch).saturating_mul(u64::from(height));
        let map = Mapping::of_ro(vmo, map_len)?;
        let pin = FbPin::pin(self.dev, &mut self.scratch, vmo, width, height, pitch, format)?;
        let slot = self.fbs.iter().position(|s| s.is_none()).unwrap_or(0);
        let fb_id = self.next_fb_id;
        self.next_fb_id += 1;
        self.fbs[slot] = Some(AmdFb { fb_id, map, pin });
        if let Some(f) = self.flip.as_mut() {
            f.age.mark_all_dirty();
        }
        Ok(fb_id)
    }

    fn set_mode(&mut self, width: u32, height: u32) -> Result<(), i64> {
        if !(320..=MAX_DIM).contains(&width) || !(200..=MAX_DIM).contains(&height) {
            return Err(sys::ERR_INVALID_ARGS);
        }
        if width == self.width && height == self.height {
            return Ok(());
        }
        self.set_mode_ex(width, height, self.measured_mhz.max(60_000), 0)
    }

    fn set_mode_ex(&mut self, width: u32, height: u32, refresh_mhz: u32, flags: u32) -> Result<(), i64> {
        if !(320..=MAX_DIM).contains(&width) || !(200..=MAX_DIM).contains(&height) {
            return Err(sys::ERR_INVALID_ARGS);
        }
        let Some(dcn) = self.dcn else {
            self.width = width;
            self.height = height;
            self.pitch = width.saturating_mul(4);
            return Ok(());
        };
        let Some(ap) = self.active_pipe() else {
            return Err(sys::ERR_BAD_STATE);
        };
        if width != ap.width() || height != ap.height() {
            println!(
                "amdgpu: mode {}x{} rejected (active pipe is {}x{}; same-resolution refresh switching supported)",
                width,
                height,
                ap.width(),
                ap.height()
            );
            return Err(sys::ERR_NOT_SUPPORTED);
        }
        // Find matching detailed timing in EDID.
        let timing = self
            .edid()
            .and_then(|ed| {
                ed.timings()
                    .iter()
                    .filter(|t| t.h_active == width && t.v_active == height)
                    .min_by_key(|t| t.refresh_mhz.abs_diff(refresh_mhz))
                    .copied()
            })
            .ok_or(sys::ERR_NOT_SUPPORTED)?;

        let bpc = if self.hdr_enabled { 10 } else { 8 };
        let allow_dsc = (flags & 1) != 0;
        let allow_retrain = (flags & 2) != 0;
        let mut use_dsc = false;
        let mut dsc_bpp = 8u8;

        if let Some(aux_p) = self.aux_probe {
            match plan_mode_bandwidth(&aux_p.link, &timing, bpc) {
                ModeBandwidthPlan::FitsCurrentLink => {}
                ModeBandwidthPlan::NeedsDscOnCurrentLink { target_bpp } => {
                    if !allow_dsc {
                        return Err(sys::ERR_NOT_SUPPORTED);
                    }
                    use_dsc = true;
                    dsc_bpp = target_bpp;
                }
                ModeBandwidthPlan::NeedsRetrain { lanes, rate_code, is_uhbr, use_dsc: need_dsc, target_bpp } => {
                    if !allow_retrain || (need_dsc && !allow_dsc) {
                        return Err(sys::ERR_NOT_SUPPORTED);
                    }
                    let mut io = MmioRef(&self.mmio);
                    let tr = aux::train_dp_link(&mut io, &dcn, aux_p.aux_idx, lanes, rate_code, is_uhbr, delay_us)
                        .map_err(|_| i64::from(proto::ERR_IO))?;
                    if !tr.cr_done || !tr.eq_done {
                        return Err(i64::from(proto::ERR_IO));
                    }
                    use_dsc = need_dsc;
                    dsc_bpp = target_bpp;
                }
                ModeBandwidthPlan::ExceedsSinkCapacity => return Err(sys::ERR_OUT_OF_RANGE),
            }
            if use_dsc {
                let mut io = MmioRef(&self.mmio);
                let _ = aux::aux_native_write(&mut io, &dcn, aux_p.aux_idx, aux::DPCD_DSC_ENABLE, &[0x01], delay_us);
            }
        }

        // Derive live DCCG DTO source clock (e.g. DTBCLK on DCN 4.0.1) from active firmware
        // registers before programming new OTG/DCCG/MSA/DSC timing guarded by verify-and-revert!
        let src_clk_khz = flip::derive_dto_source_clk_khz(
            &MmioRef(&self.mmio),
            &dcn,
            ap.pipe,
            &ap.timing,
            self.measured_mhz.max(60_000),
            100_000,
        );
        let saved = {
            let mut io = MmioRef(&self.mmio);
            program_mode_regs(&mut io, &dcn, ap.pipe, &timing, src_clk_khz, use_dsc, dsc_bpp, bpc)
        };
        // Verify OTG frame counter keeps advancing after mode switch.
        let new_hz = self.measure_pipe_refresh(&dcn, ap.pipe);
        if new_hz.is_none() {
            let mut io = MmioRef(&self.mmio);
            saved.restore(&mut io, &dcn);
            println!("amdgpu: mode {}x{}@{} Hz stalled OTG: reverted automatically", width, height, timing.refresh_mhz / 1000);
            return Err(i64::from(proto::ERR_IO));
        }
        self.pipes[self.primary_slot].timing = dcn::OtgTiming::from_detailed(&timing);
        self.measured_mhz = new_hz.unwrap_or(timing.refresh_mhz);
        self.dsc_enabled = use_dsc;
        if let Some(f) = self.flip.as_mut() {
            f.refresh_mhz = self.measured_mhz;
            f.age.mark_all_dirty();
        }
        println!(
            "amdgpu: mode set {}x{} @ {}.{:02} Hz (src_clk={} kHz, dsc={})",
            width,
            height,
            self.measured_mhz / 1000,
            (self.measured_mhz % 1000) / 10,
            src_clk_khz,
            use_dsc
        );
        Ok(())
    }

    fn present(&mut self, fb_id: u32, rect: DamageRect) -> Result<u64, i64> {
        let list = if rect.is_empty() { &[][..] } else { &[rect][..] };
        let (frames, _) = self.present_multi(fb_id, list)?;
        Ok(frames)
    }

    fn present_multi(&mut self, fb_id: u32, rects: &[DamageRect]) -> Result<(u64, bool), i64> {
        // Native verified tear-free DCN vsync flip path with buffer-age damage copying.
        if let (Some(dcn), Some(layout)) = (self.dcn, self.layout)
            && self.flip.as_ref().is_some_and(FlipEngine::is_verified)
        {
            // Never overwrite an on-screen or pending buffer: reap or wait if one is still in flight.
            self.wait_in_flight_flip();

            let now = sys::clock_ns();
            let draw_buf = {
                let Some(flip) = self.flip.as_mut() else {
                    return Err(sys::ERR_BAD_STATE);
                };
                let io = MmioRef(&self.mmio);
                flip.pick_draw_buffer(&io, &dcn, now).map_err(|_| sys::ERR_SHOULD_WAIT)?
            };

            let mut age_rects = [DamageRect::EMPTY; MAX_AGE_RECTS];
            let age_count = self
                .flip
                .as_ref()
                .map_or(0, |f| f.damage_for_buffer(draw_buf, rects, &mut age_rects));

            let Some(vram) = self.vram_map.as_ref() else {
                return Err(sys::ERR_BAD_STATE);
            };
            let Some(buf_rel) = layout.to_map_off(layout.buffers[draw_buf]) else {
                return Err(sys::ERR_OUT_OF_RANGE);
            };
            let Some(fb) = self.fbs.iter().flatten().find(|f| f.fb_id == fb_id) else {
                return Err(sys::ERR_INVALID_ARGS);
            };
            let w = fb.pin.width.min(self.width);
            let h = fb.pin.height.min(self.height);
            let fmt = PixelFormat::from_u32(fb.pin.format).unwrap_or(PixelFormat::Xrgb8888);
            let shifts = self.gop.map_or([16, 8, 0], |g| [g.red_shift, g.green_shift, g.blue_shift]);

            for &dmg in &age_rects[..age_count] {
                if self.hdr_enabled {
                    blit_rect_wc_10bpc(fb.map.bytes(), fb.pin.pitch, fmt, self.pitch, w, h, dmg, |off, px| {
                        let o = buf_rel + off;
                        if o + 4 <= vram.len {
                            vram.w32(o, px);
                        }
                    });
                } else {
                    blit_rect_wc(
                        fb.map.bytes(),
                        fb.pin.pitch,
                        fmt,
                        self.pitch,
                        shifts,
                        w,
                        h,
                        dmg,
                        |off, px| {
                            let o = buf_rel + off;
                            if o + 4 <= vram.len {
                                vram.w32(o, px);
                            }
                        },
                    );
                }
            }
            fence(Ordering::Release);

            // Commit vsync flip (`HIGH` then `LOW`, `SURFACE_FLIP_TYPE = 0`).
            let active_timing = self.active_pipe().map(|ap| ap.timing);
            let ih_ready = self.ih_ready();
            let next_dl = {
                let Some(flip) = self.flip.as_mut() else {
                    return Err(sys::ERR_BAD_STATE);
                };
                let mut io = MmioRef(&self.mmio);
                flip.commit_vsync_flip(&mut io, &dcn, draw_buf, rects, now)
                    .map_err(|_| sys::ERR_BAD_STATE)?;
                if ih_ready {
                    // Tight safety fallback deadline in case a verified IRQ is ever missed.
                    let fi = flip.frame_interval_ns();
                    now + fi + (fi / 2).max(2_000_000)
                } else if let Some(timing) = active_timing {
                    // High-resolution sleep straight to predicted vblank start (IH still wakes early if it fires).
                    now + flip.ns_until_vblank(&io, &dcn, &timing)
                } else {
                    now + flip.frame_interval_ns()
                }
            };
            self.flip_deadline_ns = Some(next_dl);
            self.frames = self.frames.saturating_add(1);
            return Ok((self.frames, true));
        }

        // Fallback WC linear VRAM copy (e.g. non-GOP test devices without verified DCN pipe).
        if self.vram_map.is_none() {
            let map_len = self.bar0_size.min(FALLBACK_VRAM_MAP_MAX);
            if !self.map_vram_window(0, map_len) {
                return Err(sys::ERR_NOT_SUPPORTED);
            }
        }
        let Some(vram) = self.vram_map.as_ref() else {
            return Err(sys::ERR_NOT_SUPPORTED);
        };
        let Some(fb) = self.fbs.iter().flatten().find(|f| f.fb_id == fb_id) else {
            return Err(sys::ERR_INVALID_ARGS);
        };
        let w = fb.pin.width.min(self.width);
        let h = fb.pin.height.min(self.height);
        let fmt = PixelFormat::from_u32(fb.pin.format).unwrap_or(PixelFormat::Xrgb8888);
        let full = [DamageRect::full(w, h)];
        let list = if rects.is_empty() { &full[..] } else { rects };
        for &r in list {
            let dmg = if r.is_empty() { DamageRect::full(w, h) } else { r };
            blit_rect_wc(fb.map.bytes(), fb.pin.pitch, fmt, self.pitch, [16, 8, 0], w, h, dmg, |off, px| {
                if off + 4 <= vram.len {
                    vram.w32(off, px);
                }
            });
        }
        fence(Ordering::Release);
        self.frames = self.frames.saturating_add(1);
        Ok((self.frames, false))
    }

    fn set_cursor(&mut self, vmo: Handle, hot_x: u32, hot_y: u32) -> Result<(), i64> {
        let Some(dcn) = self.dcn else {
            sys::handle_close(vmo);
            return Err(sys::ERR_NOT_SUPPORTED);
        };
        let Some(fb_win) = self.fb_win else {
            sys::handle_close(vmo);
            return Err(sys::ERR_NOT_SUPPORTED);
        };
        let Some(layout) = self.layout else {
            sys::handle_close(vmo);
            return Err(sys::ERR_NOT_SUPPORTED);
        };
        if !self.flip.as_ref().is_some_and(FlipEngine::is_verified) {
            sys::handle_close(vmo);
            return Err(sys::ERR_NOT_SUPPORTED);
        }
        let sz = sys::vmo_size(vmo).inspect_err(|_| {
            sys::handle_close(vmo);
        })?;
        let (cur_size, bytes) = if sz >= 256 * 256 * 4 {
            (CursorSize::Px256, 256u64 * 256 * 4)
        } else if sz >= 64 * 64 * 4 {
            (CursorSize::Px64, 64u64 * 64 * 4)
        } else {
            sys::handle_close(vmo);
            return Err(sys::ERR_OUT_OF_RANGE);
        };
        let map = Mapping::of_ro(vmo, bytes).inspect_err(|_| {
            sys::handle_close(vmo);
        })?;
        let res = (|| -> Result<(), i64> {
            let vram = self.vram_map.as_ref().ok_or(sys::ERR_BAD_STATE)?;
            let rel = layout.to_map_off(layout.cursor_vram_off).ok_or(sys::ERR_OUT_OF_RANGE)?;
            let mc = fb_win.vram_to_mc(layout.cursor_vram_off).ok_or(sys::ERR_OUT_OF_RANGE)?;
            if rel + bytes > vram.len {
                return Err(sys::ERR_OUT_OF_RANGE);
            }
            for (i, chunk) in map.bytes()[..bytes as usize].as_chunks::<4>().0.iter().enumerate() {
                vram.w32(rel + (i as u64) * 4, u32::from_le_bytes(*chunk));
            }
            fence(Ordering::Release);
            let mut io = MmioRef(&self.mmio);
            self.cursor.configure(&mut io, &dcn, mc, cur_size, hot_x, hot_y, false, self.width, self.height);
            Ok(())
        })();
        let _ = sys::vmar_unmap(libd::root_vmar(), map.addr, map.len);
        sys::handle_close(vmo);
        res
    }

    fn move_cursor(&mut self, x: u32, y: u32) -> Result<(), i64> {
        let Some(dcn) = self.dcn else {
            return Err(sys::ERR_NOT_SUPPORTED);
        };
        if !self.cursor.enabled {
            return Err(sys::ERR_BAD_STATE);
        }
        let mut io = MmioRef(&self.mmio);
        self.cursor.move_pos(&mut io, &dcn, x as i32, y as i32, self.width, self.height);
        Ok(())
    }

    fn release_display(&mut self) -> Result<(), i64> {
        let Some(dcn) = self.dcn else {
            return Ok(());
        };
        let mut io = MmioRef(&self.mmio);
        if self.cursor.enabled {
            self.cursor.disable(&mut io, &dcn);
        }
        if let Some(flip) = self.flip.as_mut() {
            flip.restore_original(&mut io, &dcn);
        }
        self.flip_deadline_ns = None;
        self.pending_async_notify = None;
        Ok(())
    }

    fn set_vrr(&mut self, enable: bool, min_hz: u16, max_hz: u16) -> Result<(), i64> {
        let (Some(dcn), Some(ap)) = (self.dcn, self.active_pipe()) else {
            return Err(sys::ERR_NOT_SUPPORTED);
        };
        let (emin, emax) = self.edid().map_or((min_hz, max_hz), |e| {
            (
                if min_hz > 0 { min_hz } else { e.vrr_min_hz },
                if max_hz > 0 { max_hz } else { e.vrr_max_hz },
            )
        });
        let mut io = MmioRef(&self.mmio);
        if flip::set_vrr(&mut io, &dcn, ap.pipe, &ap.timing, self.measured_mhz.max(60_000), emin, emax, enable) {
            self.vrr_enabled = enable;
            Ok(())
        } else {
            Err(sys::ERR_INVALID_ARGS)
        }
    }

    fn set_hdr(&mut self, enable: bool) -> Result<(), i64> {
        let (Some(dcn), Some(ap)) = (self.dcn, self.active_pipe()) else {
            return Err(sys::ERR_NOT_SUPPORTED);
        };
        let mut io = MmioRef(&self.mmio);
        flip::set_hdr(&mut io, &dcn, ap.pipe, enable);
        self.hdr_enabled = enable;
        if let Some(f) = self.flip.as_mut() {
            f.age.mark_all_dirty();
        }
        Ok(())
    }

    fn flip_test(&mut self, duration_ms: u32) -> Result<FlipTestResult, i64> {
        let Some(dcn) = self.dcn else {
            return Err(sys::ERR_NOT_SUPPORTED);
        };
        let Some(layout) = self.layout else {
            return Err(sys::ERR_NOT_SUPPORTED);
        };
        if !self.flip.as_ref().is_some_and(FlipEngine::is_verified) {
            return Err(sys::ERR_BAD_STATE);
        }
        let ap = self.active_pipe().ok_or(sys::ERR_BAD_STATE)?;
        let dur_ms = duration_ms.clamp(500, 15_000);
        let dur_ns = u64::from(dur_ms) * 1_000_000;

        // Ensure no previous flip is pending and reset counters for this test run.
        self.wait_in_flight_flip();
        let start_fc = read_frame_count(&MmioRef(&self.mmio), &dcn, ap.pipe);
        let t_start = sys::clock_ns();
        let t_end = t_start + dur_ns;
        let mut test_frames = 0u64;
        let mut missed = 0u64;
        let mut late = 0u64;

        let base_missed = self.flip.as_ref().map_or(0, |f| f.missed_flips);
        let base_late = self.flip.as_ref().map_or(0, |f| f.late_flips);

        while sys::clock_ns() < t_end {
            let now = sys::clock_ns();
            let buf_idx = {
                let Some(f) = self.flip.as_mut() else { break };
                match f.pick_draw_buffer(&MmioRef(&self.mmio), &dcn, now) {
                    Ok(b) => b,
                    Err(_) => {
                        libd::handle::sleep(200_000);
                        continue;
                    }
                }
            };
            if let (Some(vram), Some(rel)) = (self.vram_map.as_ref(), layout.to_map_off(layout.buffers[buf_idx])) {
                Self::draw_flip_test_pattern(vram, rel, self.width, self.height, self.pitch, test_frames);
            }
            let now_commit = sys::clock_ns();
            if let Some(f) = self.flip.as_mut() {
                let mut io = MmioRef(&self.mmio);
                let _ = f.commit_vsync_flip(&mut io, &dcn, buf_idx, &[], now_commit);
            }
            // Wait for this flip to latch cleanly at vblank.
            let flip_dl = sys::clock_ns() + 100_000_000;
            while sys::clock_ns() < flip_dl {
                if self.ih.active {
                    self.drain_ih_ring();
                }
                self.check_pending_flip();
                if self.flip.as_ref().is_none_or(|f| f.pending_buf.is_none()) {
                    break;
                }
                let wait_ns = self
                    .flip
                    .as_ref()
                    .map_or(200_000, |f| f.ns_until_vblank(&MmioRef(&self.mmio), &dcn, &ap.timing).min(400_000));
                libd::handle::sleep(wait_ns);
            }
            test_frames += 1;
        }

        let elapsed_ns = sys::clock_ns().saturating_sub(t_start).max(1);
        let end_fc = read_frame_count(&MmioRef(&self.mmio), &dcn, ap.pipe);
        let hw_df = frame_count_diff(end_fc, start_fc);
        if let Some(f) = self.flip.as_ref() {
            missed = f.missed_flips.saturating_sub(base_missed);
            late = f.late_flips.saturating_sub(base_late);
        }
        let measured_mhz = measure_refresh_mhz(hw_df.max(test_frames as u32), elapsed_ns).unwrap_or(self.measured_mhz);

        // ALWAYS revert cleanly to the original firmware GOP framebuffer!
        let _ = self.release_display();
        let reverted = {
            let io = MmioRef(&self.mmio);
            let dl = sys::clock_ns() + 100_000_000;
            let orig_mc = self.flip.as_ref().map_or(0, |f| f.orig_mc_addr);
            let mut ok = false;
            while sys::clock_ns() < dl {
                if let Some(f) = self.flip.as_ref() {
                    let (pend, ear) = f.read_hw_status(&io, &dcn);
                    if !pend && ear == orig_mc {
                        ok = true;
                        break;
                    }
                }
                libd::handle::sleep(500_000);
            }
            ok
        };

        Ok(FlipTestResult {
            frames: test_frames,
            missed,
            late,
            measured_mhz,
            duration_ms: (elapsed_ns / 1_000_000) as u32,
            reverted,
            used_dcn: true,
            used_ih: self.ih_ready(),
            pipe: ap.pipe,
        })
    }

    fn next_deadline_ns(&self) -> Option<u64> {
        self.flip_deadline_ns
    }

    fn poll_flip_done(&mut self) -> Option<(usize, u64, u64, bool)> {
        if self.pending_async_notify.is_none() && self.flip.as_ref().is_some_and(|f| f.pending_buf.is_some()) {
            if self.ih.active {
                self.drain_ih_ring();
            }
            self.check_pending_flip();
        }
        self.pending_async_notify.take().map(|(frames, ts, late)| (0, frames, ts, late))
    }

    fn on_shutdown(&mut self) {
        let _ = self.release_display();
        if let Some(dcn) = self.dcn {
            let mut io = MmioRef(&self.mmio);
            if let Some(ap) = self.active_pipe() {
                self.ih.disable_pipe_irqs(&mut io, &dcn, ap.pipe);
            }
            self.ih.disable(&mut io, &dcn);
        }
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
            // Command stream passed strict validation; GFX/SDMA ring execution is gated until
            // AMD PSP/MES/SDMA microcode images are loaded.
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
            self.drain_ih_ring();
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
    let mmio_len = info.bar_size[mmio_bar as usize].min(16 << 20);
    let Ok(mmio) = Mapping::of_range(mmio_vmo, 0, mmio_len) else {
        println!("amdgpu: {}: cannot map MMIO window", info.name());
        return 1;
    };
    let doorbell = if mmio_bar != 2 && info.bar_kind[2] == 1 && info.bar_size[2] >= 4096 {
        sys::device_map_bar(dev, 2)
            .ok()
            .and_then(|v| Mapping::of_range(v, 0, info.bar_size[2].min(2 << 20)).ok())
    } else {
        None
    };
    let bar0_phys = sys::device_bar_addr(dev, 0).unwrap_or(0);
    let bar0_size = if info.bar_kind[0] == 1 { info.bar_size[0] } else { 0 };
    let Ok(ring_dma) = Dma::new(dev, RING_DMA_BYTES, sys::DMA_DEVICE_READ | sys::DMA_DEVICE_WRITE) else {
        println!("amdgpu: {}: cannot pin ring/IH DMA", info.name());
        return 1;
    };
    let Ok(scratch) = gpu_drv::alloc_pin_scratch() else {
        println!("amdgpu: scratch mapping failed");
        return 1;
    };
    let irq = if info.irqs > 0 { sys::device_interrupt(dev, 0).unwrap_or(0) } else { 0 };
    let iommu = (info.flags & sys::DEV_FLAG_IOMMU) != 0;

    let mut drv = AmdGpu {
        dev,
        gpu: gpu_info,
        mmio,
        _doorbell: doorbell,
        bar0_vmo: 0,
        bar0_phys,
        bar0_size,
        vram_map: None,
        vram_map_off: 0,
        ring_dma,
        scratch,
        irq,
        iommu,
        vram_mib: (bar0_size >> 20) as u32,
        discovery: None,
        dcn: None,
        fb_win: None,
        pipes: [ActivePipe::default(); 6],
        pipe_count: 0,
        primary_slot: 0,
        measured_mhz: 60_000,
        aux_probe: None,
        gop: None,
        layout: None,
        flip: None,
        cursor: HwCursor::new(0),
        ih: IhController::new(IH_RING_BYTES),
        ih_verified: false,
        ih_missed_streak: 0,
        vrr_enabled: false,
        hdr_enabled: false,
        dsc_enabled: false,
        status_note: [0; 48],
        status_note_len: 0,
        cp_ready: false,
        width: 1920,
        height: 1080,
        pitch: 1920 * 4,
        fbs: [const { None }; MAX_FBS],
        next_fb_id: 1,
        next_ctx_id: 1,
        pending_async_notify: None,
        flip_deadline_ns: None,
        frames: 0,
        fences: 0,
        irqs: 0,
    };

    // ---- Read-only hardware probe (zero display writes) ----
    // Probe IP Discovery across candidate VRAM sizes (NBIF memsize registers + BAR 0 ReBAR size)
    // so an APU/NBIF register offset mismatch never hides the checksum-verified IP Discovery table.
    let valid_mib = |v: u32| v > 0 && v != 0xFFFF_FFFF && v <= 65536;
    let mut cand_mib = [0u32; 3];
    let mut cand_n = 0usize;
    let mut push_cand = |m: u32| {
        if valid_mib(m) && !cand_mib[..cand_n].contains(&m) && cand_n < cand_mib.len() {
            cand_mib[cand_n] = m;
            cand_n += 1;
        }
    };
    if let Some(m) = drv.rreg32(amd::REG_RCC_CONFIG_MEMSIZE) {
        push_cand(m);
    }
    if let Some(m) = drv.rreg32(amd::REG_RCC_CONFIG_MEMSIZE_ALT) {
        push_cand(m);
    }
    push_cand((bar0_size >> 20) as u32);
    if cand_n > 0 {
        drv.vram_mib = cand_mib[0];
    }
    for &mib in &cand_mib[..cand_n] {
        if let Some(disc) = drv.probe_ip_discovery(u64::from(mib) << 20) {
            drv.vram_mib = mib;
            drv.discovery = Some(disc);
            break;
        }
    }
    if let Some(disc) = drv.discovery {
        drv.dcn = DcnAccess::from_discovery(&disc, gpu_info.dcn_hint());
        if let Some(dcn) = drv.dcn {
            // Refine VRAM size via NBIF 6.3.x RCC_CONFIG_MEMSIZE when present.
            if dcn.nbif.is_some_and(|n| n.major == 6 && n.minor == 3)
                && let Some(nbif_mem) = dcn
                    .r_nbif(&MmioRef(&drv.mmio), dcn::RegAddr::new(2, amd::NBIF631_RCC_CONFIG_MEMSIZE_OFF))
                    .filter(|&v| v > 0 && v != 0xFFFF_FFFF && v <= 65536)
            {
                drv.vram_mib = nbif_mem;
            }
            let vram_b = u64::from(drv.vram_mib) << 20;
            drv.fb_win = FbWindow::read(&MmioRef(&drv.mmio), &dcn, vram_b);
            drv.pipe_count = probe_active_pipes(&MmioRef(&drv.mmio), &dcn, drv.fb_win, drv.bar0_phys, None, &mut drv.pipes);
            if drv.pipe_count > 0 {
                let ap = drv.pipes[0];
                drv.width = ap.width();
                drv.height = ap.height();
                drv.pitch = ap.pitch_bytes;
                if let Some(hz) = drv.measure_pipe_refresh(&dcn, ap.pipe) {
                    drv.measured_mhz = hz;
                }
                drv.vrr_enabled = ap.vrr_enabled;
                drv.set_note(b"read-only probe ok (awaiting GOP verify)");
            } else {
                // Unconnected GPU (e.g. integrated GPU when monitor is plugged into dGPU):
                // report 0x0 so the compositor never attaches a phantom second display.
                drv.width = 0;
                drv.height = 0;
                drv.pitch = 0;
                drv.set_note(b"no active display pipe (unconnected)");
            }
            // Read-only DP AUX probe (DPCD + multi-block EDID).
            drv.aux_probe = {
                let mut io = MmioRef(&drv.mmio);
                aux::probe_first_connected_aux(&mut io, &dcn, delay_us)
            };
            let dsc_en = drv.aux_probe.as_ref().is_some_and(|p| p.link.dsc_enabled);
            drv.dsc_enabled = dsc_en;

            println!(
                "amdgpu: probe: {} ({}.{}.{}), {} active pipe(s), {}x{} @ {}.{:02} Hz, BAR0={:#x} ({} MiB), VRAM={} MiB",
                dcn.version.name(),
                dcn.dcn.major,
                dcn.dcn.minor,
                dcn.dcn.revision,
                drv.pipe_count,
                drv.width,
                drv.height,
                drv.measured_mhz / 1000,
                (drv.measured_mhz % 1000) / 10,
                drv.bar0_phys,
                drv.bar0_size >> 20,
                drv.vram_mib,
            );
            if let Some(aux_p) = drv.aux_probe {
                println!(
                    "amdgpu: DP AUX{}: {}x {} (max {}x {}), DSC={}/{}, EDID={} blk '{}'",
                    aux_p.aux_idx,
                    aux_p.link.active_lanes,
                    dpcd_rate_label(aux_p.link.active_link_rate_mbps),
                    aux_p.link.max_lanes,
                    dpcd_rate_label(aux_p.link.max_link_rate_mbps),
                    aux_p.link.dsc_supported,
                    aux_p.link.dsc_enabled,
                    aux_p.edid_blocks_read,
                    aux_p.edid.as_ref().map_or("-", EdidInfo::name_str),
                );
            }
        }
    } else {
        drv.set_note(b"IP Discovery not present");
    }

    let caps = drv.current_caps();
    println!(
        "amdgpu: ready on {} ({:04x}:{:04x} {}, VRAM {} MiB, IOMMU={})",
        info.name(),
        info.vendor,
        info.device,
        gpu_info.name,
        drv.vram_mib,
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
    // Announce any additional active display pipes as independent outputs (multi-monitor).
    for idx in 1..drv.pipe_count.min(gpu_drv::MAX_PIPES) {
        let sec = drv.pipes[idx];
        gpu_drv::announce_output(
            ctl,
            &GpuAnnounce {
                kind: gpu::KIND_AMD_RDNA,
                vendor: info.vendor,
                device: info.device,
                vram_mib: drv.vram_mib,
                width: sec.width() as u16,
                height: sec.height() as u16,
                caps,
                name: gpu_info.name,
            },
        );
    }
    let rc = gpu_drv::serve_loop(ctl, &port, &mut drv);
    drv.on_shutdown();
    rc
}
