//! Shared GPU driver <-> `gpu.dsvc` protocol bridge and IOMMU DMA framebuffer pinning helper
//! used by `virtio-gpu.ddrv`, `amdgpu.ddrv`, `xe.ddrv`, and `nvgpu.ddrv`.

use dosgpu::{DamageRect, MAX_DIM, MAX_FB_BYTES};
use libd::gpu::{self, ModeEntry, MODE_ENTRY_BYTES};
use libd::proto::{self, HEADER, Header};
use libd::sys::{self, Handle};
use libd::{Mapping, Port};

pub const KEY_CTL: u64 = 1;
pub const KEY_SVC: u64 = 2;
pub const KEY_IRQ0: u64 = 3;
pub const KEY_IRQ1: u64 = 4;

/// Maximum coalesced DMA runs per pinned framebuffer (1 entry covers up to 64 MiB under IOMMU).
pub const MAX_DMA_RUNS: usize = 256;
/// Maximum pages per pinned framebuffer (16384 * 4 KiB = 64 MiB = 4K UHD 32bpp).
const MAX_FB_PAGES: usize = 16384;

/// A client framebuffer VMO pinned directly into a GPU's IOMMU domain (`DMA_DEVICE_READ`).
pub struct FbPin {
    pub vmo: Handle,
    pub pin: Handle,
    pub width: u32,
    pub height: u32,
    pub pitch: u32,
    pub format: u32,
    pub runs: [(u64, u32); MAX_DMA_RUNS],
    pub run_count: usize,
}

impl FbPin {
    /// Pin `vmo` for GPU DMA reads using `scratch` (128 KiB reusable page-address buffer).
    /// Closes `vmo` on failure; takes ownership of `vmo` on success.
    #[allow(clippy::too_many_arguments)]
    pub fn pin(
        dev: Handle,
        scratch: &mut Mapping,
        vmo: Handle,
        width: u32,
        height: u32,
        pitch: u32,
        format: u32,
    ) -> Result<Self, i64> {
        if width == 0 || height == 0 || width > MAX_DIM || height > MAX_DIM || pitch < width.saturating_mul(4) {
            sys::handle_close(vmo);
            return Err(sys::ERR_INVALID_ARGS);
        }
        let need = u64::from(pitch).saturating_mul(u64::from(height));
        if need == 0 || need > MAX_FB_BYTES {
            sys::handle_close(vmo);
            return Err(sys::ERR_INVALID_ARGS);
        }
        let vmo_sz = match sys::vmo_size(vmo) {
            Ok(s) if s >= need && s <= MAX_FB_BYTES => s,
            Ok(_) => {
                sys::handle_close(vmo);
                return Err(sys::ERR_OUT_OF_RANGE);
            }
            Err(e) => {
                sys::handle_close(vmo);
                return Err(e);
            }
        };
        let pin_len = need.div_ceil(sys::PAGE) * sys::PAGE;
        let pages = (pin_len / sys::PAGE) as usize;
        if pages == 0 || pages > MAX_FB_PAGES || scratch.len < (pages as u64) * 8 {
            sys::handle_close(vmo);
            return Err(sys::ERR_OUT_OF_RANGE);
        }
        // SAFETY: `scratch` is a page-aligned private Mapping of at least `pages * 8` bytes.
        let addrs: &mut [u64] = unsafe {
            core::slice::from_raw_parts_mut(scratch.addr as *mut u64, pages)
        };
        let pin = match sys::dma_map(dev, vmo, 0, pin_len, sys::DMA_DEVICE_READ, addrs) {
            Ok(p) => p,
            Err(e) => {
                sys::handle_close(vmo);
                return Err(e);
            }
        };
        let mut runs = [(0u64, 0u32); MAX_DMA_RUNS];
        let mut run_count = 0usize;
        for &pa in addrs.iter() {
            if run_count > 0 {
                let (prev_addr, prev_len) = runs[run_count - 1];
                if prev_addr.saturating_add(u64::from(prev_len)) == pa && prev_len <= u32::MAX - 4096 {
                    runs[run_count - 1].1 = prev_len + 4096;
                    continue;
                }
            }
            if run_count >= MAX_DMA_RUNS {
                sys::handle_close(pin);
                sys::handle_close(vmo);
                return Err(sys::ERR_NO_RESOURCES);
            }
            runs[run_count] = (pa, 4096);
            run_count += 1;
        }
        let _ = (vmo_sz, pin_len);
        Ok(Self { vmo, pin, width, height, pitch, format, runs, run_count })
    }
}

impl Drop for FbPin {
    fn drop(&mut self) {
        if self.pin != 0 {
            sys::handle_close(self.pin);
        }
        if self.vmo != 0 {
            sys::handle_close(self.vmo);
        }
    }
}

/// Allocate the reusable 128 KiB scratch mapping for `FbPin::pin`.
pub fn alloc_pin_scratch() -> Result<Mapping, i64> {
    Mapping::new((MAX_FB_PAGES as u64) * 8)
}

/// Announcement metadata sent from a GPU `.ddrv` to `devmgr` (`proto::GPU_DEV`).
pub struct GpuAnnounce<'a> {
    pub kind: u8,
    pub vendor: u16,
    pub device: u16,
    pub vram_mib: u32,
    pub width: u16,
    pub height: u16,
    pub caps: u32,
    pub name: &'a str,
}

/// Trait implemented by every isolated GPU driver (`.ddrv`).
pub trait GpuDriver {
    fn modes(&self, out: &mut [ModeEntry]) -> usize;
    fn monitor_name(&self) -> &[u8] {
        b""
    }
    fn attach_fb(&mut self, vmo: Handle, width: u32, height: u32, pitch: u32, format: u32) -> Result<u32, i64>;
    fn set_mode(&mut self, width: u32, height: u32) -> Result<(), i64>;
    fn present(&mut self, fb_id: u32, rect: DamageRect) -> Result<u64, i64>;
    fn set_cursor(&mut self, vmo: Handle, _hot_x: u32, _hot_y: u32) -> Result<(), i64> {
        sys::handle_close(vmo);
        Err(sys::ERR_NOT_SUPPORTED)
    }
    fn move_cursor(&mut self, _x: u32, _y: u32) -> Result<(), i64> {
        Err(sys::ERR_NOT_SUPPORTED)
    }
    fn ctx_create(&mut self) -> Result<u32, i64> {
        Err(sys::ERR_NOT_SUPPORTED)
    }
    fn ctx_destroy(&mut self, _ctx_id: u32) -> Result<(), i64> {
        Err(sys::ERR_NOT_SUPPORTED)
    }
    fn submit_cmd(&mut self, _ctx_id: u32, _engine: u32, _cmd: &[u8]) -> Result<u64, i64> {
        Err(sys::ERR_NOT_SUPPORTED)
    }
    fn irqs(&self) -> u64 {
        0
    }
    fn frames(&self) -> u64 {
        0
    }
    fn on_irq(&mut self, _key: u64) {}
}

/// Announce the GPU adapter to `devmgr` (`proto::READY` + `proto::GPU_DEV`).
pub fn announce(ctl: Handle, info: &GpuAnnounce<'_>) {
    proto::send(ctl, proto::READY, 0, 0);
    let mut msg = [0u8; HEADER + 40];
    let a = gpu::pack_dev_a(info.kind, info.vendor, info.device, info.vram_mib);
    let b = gpu::pack_dev_b(info.width, info.height, info.caps);
    let nb = info.name.as_bytes();
    let nl = nb.len().min(40);
    Header { txid: 0, op: proto::GPU_DEV, status: 0, a, b }.put(&mut msg);
    msg[HEADER..HEADER + nl].copy_from_slice(&nb[..nl]);
    let _ = sys::channel_write(ctl, &msg[..HEADER + nl]);
}

/// Shared GPU driver event loop serving `devmgr` control messages and direct `gpu.dsvc` requests.
pub fn serve_loop<D: GpuDriver>(ctl: Handle, port: &Port, drv: &mut D) -> i32 {
    port.arm(ctl, sys::READABLE | sys::PEER_CLOSED, KEY_CTL);
    let mut svc_ch: Handle = 0;
    let mut buf = [0u8; HEADER + 4096];

    loop {
        let Some((key, _)) = port.wait(sys::WAIT_FOREVER) else { continue };
        match key {
            KEY_CTL => {
                loop {
                    let mut hs = [0 as Handle; 1];
                    match sys::channel_read_h(ctl, &mut buf[..HEADER + 64], &mut hs, 0) {
                        Ok((n, nh)) => {
                            let hnd = if nh > 0 { hs[0] } else { 0 };
                            let Some(h) = Header::get(&buf[..n]) else {
                                if hnd != 0 {
                                    sys::handle_close(hnd);
                                }
                                continue;
                            };
                            match h.op {
                                proto::GPU_ATTACH if hnd != 0 => {
                                    if svc_ch != 0 {
                                        sys::handle_close(svc_ch);
                                    }
                                    svc_ch = hnd;
                                    port.arm(svc_ch, sys::READABLE | sys::PEER_CLOSED, KEY_SVC);
                                }
                                proto::STATS => {
                                    if hnd != 0 {
                                        sys::handle_close(hnd);
                                    }
                                    let mut rep = [0u8; HEADER];
                                    Header {
                                        txid: h.txid,
                                        op: proto::STATS,
                                        status: 0,
                                        a: drv.irqs(),
                                        b: drv.frames(),
                                    }
                                    .put(&mut rep);
                                    let _ = sys::channel_write(ctl, &rep);
                                }
                                proto::TEST_CRASH => {
                                    if hnd != 0 {
                                        sys::handle_close(hnd);
                                    }
                                    panic!("intentional test crash");
                                }
                                _ => {
                                    if hnd != 0 {
                                        sys::handle_close(hnd);
                                    }
                                }
                            }
                        }
                        Err(sys::ERR_SHOULD_WAIT) => {
                            port.arm(ctl, sys::READABLE | sys::PEER_CLOSED, KEY_CTL);
                            break;
                        }
                        Err(_) => return 0,
                    }
                }
            }
            KEY_SVC if svc_ch != 0 => {
                loop {
                    let mut hs = [0 as Handle; 1];
                    match sys::channel_read_h(svc_ch, &mut buf, &mut hs, 0) {
                        Ok((n, nh)) => {
                            let hnd = if nh > 0 { hs[0] } else { 0 };
                            let Some(h) = Header::get(&buf[..n]) else {
                                if hnd != 0 {
                                    sys::handle_close(hnd);
                                }
                                continue;
                            };
                            handle_svc_msg(svc_ch, drv, h, &buf[HEADER..n], hnd);
                        }
                        Err(sys::ERR_SHOULD_WAIT) => {
                            port.arm(svc_ch, sys::READABLE | sys::PEER_CLOSED, KEY_SVC);
                            break;
                        }
                        Err(_) => {
                            sys::handle_close(svc_ch);
                            svc_ch = 0;
                            break;
                        }
                    }
                }
            }
            KEY_IRQ0 | KEY_IRQ1 => drv.on_irq(key),
            _ => {}
        }
    }
}

fn reply(ch: Handle, txid: u32, op: u32, status: i32, a: u64, b: u64, payload: &[u8]) {
    let mut out = [0u8; HEADER + 320];
    let plen = payload.len().min(320);
    Header { txid, op, status, a, b }.put(&mut out);
    out[HEADER..HEADER + plen].copy_from_slice(&payload[..plen]);
    let _ = sys::channel_write(ch, &out[..HEADER + plen]);
}

fn handle_svc_msg<D: GpuDriver>(ch: Handle, drv: &mut D, h: Header, payload: &[u8], hnd: Handle) {
    match h.op {
        gpu::DRV_GET_MODES => {
            if hnd != 0 {
                sys::handle_close(hnd);
            }
            let mut modes = [ModeEntry::default(); 16];
            let count = drv.modes(&mut modes).min(16);
            let mon = drv.monitor_name();
            let mon_len = mon.len().min(24);
            let mut body = [0u8; 24 + 16 * MODE_ENTRY_BYTES];
            body[..mon_len].copy_from_slice(&mon[..mon_len]);
            for (i, m) in modes.iter().take(count).enumerate() {
                let mut enc = [0u8; MODE_ENTRY_BYTES];
                m.encode(&mut enc);
                let off = 24 + i * MODE_ENTRY_BYTES;
                body[off..off + MODE_ENTRY_BYTES].copy_from_slice(&enc);
            }
            reply(
                ch,
                h.txid,
                h.op,
                0,
                count as u64,
                mon_len as u64,
                &body[..24 + count * MODE_ENTRY_BYTES],
            );
        }
        gpu::DRV_ATTACH_FB => {
            if hnd == 0 || payload.len() < 4 {
                if hnd != 0 {
                    sys::handle_close(hnd);
                }
                reply(ch, h.txid, h.op, sys::ERR_INVALID_ARGS as i32, 0, 0, &[]);
                return;
            }
            let format = (h.a >> 32) as u32;
            let width = h.b as u32;
            let height = (h.b >> 32) as u32;
            let pitch = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
            match drv.attach_fb(hnd, width, height, pitch, format) {
                Ok(fb_id) => reply(ch, h.txid, h.op, 0, u64::from(fb_id), 0, &[]),
                Err(e) => reply(ch, h.txid, h.op, e as i32, 0, 0, &[]),
            }
        }
        gpu::DRV_SET_MODE => {
            if hnd != 0 {
                sys::handle_close(hnd);
            }
            let width = h.b as u32;
            let height = (h.b >> 32) as u32;
            match drv.set_mode(width, height) {
                Ok(()) => reply(ch, h.txid, h.op, 0, 0, 0, &[]),
                Err(e) => reply(ch, h.txid, h.op, e as i32, 0, 0, &[]),
            }
        }
        gpu::DRV_PRESENT => {
            if hnd != 0 {
                sys::handle_close(hnd);
            }
            if payload.len() < 8 {
                reply(ch, h.txid, h.op, sys::ERR_INVALID_ARGS as i32, 0, 0, &[]);
                return;
            }
            let fb_id = (h.a >> 32) as u32;
            let x = h.b as u32;
            let y = (h.b >> 32) as u32;
            let w = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
            let hh = u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]);
            match drv.present(fb_id, DamageRect { x, y, w, h: hh }) {
                Ok(frames) => reply(ch, h.txid, h.op, 0, frames, 0, &[]),
                Err(e) => reply(ch, h.txid, h.op, e as i32, 0, 0, &[]),
            }
        }
        gpu::DRV_SET_CURSOR => {
            if hnd == 0 {
                reply(ch, h.txid, h.op, sys::ERR_INVALID_ARGS as i32, 0, 0, &[]);
                return;
            }
            let hot_x = h.b as u32;
            let hot_y = (h.b >> 32) as u32;
            match drv.set_cursor(hnd, hot_x, hot_y) {
                Ok(()) => reply(ch, h.txid, h.op, 0, 0, 0, &[]),
                Err(e) => reply(ch, h.txid, h.op, e as i32, 0, 0, &[]),
            }
        }
        gpu::DRV_MOVE_CURSOR => {
            if hnd != 0 {
                sys::handle_close(hnd);
            }
            let x = h.b as u32;
            let y = (h.b >> 32) as u32;
            match drv.move_cursor(x, y) {
                Ok(()) => reply(ch, h.txid, h.op, 0, 0, 0, &[]),
                Err(e) => reply(ch, h.txid, h.op, e as i32, 0, 0, &[]),
            }
        }
        gpu::DRV_CTX_CREATE => {
            if hnd != 0 {
                sys::handle_close(hnd);
            }
            match drv.ctx_create() {
                Ok(id) => reply(ch, h.txid, h.op, 0, u64::from(id), 0, &[]),
                Err(e) => reply(ch, h.txid, h.op, e as i32, 0, 0, &[]),
            }
        }
        gpu::DRV_CTX_DESTROY => {
            if hnd != 0 {
                sys::handle_close(hnd);
            }
            match drv.ctx_destroy(h.b as u32) {
                Ok(()) => reply(ch, h.txid, h.op, 0, 0, 0, &[]),
                Err(e) => reply(ch, h.txid, h.op, e as i32, 0, 0, &[]),
            }
        }
        gpu::DRV_SUBMIT_CMD => {
            if hnd != 0 {
                sys::handle_close(hnd);
            }
            let ctx_id = (h.a >> 32) as u32;
            let engine = h.b as u32;
            match drv.submit_cmd(ctx_id, engine, payload) {
                Ok(fence) => reply(ch, h.txid, h.op, 0, fence, 0, &[]),
                Err(e) => reply(ch, h.txid, h.op, e as i32, 0, 0, &[]),
            }
        }
        gpu::DRV_TEST_CRASH => {
            if hnd != 0 {
                sys::handle_close(hnd);
            }
            libd::println!("gpu-drv: intentional crash requested");
            panic!("intentional gpu driver test crash");
        }
        _ => {
            if hnd != 0 {
                sys::handle_close(hnd);
            }
            reply(ch, h.txid, h.op, sys::ERR_NOT_SUPPORTED as i32, 0, 0, &[]);
        }
    }
}
