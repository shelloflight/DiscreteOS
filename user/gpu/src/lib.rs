//! D-OS GPU & display service (`gpu.dsvc`).
//!
//! Manages:
//! - The **GOP framebuffer baseline** (`platform:display`, `DISPLAY_RGB32`, mapped write-combining
//!   lazily on first explicit `OP_PRESENT` so normal boots keep `terminal` undisturbed).
//! - Isolated, IOMMU-confined PCI GPU drivers connected via `devmgr.gpu` (`virtio-gpu.ddrv`,
//!   `amdgpu.ddrv`, `xe.ddrv`, `nvgpu.ddrv`), with transparent driver crash/restart reconnection,
//!   firmware GOP identity hand-off (`DRV_SET_GOP_INFO`), and asynchronous vsync flip completion
//!   forwarding (`DRV_FLIP_DONE` -> `EVT_FLIP_DONE`).
//!
//! Capability separation:
//! - `gpu.query`:   read-only adapter/mode/EDID/display-probe enumeration (`OP_LIST_ADAPTERS`,
//!   `OP_GET_MODES`, `OP_GET_DISPLAY_INFO`).
//! - `gpu.display`: exclusive display/modesetting/scanout/cursor/flip-test authority.
//! - `gpu.render`:  GPU context & command-buffer submission (never touches display scanout).

#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{Ordering, fence};

use dosgpu::{DamageRect, MAX_DIM, MAX_FB_BYTES, PixelFormat, blit_rect_wc};
use libd::gpu::{
    self, ADAPTER_INFO_BYTES, AdapterInfo, DISPLAY_PROBE_BYTES, DisplayProbeInfo, FLIP_TEST_BYTES,
    GOP_INFO_BYTES, GopInfoWire, MAX_PRESENT_RECTS, MODE_ENTRY_BYTES, MODE_FLAG_CURRENT,
    MODE_FLAG_PREFERRED, ModeEntry,
};
use libd::proto::{self, HEADER, Header};
use libd::sys::{self, DisplayInfo, Handle, MsgHandle};
use libd::{Mapping, Port, Startup, println, svc};

libd::entry!(dsvc_gpu, main);

const KEY_CTL: u64 = 1;
const KEY_DEVMGR: u64 = 2;
const KEY_CLIENT_BASE: u64 = 0x100;
const KEY_BACKEND_BASE: u64 = 0x200;

const CALL_TIMEOUT_NS: u64 = 10_000_000_000;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Role {
    Query,
    Display,
    Render,
}

struct Client {
    ch: Handle,
    role: Role,
}

struct GopFb {
    fb_id: u32,
    vmo: Handle,
    map: Mapping,
    width: u32,
    height: u32,
    pitch: u32,
    format: u32,
}

impl Drop for GopFb {
    fn drop(&mut self) {
        let _ = sys::vmar_unmap(libd::root_vmar(), self.map.addr, self.map.len);
        if self.vmo != 0 {
            sys::handle_close(self.vmo);
        }
    }
}

struct GopState {
    dev: Handle,
    disp: DisplayInfo,
    phys_base: u64,
    bar0: Option<Mapping>,
    fbs: Vec<GopFb>,
    next_fb_id: u32,
}

enum Backend {
    Gop(GopState),
    Pci { drv_key: u32, ch: Handle },
}

struct Adapter {
    info: AdapterInfo,
    modes: Vec<ModeEntry>,
    backend: Backend,
}

struct GpuSvc {
    port: Port,
    ctl: Handle,
    devmgr: Handle,
    test_mode: bool,
    gop_wire: Option<GopInfoWire>,
    adapters: Vec<Adapter>,
    next_adapter_id: u32,
    clients: Vec<Client>,
}

impl GpuSvc {
    fn init_gop(&mut self, disp_dev: Handle) {
        if disp_dev == 0 {
            return;
        }
        let Ok(di) = sys::display_info(disp_dev) else {
            return;
        };
        if di.kind != sys::DISPLAY_RGB32 || di.width == 0 || di.height == 0 {
            return;
        }
        let phys_base = sys::device_bar_addr(disp_dev, 0).unwrap_or(0);
        self.gop_wire = Some(GopInfoWire {
            phys_base,
            size: di.size,
            width: di.width,
            height: di.height,
            pitch: di.pitch,
            shifts: [di.red_shift, di.green_shift, di.blue_shift],
        });

        let id = self.next_adapter_id;
        self.next_adapter_id += 1;
        let mut info = AdapterInfo::empty();
        info.id = id;
        info.kind = gpu::KIND_GOP;
        info.online = true;
        info.caps = gpu::CAP_SCANOUT_2D | gpu::CAP_WC;
        info.width = di.width;
        info.height = di.height;
        info.vram_mib = ((di.size >> 20) as u32).max(1);
        let name = b"GOP Framebuffer";
        info.name[..name.len()].copy_from_slice(name);
        info.name_len = name.len() as u8;
        let mon = b"UEFI GOP";
        info.monitor[..mon.len()].copy_from_slice(mon);
        info.monitor_len = mon.len() as u8;

        let mode = ModeEntry {
            width: di.width,
            height: di.height,
            refresh_mhz: 60_000,
            flags: MODE_FLAG_PREFERRED | MODE_FLAG_CURRENT,
        };
        let modes = alloc::vec![mode];
        println!(
            "gpu: adapter #{} 'GOP Framebuffer' (gop, {}x{}, phys={:#x}, {} MiB WC baseline) ready",
            id, di.width, di.height, phys_base, info.vram_mib
        );
        self.adapters.push(Adapter {
            info,
            modes,
            backend: Backend::Gop(GopState {
                dev: disp_dev,
                disp: di,
                phys_base,
                bar0: None,
                fbs: Vec::new(),
                next_fb_id: 1,
            }),
        });
    }

    /// Pass firmware GOP framebuffer identity to a PCI GPU driver so it can verify scanout match.
    /// Returns updated `(caps, width, height)` if the driver refined its state.
    fn send_gop_info(ch: Handle, gop: GopInfoWire) -> Option<(u32, u32, u32)> {
        let mut req = [0u8; HEADER + GOP_INFO_BYTES];
        Header { txid: 0, op: gpu::DRV_SET_GOP_INFO, status: 0, a: 0, b: 0 }.put(&mut req);
        let mut enc = [0u8; GOP_INFO_BYTES];
        gop.encode(&mut enc);
        req[HEADER..HEADER + GOP_INFO_BYTES].copy_from_slice(&enc);
        let mut rep = [0u8; HEADER];
        let n = sys::channel_call(ch, &req, &mut rep, CALL_TIMEOUT_NS).ok()? as usize;
        let h = Header::get(&rep[..n])?;
        if h.status != 0 {
            return None;
        }
        Some((h.a as u32, h.b as u32, (h.b >> 32) as u32))
    }

    fn query_pci_modes(ch: Handle) -> (Vec<ModeEntry>, [u8; 24], u8) {
        let mut req = [0u8; HEADER];
        Header { txid: 0, op: gpu::DRV_GET_MODES, status: 0, a: 0, b: 0 }.put(&mut req);
        let mut rep = [0u8; HEADER + 24 + 16 * MODE_ENTRY_BYTES];
        let mut mon = [0u8; 24];
        let mut mon_len = 0u8;
        let mut modes = Vec::new();
        if let Ok(n) = sys::channel_call(ch, &req, &mut rep, CALL_TIMEOUT_NS) {
            let n = n as usize;
            if let Some(h) = Header::get(&rep[..n])
                && h.status == 0
                && n >= HEADER + 24
            {
                let ml = (h.b as usize).min(24);
                mon[..ml].copy_from_slice(&rep[HEADER..HEADER + ml]);
                mon_len = ml as u8;
                let body = &rep[HEADER + 24..n];
                let cnt = (h.a as usize).min(body.len() / MODE_ENTRY_BYTES);
                for i in 0..cnt {
                    if let Some(m) = ModeEntry::decode(&body[i * MODE_ENTRY_BYTES..(i + 1) * MODE_ENTRY_BYTES]) {
                        modes.push(m);
                    }
                }
            }
        }
        (modes, mon, mon_len)
    }

    fn on_devmgr_msg(&mut self) {
        let mut buf = [0u8; HEADER + 64];
        loop {
            let mut hs = [0 as Handle; 1];
            match sys::channel_read_h(self.devmgr, &mut buf, &mut hs, 0) {
                Ok((n, nh)) => {
                    let hnd = if nh > 0 { hs[0] } else { 0 };
                    let Some(h) = Header::get(&buf[..n]) else {
                        if hnd != 0 {
                            sys::handle_close(hnd);
                        }
                        continue;
                    };
                    match h.op {
                        gpu::BACKEND_ADD if hnd != 0 && n >= HEADER + 4 => {
                            let drv_key = u32::from_le_bytes([
                                buf[HEADER],
                                buf[HEADER + 1],
                                buf[HEADER + 2],
                                buf[HEADER + 3],
                            ]);
                            let name_bytes = &buf[HEADER + 4..n];
                            let (kind, vendor, device, vram_mib) = gpu::unpack_dev_a(h.a);
                            let (mut width, mut height, mut caps) = gpu::unpack_dev_b(h.b);

                            // Provide firmware GOP physical base & layout to PCI GPU driver so it can
                            // verify exact scanout identity and refine caps/mode before we query modes.
                            if let Some(gop) = self.gop_wire
                                && let Some((new_caps, new_w, new_h)) = Self::send_gop_info(hnd, gop)
                            {
                                caps = new_caps;
                                if new_w > 0 && new_h > 0 {
                                    width = new_w;
                                    height = new_h;
                                }
                            }
                            let (modes, mon, mon_len) = Self::query_pci_modes(hnd);

                            if let Some((idx, ad)) = self.adapters.iter_mut().enumerate().find(|(_, a)| {
                                matches!(a.backend, Backend::Pci { drv_key: k, .. } if k == drv_key)
                            }) {
                                if let Backend::Pci { ch, .. } = &mut ad.backend {
                                    if *ch != 0 {
                                        sys::handle_close(*ch);
                                    }
                                    *ch = hnd;
                                }
                                ad.info.online = true;
                                ad.info.width = width;
                                ad.info.height = height;
                                ad.info.caps = caps;
                                ad.info.restarts += 1;
                                ad.info.monitor = mon;
                                ad.info.monitor_len = mon_len;
                                ad.modes = modes;
                                self.port.arm(hnd, sys::READABLE | sys::PEER_CLOSED, KEY_BACKEND_BASE + idx as u64);
                                println!(
                                    "gpu: adapter #{} '{}' reconnected (restart {}) caps={:#x}",
                                    ad.info.id,
                                    ad.info.name_str(),
                                    ad.info.restarts,
                                    caps
                                );
                            } else {
                                let id = self.next_adapter_id;
                                self.next_adapter_id += 1;
                                let mut info = AdapterInfo::empty();
                                info.id = id;
                                info.kind = kind;
                                info.online = true;
                                info.vendor = vendor;
                                info.device = device;
                                info.caps = caps;
                                info.width = width;
                                info.height = height;
                                info.vram_mib = vram_mib;
                                info.monitor = mon;
                                info.monitor_len = mon_len;
                                let nl = name_bytes.len().min(40);
                                info.name[..nl].copy_from_slice(&name_bytes[..nl]);
                                info.name_len = nl as u8;
                                let idx = self.adapters.len();
                                println!(
                                    "gpu: adapter #{} '{}' ({}, {:04x}:{:04x}, {}x{}, {} MiB VRAM, caps={:#x}) ready",
                                    id,
                                    info.name_str(),
                                    info.kind_name(),
                                    vendor,
                                    device,
                                    width,
                                    height,
                                    vram_mib,
                                    caps
                                );
                                self.adapters.push(Adapter {
                                    info,
                                    modes,
                                    backend: Backend::Pci { drv_key, ch: hnd },
                                });
                                self.port.arm(hnd, sys::READABLE | sys::PEER_CLOSED, KEY_BACKEND_BASE + idx as u64);
                            }
                        }
                        gpu::BACKEND_GONE => {
                            if hnd != 0 {
                                sys::handle_close(hnd);
                            }
                            let drv_key = h.a as u32;
                            for ad in &mut self.adapters {
                                if let Backend::Pci { drv_key: k, ch } = &mut ad.backend
                                    && *k == drv_key
                                {
                                    if *ch != 0 {
                                        sys::handle_close(*ch);
                                        *ch = 0;
                                    }
                                    ad.info.online = false;
                                }
                            }
                        }
                        _ => {
                            if hnd != 0 {
                                sys::handle_close(hnd);
                            }
                        }
                    }
                }
                Err(sys::ERR_SHOULD_WAIT) => {
                    self.port.arm(self.devmgr, sys::READABLE | sys::PEER_CLOSED, KEY_DEVMGR);
                    return;
                }
                Err(_) => return,
            }
        }
    }

    /// Forward unsolicited `DRV_FLIP_DONE` events from a PCI GPU driver to `gpu.display` clients,
    /// or mark the backend offline on `PEER_CLOSED`.
    fn on_backend_event(&mut self, idx: usize) {
        let mut buf = [0u8; HEADER + 64];
        loop {
            let (dch, adapter_id) = match self.adapters.get(idx) {
                Some(ad) => match ad.backend {
                    Backend::Pci { ch, .. } if ch != 0 => (ch, ad.info.id),
                    _ => return,
                },
                None => return,
            };
            match sys::channel_read(dch, &mut buf, 0) {
                Ok(n) => {
                    let Some(h) = Header::get(&buf[..n as usize]) else {
                        continue;
                    };
                    if h.op == gpu::DRV_FLIP_DONE {
                        let frames = h.a & !(1u64 << 63);
                        let late = (h.a >> 63) != 0;
                        let ts_ns = h.b;
                        if let Some(ad) = self.adapters.get_mut(idx) {
                            ad.info.frames = frames;
                        }
                        self.broadcast_flip_done(adapter_id, frames, ts_ns, late);
                    }
                }
                Err(sys::ERR_SHOULD_WAIT) => {
                    self.port.arm(dch, sys::READABLE | sys::PEER_CLOSED, KEY_BACKEND_BASE + idx as u64);
                    return;
                }
                Err(_) => {
                    self.on_backend_closed(idx);
                    return;
                }
            }
        }
    }

    fn broadcast_flip_done(&self, adapter_id: u32, frames: u64, ts_ns: u64, late: bool) {
        let mut msg = [0u8; HEADER + 8];
        Header {
            txid: 0,
            op: gpu::EVT_FLIP_DONE,
            status: 0,
            a: u64::from(adapter_id) | (u64::from(late) << 32),
            b: frames,
        }
        .put(&mut msg);
        msg[HEADER..HEADER + 8].copy_from_slice(&ts_ns.to_le_bytes());
        for c in &self.clients {
            if c.role == Role::Display && c.ch != 0 {
                let _ = sys::channel_write(c.ch, &msg);
            }
        }
    }

    fn on_backend_closed(&mut self, idx: usize) {
        if let Some(ad) = self.adapters.get_mut(idx)
            && let Backend::Pci { ch, .. } = &mut ad.backend
        {
            if *ch != 0 {
                sys::handle_close(*ch);
                *ch = 0;
            }
            ad.info.online = false;
            println!("gpu: adapter #{} '{}' offline (driver exited)", ad.info.id, ad.info.name_str());
        }
    }

    fn on_ctl_msg(&mut self) -> bool {
        let mut buf = [0u8; HEADER + 64];
        loop {
            let mut hs = [0 as Handle; 1];
            match sys::channel_read_h(self.ctl, &mut buf, &mut hs, 0) {
                Ok((n, nh)) => {
                    let hnd = if nh > 0 { hs[0] } else { 0 };
                    match Header::get(&buf[..n]) {
                        Some(h) if h.op == svc::CONNECT && hnd != 0 => {
                            let ep = &buf[HEADER..n];
                            if ep == b"devmgr.gpu" {
                                if self.devmgr != 0 {
                                    sys::handle_close(self.devmgr);
                                }
                                self.devmgr = hnd;
                                self.port.arm(hnd, sys::READABLE | sys::PEER_CLOSED, KEY_DEVMGR);
                            } else {
                                let role = match ep {
                                    b"query" => Role::Query,
                                    b"display" => Role::Display,
                                    b"render" => Role::Render,
                                    _ => {
                                        sys::handle_close(hnd);
                                        continue;
                                    }
                                };
                                let idx = self.clients.len();
                                self.clients.push(Client { ch: hnd, role });
                                self.port.arm(hnd, sys::READABLE | sys::PEER_CLOSED, KEY_CLIENT_BASE + idx as u64);
                            }
                        }
                        Some(h) if h.op == svc::SHUTDOWN => {
                            if hnd != 0 {
                                sys::handle_close(hnd);
                            }
                            // Ask every active PCI GPU driver to hand display back to firmware GOP.
                            for ad in &self.adapters {
                                if let Backend::Pci { ch: dch, .. } = ad.backend
                                    && dch != 0
                                {
                                    let mut req = [0u8; HEADER];
                                    Header { txid: 0, op: gpu::DRV_RELEASE_DISPLAY, status: 0, a: 0, b: 0 }.put(&mut req);
                                    let mut rep = [0u8; HEADER];
                                    let _ = sys::channel_call(dch, &req, &mut rep, 2_000_000_000);
                                }
                            }
                            return false;
                        }
                        _ => {
                            if hnd != 0 {
                                sys::handle_close(hnd);
                            }
                        }
                    }
                }
                Err(sys::ERR_SHOULD_WAIT) => {
                    self.port.arm(self.ctl, sys::READABLE | sys::PEER_CLOSED, KEY_CTL);
                    return true;
                }
                Err(_) => return true,
            }
        }
    }

    fn find_adapter_mut(&mut self, id: u32) -> Option<&mut Adapter> {
        if id == 0 {
            let pci = self
                .adapters
                .iter()
                .position(|a| a.info.online && a.info.kind != gpu::KIND_GOP);
            let idx = pci.or_else(|| self.adapters.iter().position(|a| a.info.online))?;
            return self.adapters.get_mut(idx);
        }
        self.adapters.iter_mut().find(|a| a.info.id == id)
    }

    fn reply(ch: Handle, txid: u32, op: u32, status: i32, a: u64, b: u64, payload: &[u8]) {
        let mut out = alloc::vec![0u8; HEADER + payload.len()];
        Header { txid, op, status, a, b }.put(&mut out);
        out[HEADER..].copy_from_slice(payload);
        let _ = sys::channel_write(ch, &out);
    }

    fn on_client_msg(&mut self, idx: usize) {
        let mut buf = alloc::vec![0u8; HEADER + 4096];
        loop {
            let Some(c) = self.clients.get(idx) else { return };
            if c.ch == 0 {
                return;
            }
            let (ch, role) = (c.ch, c.role);
            let mut hs = [0 as Handle; 1];
            match sys::channel_read_h(ch, &mut buf, &mut hs, 0) {
                Ok((n, nh)) => {
                    let hnd = if nh > 0 { hs[0] } else { 0 };
                    let Some(h) = Header::get(&buf[..n]) else {
                        if hnd != 0 {
                            sys::handle_close(hnd);
                        }
                        continue;
                    };
                    self.dispatch_client(ch, role, h, &buf[HEADER..n], hnd);
                }
                Err(sys::ERR_SHOULD_WAIT) => {
                    self.port.arm(ch, sys::READABLE | sys::PEER_CLOSED, KEY_CLIENT_BASE + idx as u64);
                    return;
                }
                Err(_) => {
                    sys::handle_close(ch);
                    if let Some(c) = self.clients.get_mut(idx) {
                        c.ch = 0;
                    }
                    return;
                }
            }
        }
    }

    fn gop_present_rects(g: &mut GopState, fb_id: u32, rects: &[DamageRect]) -> Result<(), i64> {
        if g.bar0.is_none() {
            let Ok(vmo) = sys::device_map_bar(g.dev, 0) else {
                return Err(sys::ERR_ACCESS_DENIED);
            };
            let Ok(m) = Mapping::of(vmo, g.disp.size) else {
                sys::handle_close(vmo);
                return Err(sys::ERR_NO_MEMORY);
            };
            g.bar0 = Some(m);
        }
        let Some(fb) = g.fbs.iter().find(|f| f.fb_id == fb_id) else {
            return Err(sys::ERR_INVALID_ARGS);
        };
        let Some(bar0) = g.bar0.as_ref() else {
            return Err(sys::ERR_BAD_STATE);
        };
        let bw = fb.width.min(g.disp.width);
        let bh = fb.height.min(g.disp.height);
        let fmt = PixelFormat::from_u32(fb.format).unwrap_or(PixelFormat::Xrgb8888);
        let shifts = [g.disp.red_shift, g.disp.green_shift, g.disp.blue_shift];
        let full = [DamageRect::full(bw, bh)];
        let list = if rects.is_empty() { &full[..] } else { rects };
        for &r in list {
            let rect = if r.w == 0 || r.h == 0 { DamageRect::full(bw, bh) } else { r };
            blit_rect_wc(
                fb.map.bytes(),
                fb.pitch,
                fmt,
                g.disp.pitch,
                shifts,
                bw,
                bh,
                rect,
                |off, px| {
                    if off + 4 <= bar0.len {
                        bar0.w32(off, px);
                    }
                },
            );
        }
        fence(Ordering::Release);
        Ok(())
    }

    fn dispatch_client(&mut self, ch: Handle, role: Role, h: Header, payload: &[u8], hnd: Handle) {
        let close_h = |hnd: Handle| {
            if hnd != 0 {
                sys::handle_close(hnd);
            }
        };
        match h.op {
            gpu::OP_LIST_ADAPTERS => {
                close_h(hnd);
                let mut body = Vec::with_capacity(self.adapters.len() * ADAPTER_INFO_BYTES);
                for ad in &self.adapters {
                    let mut enc = [0u8; ADAPTER_INFO_BYTES];
                    ad.info.encode(&mut enc);
                    body.extend_from_slice(&enc);
                }
                Self::reply(ch, h.txid, h.op, 0, self.adapters.len() as u64, 0, &body);
            }
            gpu::OP_GET_MODES => {
                close_h(hnd);
                let id = h.a as u32;
                let Some(ad) = self.find_adapter_mut(id) else {
                    Self::reply(ch, h.txid, h.op, sys::ERR_OUT_OF_RANGE as i32, 0, 0, &[]);
                    return;
                };
                let mut body = Vec::with_capacity(ad.modes.len() * MODE_ENTRY_BYTES);
                for m in &ad.modes {
                    let mut enc = [0u8; MODE_ENTRY_BYTES];
                    m.encode(&mut enc);
                    body.extend_from_slice(&enc);
                }
                Self::reply(ch, h.txid, h.op, 0, ad.modes.len() as u64, 0, &body);
            }
            gpu::OP_GET_DISPLAY_INFO => {
                close_h(hnd);
                let id = h.a as u32;
                let Some(ad) = self.find_adapter_mut(id) else {
                    Self::reply(ch, h.txid, h.op, sys::ERR_OUT_OF_RANGE as i32, 0, 0, &[]);
                    return;
                };
                let adapter_id = ad.info.id;
                match &ad.backend {
                    Backend::Gop(g) => {
                        let mut p = DisplayProbeInfo::empty();
                        p.adapter_id = adapter_id;
                        p.active_pipes = 1;
                        p.width = g.disp.width;
                        p.height = g.disp.height;
                        p.pitch_bytes = g.disp.pitch;
                        p.measured_mhz = 60_000;
                        p.gop_phys_base = g.phys_base;
                        p.flags = gpu::PROBE_GOP_MATCHED;
                        let mon = b"UEFI GOP";
                        p.monitor_name[..mon.len()].copy_from_slice(mon);
                        p.monitor_len = mon.len() as u8;
                        p.set_note(b"UEFI GOP linear framebuffer");
                        let mut enc = [0u8; DISPLAY_PROBE_BYTES];
                        p.encode(&mut enc);
                        Self::reply(ch, h.txid, h.op, 0, 0, 0, &enc);
                    }
                    Backend::Pci { ch: dch, .. } => {
                        if *dch == 0 {
                            Self::reply(ch, h.txid, h.op, sys::ERR_BAD_STATE as i32, 0, 0, &[]);
                            return;
                        }
                        let mut req = [0u8; HEADER];
                        Header { txid: 0, op: gpu::DRV_GET_DISPLAY_INFO, status: 0, a: 0, b: 0 }.put(&mut req);
                        let mut rep = [0u8; HEADER + DISPLAY_PROBE_BYTES];
                        match sys::channel_call(*dch, &req, &mut rep, CALL_TIMEOUT_NS) {
                            Ok(rn) => {
                                let rn = rn as usize;
                                let dh = Header::get(&rep[..rn]).unwrap_or_default();
                                if dh.status == 0 && rn >= HEADER + DISPLAY_PROBE_BYTES {
                                    let mut p = DisplayProbeInfo::decode(&rep[HEADER..rn]).unwrap_or_else(DisplayProbeInfo::empty);
                                    p.adapter_id = adapter_id;
                                    let mut enc = [0u8; DISPLAY_PROBE_BYTES];
                                    p.encode(&mut enc);
                                    Self::reply(ch, h.txid, h.op, 0, 0, 0, &enc);
                                } else {
                                    // Synthesize basic probe for drivers without DCN (e.g. virtio-gpu).
                                    let mut p = DisplayProbeInfo::empty();
                                    p.adapter_id = adapter_id;
                                    p.active_pipes = 1;
                                    p.width = ad.info.width;
                                    p.height = ad.info.height;
                                    p.pitch_bytes = ad.info.width.saturating_mul(4);
                                    p.measured_mhz = ad.modes.first().map_or(60_000, |m| m.refresh_mhz);
                                    p.monitor_name = ad.info.monitor;
                                    p.monitor_len = ad.info.monitor_len;
                                    p.set_note(b"non-DCN PCI adapter");
                                    let mut enc = [0u8; DISPLAY_PROBE_BYTES];
                                    p.encode(&mut enc);
                                    Self::reply(ch, h.txid, h.op, 0, 0, 0, &enc);
                                }
                            }
                            Err(e) => Self::reply(ch, h.txid, h.op, e as i32, 0, 0, &[]),
                        }
                    }
                }
            }
            gpu::OP_ATTACH_FB => {
                if role != Role::Display {
                    close_h(hnd);
                    println!("gpu: refused OP_ATTACH_FB on non-display endpoint");
                    Self::reply(ch, h.txid, h.op, sys::ERR_ACCESS_DENIED as i32, 0, 0, &[]);
                    return;
                }
                if hnd == 0 || payload.len() < 4 {
                    close_h(hnd);
                    Self::reply(ch, h.txid, h.op, sys::ERR_INVALID_ARGS as i32, 0, 0, &[]);
                    return;
                }
                let id = h.a as u32;
                let format = (h.a >> 32) as u32;
                let width = h.b as u32;
                let height = (h.b >> 32) as u32;
                let pitch = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
                let Some(ad) = self.find_adapter_mut(id) else {
                    close_h(hnd);
                    Self::reply(ch, h.txid, h.op, sys::ERR_OUT_OF_RANGE as i32, 0, 0, &[]);
                    return;
                };
                match &mut ad.backend {
                    Backend::Gop(g) => {
                        if width == 0 || height == 0 || width > MAX_DIM || height > MAX_DIM || pitch < width.saturating_mul(4) {
                            close_h(hnd);
                            Self::reply(ch, h.txid, h.op, sys::ERR_INVALID_ARGS as i32, 0, 0, &[]);
                            return;
                        }
                        let need = u64::from(pitch).saturating_mul(u64::from(height));
                        if need == 0 || need > MAX_FB_BYTES || sys::vmo_size(hnd).is_err_and(|_| true) || sys::vmo_size(hnd).unwrap_or(0) < need {
                            close_h(hnd);
                            Self::reply(ch, h.txid, h.op, sys::ERR_OUT_OF_RANGE as i32, 0, 0, &[]);
                            return;
                        }
                        let Ok(map) = Mapping::of_ro(hnd, need) else {
                            close_h(hnd);
                            Self::reply(ch, h.txid, h.op, sys::ERR_NO_MEMORY as i32, 0, 0, &[]);
                            return;
                        };
                        if g.fbs.len() >= 4 {
                            g.fbs.remove(0);
                        }
                        let fb_id = g.next_fb_id;
                        g.next_fb_id += 1;
                        g.fbs.push(GopFb { fb_id, vmo: hnd, map, width, height, pitch, format });
                        Self::reply(ch, h.txid, h.op, 0, u64::from(fb_id), 0, &[]);
                    }
                    Backend::Pci { ch: dch, .. } => {
                        if *dch == 0 {
                            close_h(hnd);
                            Self::reply(ch, h.txid, h.op, sys::ERR_BAD_STATE as i32, 0, 0, &[]);
                            return;
                        }
                        let mut req = [0u8; HEADER + 4];
                        Header { txid: 0, op: gpu::DRV_ATTACH_FB, status: 0, a: h.a, b: h.b }.put(&mut req);
                        req[HEADER..HEADER + 4].copy_from_slice(&payload[..4]);
                        let mut rep = [0u8; HEADER];
                        let mut rh = [0 as Handle; 1];
                        match sys::channel_call_h(
                            *dch,
                            &req,
                            &[MsgHandle { handle: hnd, rights: sys::RIGHTS_SAME }],
                            &mut rep,
                            &mut rh,
                            CALL_TIMEOUT_NS,
                        ) {
                            Ok((rn, _)) if Header::get(&rep[..rn]).is_some() => {
                                let dh = Header::get(&rep[..rn]).unwrap_or_default();
                                Self::reply(ch, h.txid, h.op, dh.status, dh.a, dh.b, &[]);
                            }
                            Ok(_) => Self::reply(ch, h.txid, h.op, sys::ERR_BAD_STATE as i32, 0, 0, &[]),
                            Err(e) => Self::reply(ch, h.txid, h.op, e as i32, 0, 0, &[]),
                        }
                    }
                }
            }
            gpu::OP_SET_MODE => {
                close_h(hnd);
                if role != Role::Display {
                    println!("gpu: refused OP_SET_MODE on non-display endpoint");
                    Self::reply(ch, h.txid, h.op, sys::ERR_ACCESS_DENIED as i32, 0, 0, &[]);
                    return;
                }
                let id = h.a as u32;
                let width = h.b as u32;
                let height = (h.b >> 32) as u32;
                let Some(ad) = self.find_adapter_mut(id) else {
                    Self::reply(ch, h.txid, h.op, sys::ERR_OUT_OF_RANGE as i32, 0, 0, &[]);
                    return;
                };
                match &mut ad.backend {
                    Backend::Gop(g) => {
                        if width == g.disp.width && height == g.disp.height {
                            Self::reply(ch, h.txid, h.op, 0, 0, 0, &[]);
                        } else {
                            Self::reply(ch, h.txid, h.op, sys::ERR_NOT_SUPPORTED as i32, 0, 0, &[]);
                        }
                    }
                    Backend::Pci { ch: dch, .. } => {
                        if *dch == 0 {
                            Self::reply(ch, h.txid, h.op, sys::ERR_BAD_STATE as i32, 0, 0, &[]);
                            return;
                        }
                        let mut req = [0u8; HEADER];
                        Header { txid: 0, op: gpu::DRV_SET_MODE, status: 0, a: 0, b: h.b }.put(&mut req);
                        let mut rep = [0u8; HEADER];
                        match sys::channel_call(*dch, &req, &mut rep, CALL_TIMEOUT_NS) {
                            Ok(rn) => {
                                let dh = Header::get(&rep[..rn as usize]).unwrap_or_default();
                                if dh.status == 0 {
                                    ad.info.width = width;
                                    ad.info.height = height;
                                }
                                Self::reply(ch, h.txid, h.op, dh.status, 0, 0, &[]);
                            }
                            Err(e) => Self::reply(ch, h.txid, h.op, e as i32, 0, 0, &[]),
                        }
                    }
                }
            }
            gpu::OP_SET_MODE_EX => {
                close_h(hnd);
                if role != Role::Display {
                    Self::reply(ch, h.txid, h.op, sys::ERR_ACCESS_DENIED as i32, 0, 0, &[]);
                    return;
                }
                if payload.len() < 4 {
                    Self::reply(ch, h.txid, h.op, sys::ERR_INVALID_ARGS as i32, 0, 0, &[]);
                    return;
                }
                let id = h.a as u32;
                let width = h.b as u32;
                let height = (h.b >> 32) as u32;
                let Some(ad) = self.find_adapter_mut(id) else {
                    Self::reply(ch, h.txid, h.op, sys::ERR_OUT_OF_RANGE as i32, 0, 0, &[]);
                    return;
                };
                match &mut ad.backend {
                    Backend::Gop(_) => Self::reply(ch, h.txid, h.op, sys::ERR_NOT_SUPPORTED as i32, 0, 0, &[]),
                    Backend::Pci { ch: dch, .. } => {
                        if *dch == 0 {
                            Self::reply(ch, h.txid, h.op, sys::ERR_BAD_STATE as i32, 0, 0, &[]);
                            return;
                        }
                        let mut req = [0u8; HEADER + 4];
                        Header { txid: 0, op: gpu::DRV_SET_MODE_EX, status: 0, a: h.a, b: h.b }.put(&mut req);
                        req[HEADER..HEADER + 4].copy_from_slice(&payload[..4]);
                        let mut rep = [0u8; HEADER];
                        match sys::channel_call(*dch, &req, &mut rep, CALL_TIMEOUT_NS) {
                            Ok(rn) => {
                                let dh = Header::get(&rep[..rn as usize]).unwrap_or_default();
                                if dh.status == 0 {
                                    ad.info.width = width;
                                    ad.info.height = height;
                                    let (modes, mon, mon_len) = Self::query_pci_modes(*dch);
                                    ad.modes = modes;
                                    ad.info.monitor = mon;
                                    ad.info.monitor_len = mon_len;
                                }
                                Self::reply(ch, h.txid, h.op, dh.status, 0, 0, &[]);
                            }
                            Err(e) => Self::reply(ch, h.txid, h.op, e as i32, 0, 0, &[]),
                        }
                    }
                }
            }
            gpu::OP_PRESENT => {
                close_h(hnd);
                if role != Role::Display {
                    println!("gpu: refused OP_PRESENT on non-display endpoint");
                    Self::reply(ch, h.txid, h.op, sys::ERR_ACCESS_DENIED as i32, 0, 0, &[]);
                    return;
                }
                if payload.len() < 8 {
                    Self::reply(ch, h.txid, h.op, sys::ERR_INVALID_ARGS as i32, 0, 0, &[]);
                    return;
                }
                let id = h.a as u32;
                let fb_id = (h.a >> 32) as u32;
                let x = h.b as u32;
                let y = (h.b >> 32) as u32;
                let w = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
                let hh = u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]);
                let Some(ad) = self.find_adapter_mut(id) else {
                    Self::reply(ch, h.txid, h.op, sys::ERR_OUT_OF_RANGE as i32, 0, 0, &[]);
                    return;
                };
                match &mut ad.backend {
                    Backend::Gop(g) => match Self::gop_present_rects(g, fb_id, &[DamageRect { x, y, w, h: hh }]) {
                        Ok(()) => {
                            ad.info.frames += 1;
                            Self::reply(ch, h.txid, h.op, 0, ad.info.frames, 0, &[]);
                        }
                        Err(e) => Self::reply(ch, h.txid, h.op, e as i32, 0, 0, &[]),
                    },
                    Backend::Pci { ch: dch, .. } => {
                        if *dch == 0 {
                            Self::reply(ch, h.txid, h.op, sys::ERR_BAD_STATE as i32, 0, 0, &[]);
                            return;
                        }
                        let mut req = [0u8; HEADER + 8];
                        Header { txid: 0, op: gpu::DRV_PRESENT, status: 0, a: h.a, b: h.b }.put(&mut req);
                        req[HEADER..HEADER + 8].copy_from_slice(&payload[..8]);
                        let mut rep = [0u8; HEADER];
                        match sys::channel_call(*dch, &req, &mut rep, CALL_TIMEOUT_NS) {
                            Ok(rn) => {
                                let dh = Header::get(&rep[..rn as usize]).unwrap_or_default();
                                if dh.status == 0 {
                                    ad.info.frames = dh.a;
                                }
                                Self::reply(ch, h.txid, h.op, dh.status, dh.a, 0, &[]);
                            }
                            Err(e) => Self::reply(ch, h.txid, h.op, e as i32, 0, 0, &[]),
                        }
                    }
                }
            }
            gpu::OP_PRESENT_MULTI => {
                close_h(hnd);
                if role != Role::Display {
                    Self::reply(ch, h.txid, h.op, sys::ERR_ACCESS_DENIED as i32, 0, 0, &[]);
                    return;
                }
                let id = h.a as u32;
                let fb_id = (h.a >> 32) as u32;
                let cnt = (h.b as usize).min(MAX_PRESENT_RECTS).min(payload.len() / 16);
                let Some(ad) = self.find_adapter_mut(id) else {
                    Self::reply(ch, h.txid, h.op, sys::ERR_OUT_OF_RANGE as i32, 0, 0, &[]);
                    return;
                };
                match &mut ad.backend {
                    Backend::Gop(g) => {
                        let mut rects = [DamageRect::EMPTY; MAX_PRESENT_RECTS];
                        for (i, slot) in rects.iter_mut().take(cnt).enumerate() {
                            let o = i * 16;
                            *slot = DamageRect {
                                x: u32::from_le_bytes([payload[o], payload[o + 1], payload[o + 2], payload[o + 3]]),
                                y: u32::from_le_bytes([payload[o + 4], payload[o + 5], payload[o + 6], payload[o + 7]]),
                                w: u32::from_le_bytes([payload[o + 8], payload[o + 9], payload[o + 10], payload[o + 11]]),
                                h: u32::from_le_bytes([payload[o + 12], payload[o + 13], payload[o + 14], payload[o + 15]]),
                            };
                        }
                        match Self::gop_present_rects(g, fb_id, &rects[..cnt]) {
                            Ok(()) => {
                                ad.info.frames += 1;
                                Self::reply(ch, h.txid, h.op, 0, ad.info.frames, 0, &[]);
                            }
                            Err(e) => Self::reply(ch, h.txid, h.op, e as i32, 0, 0, &[]),
                        }
                    }
                    Backend::Pci { ch: dch, .. } => {
                        if *dch == 0 {
                            Self::reply(ch, h.txid, h.op, sys::ERR_BAD_STATE as i32, 0, 0, &[]);
                            return;
                        }
                        let plen = cnt * 16;
                        let mut req = alloc::vec![0u8; HEADER + plen];
                        Header { txid: 0, op: gpu::DRV_PRESENT_MULTI, status: 0, a: h.a, b: cnt as u64 }.put(&mut req);
                        req[HEADER..HEADER + plen].copy_from_slice(&payload[..plen]);
                        let mut rep = [0u8; HEADER];
                        match sys::channel_call(*dch, &req, &mut rep, CALL_TIMEOUT_NS) {
                            Ok(rn) => {
                                let dh = Header::get(&rep[..rn as usize]).unwrap_or_default();
                                if dh.status == 0 {
                                    ad.info.frames = dh.a;
                                }
                                Self::reply(ch, h.txid, h.op, dh.status, dh.a, dh.b, &[]);
                            }
                            Err(e) => Self::reply(ch, h.txid, h.op, e as i32, 0, 0, &[]),
                        }
                    }
                }
            }
            gpu::OP_RELEASE_DISPLAY => {
                close_h(hnd);
                if role != Role::Display {
                    Self::reply(ch, h.txid, h.op, sys::ERR_ACCESS_DENIED as i32, 0, 0, &[]);
                    return;
                }
                let id = h.a as u32;
                let Some(ad) = self.find_adapter_mut(id) else {
                    Self::reply(ch, h.txid, h.op, sys::ERR_OUT_OF_RANGE as i32, 0, 0, &[]);
                    return;
                };
                match &ad.backend {
                    Backend::Gop(_) => Self::reply(ch, h.txid, h.op, 0, 0, 0, &[]),
                    Backend::Pci { ch: dch, .. } => {
                        if *dch == 0 {
                            Self::reply(ch, h.txid, h.op, 0, 0, 0, &[]);
                            return;
                        }
                        let mut req = [0u8; HEADER];
                        Header { txid: 0, op: gpu::DRV_RELEASE_DISPLAY, status: 0, a: 0, b: 0 }.put(&mut req);
                        let mut rep = [0u8; HEADER];
                        match sys::channel_call(*dch, &req, &mut rep, CALL_TIMEOUT_NS) {
                            Ok(rn) => {
                                let dh = Header::get(&rep[..rn as usize]).unwrap_or_default();
                                Self::reply(ch, h.txid, h.op, dh.status, 0, 0, &[]);
                            }
                            Err(e) => Self::reply(ch, h.txid, h.op, e as i32, 0, 0, &[]),
                        }
                    }
                }
            }
            gpu::OP_SET_VRR | gpu::OP_SET_HDR => {
                close_h(hnd);
                if role != Role::Display {
                    Self::reply(ch, h.txid, h.op, sys::ERR_ACCESS_DENIED as i32, 0, 0, &[]);
                    return;
                }
                let id = h.a as u32;
                let Some(ad) = self.find_adapter_mut(id) else {
                    Self::reply(ch, h.txid, h.op, sys::ERR_OUT_OF_RANGE as i32, 0, 0, &[]);
                    return;
                };
                let drv_op = if h.op == gpu::OP_SET_VRR { gpu::DRV_SET_VRR } else { gpu::DRV_SET_HDR };
                match &ad.backend {
                    Backend::Gop(_) => Self::reply(ch, h.txid, h.op, sys::ERR_NOT_SUPPORTED as i32, 0, 0, &[]),
                    Backend::Pci { ch: dch, .. } if *dch != 0 => {
                        let mut req = [0u8; HEADER];
                        Header { txid: 0, op: drv_op, status: 0, a: 0, b: h.b }.put(&mut req);
                        let mut rep = [0u8; HEADER];
                        match sys::channel_call(*dch, &req, &mut rep, CALL_TIMEOUT_NS) {
                            Ok(rn) => {
                                let dh = Header::get(&rep[..rn as usize]).unwrap_or_default();
                                Self::reply(ch, h.txid, h.op, dh.status, 0, 0, &[]);
                            }
                            Err(e) => Self::reply(ch, h.txid, h.op, e as i32, 0, 0, &[]),
                        }
                    }
                    _ => Self::reply(ch, h.txid, h.op, sys::ERR_BAD_STATE as i32, 0, 0, &[]),
                }
            }
            gpu::OP_FLIP_TEST => {
                close_h(hnd);
                if role != Role::Display {
                    println!("gpu: refused OP_FLIP_TEST on non-display endpoint");
                    Self::reply(ch, h.txid, h.op, sys::ERR_ACCESS_DENIED as i32, 0, 0, &[]);
                    return;
                }
                let id = h.a as u32;
                let dur = (h.b as u32).clamp(500, 15_000);
                let Some(ad) = self.find_adapter_mut(id) else {
                    Self::reply(ch, h.txid, h.op, sys::ERR_OUT_OF_RANGE as i32, 0, 0, &[]);
                    return;
                };
                match &ad.backend {
                    Backend::Gop(_) => Self::reply(ch, h.txid, h.op, sys::ERR_NOT_SUPPORTED as i32, 0, 0, &[]),
                    Backend::Pci { ch: dch, .. } if *dch != 0 => {
                        let mut req = [0u8; HEADER];
                        Header { txid: 0, op: gpu::DRV_FLIP_TEST, status: 0, a: 0, b: u64::from(dur) }.put(&mut req);
                        let mut rep = [0u8; HEADER + FLIP_TEST_BYTES];
                        let timeout = u64::from(dur) * 1_000_000 + CALL_TIMEOUT_NS;
                        match sys::channel_call(*dch, &req, &mut rep, timeout) {
                            Ok(rn) => {
                                let rn = rn as usize;
                                let dh = Header::get(&rep[..rn]).unwrap_or_default();
                                let body = if rn > HEADER { &rep[HEADER..rn] } else { &[] };
                                Self::reply(ch, h.txid, h.op, dh.status, dh.a, dh.b, body);
                            }
                            Err(e) => Self::reply(ch, h.txid, h.op, e as i32, 0, 0, &[]),
                        }
                    }
                    _ => Self::reply(ch, h.txid, h.op, sys::ERR_BAD_STATE as i32, 0, 0, &[]),
                }
            }
            gpu::OP_SET_CURSOR => {
                if role != Role::Display {
                    close_h(hnd);
                    Self::reply(ch, h.txid, h.op, sys::ERR_ACCESS_DENIED as i32, 0, 0, &[]);
                    return;
                }
                if hnd == 0 {
                    Self::reply(ch, h.txid, h.op, sys::ERR_INVALID_ARGS as i32, 0, 0, &[]);
                    return;
                }
                let id = h.a as u32;
                let Some(ad) = self.find_adapter_mut(id) else {
                    close_h(hnd);
                    Self::reply(ch, h.txid, h.op, sys::ERR_OUT_OF_RANGE as i32, 0, 0, &[]);
                    return;
                };
                match &ad.backend {
                    Backend::Gop(_) => {
                        close_h(hnd);
                        Self::reply(ch, h.txid, h.op, sys::ERR_NOT_SUPPORTED as i32, 0, 0, &[]);
                    }
                    Backend::Pci { ch: dch, .. } => {
                        if *dch == 0 {
                            close_h(hnd);
                            Self::reply(ch, h.txid, h.op, sys::ERR_BAD_STATE as i32, 0, 0, &[]);
                            return;
                        }
                        let mut req = [0u8; HEADER];
                        Header { txid: 0, op: gpu::DRV_SET_CURSOR, status: 0, a: 0, b: h.b }.put(&mut req);
                        let mut rep = [0u8; HEADER];
                        let mut rh = [0 as Handle; 1];
                        match sys::channel_call_h(
                            *dch,
                            &req,
                            &[MsgHandle { handle: hnd, rights: sys::RIGHTS_SAME }],
                            &mut rep,
                            &mut rh,
                            CALL_TIMEOUT_NS,
                        ) {
                            Ok((rn, _)) => {
                                let dh = Header::get(&rep[..rn]).unwrap_or_default();
                                Self::reply(ch, h.txid, h.op, dh.status, 0, 0, &[]);
                            }
                            Err(e) => Self::reply(ch, h.txid, h.op, e as i32, 0, 0, &[]),
                        }
                    }
                }
            }
            gpu::OP_MOVE_CURSOR => {
                close_h(hnd);
                if role != Role::Display {
                    Self::reply(ch, h.txid, h.op, sys::ERR_ACCESS_DENIED as i32, 0, 0, &[]);
                    return;
                }
                let id = h.a as u32;
                let Some(ad) = self.find_adapter_mut(id) else {
                    Self::reply(ch, h.txid, h.op, sys::ERR_OUT_OF_RANGE as i32, 0, 0, &[]);
                    return;
                };
                match &ad.backend {
                    Backend::Gop(_) => Self::reply(ch, h.txid, h.op, sys::ERR_NOT_SUPPORTED as i32, 0, 0, &[]),
                    Backend::Pci { ch: dch, .. } => {
                        if *dch == 0 {
                            Self::reply(ch, h.txid, h.op, sys::ERR_BAD_STATE as i32, 0, 0, &[]);
                            return;
                        }
                        let mut req = [0u8; HEADER];
                        Header { txid: 0, op: gpu::DRV_MOVE_CURSOR, status: 0, a: 0, b: h.b }.put(&mut req);
                        let mut rep = [0u8; HEADER];
                        match sys::channel_call(*dch, &req, &mut rep, CALL_TIMEOUT_NS) {
                            Ok(rn) => {
                                let dh = Header::get(&rep[..rn as usize]).unwrap_or_default();
                                Self::reply(ch, h.txid, h.op, dh.status, 0, 0, &[]);
                            }
                            Err(e) => Self::reply(ch, h.txid, h.op, e as i32, 0, 0, &[]),
                        }
                    }
                }
            }
            gpu::OP_CTX_CREATE | gpu::OP_CTX_DESTROY | gpu::OP_SUBMIT_CMD => {
                close_h(hnd);
                if role != Role::Render {
                    println!("gpu: refused render op {} on non-render endpoint", h.op);
                    Self::reply(ch, h.txid, h.op, sys::ERR_ACCESS_DENIED as i32, 0, 0, &[]);
                    return;
                }
                let id = h.a as u32;
                let Some(ad) = self.find_adapter_mut(id) else {
                    Self::reply(ch, h.txid, h.op, sys::ERR_OUT_OF_RANGE as i32, 0, 0, &[]);
                    return;
                };
                let drv_op = match h.op {
                    gpu::OP_CTX_CREATE => gpu::DRV_CTX_CREATE,
                    gpu::OP_CTX_DESTROY => gpu::DRV_CTX_DESTROY,
                    _ => gpu::DRV_SUBMIT_CMD,
                };
                match &ad.backend {
                    Backend::Gop(_) => Self::reply(ch, h.txid, h.op, sys::ERR_NOT_SUPPORTED as i32, 0, 0, &[]),
                    Backend::Pci { ch: dch, .. } => {
                        if *dch == 0 {
                            Self::reply(ch, h.txid, h.op, sys::ERR_BAD_STATE as i32, 0, 0, &[]);
                            return;
                        }
                        let mut req = alloc::vec![0u8; HEADER + payload.len()];
                        Header { txid: 0, op: drv_op, status: 0, a: h.a, b: h.b }.put(&mut req);
                        req[HEADER..].copy_from_slice(payload);
                        let mut rep = [0u8; HEADER];
                        match sys::channel_call(*dch, &req, &mut rep, CALL_TIMEOUT_NS) {
                            Ok(rn) => {
                                let dh = Header::get(&rep[..rn as usize]).unwrap_or_default();
                                Self::reply(ch, h.txid, h.op, dh.status, dh.a, dh.b, &[]);
                            }
                            Err(e) => Self::reply(ch, h.txid, h.op, e as i32, 0, 0, &[]),
                        }
                    }
                }
            }
            gpu::OP_CRASH_DRIVER => {
                close_h(hnd);
                if !self.test_mode || role != Role::Display {
                    Self::reply(ch, h.txid, h.op, sys::ERR_ACCESS_DENIED as i32, 0, 0, &[]);
                    return;
                }
                let id = h.a as u32;
                let Some(ad) = self.find_adapter_mut(id) else {
                    Self::reply(ch, h.txid, h.op, sys::ERR_OUT_OF_RANGE as i32, 0, 0, &[]);
                    return;
                };
                match &ad.backend {
                    Backend::Pci { ch: dch, .. } if *dch != 0 => {
                        proto::send(*dch, gpu::DRV_TEST_CRASH, 0, 0);
                        Self::reply(ch, h.txid, h.op, 0, 0, 0, &[]);
                    }
                    _ => Self::reply(ch, h.txid, h.op, sys::ERR_NOT_SUPPORTED as i32, 0, 0, &[]),
                }
            }
            _ => {
                close_h(hnd);
                Self::reply(ch, h.txid, h.op, sys::ERR_NOT_SUPPORTED as i32, 0, 0, &[]);
            }
        }
    }
}

fn main(s: *const Startup) -> i32 {
    // SAFETY: `s` is the startup block pointer passed by the kernel.
    if !unsafe { libd::init(s, "gpu") } {
        return 1;
    }
    let test_mode = libd::args().split(|&c| c == b' ' || c == 0).any(|a| a == b"test");
    let ctl = libd::startup_handle(proto::TAG_CONTROL);
    let devmgr = svc::endpoint(b"devmgr.gpu");
    let disp_dev = libd::startup_handle(sys::TAG_DEVICE);
    let Ok(port) = Port::new(128) else { return 1 };

    let mut svc = GpuSvc {
        port,
        ctl,
        devmgr,
        test_mode,
        gop_wire: None,
        adapters: Vec::new(),
        next_adapter_id: 1,
        clients: Vec::new(),
    };
    svc.init_gop(disp_dev);

    if ctl != 0 {
        svc.port.arm(ctl, sys::READABLE | sys::PEER_CLOSED, KEY_CTL);
    }
    if devmgr != 0 {
        svc.port.arm(devmgr, sys::READABLE | sys::PEER_CLOSED, KEY_DEVMGR);
    }
    println!(
        "gpu: ready (endpoints: query, display, render; adapters={}{})",
        svc.adapters.len(),
        if test_mode { ", test mode" } else { "" }
    );

    loop {
        let Some((key, _)) = svc.port.wait(sys::WAIT_FOREVER) else { continue };
        match key {
            KEY_CTL => {
                if !svc.on_ctl_msg() {
                    return 0;
                }
            }
            KEY_DEVMGR => svc.on_devmgr_msg(),
            k if (KEY_CLIENT_BASE..KEY_BACKEND_BASE).contains(&k) => {
                svc.on_client_msg((k - KEY_CLIENT_BASE) as usize);
            }
            k if k >= KEY_BACKEND_BASE => {
                svc.on_backend_event((k - KEY_BACKEND_BASE) as usize);
            }
            _ => {}
        }
    }
}
