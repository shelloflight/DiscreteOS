//! D-OS GPU & display service (`gpu.dsvc`).
//!
//! Manages:
//! - The **GOP framebuffer baseline** (`platform:display`, `DISPLAY_RGB32`, mapped write-combining
//!   lazily on first explicit `OP_PRESENT` so normal boots keep `terminal` undisturbed).
//! - Isolated, IOMMU-confined PCI GPU drivers connected via `devmgr.gpu` (`virtio-gpu.ddrv`,
//!   `amdgpu.ddrv`, `xe.ddrv`, `nvgpu.ddrv`), with transparent driver crash/restart reconnection.
//!
//! Capability separation:
//! - `gpu.query`:   read-only adapter/mode/EDID/capability enumeration.
//! - `gpu.display`: exclusive display/modesetting/scanout/cursor authority.
//! - `gpu.render`:  GPU context & command-buffer submission (never touches display scanout).

#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{Ordering, fence};

use dosgpu::{DamageRect, MAX_DIM, MAX_FB_BYTES, PixelFormat, blit_rect_wc};
use libd::gpu::{
    self, ADAPTER_INFO_BYTES, AdapterInfo, MODE_ENTRY_BYTES, MODE_FLAG_CURRENT, MODE_FLAG_PREFERRED, ModeEntry,
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
            "gpu: adapter #{} 'GOP Framebuffer' (gop, {}x{}, {} MiB WC baseline) ready",
            id, di.width, di.height, info.vram_mib
        );
        self.adapters.push(Adapter {
            info,
            modes,
            backend: Backend::Gop(GopState {
                dev: disp_dev,
                disp: di,
                bar0: None,
                fbs: Vec::new(),
                next_fb_id: 1,
            }),
        });
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
                            let (width, height, caps) = gpu::unpack_dev_b(h.b);
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
                                self.port.arm(hnd, sys::PEER_CLOSED, KEY_BACKEND_BASE + idx as u64);
                                println!(
                                    "gpu: adapter #{} '{}' reconnected (restart {})",
                                    ad.info.id,
                                    ad.info.name_str(),
                                    ad.info.restarts
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
                                self.port.arm(hnd, sys::PEER_CLOSED, KEY_BACKEND_BASE + idx as u64);
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
            // Prefer first online PCI GPU, else GOP baseline.
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
                            // GOP framebuffer has a fixed firmware mode.
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
                    Backend::Gop(g) => {
                        if g.bar0.is_none() {
                            let Ok(vmo) = sys::device_map_bar(g.dev, 0) else {
                                Self::reply(ch, h.txid, h.op, sys::ERR_ACCESS_DENIED as i32, 0, 0, &[]);
                                return;
                            };
                            let Ok(m) = Mapping::of(vmo, g.disp.size) else {
                                sys::handle_close(vmo);
                                Self::reply(ch, h.txid, h.op, sys::ERR_NO_MEMORY as i32, 0, 0, &[]);
                                return;
                            };
                            g.bar0 = Some(m);
                        }
                        let Some(fb) = g.fbs.iter().find(|f| f.fb_id == fb_id) else {
                            Self::reply(ch, h.txid, h.op, sys::ERR_INVALID_ARGS as i32, 0, 0, &[]);
                            return;
                        };
                        let Some(bar0) = g.bar0.as_ref() else {
                            Self::reply(ch, h.txid, h.op, sys::ERR_BAD_STATE as i32, 0, 0, &[]);
                            return;
                        };
                        let bw = fb.width.min(g.disp.width);
                        let bh = fb.height.min(g.disp.height);
                        let rect = if w == 0 || hh == 0 {
                            DamageRect::full(bw, bh)
                        } else {
                            DamageRect { x, y, w, h: hh }
                        };
                        let fmt = PixelFormat::from_u32(fb.format).unwrap_or(PixelFormat::Xrgb8888);
                        let shifts = [g.disp.red_shift, g.disp.green_shift, g.disp.blue_shift];
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
                        fence(Ordering::Release);
                        ad.info.frames += 1;
                        Self::reply(ch, h.txid, h.op, 0, ad.info.frames, 0, &[]);
                    }
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
                svc.on_backend_closed((k - KEY_BACKEND_BASE) as usize);
            }
            _ => {}
        }
    }
}
