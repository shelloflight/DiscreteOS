//! D-OS GPU, Atomic KMS, GEM/GPU-VM, and timeline `syncobj` service (`gpu.dsvc`).
//!
//! Manages:
//! - The **UEFI GOP framebuffer baseline** (`platform:display`, `DISPLAY_RGB32`), modeled natively
//!   through `dosdrm::kms::KmsState` + `GemTable` and mapped write-combining lazily on first atomic
//!   primary-plane commit so text-console boots remain undisturbed.
//! - Isolated Ring-3 PCI GPU drivers connected via `devmgr.gpu` (`virtio-gpu.ddrv`,
//!   `amdgpu.ddrv`, `xe.ddrv`, `nvgpu.ddrv`), loaded from verified `sys:/bin/` with read-only
//!   `sys:/firmware/<vendor>/` grants, transparent crash/restart recovery, 12-second automatic
//!   mode-revert guarding (`ModeRevertGuard`), and vblank completion forwarding (`DRV_EVENT_VBLANK`
//!   -> `EVT_VBLANK`).
//!
//! Capability separation:
//! - `gpu.query`: read-only adapter & Atomic KMS topology/EDID/mode enumeration.
//! - `gpu.display`: exclusive Atomic KMS modeset, plane/cursor commit, mode confirm/revert, and
//!   scanout GEM import/close authority.
//! - `gpu.render`: per-client isolated GEM BOs, GPU-VM address spaces, timeline `syncobj`s, and
//!   context command submission (never touches display scanout).

#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{Ordering, fence};

use dosdrm::gem::{DrmMemError, GemTable};
use dosdrm::kms::{
    self, AtomicCommit, ConnectorKind, DEFAULT_REVERT_TIMEOUT_NS, KmsError, KmsMode, KmsState,
    ModeRevertGuard,
};
use dosdrm::{DamageRect, MAX_FB_BYTES, PixelFormat, blit_rect_wc};
use libd::gpu::{
    self, ADAPTER_INFO_BYTES, ATOMIC_COMMIT_HDR_BYTES, AdapterInfo, AtomicCommitWire,
    KMS_RESOURCES_HDR_BYTES, KmsResourcesWire, MAX_PRESENT_RECTS, MODE_ENTRY_BYTES, ModeEntry,
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
    id: u32,
    ch: Handle,
    role: Role,
}

struct GopBo {
    gem_handle: u32,
    vmo: Handle,
    map: Mapping,
}

impl Drop for GopBo {
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
    kms: KmsState,
    gem: GemTable,
    bos: Vec<GopBo>,
}

#[allow(clippy::large_enum_variant)]
enum Backend {
    Gop(GopState),
    Pci { drv_key: u32, ch: Handle },
}

struct OwnedGem {
    client_id: u32,
    adapter_id: u32,
    gem_handle: u32,
}

struct OwnedVm {
    client_id: u32,
    adapter_id: u32,
    vm_id: u32,
}

struct OwnedCtx {
    client_id: u32,
    adapter_id: u32,
    ctx_id: u32,
}

struct Adapter {
    info: AdapterInfo,
    kms_res: KmsResourcesWire,
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
    next_client_id: u32,
    owned_gems: Vec<OwnedGem>,
    owned_vms: Vec<OwnedVm>,
    owned_ctxs: Vec<OwnedCtx>,
    revert_guard: ModeRevertGuard,
}

fn kms_err_to_sys(e: KmsError) -> i64 {
    match e {
        KmsError::InvalidArgs => sys::ERR_INVALID_ARGS,
        KmsError::UnknownObject | KmsError::BufferTooSmall => sys::ERR_OUT_OF_RANGE,
        KmsError::UnsupportedFormat | KmsError::UnsupportedMode | KmsError::CapabilityUnsupported => {
            sys::ERR_NOT_SUPPORTED
        }
        KmsError::ModesetRequired => sys::ERR_BAD_STATE,
        KmsError::NoResources => sys::ERR_NO_RESOURCES,
    }
}

fn mem_err_to_sys(e: DrmMemError) -> i64 {
    match e {
        DrmMemError::InvalidArgs | DrmMemError::Unaligned => sys::ERR_INVALID_ARGS,
        DrmMemError::UnknownHandle | DrmMemError::OutOfRange => sys::ERR_OUT_OF_RANGE,
        DrmMemError::AddressOverlap | DrmMemError::Busy => sys::ERR_BAD_STATE,
        DrmMemError::NoResources => sys::ERR_NO_RESOURCES,
    }
}

fn wire_to_atomic(w: &AtomicCommitWire) -> AtomicCommit {
    let mut damage = [DamageRect::EMPTY; kms::MAX_COMMIT_DAMAGE];
    let cnt = w.damage_count.min(kms::MAX_COMMIT_DAMAGE);
    for (i, &(x, y, rw, rh)) in w.damage.iter().take(cnt).enumerate() {
        damage[i] = DamageRect { x, y, w: rw, h: rh };
    }
    AtomicCommit {
        flags: w.flags,
        crtc_id: w.crtc_id,
        connector_id: w.connector_id,
        mode_changed: (w.change_mask & gpu::COMMIT_MODE) != 0,
        mode_width: w.mode_width,
        mode_height: w.mode_height,
        mode_refresh_mhz: w.mode_refresh_mhz,
        vrr_changed: (w.change_mask & gpu::COMMIT_VRR) != 0,
        vrr_enable: w.vrr_enable,
        hdr_changed: (w.change_mask & gpu::COMMIT_HDR) != 0,
        hdr_enable: w.hdr_enable,
        primary_changed: (w.change_mask & gpu::COMMIT_PRIMARY) != 0,
        primary_fb_id: w.primary_fb_id,
        damage,
        damage_count: cnt as u8,
        cursor_changed: (w.change_mask & gpu::COMMIT_CURSOR) != 0,
        cursor_fb_id: w.cursor_fb_id,
        cursor_x: w.cursor_x,
        cursor_y: w.cursor_y,
        cursor_hot_x: w.cursor_hot_x,
        cursor_hot_y: w.cursor_hot_y,
        in_syncobj: w.in_syncobj,
        in_point: w.in_point,
        out_syncobj: w.out_syncobj,
        out_point: w.out_point,
    }
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
        let id = self.next_adapter_id;
        self.next_adapter_id += 1;

        let mut kms_state = KmsState::new();
        kms_state.init_single_pipe(ConnectorKind::FirmwareGop, b"UEFI GOP", di.width, di.height, 60_000, false);

        let mut info = AdapterInfo::empty();
        info.id = id;
        info.kind = gpu::KIND_GOP;
        info.online = true;
        info.caps = gpu::CAP_SCANOUT_2D | gpu::CAP_WC | gpu::CAP_ATOMIC_KMS;
        info.width = di.width;
        info.height = di.height;
        info.vram_mib = ((di.size >> 20) as u32).max(1);
        let name = b"GOP Framebuffer";
        info.name[..name.len()].copy_from_slice(name);
        info.name_len = name.len() as u8;
        let mon = b"UEFI GOP";
        info.monitor[..mon.len()].copy_from_slice(mon);
        info.monitor_len = mon.len() as u8;

        let m0 = kms_state.modes[0];
        let mode = ModeEntry {
            width: m0.width,
            height: m0.height,
            refresh_mhz: m0.refresh_mhz,
            pixel_clock_khz: m0.pixel_clock_khz,
            htotal: m0.htotal,
            vtotal: m0.vtotal,
            flags: m0.flags,
        };

        let mut kres = KmsResourcesWire::empty();
        kres.adapter_id = id;
        kres.connector_id = 1;
        kres.connector_kind = ConnectorKind::FirmwareGop as u8;
        kres.crtc_id = 1;
        kres.pipe = 0;
        kres.plane_count = 1;
        kres.status_flags = gpu::KMS_STATUS_CONNECTED | gpu::KMS_STATUS_CRTC_ACTIVE;
        kres.width = di.width;
        kres.height = di.height;
        kres.pitch_bytes = di.pitch;
        kres.refresh_mhz = 60_000;
        kres.htotal = m0.htotal;
        kres.vtotal = m0.vtotal;
        kres.set_monitor(b"UEFI GOP");
        kres.set_note(b"UEFI GOP Atomic KMS (WC linear baseline)");

        println!(
            "gpu: adapter #{} 'GOP Framebuffer' (gop, {}x{}, phys={:#x}, {} MiB WC baseline) ready",
            id, di.width, di.height, phys_base, info.vram_mib
        );
        self.adapters.push(Adapter {
            info,
            kms_res: kres,
            modes: alloc::vec![mode],
            backend: Backend::Gop(GopState {
                dev: disp_dev,
                disp: di,
                bar0: None,
                kms: kms_state,
                gem: GemTable::new(),
                bos: Vec::new(),
            }),
        });
    }

    fn query_pci_kms(ch: Handle, adapter_id: u32) -> (KmsResourcesWire, Vec<ModeEntry>) {
        let mut req = [0u8; HEADER];
        Header {
            txid: 0,
            op: gpu::DRV_KMS_GET_RESOURCES,
            status: 0,
            a: 0,
            b: 0,
        }
        .put(&mut req);
        let mut rep = [0u8; HEADER + KMS_RESOURCES_HDR_BYTES + 16 * MODE_ENTRY_BYTES];
        let mut kres = KmsResourcesWire::empty();
        kres.adapter_id = adapter_id;
        let mut modes = Vec::new();
        if let Ok(n) = sys::channel_call(ch, &req, &mut rep, CALL_TIMEOUT_NS) {
            let n = n as usize;
            if let Some(h) = Header::get(&rep[..n])
                && h.status == 0
                && n >= HEADER + KMS_RESOURCES_HDR_BYTES
            {
                if let Some(decoded) = KmsResourcesWire::decode(&rep[HEADER..n]) {
                    kres = decoded;
                    kres.adapter_id = adapter_id;
                }
                let mslice = &rep[HEADER + KMS_RESOURCES_HDR_BYTES..n];
                let cnt = (h.a as usize).min(mslice.len() / MODE_ENTRY_BYTES);
                for i in 0..cnt {
                    if let Some(m) = ModeEntry::decode(&mslice[i * MODE_ENTRY_BYTES..(i + 1) * MODE_ENTRY_BYTES]) {
                        modes.push(m);
                    }
                }
            }
        }
        (kres, modes)
    }

    fn refresh_pci_adapter(ad: &mut Adapter) {
        if let Backend::Pci { ch, .. } = ad.backend
            && ch != 0
        {
            let (kres, modes) = Self::query_pci_kms(ch, ad.info.id);
            if kres.width > 0 && kres.height > 0 {
                ad.info.width = kres.width;
                ad.info.height = kres.height;
            }
            ad.info.monitor = kres.monitor_name;
            ad.info.monitor_len = kres.monitor_len;
            ad.kms_res = kres;
            ad.modes = modes;
        }
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
                            let (mut width, mut height, caps) = gpu::unpack_dev_b(h.b);

                            if let Some((idx, ad)) = self.adapters.iter_mut().enumerate().find(|(_, a)| {
                                matches!(a.backend, Backend::Pci { drv_key: k, .. } if k == drv_key)
                            }) {
                                let aid = ad.info.id;
                                let (kres, modes) = Self::query_pci_kms(hnd, aid);
                                if kres.width > 0 && kres.height > 0 {
                                    width = kres.width;
                                    height = kres.height;
                                }
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
                                ad.info.monitor = kres.monitor_name;
                                ad.info.monitor_len = kres.monitor_len;
                                ad.kms_res = kres;
                                ad.modes = modes;
                                self.owned_gems.retain(|g| g.adapter_id != aid);
                                self.owned_vms.retain(|v| v.adapter_id != aid);
                                self.owned_ctxs.retain(|c| c.adapter_id != aid);
                                let _ = self.revert_guard.confirm(aid);
                                self.port.arm(hnd, sys::READABLE | sys::PEER_CLOSED, KEY_BACKEND_BASE + idx as u64);
                                println!(
                                    "gpu: adapter #{} '{}' reconnected (restart {}) caps={:#x}",
                                    aid,
                                    ad.info.name_str(),
                                    ad.info.restarts,
                                    caps
                                );
                                self.broadcast_adapters_changed(aid);
                            } else {
                                let id = self.next_adapter_id;
                                self.next_adapter_id += 1;
                                let (kres, modes) = Self::query_pci_kms(hnd, id);
                                if kres.width > 0 && kres.height > 0 {
                                    width = kres.width;
                                    height = kres.height;
                                }
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
                                info.monitor = kres.monitor_name;
                                info.monitor_len = kres.monitor_len;
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
                                    kms_res: kres,
                                    modes,
                                    backend: Backend::Pci { drv_key, ch: hnd },
                                });
                                self.port.arm(hnd, sys::READABLE | sys::PEER_CLOSED, KEY_BACKEND_BASE + idx as u64);
                                self.broadcast_adapters_changed(id);
                            }
                        }
                        gpu::BACKEND_GONE => {
                            if hnd != 0 {
                                sys::handle_close(hnd);
                            }
                            let drv_key = h.a as u32;
                            let mut gone_id = 0u32;
                            for ad in &mut self.adapters {
                                if let Backend::Pci { drv_key: k, ch } = &mut ad.backend
                                    && *k == drv_key
                                {
                                    if *ch != 0 {
                                        sys::handle_close(*ch);
                                        *ch = 0;
                                    }
                                    ad.info.online = false;
                                    gone_id = ad.info.id;
                                }
                            }
                            if gone_id != 0 {
                                self.owned_gems.retain(|g| g.adapter_id != gone_id);
                                self.owned_vms.retain(|v| v.adapter_id != gone_id);
                                self.owned_ctxs.retain(|c| c.adapter_id != gone_id);
                                let _ = self.revert_guard.confirm(gone_id);
                                self.broadcast_adapters_changed(gone_id);
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
                    match h.op {
                        gpu::DRV_EVENT_VBLANK => {
                            let seq = h.a & !(1u64 << 63);
                            let late = (h.a >> 63) != 0;
                            let ts_ns = h.b;
                            if let Some(ad) = self.adapters.get_mut(idx) {
                                ad.info.frames = seq;
                                ad.kms_res.vblank_seq = seq;
                            }
                            self.broadcast_vblank(adapter_id, seq, ts_ns, late);
                        }
                        gpu::DRV_EVENT_HOTPLUG => {
                            if let Some(ad) = self.adapters.get_mut(idx) {
                                Self::refresh_pci_adapter(ad);
                            }
                            self.broadcast_adapters_changed(adapter_id);
                        }
                        _ => {}
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

    fn broadcast_vblank(&self, adapter_id: u32, seq: u64, ts_ns: u64, late: bool) {
        let mut msg = [0u8; HEADER + 8];
        Header {
            txid: 0,
            op: gpu::EVT_VBLANK,
            status: 0,
            a: u64::from(adapter_id) | (u64::from(late) << 32),
            b: seq,
        }
        .put(&mut msg);
        msg[HEADER..HEADER + 8].copy_from_slice(&ts_ns.to_le_bytes());
        for c in &self.clients {
            if c.role == Role::Display && c.ch != 0 {
                let _ = sys::channel_write(c.ch, &msg);
            }
        }
    }

    fn broadcast_adapters_changed(&self, adapter_id: u32) {
        let mut msg = [0u8; HEADER];
        Header {
            txid: 0,
            op: gpu::EVT_ADAPTERS_CHANGED,
            status: 0,
            a: u64::from(adapter_id),
            b: 0,
        }
        .put(&mut msg);
        for c in &self.clients {
            if c.role == Role::Display && c.ch != 0 {
                let _ = sys::channel_write(c.ch, &msg);
            }
        }
    }

    fn on_backend_closed(&mut self, idx: usize) {
        let mut closed_id = 0u32;
        if let Some(ad) = self.adapters.get_mut(idx)
            && let Backend::Pci { ch, .. } = &mut ad.backend
        {
            if *ch != 0 {
                sys::handle_close(*ch);
                *ch = 0;
            }
            ad.info.online = false;
            closed_id = ad.info.id;
            println!("gpu: adapter #{} '{}' offline (driver exited)", ad.info.id, ad.info.name_str());
        }
        if closed_id != 0 {
            self.owned_gems.retain(|g| g.adapter_id != closed_id);
            self.owned_vms.retain(|v| v.adapter_id != closed_id);
            self.owned_ctxs.retain(|c| c.adapter_id != closed_id);
            let _ = self.revert_guard.confirm(closed_id);
            self.broadcast_adapters_changed(closed_id);
        }
    }

    fn apply_mode_revert(&mut self, adapter_id: u32, mode: KmsMode) {
        let Some(ad) = self.find_adapter_mut(adapter_id) else {
            return;
        };
        let aid = ad.info.id;
        if let Backend::Pci { ch: dch, .. } = ad.backend
            && dch != 0
        {
            let wire = AtomicCommitWire {
                flags: gpu::ATOMIC_ALLOW_MODESET,
                change_mask: gpu::COMMIT_MODE,
                mode_width: mode.width,
                mode_height: mode.height,
                mode_refresh_mhz: mode.refresh_mhz,
                ..AtomicCommitWire::default()
            };
            let mut body = [0u8; ATOMIC_COMMIT_HDR_BYTES + MAX_PRESENT_RECTS * 16];
            let blen = wire.encode(&mut body);
            let mut req = [0u8; HEADER + ATOMIC_COMMIT_HDR_BYTES + MAX_PRESENT_RECTS * 16];
            Header {
                txid: 0,
                op: gpu::DRV_KMS_ATOMIC_COMMIT,
                status: 0,
                a: 0,
                b: blen as u64,
            }
            .put(&mut req);
            req[HEADER..HEADER + blen].copy_from_slice(&body[..blen]);
            let mut rep = [0u8; HEADER];
            let _ = sys::channel_call(dch, &req[..HEADER + blen], &mut rep, CALL_TIMEOUT_NS);
            Self::refresh_pci_adapter(ad);
            println!(
                "gpu: adapter #{} reverted unconfirmed mode back to {}x{} @ {} Hz",
                aid,
                mode.width,
                mode.height,
                mode.refresh_mhz / 1000
            );
            self.broadcast_adapters_changed(aid);
        }
    }

    fn cleanup_client_resources(&mut self, client_id: u32) {
        let ctxs: Vec<(u32, u32)> = self
            .owned_ctxs
            .iter()
            .filter(|c| c.client_id == client_id)
            .map(|c| (c.adapter_id, c.ctx_id))
            .collect();
        self.owned_ctxs.retain(|c| c.client_id != client_id);
        for (aid, ctx_id) in ctxs {
            if let Some(ad) = self.adapters.iter().find(|a| a.info.id == aid)
                && let Backend::Pci { ch: dch, .. } = ad.backend
                && dch != 0
            {
                let mut req = [0u8; HEADER];
                Header { txid: 0, op: gpu::DRV_CTX_DESTROY, status: 0, a: 0, b: u64::from(ctx_id) }.put(&mut req);
                let mut rep = [0u8; HEADER];
                let _ = sys::channel_call(dch, &req, &mut rep, 2_000_000_000);
            }
        }

        let vms: Vec<(u32, u32)> = self
            .owned_vms
            .iter()
            .filter(|v| v.client_id == client_id)
            .map(|v| (v.adapter_id, v.vm_id))
            .collect();
        self.owned_vms.retain(|v| v.client_id != client_id);
        for (aid, vm_id) in vms {
            if let Some(ad) = self.adapters.iter().find(|a| a.info.id == aid)
                && let Backend::Pci { ch: dch, .. } = ad.backend
                && dch != 0
            {
                let mut req = [0u8; HEADER];
                Header { txid: 0, op: gpu::DRV_VM_DESTROY, status: 0, a: 0, b: u64::from(vm_id) }.put(&mut req);
                let mut rep = [0u8; HEADER];
                let _ = sys::channel_call(dch, &req, &mut rep, 2_000_000_000);
            }
        }

        let gems: Vec<(u32, u32)> = self
            .owned_gems
            .iter()
            .filter(|g| g.client_id == client_id)
            .map(|g| (g.adapter_id, g.gem_handle))
            .collect();
        self.owned_gems.retain(|g| g.client_id != client_id);
        for (aid, gem_h) in gems {
            if let Some(ad) = self.adapters.iter_mut().find(|a| a.info.id == aid) {
                match &mut ad.backend {
                    Backend::Gop(g) => {
                        if let Ok(Some(_)) = g.gem.release(gem_h) {
                            g.bos.retain(|b| b.gem_handle != gem_h);
                        }
                    }
                    Backend::Pci { ch: dch, .. } if *dch != 0 => {
                        let mut req = [0u8; HEADER];
                        Header { txid: 0, op: gpu::DRV_GEM_CLOSE, status: 0, a: 0, b: u64::from(gem_h) }.put(&mut req);
                        let mut rep = [0u8; HEADER];
                        let _ = sys::channel_call(*dch, &req, &mut rep, 2_000_000_000);
                    }
                    _ => {}
                }
            }
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
                                let cid = self.next_client_id;
                                self.next_client_id = self.next_client_id.wrapping_add(1).max(1);
                                let idx = self.clients.len();
                                self.clients.push(Client { id: cid, ch: hnd, role });
                                self.port.arm(hnd, sys::READABLE | sys::PEER_CLOSED, KEY_CLIENT_BASE + idx as u64);
                            }
                        }
                        Some(h) if h.op == svc::SHUTDOWN => {
                            if hnd != 0 {
                                sys::handle_close(hnd);
                            }
                            for ad in &self.adapters {
                                if let Backend::Pci { ch: dch, .. } = ad.backend
                                    && dch != 0
                                {
                                    let wire = AtomicCommitWire {
                                        flags: gpu::ATOMIC_ALLOW_MODESET | gpu::ATOMIC_RESET_BOOT,
                                        ..AtomicCommitWire::default()
                                    };
                                    let mut body = [0u8; ATOMIC_COMMIT_HDR_BYTES + MAX_PRESENT_RECTS * 16];
                                    let blen = wire.encode(&mut body);
                                    let mut req = [0u8; HEADER + ATOMIC_COMMIT_HDR_BYTES];
                                    Header {
                                        txid: 0,
                                        op: gpu::DRV_KMS_ATOMIC_COMMIT,
                                        status: 0,
                                        a: 0,
                                        b: blen as u64,
                                    }
                                    .put(&mut req);
                                    req[HEADER..HEADER + ATOMIC_COMMIT_HDR_BYTES]
                                        .copy_from_slice(&body[..ATOMIC_COMMIT_HDR_BYTES]);
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

    fn resolve_adapter_id(&self, id: u32) -> Option<u32> {
        if id == 0 {
            self.adapters
                .iter()
                .find(|a| a.info.online && a.info.kind != gpu::KIND_GOP && (a.info.caps & gpu::CAP_NATIVE_KMS) != 0)
                .or_else(|| {
                    self.adapters
                        .iter()
                        .find(|a| a.info.online && a.info.kind != gpu::KIND_GOP && a.info.width > 0 && a.info.height > 0)
                })
                .or_else(|| self.adapters.iter().find(|a| a.info.online && a.info.kind != gpu::KIND_GOP))
                .or_else(|| self.adapters.iter().find(|a| a.info.online))
                .map(|a| a.info.id)
        } else {
            self.adapters.iter().find(|a| a.info.id == id).map(|a| a.info.id)
        }
    }

    fn find_adapter_mut(&mut self, id: u32) -> Option<&mut Adapter> {
        let resolved = self.resolve_adapter_id(id)?;
        self.adapters.iter_mut().find(|a| a.info.id == resolved)
    }

    fn reply(ch: Handle, txid: u32, op: u32, status: i32, a: u64, b: u64, payload: &[u8]) {
        let mut out = alloc::vec![0u8; HEADER + payload.len()];
        Header { txid, op, status, a, b }.put(&mut out);
        out[HEADER..].copy_from_slice(payload);
        let _ = sys::channel_write(ch, &out);
    }

    #[allow(clippy::too_many_arguments)]
    fn reply_with_handle(ch: Handle, txid: u32, op: u32, status: i32, a: u64, b: u64, payload: &[u8], hnd: Handle) {
        let mut out = alloc::vec![0u8; HEADER + payload.len()];
        Header { txid, op, status, a, b }.put(&mut out);
        out[HEADER..].copy_from_slice(payload);
        let _ = sys::channel_write_h(
            ch,
            &out,
            &[MsgHandle { handle: hnd, rights: sys::RIGHTS_SAME }],
        );
    }

    fn on_client_msg(&mut self, idx: usize) {
        let mut buf = alloc::vec![0u8; HEADER + 4096];
        loop {
            let Some(c) = self.clients.get(idx) else { return };
            if c.ch == 0 {
                return;
            }
            let (cid, ch, role) = (c.id, c.ch, c.role);
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
                    self.dispatch_client(cid, ch, role, h, &buf[HEADER..n], hnd);
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
                    self.cleanup_client_resources(cid);
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
        let Some(fb) = g.kms.get_fb(fb_id) else {
            return Err(sys::ERR_OUT_OF_RANGE);
        };
        let Some(bo) = g.bos.iter().find(|b| b.gem_handle == fb.gem_handle) else {
            return Err(sys::ERR_OUT_OF_RANGE);
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
                bo.map.bytes(),
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

    fn client_owns_gem(&self, client_id: u32, adapter_id: u32, gem_handle: u32) -> bool {
        self.owned_gems
            .iter()
            .any(|g| g.client_id == client_id && g.adapter_id == adapter_id && g.gem_handle == gem_handle)
    }

    fn client_owns_vm(&self, client_id: u32, adapter_id: u32, vm_id: u32) -> bool {
        self.owned_vms
            .iter()
            .any(|v| v.client_id == client_id && v.adapter_id == adapter_id && v.vm_id == vm_id)
    }

    fn client_owns_ctx(&self, client_id: u32, adapter_id: u32, ctx_id: u32) -> bool {
        self.owned_ctxs
            .iter()
            .any(|c| c.client_id == client_id && c.adapter_id == adapter_id && c.ctx_id == ctx_id)
    }

    fn dispatch_client(&mut self, client_id: u32, ch: Handle, role: Role, h: Header, payload: &[u8], hnd: Handle) {
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
            gpu::OP_KMS_GET_RESOURCES => {
                close_h(hnd);
                let req_id = h.a as u32;
                let Some(aid) = self.resolve_adapter_id(req_id) else {
                    Self::reply(ch, h.txid, h.op, sys::ERR_OUT_OF_RANGE as i32, 0, 0, &[]);
                    return;
                };
                let secs_left = self.revert_guard.secs_left(aid, sys::clock_ns());
                let Some(ad) = self.adapters.iter_mut().find(|a| a.info.id == aid) else {
                    Self::reply(ch, h.txid, h.op, sys::ERR_OUT_OF_RANGE as i32, 0, 0, &[]);
                    return;
                };
                if matches!(ad.backend, Backend::Pci { ch: dch, .. } if dch != 0) {
                    Self::refresh_pci_adapter(ad);
                } else if let Backend::Gop(g) = &ad.backend {
                    ad.kms_res.vblank_seq = g.kms.crtcs[0].map_or(ad.info.frames, |c| c.vblank_seq);
                }
                let mut res = ad.kms_res;
                res.adapter_id = aid;
                res.revert_secs_left = secs_left;
                if secs_left > 0 {
                    res.status_flags |= gpu::KMS_STATUS_REVERT_PENDING;
                }
                let mut body = Vec::with_capacity(KMS_RESOURCES_HDR_BYTES + ad.modes.len() * MODE_ENTRY_BYTES);
                let mut hdr = [0u8; KMS_RESOURCES_HDR_BYTES];
                res.encode(&mut hdr);
                body.extend_from_slice(&hdr);
                for m in &ad.modes {
                    let mut enc = [0u8; MODE_ENTRY_BYTES];
                    m.encode(&mut enc);
                    body.extend_from_slice(&enc);
                }
                Self::reply(ch, h.txid, h.op, 0, ad.modes.len() as u64, 0, &body);
            }
            gpu::OP_GEM_IMPORT => {
                if role == Role::Query {
                    close_h(hnd);
                    Self::reply(ch, h.txid, h.op, sys::ERR_ACCESS_DENIED as i32, 0, 0, &[]);
                    return;
                }
                if hnd == 0 {
                    Self::reply(ch, h.txid, h.op, sys::ERR_INVALID_ARGS as i32, 0, 0, &[]);
                    return;
                }
                let req_id = h.a as u32;
                let bo_flags = (h.a >> 32) as u32;
                let size = h.b;
                // Display clients may only import scanout/cursor BOs; render clients may only import render BOs.
                if role == Role::Display && (bo_flags & gpu::BO_RENDER) != 0 {
                    close_h(hnd);
                    Self::reply(ch, h.txid, h.op, sys::ERR_ACCESS_DENIED as i32, 0, 0, &[]);
                    return;
                }
                if role == Role::Render && (bo_flags & (gpu::BO_SCANOUT | gpu::BO_CURSOR)) != 0 {
                    close_h(hnd);
                    Self::reply(ch, h.txid, h.op, sys::ERR_ACCESS_DENIED as i32, 0, 0, &[]);
                    return;
                }
                let Some(aid) = self.resolve_adapter_id(req_id) else {
                    close_h(hnd);
                    Self::reply(ch, h.txid, h.op, sys::ERR_OUT_OF_RANGE as i32, 0, 0, &[]);
                    return;
                };
                let Some(ad) = self.adapters.iter_mut().find(|a| a.info.id == aid) else {
                    close_h(hnd);
                    Self::reply(ch, h.txid, h.op, sys::ERR_OUT_OF_RANGE as i32, 0, 0, &[]);
                    return;
                };
                match &mut ad.backend {
                    Backend::Gop(g) => {
                        if role != Role::Display {
                            close_h(hnd);
                            Self::reply(ch, h.txid, h.op, sys::ERR_NOT_SUPPORTED as i32, 0, 0, &[]);
                            return;
                        }
                        if size == 0 || size > MAX_FB_BYTES || sys::vmo_size(hnd).unwrap_or(0) < size {
                            close_h(hnd);
                            Self::reply(ch, h.txid, h.op, sys::ERR_OUT_OF_RANGE as i32, 0, 0, &[]);
                            return;
                        }
                        let map_len = size.div_ceil(sys::PAGE) * sys::PAGE;
                        let Ok(map) = Mapping::of_ro(hnd, map_len) else {
                            close_h(hnd);
                            Self::reply(ch, h.txid, h.op, sys::ERR_NO_MEMORY as i32, 0, 0, &[]);
                            return;
                        };
                        let mut uuid = [0u8; 16];
                        uuid[0..4].copy_from_slice(b"GOPB");
                        match g.gem.insert(size, bo_flags, 0, uuid) {
                            Ok(gem_h) => {
                                uuid[4..8].copy_from_slice(&gem_h.to_le_bytes());
                                g.bos.push(GopBo { gem_handle: gem_h, vmo: hnd, map });
                                self.owned_gems.push(OwnedGem {
                                    client_id,
                                    adapter_id: aid,
                                    gem_handle: gem_h,
                                });
                                Self::reply(ch, h.txid, h.op, 0, u64::from(gem_h), 0, &uuid);
                            }
                            Err(e) => {
                                drop(GopBo { gem_handle: 0, vmo: hnd, map });
                                Self::reply(ch, h.txid, h.op, mem_err_to_sys(e) as i32, 0, 0, &[]);
                            }
                        }
                    }
                    Backend::Pci { ch: dch, .. } => {
                        if *dch == 0 {
                            close_h(hnd);
                            Self::reply(ch, h.txid, h.op, sys::ERR_BAD_STATE as i32, 0, 0, &[]);
                            return;
                        }
                        let mut req = [0u8; HEADER];
                        Header { txid: 0, op: gpu::DRV_GEM_IMPORT, status: 0, a: h.a, b: size }.put(&mut req);
                        let mut rep = [0u8; HEADER + 16];
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
                                if dh.status == 0 {
                                    self.owned_gems.push(OwnedGem {
                                        client_id,
                                        adapter_id: aid,
                                        gem_handle: dh.a as u32,
                                    });
                                }
                                let body = if rn > HEADER { &rep[HEADER..rn] } else { &[] };
                                Self::reply(ch, h.txid, h.op, dh.status, dh.a, dh.b, body);
                            }
                            Err(e) => Self::reply(ch, h.txid, h.op, e as i32, 0, 0, &[]),
                        }
                    }
                }
            }
            gpu::OP_GEM_CREATE => {
                close_h(hnd);
                if role != Role::Render {
                    Self::reply(ch, h.txid, h.op, sys::ERR_ACCESS_DENIED as i32, 0, 0, &[]);
                    return;
                }
                let req_id = h.a as u32;
                let Some(aid) = self.resolve_adapter_id(req_id) else {
                    Self::reply(ch, h.txid, h.op, sys::ERR_OUT_OF_RANGE as i32, 0, 0, &[]);
                    return;
                };
                let Some(ad) = self.adapters.iter().find(|a| a.info.id == aid) else {
                    Self::reply(ch, h.txid, h.op, sys::ERR_OUT_OF_RANGE as i32, 0, 0, &[]);
                    return;
                };
                match ad.backend {
                    Backend::Gop(_) => Self::reply(ch, h.txid, h.op, sys::ERR_NOT_SUPPORTED as i32, 0, 0, &[]),
                    Backend::Pci { ch: dch, .. } if dch != 0 => {
                        let mut req = [0u8; HEADER];
                        Header { txid: 0, op: gpu::DRV_GEM_CREATE, status: 0, a: h.a, b: h.b }.put(&mut req);
                        let mut rep = [0u8; HEADER + 16];
                        let mut rh = [0 as Handle; 1];
                        match sys::channel_call_h(dch, &req, &[], &mut rep, &mut rh, CALL_TIMEOUT_NS) {
                            Ok((rn, rnh)) => {
                                let dh = Header::get(&rep[..rn]).unwrap_or_default();
                                let got_vmo = if rnh > 0 { rh[0] } else { 0 };
                                let body = if rn > HEADER { &rep[HEADER..rn] } else { &[] };
                                if dh.status == 0 && got_vmo != 0 {
                                    self.owned_gems.push(OwnedGem {
                                        client_id,
                                        adapter_id: aid,
                                        gem_handle: dh.a as u32,
                                    });
                                    Self::reply_with_handle(ch, h.txid, h.op, 0, dh.a, 0, body, got_vmo);
                                } else {
                                    if got_vmo != 0 {
                                        sys::handle_close(got_vmo);
                                    }
                                    Self::reply(
                                        ch,
                                        h.txid,
                                        h.op,
                                        if dh.status != 0 { dh.status } else { sys::ERR_BAD_STATE as i32 },
                                        0,
                                        0,
                                        &[],
                                    );
                                }
                            }
                            Err(e) => Self::reply(ch, h.txid, h.op, e as i32, 0, 0, &[]),
                        }
                    }
                    _ => Self::reply(ch, h.txid, h.op, sys::ERR_BAD_STATE as i32, 0, 0, &[]),
                }
            }
            gpu::OP_GEM_CLOSE => {
                close_h(hnd);
                if role == Role::Query {
                    Self::reply(ch, h.txid, h.op, sys::ERR_ACCESS_DENIED as i32, 0, 0, &[]);
                    return;
                }
                let req_id = h.a as u32;
                let gem_h = h.b as u32;
                let Some(aid) = self.resolve_adapter_id(req_id) else {
                    Self::reply(ch, h.txid, h.op, sys::ERR_OUT_OF_RANGE as i32, 0, 0, &[]);
                    return;
                };
                if !self.client_owns_gem(client_id, aid, gem_h) {
                    Self::reply(ch, h.txid, h.op, sys::ERR_ACCESS_DENIED as i32, 0, 0, &[]);
                    return;
                }
                self.owned_gems
                    .retain(|g| !(g.client_id == client_id && g.adapter_id == aid && g.gem_handle == gem_h));
                let Some(ad) = self.adapters.iter_mut().find(|a| a.info.id == aid) else {
                    Self::reply(ch, h.txid, h.op, sys::ERR_OUT_OF_RANGE as i32, 0, 0, &[]);
                    return;
                };
                match &mut ad.backend {
                    Backend::Gop(g) => match g.gem.release(gem_h) {
                        Ok(released) => {
                            if released.is_some() {
                                g.bos.retain(|b| b.gem_handle != gem_h);
                            }
                            Self::reply(ch, h.txid, h.op, 0, 0, 0, &[]);
                        }
                        Err(e) => Self::reply(ch, h.txid, h.op, mem_err_to_sys(e) as i32, 0, 0, &[]),
                    },
                    Backend::Pci { ch: dch, .. } if *dch != 0 => {
                        let mut req = [0u8; HEADER];
                        Header { txid: 0, op: gpu::DRV_GEM_CLOSE, status: 0, a: 0, b: u64::from(gem_h) }.put(&mut req);
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
            gpu::OP_KMS_CREATE_FB => {
                close_h(hnd);
                if role != Role::Display {
                    println!("gpu: refused OP_KMS_CREATE_FB on non-display endpoint");
                    Self::reply(ch, h.txid, h.op, sys::ERR_ACCESS_DENIED as i32, 0, 0, &[]);
                    return;
                }
                if payload.len() < 16 {
                    Self::reply(ch, h.txid, h.op, sys::ERR_INVALID_ARGS as i32, 0, 0, &[]);
                    return;
                }
                let req_id = h.a as u32;
                let gem_h = (h.a >> 32) as u32;
                let width = h.b as u32;
                let height = (h.b >> 32) as u32;
                let pitch = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
                let format = u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]);
                let modifier = u64::from_le_bytes([
                    payload[8],
                    payload[9],
                    payload[10],
                    payload[11],
                    payload[12],
                    payload[13],
                    payload[14],
                    payload[15],
                ]);
                let Some(aid) = self.resolve_adapter_id(req_id) else {
                    Self::reply(ch, h.txid, h.op, sys::ERR_OUT_OF_RANGE as i32, 0, 0, &[]);
                    return;
                };
                if !self.client_owns_gem(client_id, aid, gem_h) {
                    Self::reply(ch, h.txid, h.op, sys::ERR_ACCESS_DENIED as i32, 0, 0, &[]);
                    return;
                }
                let Some(ad) = self.adapters.iter_mut().find(|a| a.info.id == aid) else {
                    Self::reply(ch, h.txid, h.op, sys::ERR_OUT_OF_RANGE as i32, 0, 0, &[]);
                    return;
                };
                match &mut ad.backend {
                    Backend::Gop(g) => {
                        let Some(bo) = g.gem.get(gem_h) else {
                            Self::reply(ch, h.txid, h.op, sys::ERR_OUT_OF_RANGE as i32, 0, 0, &[]);
                            return;
                        };
                        let _ = g.gem.add_ref(gem_h);
                        match g.kms.add_fb(gem_h, width, height, pitch, format, modifier, bo.size) {
                            Ok(fb_id) => Self::reply(ch, h.txid, h.op, 0, u64::from(fb_id), 0, &[]),
                            Err(e) => {
                                let _ = g.gem.release(gem_h);
                                Self::reply(ch, h.txid, h.op, kms_err_to_sys(e) as i32, 0, 0, &[]);
                            }
                        }
                    }
                    Backend::Pci { ch: dch, .. } if *dch != 0 => {
                        let mut req = [0u8; HEADER + 16];
                        Header { txid: 0, op: gpu::DRV_KMS_CREATE_FB, status: 0, a: h.a, b: h.b }.put(&mut req);
                        req[HEADER..HEADER + 16].copy_from_slice(&payload[..16]);
                        let mut rep = [0u8; HEADER];
                        match sys::channel_call(*dch, &req, &mut rep, CALL_TIMEOUT_NS) {
                            Ok(rn) => {
                                let dh = Header::get(&rep[..rn as usize]).unwrap_or_default();
                                Self::reply(ch, h.txid, h.op, dh.status, dh.a, 0, &[]);
                            }
                            Err(e) => Self::reply(ch, h.txid, h.op, e as i32, 0, 0, &[]),
                        }
                    }
                    _ => Self::reply(ch, h.txid, h.op, sys::ERR_BAD_STATE as i32, 0, 0, &[]),
                }
            }
            gpu::OP_KMS_DESTROY_FB => {
                close_h(hnd);
                if role != Role::Display {
                    Self::reply(ch, h.txid, h.op, sys::ERR_ACCESS_DENIED as i32, 0, 0, &[]);
                    return;
                }
                let req_id = h.a as u32;
                let fb_id = h.b as u32;
                let Some(ad) = self.find_adapter_mut(req_id) else {
                    Self::reply(ch, h.txid, h.op, sys::ERR_OUT_OF_RANGE as i32, 0, 0, &[]);
                    return;
                };
                match &mut ad.backend {
                    Backend::Gop(g) => match g.kms.remove_fb(fb_id) {
                        Some(fb) => {
                            if let Ok(Some(_)) = g.gem.release(fb.gem_handle) {
                                g.bos.retain(|b| b.gem_handle != fb.gem_handle);
                            }
                            Self::reply(ch, h.txid, h.op, 0, 0, 0, &[]);
                        }
                        None => Self::reply(ch, h.txid, h.op, sys::ERR_OUT_OF_RANGE as i32, 0, 0, &[]),
                    },
                    Backend::Pci { ch: dch, .. } if *dch != 0 => {
                        let mut req = [0u8; HEADER];
                        Header { txid: 0, op: gpu::DRV_KMS_DESTROY_FB, status: 0, a: 0, b: u64::from(fb_id) }
                            .put(&mut req);
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
            gpu::OP_KMS_ATOMIC_COMMIT => {
                close_h(hnd);
                if role != Role::Display {
                    println!("gpu: refused OP_KMS_ATOMIC_COMMIT on non-display endpoint");
                    Self::reply(ch, h.txid, h.op, sys::ERR_ACCESS_DENIED as i32, 0, 0, &[]);
                    return;
                }
                let max_len = ATOMIC_COMMIT_HDR_BYTES + MAX_PRESENT_RECTS * 16;
                let Some(wire) = AtomicCommitWire::decode(&payload[..payload.len().min(max_len)]) else {
                    Self::reply(ch, h.txid, h.op, sys::ERR_INVALID_ARGS as i32, 0, 0, &[]);
                    return;
                };
                let commit = wire_to_atomic(&wire);
                let req_id = h.a as u32;
                let Some(aid) = self.resolve_adapter_id(req_id) else {
                    Self::reply(ch, h.txid, h.op, sys::ERR_OUT_OF_RANGE as i32, 0, 0, &[]);
                    return;
                };
                let Some(ad) = self.adapters.iter_mut().find(|a| a.info.id == aid) else {
                    Self::reply(ch, h.txid, h.op, sys::ERR_OUT_OF_RANGE as i32, 0, 0, &[]);
                    return;
                };
                let prev_mode = ad
                    .modes
                    .iter()
                    .find(|m| (m.flags & gpu::MODE_FLAG_CURRENT) != 0)
                    .map(|m| KmsMode {
                        width: m.width,
                        height: m.height,
                        refresh_mhz: m.refresh_mhz,
                        pixel_clock_khz: m.pixel_clock_khz,
                        htotal: m.htotal,
                        vtotal: m.vtotal,
                        flags: m.flags,
                    })
                    .unwrap_or_else(|| KmsMode::simple(ad.info.width, ad.info.height, 60_000, 0));

                match &mut ad.backend {
                    Backend::Gop(g) => {
                        if (commit.flags & kms::ATOMIC_RESET_BOOT) != 0 {
                            Self::reply(ch, h.txid, h.op, 0, ad.info.frames, 0, &[]);
                            return;
                        }
                        let resolved = match g.kms.validate_commit(&commit) {
                            Ok(r) => r,
                            Err(e) => {
                                Self::reply(ch, h.txid, h.op, kms_err_to_sys(e) as i32, 0, 0, &[]);
                                return;
                            }
                        };
                        if (commit.flags & kms::ATOMIC_TEST_ONLY) != 0 {
                            Self::reply(ch, h.txid, h.op, 0, ad.info.frames, 0, &[]);
                            return;
                        }
                        if commit.primary_changed && commit.primary_fb_id != 0 {
                            let cnt = usize::from(commit.damage_count).min(kms::MAX_COMMIT_DAMAGE);
                            if let Err(e) = Self::gop_present_rects(g, commit.primary_fb_id, &commit.damage[..cnt]) {
                                Self::reply(ch, h.txid, h.op, e as i32, 0, 0, &[]);
                                return;
                            }
                        }
                        g.kms.apply_commit(&commit, resolved);
                        if commit.primary_changed && commit.primary_fb_id != 0 {
                            ad.info.frames = g.kms.crtcs[0].map_or(ad.info.frames + 1, |c| c.vblank_seq);
                            ad.kms_res.vblank_seq = ad.info.frames;
                        }
                        Self::reply(ch, h.txid, h.op, 0, ad.info.frames, 0, &[]);
                    }
                    Backend::Pci { ch: dch, .. } => {
                        if *dch == 0 {
                            Self::reply(ch, h.txid, h.op, sys::ERR_BAD_STATE as i32, 0, 0, &[]);
                            return;
                        }
                        let plen = payload.len().min(max_len);
                        let mut req = [0u8; HEADER + ATOMIC_COMMIT_HDR_BYTES + MAX_PRESENT_RECTS * 16];
                        Header {
                            txid: 0,
                            op: gpu::DRV_KMS_ATOMIC_COMMIT,
                            status: 0,
                            a: 0,
                            b: plen as u64,
                        }
                        .put(&mut req);
                        req[HEADER..HEADER + plen].copy_from_slice(&payload[..plen]);
                        let mut rep = [0u8; HEADER];
                        match sys::channel_call(*dch, &req[..HEADER + plen], &mut rep, CALL_TIMEOUT_NS) {
                            Ok(rn) => {
                                let dh = Header::get(&rep[..rn as usize]).unwrap_or_default();
                                let mut broadcast = false;
                                if dh.status == 0 && (commit.flags & kms::ATOMIC_TEST_ONLY) == 0 {
                                    if commit.primary_changed && commit.primary_fb_id != 0 {
                                        ad.info.frames = dh.a;
                                        ad.kms_res.vblank_seq = dh.a;
                                    }
                                    if commit.mode_changed
                                        || commit.vrr_changed
                                        || commit.hdr_changed
                                        || (commit.flags & kms::ATOMIC_RESET_BOOT) != 0
                                    {
                                        Self::refresh_pci_adapter(ad);
                                        broadcast = true;
                                        if commit.mode_changed && (commit.flags & kms::ATOMIC_REQUIRE_CONFIRM) != 0 {
                                            self.revert_guard.arm(
                                                aid,
                                                prev_mode,
                                                sys::clock_ns(),
                                                DEFAULT_REVERT_TIMEOUT_NS,
                                            );
                                        } else if (commit.flags & kms::ATOMIC_RESET_BOOT) != 0 {
                                            let _ = self.revert_guard.confirm(aid);
                                        }
                                    }
                                }
                                Self::reply(ch, h.txid, h.op, dh.status, dh.a, dh.b, &[]);
                                if broadcast {
                                    self.broadcast_adapters_changed(aid);
                                }
                            }
                            Err(e) => Self::reply(ch, h.txid, h.op, e as i32, 0, 0, &[]),
                        }
                    }
                }
            }
            gpu::OP_KMS_CONFIRM_MODE => {
                close_h(hnd);
                if role != Role::Display {
                    Self::reply(ch, h.txid, h.op, sys::ERR_ACCESS_DENIED as i32, 0, 0, &[]);
                    return;
                }
                let req_id = h.a as u32;
                let confirm = (h.b & 1) != 0;
                let aid = self.resolve_adapter_id(req_id).unwrap_or(req_id);
                if confirm {
                    let _ = self.revert_guard.confirm(aid);
                    Self::reply(ch, h.txid, h.op, 0, 0, 0, &[]);
                } else if let Some((rev_id, rev_mode)) = self.revert_guard.take_pending(aid) {
                    self.apply_mode_revert(rev_id, rev_mode);
                    Self::reply(ch, h.txid, h.op, 0, 0, 0, &[]);
                } else {
                    Self::reply(ch, h.txid, h.op, sys::ERR_BAD_STATE as i32, 0, 0, &[]);
                }
            }
            gpu::OP_VM_CREATE
            | gpu::OP_VM_DESTROY
            | gpu::OP_VM_BIND
            | gpu::OP_VM_UNBIND
            | gpu::OP_SYNCOBJ_CREATE
            | gpu::OP_SYNCOBJ_DESTROY
            | gpu::OP_SYNCOBJ_SIGNAL
            | gpu::OP_SYNCOBJ_WAIT
            | gpu::OP_CTX_CREATE
            | gpu::OP_CTX_DESTROY
            | gpu::OP_SUBMIT => {
                close_h(hnd);
                if role != Role::Render {
                    println!("gpu: refused render op {} on non-render endpoint", h.op);
                    Self::reply(ch, h.txid, h.op, sys::ERR_ACCESS_DENIED as i32, 0, 0, &[]);
                    return;
                }
                let req_id = h.a as u32;
                let Some(aid) = self.resolve_adapter_id(req_id) else {
                    Self::reply(ch, h.txid, h.op, sys::ERR_OUT_OF_RANGE as i32, 0, 0, &[]);
                    return;
                };
                // Enforce per-client ownership on VM, GEM, and Context handles!
                match h.op {
                    gpu::OP_VM_DESTROY => {
                        let vm_id = h.b as u32;
                        if !self.client_owns_vm(client_id, aid, vm_id) {
                            Self::reply(ch, h.txid, h.op, sys::ERR_ACCESS_DENIED as i32, 0, 0, &[]);
                            return;
                        }
                    }
                    gpu::OP_VM_BIND => {
                        let vm_id = (h.a >> 32) as u32;
                        let gem_h = h.b as u32;
                        if !self.client_owns_vm(client_id, aid, vm_id)
                            || !self.client_owns_gem(client_id, aid, gem_h)
                        {
                            Self::reply(ch, h.txid, h.op, sys::ERR_ACCESS_DENIED as i32, 0, 0, &[]);
                            return;
                        }
                    }
                    gpu::OP_VM_UNBIND => {
                        let vm_id = (h.a >> 32) as u32;
                        if !self.client_owns_vm(client_id, aid, vm_id) {
                            Self::reply(ch, h.txid, h.op, sys::ERR_ACCESS_DENIED as i32, 0, 0, &[]);
                            return;
                        }
                    }
                    gpu::OP_CTX_CREATE => {
                        let vm_id = h.b as u32;
                        if vm_id != 0 && !self.client_owns_vm(client_id, aid, vm_id) {
                            Self::reply(ch, h.txid, h.op, sys::ERR_ACCESS_DENIED as i32, 0, 0, &[]);
                            return;
                        }
                    }
                    gpu::OP_CTX_DESTROY => {
                        let ctx_id = h.b as u32;
                        if !self.client_owns_ctx(client_id, aid, ctx_id) {
                            Self::reply(ch, h.txid, h.op, sys::ERR_ACCESS_DENIED as i32, 0, 0, &[]);
                            return;
                        }
                    }
                    gpu::OP_SUBMIT => {
                        let ctx_id = (h.a >> 32) as u32;
                        if !self.client_owns_ctx(client_id, aid, ctx_id) {
                            Self::reply(ch, h.txid, h.op, sys::ERR_ACCESS_DENIED as i32, 0, 0, &[]);
                            return;
                        }
                    }
                    _ => {}
                }

                let drv_op = match h.op {
                    gpu::OP_VM_CREATE => gpu::DRV_VM_CREATE,
                    gpu::OP_VM_DESTROY => gpu::DRV_VM_DESTROY,
                    gpu::OP_VM_BIND => gpu::DRV_VM_BIND,
                    gpu::OP_VM_UNBIND => gpu::DRV_VM_UNBIND,
                    gpu::OP_SYNCOBJ_CREATE => gpu::DRV_SYNCOBJ_CREATE,
                    gpu::OP_SYNCOBJ_DESTROY => gpu::DRV_SYNCOBJ_DESTROY,
                    gpu::OP_SYNCOBJ_SIGNAL => gpu::DRV_SYNCOBJ_SIGNAL,
                    gpu::OP_SYNCOBJ_WAIT => gpu::DRV_SYNCOBJ_WAIT,
                    gpu::OP_CTX_CREATE => gpu::DRV_CTX_CREATE,
                    gpu::OP_CTX_DESTROY => gpu::DRV_CTX_DESTROY,
                    _ => gpu::DRV_SUBMIT,
                };
                let Some(ad) = self.adapters.iter().find(|a| a.info.id == aid) else {
                    Self::reply(ch, h.txid, h.op, sys::ERR_OUT_OF_RANGE as i32, 0, 0, &[]);
                    return;
                };
                match ad.backend {
                    Backend::Gop(_) => Self::reply(ch, h.txid, h.op, sys::ERR_NOT_SUPPORTED as i32, 0, 0, &[]),
                    Backend::Pci { ch: dch, .. } if dch != 0 => {
                        let mut req = alloc::vec![0u8; HEADER + payload.len()];
                        Header { txid: 0, op: drv_op, status: 0, a: h.a, b: h.b }.put(&mut req);
                        req[HEADER..].copy_from_slice(payload);
                        let mut rep = [0u8; HEADER];
                        match sys::channel_call(dch, &req, &mut rep, CALL_TIMEOUT_NS) {
                            Ok(rn) => {
                                let dh = Header::get(&rep[..rn as usize]).unwrap_or_default();
                                if dh.status == 0 {
                                    match h.op {
                                        gpu::OP_VM_CREATE => self.owned_vms.push(OwnedVm {
                                            client_id,
                                            adapter_id: aid,
                                            vm_id: dh.a as u32,
                                        }),
                                        gpu::OP_VM_DESTROY => {
                                            let vm_id = h.b as u32;
                                            self.owned_vms.retain(|v| !(v.adapter_id == aid && v.vm_id == vm_id));
                                        }
                                        gpu::OP_CTX_CREATE => self.owned_ctxs.push(OwnedCtx {
                                            client_id,
                                            adapter_id: aid,
                                            ctx_id: dh.a as u32,
                                        }),
                                        gpu::OP_CTX_DESTROY => {
                                            let ctx_id = h.b as u32;
                                            self.owned_ctxs.retain(|c| !(c.adapter_id == aid && c.ctx_id == ctx_id));
                                        }
                                        _ => {}
                                    }
                                }
                                Self::reply(ch, h.txid, h.op, dh.status, dh.a, dh.b, &[]);
                            }
                            Err(e) => Self::reply(ch, h.txid, h.op, e as i32, 0, 0, &[]),
                        }
                    }
                    _ => Self::reply(ch, h.txid, h.op, sys::ERR_BAD_STATE as i32, 0, 0, &[]),
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
        next_client_id: 1,
        owned_gems: Vec::new(),
        owned_vms: Vec::new(),
        owned_ctxs: Vec::new(),
        revert_guard: ModeRevertGuard::new(),
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
        if let Some((rev_id, rev_mode)) = svc.revert_guard.poll_expired(sys::clock_ns()) {
            svc.apply_mode_revert(rev_id, rev_mode);
        }
        let timeout = match svc.revert_guard.deadline_ns() {
            Some(dl) => dl.saturating_sub(sys::clock_ns()),
            None => sys::WAIT_FOREVER,
        };
        let Some((key, _)) = svc.port.wait(timeout) else {
            continue;
        };
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
