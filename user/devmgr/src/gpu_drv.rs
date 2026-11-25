//! Shared Ring-3 DRM/KMS/GEM/VM/Syncobj driver <-> `gpu.dsvc` protocol bridge (`gpu_drv.rs`)
//! used by `virtio-gpu.ddrv`, `amdgpu.ddrv`, `xe.ddrv`, and `nvgpu.ddrv`.

use dosdrm::DamageRect;
use dosdrm::gem::DrmMemError;
use dosdrm::kms::{self, AtomicCommit, KmsError};
use libd::gpu::{
    self, ATOMIC_COMMIT_HDR_BYTES, AtomicCommitWire, KMS_RESOURCES_HDR_BYTES, KmsResourcesWire,
    MAX_PRESENT_RECTS, MODE_ENTRY_BYTES, ModeEntry,
};
use libd::proto::{self, HEADER, Header};
use libd::sys::{self, Handle, MsgHandle};
use libd::Port;

pub const KEY_CTL: u64 = 1;
pub const KEY_SVC_BASE: u64 = 0x10;
pub const KEY_IRQ0: u64 = 3;
pub const KEY_IRQ1: u64 = 4;

/// Maximum simultaneous display pipes (outputs) announced by one GPU driver process.
pub const MAX_PIPES: usize = 4;

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

pub fn kms_err_to_sys(e: KmsError) -> i64 {
    match e {
        KmsError::InvalidArgs => sys::ERR_INVALID_ARGS,
        KmsError::UnknownObject => sys::ERR_OUT_OF_RANGE,
        KmsError::UnsupportedFormat | KmsError::UnsupportedMode | KmsError::CapabilityUnsupported => {
            sys::ERR_NOT_SUPPORTED
        }
        KmsError::ModesetRequired => sys::ERR_BAD_STATE,
        KmsError::BufferTooSmall => sys::ERR_OUT_OF_RANGE,
        KmsError::NoResources => sys::ERR_NO_RESOURCES,
    }
}

pub fn mem_err_to_sys(e: DrmMemError) -> i64 {
    match e {
        DrmMemError::InvalidArgs | DrmMemError::Unaligned => sys::ERR_INVALID_ARGS,
        DrmMemError::UnknownHandle | DrmMemError::OutOfRange => sys::ERR_OUT_OF_RANGE,
        DrmMemError::AddressOverlap | DrmMemError::Busy => sys::ERR_BAD_STATE,
        DrmMemError::NoResources => sys::ERR_NO_RESOURCES,
    }
}

/// Convert wire `AtomicCommitWire` into `dosdrm::kms::AtomicCommit`.
pub fn wire_to_atomic(w: &AtomicCommitWire) -> AtomicCommit {
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

/// Unified Atomic KMS + GEM/VM/Syncobj driver trait implemented by every `.ddrv` GPU process.
pub trait DrmDriver {
    fn set_active_slot(&mut self, _slot: usize) {}

    fn kms_get_resources(&self, res_out: &mut KmsResourcesWire, modes_out: &mut [ModeEntry]) -> usize;

    fn gem_import(&mut self, vmo: Handle, size: u64, bo_flags: u32) -> Result<(u32, [u8; 16]), i64>;

    fn gem_create(&mut self, size: u64, bo_flags: u32) -> Result<(u32, Handle, [u8; 16]), i64> {
        let _ = (size, bo_flags);
        Err(sys::ERR_NOT_SUPPORTED)
    }

    fn gem_close(&mut self, gem_handle: u32) -> Result<(), i64>;

    fn kms_create_fb(
        &mut self,
        gem_handle: u32,
        width: u32,
        height: u32,
        pitch: u32,
        format: u32,
        modifier: u64,
    ) -> Result<u32, i64>;

    fn kms_destroy_fb(&mut self, fb_id: u32) -> Result<(), i64>;

    /// Validate (`ATOMIC_TEST_ONLY`) or commit an atomic KMS state update.
    /// Returns `(vblank_seq, async_vblank_pending)`.
    fn kms_atomic_commit(&mut self, commit: &AtomicCommit) -> Result<(u64, bool), i64>;

    fn vm_create(&mut self) -> Result<u32, i64> {
        Err(sys::ERR_NOT_SUPPORTED)
    }

    fn vm_destroy(&mut self, _vm_id: u32) -> Result<(), i64> {
        Err(sys::ERR_NOT_SUPPORTED)
    }

    fn vm_bind(
        &mut self,
        _vm_id: u32,
        _gem_handle: u32,
        _bo_offset: u64,
        _gpu_va: u64,
        _size: u64,
        _flags: u32,
    ) -> Result<(), i64> {
        Err(sys::ERR_NOT_SUPPORTED)
    }

    fn vm_unbind(&mut self, _vm_id: u32, _gpu_va: u64, _size: u64) -> Result<(), i64> {
        Err(sys::ERR_NOT_SUPPORTED)
    }

    fn syncobj_create(&mut self, _initial_point: u64) -> Result<u32, i64> {
        Err(sys::ERR_NOT_SUPPORTED)
    }

    fn syncobj_destroy(&mut self, _syncobj: u32) -> Result<(), i64> {
        Err(sys::ERR_NOT_SUPPORTED)
    }

    fn syncobj_signal(&mut self, _syncobj: u32, _point: u64) -> Result<u64, i64> {
        Err(sys::ERR_NOT_SUPPORTED)
    }

    fn syncobj_wait(&mut self, _syncobj: u32, _point: u64) -> Result<u64, i64> {
        Err(sys::ERR_NOT_SUPPORTED)
    }

    fn ctx_create(&mut self, _engine: u32, _vm_id: u32) -> Result<u32, i64> {
        Err(sys::ERR_NOT_SUPPORTED)
    }

    fn ctx_destroy(&mut self, _ctx_id: u32) -> Result<(), i64> {
        Err(sys::ERR_NOT_SUPPORTED)
    }

    #[allow(clippy::too_many_arguments)]
    fn submit(
        &mut self,
        _ctx_id: u32,
        _engine: u32,
        _wait_syncobj: u32,
        _wait_point: u64,
        _signal_syncobj: u32,
        _signal_point: u64,
        _cmd: &[u8],
    ) -> Result<u64, i64> {
        Err(sys::ERR_NOT_SUPPORTED)
    }

    fn next_deadline_ns(&self) -> Option<u64> {
        None
    }

    /// Poll completed asynchronous vblank flips: `(pipe_slot, vblank_seq, timestamp_ns, late)`.
    fn poll_vblank(&mut self) -> Option<(usize, u64, u64, bool)> {
        None
    }

    fn on_shutdown(&mut self) {}
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
    announce_output(ctl, info);
}

/// Announce one output of a GPU adapter to `devmgr` (`proto::GPU_DEV`).
pub fn announce_output(ctl: Handle, info: &GpuAnnounce<'_>) {
    let mut msg = [0u8; HEADER + 40];
    let a = gpu::pack_dev_a(info.kind, info.vendor, info.device, info.vram_mib);
    let b = gpu::pack_dev_b(info.width, info.height, info.caps);
    let nb = info.name.as_bytes();
    let nl = nb.len().min(40);
    Header { txid: 0, op: proto::GPU_DEV, status: 0, a, b }.put(&mut msg);
    msg[HEADER..HEADER + nl].copy_from_slice(&nb[..nl]);
    let _ = sys::channel_write(ctl, &msg[..HEADER + nl]);
}

/// Shared `.ddrv` event loop serving `devmgr` control messages, `gpu.dsvc` Atomic KMS / GEM / VM /
/// Syncobj requests, hardware interrupts, and asynchronous vblank events.
pub fn serve_loop<D: DrmDriver>(ctl: Handle, port: &Port, drv: &mut D) -> i32 {
    port.arm(ctl, sys::READABLE | sys::PEER_CLOSED, KEY_CTL);
    let mut svc_ch = [0 as Handle; MAX_PIPES];
    let mut buf = [0u8; HEADER + 4096];

    loop {
        while let Some((slot, seq, ts_ns, late)) = drv.poll_vblank() {
            if let Some(&ch) = svc_ch.get(slot)
                && ch != 0
            {
                let a = (seq & !(1u64 << 63)) | (u64::from(late) << 63);
                proto::send(ch, gpu::DRV_EVENT_VBLANK, a, ts_ns);
            }
        }

        let timeout = match drv.next_deadline_ns() {
            Some(dl) => dl.saturating_sub(sys::clock_ns()),
            None => sys::WAIT_FOREVER,
        };
        let Some((key, _)) = port.wait(timeout) else {
            continue;
        };
        match key {
            KEY_CTL => loop {
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
                                let slot = (h.a as usize).min(MAX_PIPES - 1);
                                if svc_ch[slot] != 0 {
                                    sys::handle_close(svc_ch[slot]);
                                }
                                svc_ch[slot] = hnd;
                                port.arm(hnd, sys::READABLE | sys::PEER_CLOSED, KEY_SVC_BASE + slot as u64);
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
                    Err(_) => {
                        drv.on_shutdown();
                        return 0;
                    }
                }
            },
            k if (KEY_SVC_BASE..KEY_SVC_BASE + MAX_PIPES as u64).contains(&k) => {
                let slot = (k - KEY_SVC_BASE) as usize;
                let ch = svc_ch[slot];
                if ch == 0 {
                    continue;
                }
                loop {
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
                            drv.set_active_slot(slot);
                            handle_svc_msg(ch, drv, h, &buf[HEADER..n], hnd);
                        }
                        Err(sys::ERR_SHOULD_WAIT) => {
                            port.arm(ch, sys::READABLE | sys::PEER_CLOSED, k);
                            break;
                        }
                        Err(_) => {
                            sys::handle_close(ch);
                            svc_ch[slot] = 0;
                            drv.on_shutdown();
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
    let mut out = [0u8; HEADER + KMS_RESOURCES_HDR_BYTES + 16 * MODE_ENTRY_BYTES];
    let plen = payload.len().min(out.len() - HEADER);
    Header { txid, op, status, a, b }.put(&mut out);
    out[HEADER..HEADER + plen].copy_from_slice(&payload[..plen]);
    let _ = sys::channel_write(ch, &out[..HEADER + plen]);
}

#[allow(clippy::too_many_arguments)]
fn reply_with_handle(ch: Handle, txid: u32, op: u32, status: i32, a: u64, b: u64, payload: &[u8], hnd: Handle) {
    let mut out = [0u8; HEADER + 64];
    let plen = payload.len().min(64);
    Header { txid, op, status, a, b }.put(&mut out);
    out[HEADER..HEADER + plen].copy_from_slice(&payload[..plen]);
    let _ = sys::channel_write_h(
        ch,
        &out[..HEADER + plen],
        &[MsgHandle { handle: hnd, rights: sys::RIGHTS_SAME }],
    );
}

fn handle_svc_msg<D: DrmDriver>(ch: Handle, drv: &mut D, h: Header, payload: &[u8], hnd: Handle) {
    let close_h = |hnd: Handle| {
        if hnd != 0 {
            sys::handle_close(hnd);
        }
    };
    match h.op {
        gpu::DRV_KMS_GET_RESOURCES => {
            close_h(hnd);
            let mut res = KmsResourcesWire::empty();
            let mut modes = [ModeEntry::default(); 16];
            let count = drv.kms_get_resources(&mut res, &mut modes).min(16);
            let mut body = [0u8; KMS_RESOURCES_HDR_BYTES + 16 * MODE_ENTRY_BYTES];
            let mut hdr_bytes = [0u8; KMS_RESOURCES_HDR_BYTES];
            res.encode(&mut hdr_bytes);
            body[..KMS_RESOURCES_HDR_BYTES].copy_from_slice(&hdr_bytes);
            for (i, m) in modes.iter().take(count).enumerate() {
                let mut enc = [0u8; MODE_ENTRY_BYTES];
                m.encode(&mut enc);
                let off = KMS_RESOURCES_HDR_BYTES + i * MODE_ENTRY_BYTES;
                body[off..off + MODE_ENTRY_BYTES].copy_from_slice(&enc);
            }
            reply(
                ch,
                h.txid,
                h.op,
                0,
                count as u64,
                0,
                &body[..KMS_RESOURCES_HDR_BYTES + count * MODE_ENTRY_BYTES],
            );
        }
        gpu::DRV_GEM_IMPORT => {
            if hnd == 0 {
                reply(ch, h.txid, h.op, sys::ERR_INVALID_ARGS as i32, 0, 0, &[]);
                return;
            }
            let bo_flags = (h.a >> 32) as u32;
            let size = h.b;
            match drv.gem_import(hnd, size, bo_flags) {
                Ok((gem_h, uuid)) => reply(ch, h.txid, h.op, 0, u64::from(gem_h), 0, &uuid),
                Err(e) => reply(ch, h.txid, h.op, e as i32, 0, 0, &[]),
            }
        }
        gpu::DRV_GEM_CREATE => {
            close_h(hnd);
            let bo_flags = (h.a >> 32) as u32;
            let size = h.b;
            match drv.gem_create(size, bo_flags) {
                Ok((gem_h, vmo_h, uuid)) => reply_with_handle(ch, h.txid, h.op, 0, u64::from(gem_h), 0, &uuid, vmo_h),
                Err(e) => reply(ch, h.txid, h.op, e as i32, 0, 0, &[]),
            }
        }
        gpu::DRV_GEM_CLOSE => {
            close_h(hnd);
            match drv.gem_close(h.b as u32) {
                Ok(()) => reply(ch, h.txid, h.op, 0, 0, 0, &[]),
                Err(e) => reply(ch, h.txid, h.op, e as i32, 0, 0, &[]),
            }
        }
        gpu::DRV_KMS_CREATE_FB => {
            close_h(hnd);
            if payload.len() < 16 {
                reply(ch, h.txid, h.op, sys::ERR_INVALID_ARGS as i32, 0, 0, &[]);
                return;
            }
            let gem_handle = (h.a >> 32) as u32;
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
            match drv.kms_create_fb(gem_handle, width, height, pitch, format, modifier) {
                Ok(fb_id) => reply(ch, h.txid, h.op, 0, u64::from(fb_id), 0, &[]),
                Err(e) => reply(ch, h.txid, h.op, e as i32, 0, 0, &[]),
            }
        }
        gpu::DRV_KMS_DESTROY_FB => {
            close_h(hnd);
            match drv.kms_destroy_fb(h.b as u32) {
                Ok(()) => reply(ch, h.txid, h.op, 0, 0, 0, &[]),
                Err(e) => reply(ch, h.txid, h.op, e as i32, 0, 0, &[]),
            }
        }
        gpu::DRV_KMS_ATOMIC_COMMIT => {
            close_h(hnd);
            let max_len = ATOMIC_COMMIT_HDR_BYTES + MAX_PRESENT_RECTS * 16;
            let Some(wire) = AtomicCommitWire::decode(&payload[..payload.len().min(max_len)]) else {
                reply(ch, h.txid, h.op, sys::ERR_INVALID_ARGS as i32, 0, 0, &[]);
                return;
            };
            let commit = wire_to_atomic(&wire);
            match drv.kms_atomic_commit(&commit) {
                Ok((seq, is_async)) => reply(ch, h.txid, h.op, 0, seq, u64::from(is_async), &[]),
                Err(e) => reply(ch, h.txid, h.op, e as i32, 0, 0, &[]),
            }
        }
        gpu::DRV_VM_CREATE => {
            close_h(hnd);
            match drv.vm_create() {
                Ok(vm_id) => reply(ch, h.txid, h.op, 0, u64::from(vm_id), 0, &[]),
                Err(e) => reply(ch, h.txid, h.op, e as i32, 0, 0, &[]),
            }
        }
        gpu::DRV_VM_DESTROY => {
            close_h(hnd);
            match drv.vm_destroy(h.b as u32) {
                Ok(()) => reply(ch, h.txid, h.op, 0, 0, 0, &[]),
                Err(e) => reply(ch, h.txid, h.op, e as i32, 0, 0, &[]),
            }
        }
        gpu::DRV_VM_BIND => {
            close_h(hnd);
            if payload.len() < 24 {
                reply(ch, h.txid, h.op, sys::ERR_INVALID_ARGS as i32, 0, 0, &[]);
                return;
            }
            let vm_id = (h.a >> 32) as u32;
            let gem_handle = h.b as u32;
            let flags = (h.b >> 32) as u32;
            let bo_offset = u64::from_le_bytes([
                payload[0], payload[1], payload[2], payload[3], payload[4], payload[5], payload[6], payload[7],
            ]);
            let gpu_va = u64::from_le_bytes([
                payload[8], payload[9], payload[10], payload[11], payload[12], payload[13], payload[14], payload[15],
            ]);
            let size = u64::from_le_bytes([
                payload[16], payload[17], payload[18], payload[19], payload[20], payload[21], payload[22], payload[23],
            ]);
            match drv.vm_bind(vm_id, gem_handle, bo_offset, gpu_va, size, flags) {
                Ok(()) => reply(ch, h.txid, h.op, 0, 0, 0, &[]),
                Err(e) => reply(ch, h.txid, h.op, e as i32, 0, 0, &[]),
            }
        }
        gpu::DRV_VM_UNBIND => {
            close_h(hnd);
            if payload.len() < 8 {
                reply(ch, h.txid, h.op, sys::ERR_INVALID_ARGS as i32, 0, 0, &[]);
                return;
            }
            let vm_id = (h.a >> 32) as u32;
            let gpu_va = h.b;
            let size = u64::from_le_bytes([
                payload[0], payload[1], payload[2], payload[3], payload[4], payload[5], payload[6], payload[7],
            ]);
            match drv.vm_unbind(vm_id, gpu_va, size) {
                Ok(()) => reply(ch, h.txid, h.op, 0, 0, 0, &[]),
                Err(e) => reply(ch, h.txid, h.op, e as i32, 0, 0, &[]),
            }
        }
        gpu::DRV_SYNCOBJ_CREATE => {
            close_h(hnd);
            match drv.syncobj_create(h.b) {
                Ok(id) => reply(ch, h.txid, h.op, 0, u64::from(id), 0, &[]),
                Err(e) => reply(ch, h.txid, h.op, e as i32, 0, 0, &[]),
            }
        }
        gpu::DRV_SYNCOBJ_DESTROY => {
            close_h(hnd);
            match drv.syncobj_destroy(h.b as u32) {
                Ok(()) => reply(ch, h.txid, h.op, 0, 0, 0, &[]),
                Err(e) => reply(ch, h.txid, h.op, e as i32, 0, 0, &[]),
            }
        }
        gpu::DRV_SYNCOBJ_SIGNAL => {
            close_h(hnd);
            let syncobj = (h.a >> 32) as u32;
            match drv.syncobj_signal(syncobj, h.b) {
                Ok(val) => reply(ch, h.txid, h.op, 0, val, 0, &[]),
                Err(e) => reply(ch, h.txid, h.op, e as i32, 0, 0, &[]),
            }
        }
        gpu::DRV_SYNCOBJ_WAIT => {
            close_h(hnd);
            let syncobj = (h.a >> 32) as u32;
            match drv.syncobj_wait(syncobj, h.b) {
                Ok(val) => reply(ch, h.txid, h.op, 0, val, 0, &[]),
                Err(e) => reply(ch, h.txid, h.op, e as i32, 0, 0, &[]),
            }
        }
        gpu::DRV_CTX_CREATE => {
            close_h(hnd);
            let engine = (h.a >> 32) as u32;
            let vm_id = h.b as u32;
            match drv.ctx_create(engine, vm_id) {
                Ok(id) => reply(ch, h.txid, h.op, 0, u64::from(id), 0, &[]),
                Err(e) => reply(ch, h.txid, h.op, e as i32, 0, 0, &[]),
            }
        }
        gpu::DRV_CTX_DESTROY => {
            close_h(hnd);
            match drv.ctx_destroy(h.b as u32) {
                Ok(()) => reply(ch, h.txid, h.op, 0, 0, 0, &[]),
                Err(e) => reply(ch, h.txid, h.op, e as i32, 0, 0, &[]),
            }
        }
        gpu::DRV_SUBMIT => {
            close_h(hnd);
            if payload.len() < 24 {
                reply(ch, h.txid, h.op, sys::ERR_INVALID_ARGS as i32, 0, 0, &[]);
                return;
            }
            let ctx_id = (h.a >> 32) as u32;
            let engine = h.b as u32;
            let cmd_len = ((h.b >> 32) as usize).min(payload.len() - 24);
            let wait_sync = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
            let sig_sync = u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]);
            let wait_pt = u64::from_le_bytes([
                payload[8], payload[9], payload[10], payload[11], payload[12], payload[13], payload[14], payload[15],
            ]);
            let sig_pt = u64::from_le_bytes([
                payload[16], payload[17], payload[18], payload[19], payload[20], payload[21], payload[22], payload[23],
            ]);
            match drv.submit(ctx_id, engine, wait_sync, wait_pt, sig_sync, sig_pt, &payload[24..24 + cmd_len]) {
                Ok(seq) => reply(ch, h.txid, h.op, 0, seq, 0, &[]),
                Err(e) => reply(ch, h.txid, h.op, e as i32, 0, 0, &[]),
            }
        }
        gpu::DRV_TEST_CRASH => {
            close_h(hnd);
            libd::println!("gpu-drv: intentional crash requested");
            panic!("intentional gpu driver test crash");
        }
        _ => {
            close_h(hnd);
            reply(ch, h.txid, h.op, sys::ERR_NOT_SUPPORTED as i32, 0, 0, &[]);
        }
    }
}
