//! GPU & display service, driver, and client IPC protocol (`libd::gpu`).
//!
//! Capability separation:
//! - `gpu.query`: read-only adapter/mode/EDID/capability enumeration (`OP_LIST_ADAPTERS`,
//!   `OP_GET_MODES`, `OP_GET_DISPLAY_INFO`).
//! - `gpu.display`: exclusive display/modesetting authority (`OP_ATTACH_FB`, `OP_SET_MODE`,
//!   `OP_SET_MODE_EX`, `OP_PRESENT`, `OP_PRESENT_MULTI`, `OP_SET_CURSOR`, `OP_MOVE_CURSOR`,
//!   `OP_RELEASE_DISPLAY`, `OP_SET_VRR`, `OP_SET_HDR`, `OP_FLIP_TEST`, plus query ops).
//! - `gpu.render`: GPU command submission & context lifecycle (`OP_CTX_CREATE`,
//!   `OP_CTX_DESTROY`, `OP_SUBMIT_CMD`, plus query ops; never touches display scanout).
//!
//! Zero-copy framebuffer scanout:
//! Clients create a pixel VMO and pass it once via `OP_ATTACH_FB`; `gpu.dsvc` hands it to the
//! PCI GPU driver, which pins it directly into the device's IOMMU domain (`DMA_DEVICE_READ`).

use crate::proto::{HEADER, Header};
use crate::svc;
use crate::sys::{self, Handle, MsgHandle};

// ---- Backend registration (devmgr -> gpu.dsvc on `devmgr.gpu`) ----------------------------------

pub const BACKEND_ADD: u32 = 800;
pub const BACKEND_GONE: u32 = 801;

// ---- GPU driver direct protocol (gpu.dsvc <-> GPU `.ddrv` channel) ------------------------------

pub const DRV_GET_MODES: u32 = 810;
pub const DRV_ATTACH_FB: u32 = 811;
pub const DRV_SET_MODE: u32 = 812;
pub const DRV_PRESENT: u32 = 813;
pub const DRV_SET_CURSOR: u32 = 814;
pub const DRV_MOVE_CURSOR: u32 = 815;
pub const DRV_CTX_CREATE: u32 = 816;
pub const DRV_CTX_DESTROY: u32 = 817;
pub const DRV_SUBMIT_CMD: u32 = 818;
pub const DRV_TEST_CRASH: u32 = 819;
pub const DRV_SET_GOP_INFO: u32 = 831;
pub const DRV_GET_DISPLAY_INFO: u32 = 832;
pub const DRV_PRESENT_MULTI: u32 = 833;
pub const DRV_RELEASE_DISPLAY: u32 = 834;
pub const DRV_SET_MODE_EX: u32 = 835;
pub const DRV_SET_VRR: u32 = 836;
pub const DRV_SET_HDR: u32 = 837;
pub const DRV_FLIP_TEST: u32 = 838;
/// Unsolicited driver -> `gpu.dsvc` event (txid=0): `a` = frames | (late << 63), `b` = timestamp_ns.
pub const DRV_FLIP_DONE: u32 = 839;

// ---- Client <-> gpu.dsvc protocol (`gpu.query`, `gpu.display`, `gpu.render`) --------------------

pub const OP_LIST_ADAPTERS: u32 = 820;
pub const OP_GET_MODES: u32 = 821;
pub const OP_ATTACH_FB: u32 = 822;
pub const OP_SET_MODE: u32 = 823;
pub const OP_PRESENT: u32 = 824;
pub const OP_SET_CURSOR: u32 = 825;
pub const OP_MOVE_CURSOR: u32 = 826;
pub const OP_CTX_CREATE: u32 = 827;
pub const OP_CTX_DESTROY: u32 = 828;
pub const OP_SUBMIT_CMD: u32 = 829;
pub const OP_CRASH_DRIVER: u32 = 830;
pub const OP_GET_DISPLAY_INFO: u32 = 840;
pub const OP_PRESENT_MULTI: u32 = 841;
pub const OP_RELEASE_DISPLAY: u32 = 842;
pub const OP_SET_MODE_EX: u32 = 843;
pub const OP_SET_VRR: u32 = 844;
pub const OP_SET_HDR: u32 = 845;
pub const OP_FLIP_TEST: u32 = 846;
/// Unsolicited `gpu.dsvc` -> `gpu.display` event (txid=0):
/// `a` = adapter_id | (late << 32), `b` = frames, payload = optional timestamp_ns (u64).
pub const EVT_FLIP_DONE: u32 = 849;
/// Unsolicited `gpu.dsvc` -> `gpu.display` event (txid=0):
/// `a` = adapter_id whose online state, capabilities, or active mode changed.
pub const EVT_ADAPTERS_CHANGED: u32 = 850;

// Adapter kinds (mirroring `dosgpu::AdapterKind`).
pub const KIND_GOP: u8 = 1;
pub const KIND_VIRTIO_GPU: u8 = 2;
pub const KIND_AMD_RDNA: u8 = 3;
pub const KIND_INTEL_XE: u8 = 4;
pub const KIND_NVIDIA_GSP: u8 = 5;

// Capability bits (mirroring `dosgpu::caps`).
pub const CAP_SCANOUT_2D: u32 = 1 << 0;
pub const CAP_HW_CURSOR: u32 = 1 << 1;
pub const CAP_EDID: u32 = 1 << 2;
pub const CAP_VIRGL_3D: u32 = 1 << 3;
pub const CAP_PAGE_FLIP: u32 = 1 << 4;
pub const CAP_CMD_GFX: u32 = 1 << 5;
pub const CAP_CMD_DMA: u32 = 1 << 6;
pub const CAP_IOMMU: u32 = 1 << 7;
pub const CAP_WC: u32 = 1 << 8;
pub const CAP_GSP_RPC: u32 = 1 << 9;
pub const CAP_ASYNC_FLIP: u32 = 1 << 10;
pub const CAP_NATIVE_GOP_MATCH: u32 = 1 << 11;
pub const CAP_VRR: u32 = 1 << 12;
pub const CAP_HDR: u32 = 1 << 13;
pub const CAP_DSC: u32 = 1 << 14;

// Pixel formats (mirroring `dosgpu::PixelFormat`).
pub const FMT_XRGB8888: u32 = 1;
pub const FMT_ARGB8888: u32 = 2;
pub const FMT_XBGR8888: u32 = 3;
pub const FMT_ARGB2101010: u32 = 4;

pub const MAX_PRESENT_RECTS: usize = 16;

// Command submission engines (mirroring `dosgpu::EngineKind`).
pub const ENGINE_VIRGL_3D: u32 = 1;
pub const ENGINE_AMD_PM4: u32 = 2;
pub const ENGINE_AMD_SDMA: u32 = 3;
pub const ENGINE_INTEL_BLIT: u32 = 4;
pub const ENGINE_NVIDIA_GSP: u32 = 5;

const CALL_TIMEOUT_NS: u64 = 10_000_000_000;

/// Look up the granted `gpu.query` endpoint handle (0 if not granted).
pub fn query_endpoint() -> Handle {
    svc::endpoint(b"gpu.query")
}

/// Look up the granted `gpu.display` endpoint handle (0 if not granted).
pub fn display_endpoint() -> Handle {
    svc::endpoint(b"gpu.display")
}

/// Look up the granted `gpu.render` endpoint handle (0 if not granted).
pub fn render_endpoint() -> Handle {
    svc::endpoint(b"gpu.render")
}

/// Fixed-size binary adapter descriptor returned by `OP_LIST_ADAPTERS` (128 bytes each).
pub const ADAPTER_INFO_BYTES: usize = 128;

#[derive(Clone, Copy, Debug)]
pub struct AdapterInfo {
    pub id: u32,
    pub kind: u8,
    pub online: bool,
    pub vendor: u16,
    pub device: u16,
    pub caps: u32,
    pub width: u32,
    pub height: u32,
    pub vram_mib: u32,
    pub frames: u64,
    pub restarts: u32,
    pub monitor: [u8; 24],
    pub monitor_len: u8,
    pub name: [u8; 40],
    pub name_len: u8,
}

impl AdapterInfo {
    pub const fn empty() -> Self {
        Self {
            id: 0,
            kind: 0,
            online: false,
            vendor: 0,
            device: 0,
            caps: 0,
            width: 0,
            height: 0,
            vram_mib: 0,
            frames: 0,
            restarts: 0,
            monitor: [0; 24],
            monitor_len: 0,
            name: [0; 40],
            name_len: 0,
        }
    }

    pub fn name_str(&self) -> &str {
        let n = (self.name_len as usize).min(self.name.len());
        core::str::from_utf8(&self.name[..n]).unwrap_or("?")
    }

    pub fn monitor_str(&self) -> &str {
        let n = (self.monitor_len as usize).min(self.monitor.len());
        core::str::from_utf8(&self.monitor[..n]).unwrap_or("")
    }

    pub const fn kind_name(&self) -> &'static str {
        match self.kind {
            KIND_GOP => "gop",
            KIND_VIRTIO_GPU => "virtio-gpu",
            KIND_AMD_RDNA => "amdgpu",
            KIND_INTEL_XE => "xe",
            KIND_NVIDIA_GSP => "nvgpu",
            _ => "unknown",
        }
    }

    pub fn encode(&self, out: &mut [u8; ADAPTER_INFO_BYTES]) {
        out.fill(0);
        out[0..4].copy_from_slice(&self.id.to_le_bytes());
        out[4] = self.kind;
        out[5] = u8::from(self.online);
        out[6..8].copy_from_slice(&self.vendor.to_le_bytes());
        out[8..10].copy_from_slice(&self.device.to_le_bytes());
        out[12..16].copy_from_slice(&self.caps.to_le_bytes());
        out[16..20].copy_from_slice(&self.width.to_le_bytes());
        out[20..24].copy_from_slice(&self.height.to_le_bytes());
        out[24..28].copy_from_slice(&self.vram_mib.to_le_bytes());
        out[28..32].copy_from_slice(&self.restarts.to_le_bytes());
        out[32..40].copy_from_slice(&self.frames.to_le_bytes());
        out[40] = self.monitor_len;
        out[41] = self.name_len;
        out[44..68].copy_from_slice(&self.monitor);
        out[68..108].copy_from_slice(&self.name);
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.len() < ADAPTER_INFO_BYTES {
            return None;
        }
        let u16_at = |o: usize| u16::from_le_bytes([b[o], b[o + 1]]);
        let u32_at = |o: usize| u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]);
        let u64_at = |o: usize| {
            u64::from_le_bytes([
                b[o], b[o + 1], b[o + 2], b[o + 3], b[o + 4], b[o + 5], b[o + 6], b[o + 7],
            ])
        };
        let mut a = Self::empty();
        a.id = u32_at(0);
        a.kind = b[4];
        a.online = b[5] != 0;
        a.vendor = u16_at(6);
        a.device = u16_at(8);
        a.caps = u32_at(12);
        a.width = u32_at(16);
        a.height = u32_at(20);
        a.vram_mib = u32_at(24);
        a.restarts = u32_at(28);
        a.frames = u64_at(32);
        a.monitor_len = b[40].min(24);
        a.name_len = b[41].min(40);
        a.monitor.copy_from_slice(&b[44..68]);
        a.name.copy_from_slice(&b[68..108]);
        Some(a)
    }
}

/// Fixed-size display mode entry returned by `OP_GET_MODES` (16 bytes each).
pub const MODE_ENTRY_BYTES: usize = 16;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ModeEntry {
    pub width: u32,
    pub height: u32,
    pub refresh_mhz: u32,
    pub flags: u32,
}

pub const MODE_FLAG_PREFERRED: u32 = 1 << 0;
pub const MODE_FLAG_CURRENT: u32 = 1 << 1;

impl ModeEntry {
    pub fn encode(&self, out: &mut [u8; MODE_ENTRY_BYTES]) {
        out[0..4].copy_from_slice(&self.width.to_le_bytes());
        out[4..8].copy_from_slice(&self.height.to_le_bytes());
        out[8..12].copy_from_slice(&self.refresh_mhz.to_le_bytes());
        out[12..16].copy_from_slice(&self.flags.to_le_bytes());
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.len() < MODE_ENTRY_BYTES {
            return None;
        }
        let u32_at = |o: usize| u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]);
        Some(Self {
            width: u32_at(0),
            height: u32_at(4),
            refresh_mhz: u32_at(8),
            flags: u32_at(12),
        })
    }
}

/// Pack `(kind, vendor, device, vram_mib)` into `Header::a` for `GPU_DEV`/`BACKEND_ADD`.
pub const fn pack_dev_a(kind: u8, vendor: u16, device: u16, vram_mib: u32) -> u64 {
    (kind as u64)
        | ((vendor as u64) << 8)
        | ((device as u64) << 24)
        | ((vram_mib as u64 & 0xFF_FFFF) << 40)
}

/// Unpack `(kind, vendor, device, vram_mib)` from `Header::a`.
pub const fn unpack_dev_a(a: u64) -> (u8, u16, u16, u32) {
    (
        (a & 0xFF) as u8,
        ((a >> 8) & 0xFFFF) as u16,
        ((a >> 24) & 0xFFFF) as u16,
        ((a >> 40) & 0xFF_FFFF) as u32,
    )
}

/// Pack `(width, height, caps)` into `Header::b` for `GPU_DEV`/`BACKEND_ADD`.
pub const fn pack_dev_b(width: u16, height: u16, caps: u32) -> u64 {
    (width as u64) | ((height as u64) << 16) | ((caps as u64) << 32)
}

/// Unpack `(width, height, caps)` from `Header::b`.
pub const fn unpack_dev_b(b: u64) -> (u32, u32, u32) {
    ((b & 0xFFFF) as u32, ((b >> 16) & 0xFFFF) as u32, (b >> 32) as u32)
}

/// List all GPU adapters into `out`; returns count written.
pub fn list_adapters(ep: Handle, out: &mut [AdapterInfo]) -> Result<usize, i64> {
    if ep == 0 {
        return Err(sys::ERR_BAD_HANDLE);
    }
    let mut req = [0u8; HEADER];
    Header { txid: 0, op: OP_LIST_ADAPTERS, status: 0, a: 0, b: 0 }.put(&mut req);
    let mut rep = [0u8; HEADER + 8 * ADAPTER_INFO_BYTES];
    let n = sys::channel_call(ep, &req, &mut rep, CALL_TIMEOUT_NS)? as usize;
    let h = Header::get(&rep[..n]).ok_or(sys::ERR_INVALID_ARGS)?;
    if h.status != 0 {
        return Err(i64::from(h.status));
    }
    let body = &rep[HEADER..n];
    let count = (body.len() / ADAPTER_INFO_BYTES).min(out.len());
    for (i, slot) in out.iter_mut().take(count).enumerate() {
        let off = i * ADAPTER_INFO_BYTES;
        if let Some(a) = AdapterInfo::decode(&body[off..off + ADAPTER_INFO_BYTES]) {
            *slot = a;
        }
    }
    Ok(count)
}

/// Query supported modes and monitor label for adapter `adapter_id`.
pub fn get_modes(ep: Handle, adapter_id: u32, out: &mut [ModeEntry]) -> Result<usize, i64> {
    if ep == 0 {
        return Err(sys::ERR_BAD_HANDLE);
    }
    let mut req = [0u8; HEADER];
    Header { txid: 0, op: OP_GET_MODES, status: 0, a: u64::from(adapter_id), b: 0 }.put(&mut req);
    let mut rep = [0u8; HEADER + 16 * MODE_ENTRY_BYTES];
    let n = sys::channel_call(ep, &req, &mut rep, CALL_TIMEOUT_NS)? as usize;
    let h = Header::get(&rep[..n]).ok_or(sys::ERR_INVALID_ARGS)?;
    if h.status != 0 {
        return Err(i64::from(h.status));
    }
    let body = &rep[HEADER..n];
    let count = (body.len() / MODE_ENTRY_BYTES).min(out.len());
    for (i, slot) in out.iter_mut().take(count).enumerate() {
        let off = i * MODE_ENTRY_BYTES;
        if let Some(m) = ModeEntry::decode(&body[off..off + MODE_ENTRY_BYTES]) {
            *slot = m;
        }
    }
    Ok(count)
}

/// Attach a framebuffer VMO to `adapter_id` (`gpu.display` required). Duplicates the VMO handle
/// with `RIGHT_READ | RIGHT_MAP | RIGHT_TRANSFER` so the caller keeps its own mapping.
pub fn attach_fb(
    ep: Handle,
    adapter_id: u32,
    vmo: Handle,
    width: u32,
    height: u32,
    pitch: u32,
    format: u32,
) -> Result<u32, i64> {
    if ep == 0 {
        return Err(sys::ERR_BAD_HANDLE);
    }
    let dup = sys::handle_duplicate(vmo, sys::RIGHT_READ | sys::RIGHT_MAP | sys::RIGHT_TRANSFER)?;
    let mut req = [0u8; HEADER + 16];
    let a = u64::from(adapter_id) | (u64::from(format) << 32);
    let b = u64::from(width) | (u64::from(height) << 32);
    Header { txid: 0, op: OP_ATTACH_FB, status: 0, a, b }.put(&mut req);
    req[HEADER..HEADER + 4].copy_from_slice(&pitch.to_le_bytes());
    let mut rep = [0u8; HEADER];
    let mut rh = [0 as Handle; 1];
    let (n, _) = sys::channel_call_h(
        ep,
        &req[..HEADER + 4],
        &[MsgHandle { handle: dup, rights: sys::RIGHTS_SAME }],
        &mut rep,
        &mut rh,
        CALL_TIMEOUT_NS,
    )?;
    let h = Header::get(&rep[..n]).ok_or(sys::ERR_INVALID_ARGS)?;
    if h.status != 0 {
        return Err(i64::from(h.status));
    }
    Ok(h.a as u32)
}

/// Set active scanout mode on `adapter_id` (`gpu.display` required).
pub fn set_mode(ep: Handle, adapter_id: u32, width: u32, height: u32) -> Result<(), i64> {
    if ep == 0 {
        return Err(sys::ERR_BAD_HANDLE);
    }
    let mut req = [0u8; HEADER];
    Header {
        txid: 0,
        op: OP_SET_MODE,
        status: 0,
        a: u64::from(adapter_id),
        b: u64::from(width) | (u64::from(height) << 32),
    }
    .put(&mut req);
    let mut rep = [0u8; HEADER];
    let n = sys::channel_call(ep, &req, &mut rep, CALL_TIMEOUT_NS)? as usize;
    let h = Header::get(&rep[..n]).ok_or(sys::ERR_INVALID_ARGS)?;
    if h.status != 0 { Err(i64::from(h.status)) } else { Ok(()) }
}

/// Present damage rectangle `(x, y, w, h)` of attached framebuffer `fb_id` (`gpu.display` required).
/// Returns total frames presented on the adapter.
#[allow(clippy::too_many_arguments)]
pub fn present(
    ep: Handle,
    adapter_id: u32,
    fb_id: u32,
    x: u32,
    y: u32,
    w: u32,
    h: u32,
) -> Result<u64, i64> {
    if ep == 0 {
        return Err(sys::ERR_BAD_HANDLE);
    }
    let mut req = [0u8; HEADER + 16];
    Header {
        txid: 0,
        op: OP_PRESENT,
        status: 0,
        a: u64::from(adapter_id) | (u64::from(fb_id) << 32),
        b: u64::from(x) | (u64::from(y) << 32),
    }
    .put(&mut req);
    req[HEADER..HEADER + 4].copy_from_slice(&w.to_le_bytes());
    req[HEADER + 4..HEADER + 8].copy_from_slice(&h.to_le_bytes());
    let mut rep = [0u8; HEADER];
    let n = sys::channel_call(ep, &req[..HEADER + 8], &mut rep, CALL_TIMEOUT_NS)? as usize;
    let hdr = Header::get(&rep[..n]).ok_or(sys::ERR_INVALID_ARGS)?;
    if hdr.status != 0 { Err(i64::from(hdr.status)) } else { Ok(hdr.a) }
}

/// Upload a 64x64 ARGB8888 hardware cursor image VMO (`gpu.display` required).
pub fn set_cursor(ep: Handle, adapter_id: u32, vmo: Handle, hot_x: u32, hot_y: u32) -> Result<(), i64> {
    if ep == 0 {
        return Err(sys::ERR_BAD_HANDLE);
    }
    let dup = sys::handle_duplicate(vmo, sys::RIGHT_READ | sys::RIGHT_MAP | sys::RIGHT_TRANSFER)?;
    let mut req = [0u8; HEADER];
    Header {
        txid: 0,
        op: OP_SET_CURSOR,
        status: 0,
        a: u64::from(adapter_id),
        b: u64::from(hot_x) | (u64::from(hot_y) << 32),
    }
    .put(&mut req);
    let mut rep = [0u8; HEADER];
    let mut rh = [0 as Handle; 1];
    let (n, _) = sys::channel_call_h(
        ep,
        &req,
        &[MsgHandle { handle: dup, rights: sys::RIGHTS_SAME }],
        &mut rep,
        &mut rh,
        CALL_TIMEOUT_NS,
    )?;
    let hdr = Header::get(&rep[..n]).ok_or(sys::ERR_INVALID_ARGS)?;
    if hdr.status != 0 { Err(i64::from(hdr.status)) } else { Ok(()) }
}

/// Move hardware cursor to `(x, y)` (`gpu.display` required).
pub fn move_cursor(ep: Handle, adapter_id: u32, x: u32, y: u32) -> Result<(), i64> {
    if ep == 0 {
        return Err(sys::ERR_BAD_HANDLE);
    }
    let mut req = [0u8; HEADER];
    Header {
        txid: 0,
        op: OP_MOVE_CURSOR,
        status: 0,
        a: u64::from(adapter_id),
        b: u64::from(x) | (u64::from(y) << 32),
    }
    .put(&mut req);
    let mut rep = [0u8; HEADER];
    let n = sys::channel_call(ep, &req, &mut rep, CALL_TIMEOUT_NS)? as usize;
    let hdr = Header::get(&rep[..n]).ok_or(sys::ERR_INVALID_ARGS)?;
    if hdr.status != 0 { Err(i64::from(hdr.status)) } else { Ok(()) }
}

/// Create a GPU render/compute context on `adapter_id` (`gpu.render` required).
pub fn ctx_create(ep: Handle, adapter_id: u32) -> Result<u32, i64> {
    if ep == 0 {
        return Err(sys::ERR_BAD_HANDLE);
    }
    let mut req = [0u8; HEADER];
    Header { txid: 0, op: OP_CTX_CREATE, status: 0, a: u64::from(adapter_id), b: 0 }.put(&mut req);
    let mut rep = [0u8; HEADER];
    let n = sys::channel_call(ep, &req, &mut rep, CALL_TIMEOUT_NS)? as usize;
    let hdr = Header::get(&rep[..n]).ok_or(sys::ERR_INVALID_ARGS)?;
    if hdr.status != 0 { Err(i64::from(hdr.status)) } else { Ok(hdr.a as u32) }
}

/// Destroy a GPU render/compute context (`gpu.render` required).
pub fn ctx_destroy(ep: Handle, adapter_id: u32, ctx_id: u32) -> Result<(), i64> {
    if ep == 0 {
        return Err(sys::ERR_BAD_HANDLE);
    }
    let mut req = [0u8; HEADER];
    Header {
        txid: 0,
        op: OP_CTX_DESTROY,
        status: 0,
        a: u64::from(adapter_id),
        b: u64::from(ctx_id),
    }
    .put(&mut req);
    let mut rep = [0u8; HEADER];
    let n = sys::channel_call(ep, &req, &mut rep, CALL_TIMEOUT_NS)? as usize;
    let hdr = Header::get(&rep[..n]).ok_or(sys::ERR_INVALID_ARGS)?;
    if hdr.status != 0 { Err(i64::from(hdr.status)) } else { Ok(()) }
}

/// Submit a command buffer to `engine` on `adapter_id` (`gpu.render` required). Returns fence seq.
pub fn submit_cmd(
    ep: Handle,
    adapter_id: u32,
    ctx_id: u32,
    engine: u32,
    cmd: &[u8],
) -> Result<u64, i64> {
    if ep == 0 {
        return Err(sys::ERR_BAD_HANDLE);
    }
    if cmd.len() > 4096 {
        return Err(sys::ERR_INVALID_ARGS);
    }
    let mut req = [0u8; HEADER + 4096];
    Header {
        txid: 0,
        op: OP_SUBMIT_CMD,
        status: 0,
        a: u64::from(adapter_id) | (u64::from(ctx_id) << 32),
        b: u64::from(engine),
    }
    .put(&mut req);
    req[HEADER..HEADER + cmd.len()].copy_from_slice(cmd);
    let mut rep = [0u8; HEADER];
    let n = sys::channel_call(ep, &req[..HEADER + cmd.len()], &mut rep, CALL_TIMEOUT_NS)? as usize;
    let hdr = Header::get(&rep[..n]).ok_or(sys::ERR_INVALID_ARGS)?;
    if hdr.status != 0 { Err(i64::from(hdr.status)) } else { Ok(hdr.a) }
}

/// Test-only hook (`gpu.dsvc` started with `test`): crash GPU driver `adapter_id` to prove restart recovery.
pub fn crash_driver(ep: Handle, adapter_id: u32) -> Result<(), i64> {
    if ep == 0 {
        return Err(sys::ERR_BAD_HANDLE);
    }
    let mut req = [0u8; HEADER];
    Header { txid: 0, op: OP_CRASH_DRIVER, status: 0, a: u64::from(adapter_id), b: 0 }.put(&mut req);
    let mut rep = [0u8; HEADER];
    let n = sys::channel_call(ep, &req, &mut rep, CALL_TIMEOUT_NS)? as usize;
    let hdr = Header::get(&rep[..n]).ok_or(sys::ERR_INVALID_ARGS)?;
    if hdr.status != 0 { Err(i64::from(hdr.status)) } else { Ok(()) }
}

// ---- Extended Native Display Probe, Multi-Damage Present, VRR/HDR & Flip Test -------------------

pub const GOP_INFO_BYTES: usize = 32;

/// Firmware GOP framebuffer layout passed from `gpu.dsvc` to PCI GPU drivers (`DRV_SET_GOP_INFO`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GopInfoWire {
    pub phys_base: u64,
    pub size: u64,
    pub width: u32,
    pub height: u32,
    pub pitch: u32,
    pub shifts: [u8; 3],
}

impl GopInfoWire {
    pub fn encode(&self, out: &mut [u8; GOP_INFO_BYTES]) {
        out.fill(0);
        out[0..8].copy_from_slice(&self.phys_base.to_le_bytes());
        out[8..16].copy_from_slice(&self.size.to_le_bytes());
        out[16..20].copy_from_slice(&self.width.to_le_bytes());
        out[20..24].copy_from_slice(&self.height.to_le_bytes());
        out[24..28].copy_from_slice(&self.pitch.to_le_bytes());
        out[28..31].copy_from_slice(&self.shifts);
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.len() < GOP_INFO_BYTES {
            return None;
        }
        let u32_at = |o: usize| u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]);
        let u64_at = |o: usize| {
            u64::from_le_bytes([
                b[o], b[o + 1], b[o + 2], b[o + 3], b[o + 4], b[o + 5], b[o + 6], b[o + 7],
            ])
        };
        Some(Self {
            phys_base: u64_at(0),
            size: u64_at(8),
            width: u32_at(16),
            height: u32_at(20),
            pitch: u32_at(24),
            shifts: [b[28], b[29], b[30]],
        })
    }
}

pub const DISPLAY_PROBE_BYTES: usize = 224;

// `DisplayProbeInfo::flags` bits.
pub const PROBE_GOP_MATCHED: u8 = 1 << 0;
pub const PROBE_FLIP_VERIFIED: u8 = 1 << 1;
pub const PROBE_IH_IRQ_ACTIVE: u8 = 1 << 2;
pub const PROBE_VRR_SUPPORTED: u8 = 1 << 3;
pub const PROBE_VRR_ENABLED: u8 = 1 << 4;
pub const PROBE_HDR_SUPPORTED: u8 = 1 << 5;
pub const PROBE_HDR_ENABLED: u8 = 1 << 6;
pub const PROBE_DSC_SUPPORTED: u8 = 1 << 7;

// `DisplayProbeInfo::flags2` bits.
pub const PROBE2_DSC_ENABLED: u8 = 1 << 0;
pub const PROBE2_IS_UHBR: u8 = 1 << 1;
pub const PROBE2_CR_DONE: u8 = 1 << 2;
pub const PROBE2_EQ_DONE: u8 = 1 << 3;
pub const PROBE2_SELF_CHECK_FAILED: u8 = 1 << 4;

/// Live display hardware probe report (`OP_GET_DISPLAY_INFO`, 224 bytes on the wire).
#[derive(Clone, Copy, Debug)]
pub struct DisplayProbeInfo {
    pub adapter_id: u32,
    pub pipe: u8,
    pub active_pipes: u8,
    pub dcn_major: u8,
    pub dcn_minor: u8,
    pub dcn_rev: u8,
    pub flags: u8,
    pub flags2: u8,
    pub edid_blocks: u8,
    pub width: u32,
    pub height: u32,
    pub h_total: u32,
    pub v_total: u32,
    pub pitch_bytes: u32,
    pub measured_mhz: u32,
    pub raw_format: u32,
    pub vrr_min_hz: u16,
    pub vrr_max_hz: u16,
    pub mc_addr: u64,
    pub vram_off: u64,
    pub gop_phys_base: u64,
    pub dp_lanes: u8,
    pub dp_max_lanes: u8,
    pub dp_rate_mbps: u32,
    pub dp_max_rate_mbps: u32,
    pub dpcd_000: [u8; 16],
    pub dpcd_060: [u8; 4],
    pub dpcd_100: [u8; 2],
    pub dpcd_202: [u8; 4],
    pub monitor_name: [u8; 24],
    pub monitor_len: u8,
    pub status_note: [u8; 48],
    pub status_note_len: u8,
}

impl DisplayProbeInfo {
    pub const fn empty() -> Self {
        Self {
            adapter_id: 0,
            pipe: 0,
            active_pipes: 0,
            dcn_major: 0,
            dcn_minor: 0,
            dcn_rev: 0,
            flags: 0,
            flags2: 0,
            edid_blocks: 0,
            width: 0,
            height: 0,
            h_total: 0,
            v_total: 0,
            pitch_bytes: 0,
            measured_mhz: 0,
            raw_format: 0,
            vrr_min_hz: 0,
            vrr_max_hz: 0,
            mc_addr: 0,
            vram_off: 0,
            gop_phys_base: 0,
            dp_lanes: 0,
            dp_max_lanes: 0,
            dp_rate_mbps: 0,
            dp_max_rate_mbps: 0,
            dpcd_000: [0; 16],
            dpcd_060: [0; 4],
            dpcd_100: [0; 2],
            dpcd_202: [0; 4],
            monitor_name: [0; 24],
            monitor_len: 0,
            status_note: [0; 48],
            status_note_len: 0,
        }
    }

    pub fn monitor_str(&self) -> &str {
        let n = usize::from(self.monitor_len).min(self.monitor_name.len());
        core::str::from_utf8(&self.monitor_name[..n]).unwrap_or("")
    }

    pub fn note_str(&self) -> &str {
        let n = usize::from(self.status_note_len).min(self.status_note.len());
        core::str::from_utf8(&self.status_note[..n]).unwrap_or("")
    }

    pub fn set_note(&mut self, s: &[u8]) {
        let n = s.len().min(self.status_note.len());
        self.status_note.fill(0);
        self.status_note[..n].copy_from_slice(&s[..n]);
        self.status_note_len = n as u8;
    }

    pub fn encode(&self, out: &mut [u8; DISPLAY_PROBE_BYTES]) {
        out.fill(0);
        out[0..4].copy_from_slice(&self.adapter_id.to_le_bytes());
        out[4] = self.pipe;
        out[5] = self.active_pipes;
        out[6] = self.dcn_major;
        out[7] = self.dcn_minor;
        out[8] = self.dcn_rev;
        out[9] = self.flags;
        out[10] = self.flags2;
        out[11] = self.edid_blocks;
        out[12..16].copy_from_slice(&self.width.to_le_bytes());
        out[16..20].copy_from_slice(&self.height.to_le_bytes());
        out[20..24].copy_from_slice(&self.h_total.to_le_bytes());
        out[24..28].copy_from_slice(&self.v_total.to_le_bytes());
        out[28..32].copy_from_slice(&self.pitch_bytes.to_le_bytes());
        out[32..36].copy_from_slice(&self.measured_mhz.to_le_bytes());
        out[36..40].copy_from_slice(&self.raw_format.to_le_bytes());
        out[40..42].copy_from_slice(&self.vrr_min_hz.to_le_bytes());
        out[42..44].copy_from_slice(&self.vrr_max_hz.to_le_bytes());
        out[44] = self.dp_lanes;
        out[45] = self.dp_max_lanes;
        out[46] = self.monitor_len;
        out[47] = self.status_note_len;
        out[48..56].copy_from_slice(&self.mc_addr.to_le_bytes());
        out[56..64].copy_from_slice(&self.vram_off.to_le_bytes());
        out[64..72].copy_from_slice(&self.gop_phys_base.to_le_bytes());
        out[72..76].copy_from_slice(&self.dp_rate_mbps.to_le_bytes());
        out[76..80].copy_from_slice(&self.dp_max_rate_mbps.to_le_bytes());
        out[80..96].copy_from_slice(&self.dpcd_000);
        out[96..100].copy_from_slice(&self.dpcd_060);
        out[100..102].copy_from_slice(&self.dpcd_100);
        out[102..106].copy_from_slice(&self.dpcd_202);
        out[108..132].copy_from_slice(&self.monitor_name);
        out[132..180].copy_from_slice(&self.status_note);
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.len() < DISPLAY_PROBE_BYTES {
            return None;
        }
        let u16_at = |o: usize| u16::from_le_bytes([b[o], b[o + 1]]);
        let u32_at = |o: usize| u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]);
        let u64_at = |o: usize| {
            u64::from_le_bytes([
                b[o], b[o + 1], b[o + 2], b[o + 3], b[o + 4], b[o + 5], b[o + 6], b[o + 7],
            ])
        };
        let mut p = Self::empty();
        p.adapter_id = u32_at(0);
        p.pipe = b[4];
        p.active_pipes = b[5];
        p.dcn_major = b[6];
        p.dcn_minor = b[7];
        p.dcn_rev = b[8];
        p.flags = b[9];
        p.flags2 = b[10];
        p.edid_blocks = b[11];
        p.width = u32_at(12);
        p.height = u32_at(16);
        p.h_total = u32_at(20);
        p.v_total = u32_at(24);
        p.pitch_bytes = u32_at(28);
        p.measured_mhz = u32_at(32);
        p.raw_format = u32_at(36);
        p.vrr_min_hz = u16_at(40);
        p.vrr_max_hz = u16_at(42);
        p.dp_lanes = b[44];
        p.dp_max_lanes = b[45];
        p.monitor_len = b[46].min(24);
        p.status_note_len = b[47].min(48);
        p.mc_addr = u64_at(48);
        p.vram_off = u64_at(56);
        p.gop_phys_base = u64_at(64);
        p.dp_rate_mbps = u32_at(72);
        p.dp_max_rate_mbps = u32_at(76);
        p.dpcd_000.copy_from_slice(&b[80..96]);
        p.dpcd_060.copy_from_slice(&b[96..100]);
        p.dpcd_100.copy_from_slice(&b[100..102]);
        p.dpcd_202.copy_from_slice(&b[102..106]);
        p.monitor_name.copy_from_slice(&b[108..132]);
        p.status_note.copy_from_slice(&b[132..180]);
        Some(p)
    }
}

pub const FLIP_TEST_BYTES: usize = 40;

/// Result returned by `OP_FLIP_TEST` / `awmi::OP_FLIP_TEST` (40 bytes on the wire).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FlipTestResult {
    pub frames: u64,
    pub missed: u64,
    pub late: u64,
    pub measured_mhz: u32,
    pub duration_ms: u32,
    pub reverted: bool,
    pub used_dcn: bool,
    pub used_ih: bool,
    pub pipe: u8,
}

impl FlipTestResult {
    pub fn encode(&self, out: &mut [u8; FLIP_TEST_BYTES]) {
        out.fill(0);
        out[0..8].copy_from_slice(&self.frames.to_le_bytes());
        out[8..16].copy_from_slice(&self.missed.to_le_bytes());
        out[16..24].copy_from_slice(&self.late.to_le_bytes());
        out[24..28].copy_from_slice(&self.measured_mhz.to_le_bytes());
        out[28..32].copy_from_slice(&self.duration_ms.to_le_bytes());
        out[32] = u8::from(self.reverted);
        out[33] = u8::from(self.used_dcn);
        out[34] = u8::from(self.used_ih);
        out[35] = self.pipe;
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.len() < FLIP_TEST_BYTES {
            return None;
        }
        let u32_at = |o: usize| u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]);
        let u64_at = |o: usize| {
            u64::from_le_bytes([
                b[o], b[o + 1], b[o + 2], b[o + 3], b[o + 4], b[o + 5], b[o + 6], b[o + 7],
            ])
        };
        Some(Self {
            frames: u64_at(0),
            missed: u64_at(8),
            late: u64_at(16),
            measured_mhz: u32_at(24),
            duration_ms: u32_at(28),
            reverted: b[32] != 0,
            used_dcn: b[33] != 0,
            used_ih: b[34] != 0,
            pipe: b[35],
        })
    }
}

/// Query detailed display probe state for `adapter_id` (`gpu.query` or higher; strictly read-only).
pub fn get_display_info(ep: Handle, adapter_id: u32) -> Result<DisplayProbeInfo, i64> {
    if ep == 0 {
        return Err(sys::ERR_BAD_HANDLE);
    }
    let mut req = [0u8; HEADER];
    Header { txid: 0, op: OP_GET_DISPLAY_INFO, status: 0, a: u64::from(adapter_id), b: 0 }.put(&mut req);
    let mut rep = [0u8; HEADER + DISPLAY_PROBE_BYTES];
    let n = sys::channel_call(ep, &req, &mut rep, CALL_TIMEOUT_NS)? as usize;
    let h = Header::get(&rep[..n]).ok_or(sys::ERR_INVALID_ARGS)?;
    if h.status != 0 {
        return Err(i64::from(h.status));
    }
    DisplayProbeInfo::decode(&rep[HEADER..n]).ok_or(sys::ERR_INVALID_ARGS)
}

/// Present up to 16 damage rectangles `(x, y, w, h)` in one IPC (`gpu.display` required).
/// Returns `(frames, async_pending)`: if `async_pending` is true, `EVT_FLIP_DONE` follows at vblank.
pub fn present_multi(
    ep: Handle,
    adapter_id: u32,
    fb_id: u32,
    rects: &[(u32, u32, u32, u32)],
) -> Result<(u64, bool), i64> {
    if ep == 0 {
        return Err(sys::ERR_BAD_HANDLE);
    }
    let cnt = rects.len().min(MAX_PRESENT_RECTS);
    let mut req = [0u8; HEADER + MAX_PRESENT_RECTS * 16];
    Header {
        txid: 0,
        op: OP_PRESENT_MULTI,
        status: 0,
        a: u64::from(adapter_id) | (u64::from(fb_id) << 32),
        b: cnt as u64,
    }
    .put(&mut req);
    for (i, &(x, y, w, h)) in rects.iter().take(cnt).enumerate() {
        let o = HEADER + i * 16;
        req[o..o + 4].copy_from_slice(&x.to_le_bytes());
        req[o + 4..o + 8].copy_from_slice(&y.to_le_bytes());
        req[o + 8..o + 12].copy_from_slice(&w.to_le_bytes());
        req[o + 12..o + 16].copy_from_slice(&h.to_le_bytes());
    }
    let mut rep = [0u8; HEADER];
    let n = sys::channel_call(ep, &req[..HEADER + cnt * 16], &mut rep, CALL_TIMEOUT_NS)? as usize;
    let hdr = Header::get(&rep[..n]).ok_or(sys::ERR_INVALID_ARGS)?;
    if hdr.status != 0 {
        Err(i64::from(hdr.status))
    } else {
        Ok((hdr.a, hdr.b != 0))
    }
}

/// Release native display scanout and restore the firmware GOP framebuffer (`gpu.display` required).
pub fn release_display(ep: Handle, adapter_id: u32) -> Result<(), i64> {
    if ep == 0 {
        return Err(sys::ERR_BAD_HANDLE);
    }
    let mut req = [0u8; HEADER];
    Header { txid: 0, op: OP_RELEASE_DISPLAY, status: 0, a: u64::from(adapter_id), b: 0 }.put(&mut req);
    let mut rep = [0u8; HEADER];
    let n = sys::channel_call(ep, &req, &mut rep, CALL_TIMEOUT_NS)? as usize;
    let hdr = Header::get(&rep[..n]).ok_or(sys::ERR_INVALID_ARGS)?;
    if hdr.status != 0 { Err(i64::from(hdr.status)) } else { Ok(()) }
}

/// Set mode with target refresh rate in mHz and optional flags (`bit 0=allow DSC`, `bit 1=allow retrain`).
pub fn set_mode_ex(
    ep: Handle,
    adapter_id: u32,
    width: u32,
    height: u32,
    refresh_mhz: u32,
    flags: u32,
) -> Result<(), i64> {
    if ep == 0 {
        return Err(sys::ERR_BAD_HANDLE);
    }
    let mut req = [0u8; HEADER + 4];
    Header {
        txid: 0,
        op: OP_SET_MODE_EX,
        status: 0,
        a: u64::from(adapter_id) | (u64::from(flags) << 32),
        b: u64::from(width) | (u64::from(height) << 32),
    }
    .put(&mut req);
    req[HEADER..HEADER + 4].copy_from_slice(&refresh_mhz.to_le_bytes());
    let mut rep = [0u8; HEADER];
    let n = sys::channel_call(ep, &req, &mut rep, CALL_TIMEOUT_NS)? as usize;
    let hdr = Header::get(&rep[..n]).ok_or(sys::ERR_INVALID_ARGS)?;
    if hdr.status != 0 { Err(i64::from(hdr.status)) } else { Ok(()) }
}

/// Toggle FreeSync / Adaptive-Sync VRR (`gpu.display` required).
pub fn set_vrr(ep: Handle, adapter_id: u32, enable: bool, min_hz: u16, max_hz: u16) -> Result<(), i64> {
    if ep == 0 {
        return Err(sys::ERR_BAD_HANDLE);
    }
    let mut req = [0u8; HEADER];
    Header {
        txid: 0,
        op: OP_SET_VRR,
        status: 0,
        a: u64::from(adapter_id),
        b: u64::from(enable) | (u64::from(min_hz) << 16) | (u64::from(max_hz) << 32),
    }
    .put(&mut req);
    let mut rep = [0u8; HEADER];
    let n = sys::channel_call(ep, &req, &mut rep, CALL_TIMEOUT_NS)? as usize;
    let hdr = Header::get(&rep[..n]).ok_or(sys::ERR_INVALID_ARGS)?;
    if hdr.status != 0 { Err(i64::from(hdr.status)) } else { Ok(()) }
}

/// Toggle 10-bit HDR10 scanout (`gpu.display` required).
pub fn set_hdr(ep: Handle, adapter_id: u32, enable: bool) -> Result<(), i64> {
    if ep == 0 {
        return Err(sys::ERR_BAD_HANDLE);
    }
    let mut req = [0u8; HEADER];
    Header { txid: 0, op: OP_SET_HDR, status: 0, a: u64::from(adapter_id), b: u64::from(enable) }.put(&mut req);
    let mut rep = [0u8; HEADER];
    let n = sys::channel_call(ep, &req, &mut rep, CALL_TIMEOUT_NS)? as usize;
    let hdr = Header::get(&rep[..n]).ok_or(sys::ERR_INVALID_ARGS)?;
    if hdr.status != 0 { Err(i64::from(hdr.status)) } else { Ok(()) }
}

/// Run the 5-second alternating-pattern hardware flip test and automatically revert (`gpu.display` required).
pub fn flip_test(ep: Handle, adapter_id: u32, duration_ms: u32) -> Result<FlipTestResult, i64> {
    if ep == 0 {
        return Err(sys::ERR_BAD_HANDLE);
    }
    let mut req = [0u8; HEADER];
    Header { txid: 0, op: OP_FLIP_TEST, status: 0, a: u64::from(adapter_id), b: u64::from(duration_ms) }.put(&mut req);
    let mut rep = [0u8; HEADER + FLIP_TEST_BYTES];
    let timeout = u64::from(duration_ms.clamp(500, 15_000)) * 1_000_000 + 10_000_000_000;
    let n = sys::channel_call(ep, &req, &mut rep, timeout)? as usize;
    let hdr = Header::get(&rep[..n]).ok_or(sys::ERR_INVALID_ARGS)?;
    if hdr.status != 0 {
        return Err(i64::from(hdr.status));
    }
    FlipTestResult::decode(&rep[HEADER..n]).ok_or(sys::ERR_INVALID_ARGS)
}
