//! GPU & display service, driver, and client IPC protocol (`libd::gpu`).
//!
//! Capability separation:
//! - `gpu.query`: read-only adapter/mode/EDID/capability enumeration (`OP_LIST_ADAPTERS`,
//!   `OP_GET_MODES`).
//! - `gpu.display`: exclusive display/modesetting authority (`OP_ATTACH_FB`, `OP_SET_MODE`,
//!   `OP_PRESENT`, `OP_SET_CURSOR`, `OP_MOVE_CURSOR`, plus query ops).
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

// Pixel formats (mirroring `dosgpu::PixelFormat`).
pub const FMT_XRGB8888: u32 = 1;
pub const FMT_ARGB8888: u32 = 2;
pub const FMT_XBGR8888: u32 = 3;

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
