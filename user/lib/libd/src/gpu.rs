//! GPU, Atomic KMS display, GEM/GPU-VM, and timeline `syncobj` IPC protocol (`libd::gpu`).
//!
//! Capability separation:
//! - `gpu.query`: read-only adapter & KMS resource/connector/CRTC/plane/EDID/mode enumeration
//!   (`OP_LIST_ADAPTERS`, `OP_KMS_GET_RESOURCES`).
//! - `gpu.display`: exclusive Atomic KMS authority (`OP_KMS_CREATE_FB`, `OP_KMS_DESTROY_FB`,
//!   `OP_KMS_ATOMIC_COMMIT`, `OP_KMS_CONFIRM_MODE`, plus scanout `OP_GEM_IMPORT` / `OP_GEM_CLOSE`
//!   and query ops).
//! - `gpu.render`: isolated GPU memory, VM, timeline syncobj, and hardware queue submission
//!   (`OP_GEM_CREATE`, `OP_GEM_IMPORT`, `OP_GEM_CLOSE`, `OP_VM_CREATE`, `OP_VM_DESTROY`,
//!   `OP_VM_BIND`, `OP_VM_UNBIND`, `OP_SYNCOBJ_CREATE`, `OP_SYNCOBJ_DESTROY`,
//!   `OP_SYNCOBJ_SIGNAL`, `OP_SYNCOBJ_WAIT`, `OP_CTX_CREATE`, `OP_CTX_DESTROY`, `OP_SUBMIT`, plus
//!   query ops; never touches display scanout).

use crate::proto::{HEADER, Header};
use crate::svc;
use crate::sys::{self, Handle, MsgHandle};

// ---- Backend registration (devmgr -> gpu.dsvc on `devmgr.gpu`) ----------------------------------

pub const BACKEND_ADD: u32 = 800;
pub const BACKEND_GONE: u32 = 801;

// ---- GPU `.ddrv` direct protocol (`gpu.dsvc` <-> `.ddrv` channel) -------------------------------

pub const DRV_KMS_GET_RESOURCES: u32 = 810;
pub const DRV_GEM_IMPORT: u32 = 811;
pub const DRV_GEM_CREATE: u32 = 812;
pub const DRV_GEM_CLOSE: u32 = 813;
pub const DRV_KMS_CREATE_FB: u32 = 814;
pub const DRV_KMS_DESTROY_FB: u32 = 815;
pub const DRV_KMS_ATOMIC_COMMIT: u32 = 816;
pub const DRV_VM_CREATE: u32 = 817;
pub const DRV_VM_DESTROY: u32 = 818;
pub const DRV_VM_BIND: u32 = 819;
pub const DRV_VM_UNBIND: u32 = 820;
pub const DRV_SYNCOBJ_CREATE: u32 = 821;
pub const DRV_SYNCOBJ_DESTROY: u32 = 822;
pub const DRV_SYNCOBJ_SIGNAL: u32 = 823;
pub const DRV_SYNCOBJ_WAIT: u32 = 824;
pub const DRV_CTX_CREATE: u32 = 825;
pub const DRV_CTX_DESTROY: u32 = 826;
pub const DRV_SUBMIT: u32 = 827;
pub const DRV_TEST_CRASH: u32 = 828;
/// Unsolicited `.ddrv` -> `gpu.dsvc` vblank/flip completion (`txid = 0`):
/// `a` = `vblank_seq | (late << 63)`, `b` = `timestamp_ns`.
pub const DRV_EVENT_VBLANK: u32 = 829;
/// Unsolicited `.ddrv` -> `gpu.dsvc` hotplug/connector change (`txid = 0`).
pub const DRV_EVENT_HOTPLUG: u32 = 830;

// ---- Client <-> `gpu.dsvc` protocol (`gpu.query`, `gpu.display`, `gpu.render`) ------------------

pub const OP_LIST_ADAPTERS: u32 = 840;
pub const OP_KMS_GET_RESOURCES: u32 = 841;
pub const OP_KMS_CREATE_FB: u32 = 842;
pub const OP_KMS_DESTROY_FB: u32 = 843;
pub const OP_KMS_ATOMIC_COMMIT: u32 = 844;
pub const OP_KMS_CONFIRM_MODE: u32 = 845;
pub const OP_GEM_IMPORT: u32 = 846;
pub const OP_GEM_CLOSE: u32 = 847;
pub const OP_GEM_CREATE: u32 = 848;
pub const OP_VM_CREATE: u32 = 849;
pub const OP_VM_DESTROY: u32 = 850;
pub const OP_VM_BIND: u32 = 851;
pub const OP_VM_UNBIND: u32 = 852;
pub const OP_SYNCOBJ_CREATE: u32 = 853;
pub const OP_SYNCOBJ_DESTROY: u32 = 854;
pub const OP_SYNCOBJ_SIGNAL: u32 = 855;
pub const OP_SYNCOBJ_WAIT: u32 = 856;
pub const OP_CTX_CREATE: u32 = 857;
pub const OP_CTX_DESTROY: u32 = 858;
pub const OP_CRASH_DRIVER: u32 = 859;
pub const OP_SUBMIT: u32 = 860;

/// Unsolicited `gpu.dsvc` -> `gpu.display` vblank/flip event (`txid = 0`):
/// `a` = `adapter_id | (late << 32)`, `b` = `vblank_seq`, payload = `timestamp_ns` (8 bytes).
pub const EVT_VBLANK: u32 = 870;
/// Unsolicited `gpu.dsvc` -> `gpu.display` adapter/connector/mode change event (`txid = 0`):
/// `a` = `adapter_id`.
pub const EVT_ADAPTERS_CHANGED: u32 = 871;

// Adapter kinds (mirroring `dosdrm::AdapterKind`).
pub const KIND_GOP: u8 = 1;
pub const KIND_VIRTIO_GPU: u8 = 2;
pub const KIND_AMD_RDNA: u8 = 3;
pub const KIND_INTEL_XE: u8 = 4;
pub const KIND_NVIDIA_GSP: u8 = 5;

// Capability bits (mirroring `dosdrm::caps`).
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
pub const CAP_NATIVE_KMS: u32 = 1 << 11;
pub const CAP_VRR: u32 = 1 << 12;
pub const CAP_HDR: u32 = 1 << 13;
pub const CAP_DSC: u32 = 1 << 14;
pub const CAP_ATOMIC_KMS: u32 = 1 << 15;
pub const CAP_GEM_VM: u32 = 1 << 16;
pub const CAP_SYNCOBJ_TIMELINE: u32 = 1 << 17;
pub const CAP_VENUS_VK: u32 = 1 << 18;
pub const CAP_SYS_FIRMWARE: u32 = 1 << 19;

// Pixel formats (compact & DRM FourCC compatible).
pub const FMT_XRGB8888: u32 = 1;
pub const FMT_ARGB8888: u32 = 2;
pub const FMT_XBGR8888: u32 = 3;
pub const FMT_ARGB2101010: u32 = 4;

// GEM BO flags.
pub const BO_SCANOUT: u32 = 1 << 0;
pub const BO_CURSOR: u32 = 1 << 1;
pub const BO_RENDER: u32 = 1 << 2;
pub const BO_VRAM: u32 = 1 << 3;
pub const BO_GTT: u32 = 1 << 4;
pub const BO_WC: u32 = 1 << 5;
pub const BO_HOST_VISIBLE: u32 = 1 << 6;

// GPU VM bind flags.
pub const VM_READ: u32 = 1 << 0;
pub const VM_WRITE: u32 = 1 << 1;
pub const VM_EXEC: u32 = 1 << 2;

// Atomic KMS commit flags (`AtomicCommitWire::flags`).
pub const ATOMIC_TEST_ONLY: u32 = 1 << 0;
pub const ATOMIC_ALLOW_MODESET: u32 = 1 << 1;
pub const ATOMIC_NONBLOCK: u32 = 1 << 2;
pub const ATOMIC_PAGE_FLIP_EVENT: u32 = 1 << 3;
pub const ATOMIC_CURSOR_ONLY: u32 = 1 << 4;
pub const ATOMIC_REQUIRE_CONFIRM: u32 = 1 << 5;
pub const ATOMIC_RESET_BOOT: u32 = 1 << 6;

// Atomic commit property change mask (`AtomicCommitWire::change_mask`).
pub const COMMIT_MODE: u32 = 1 << 0;
pub const COMMIT_VRR: u32 = 1 << 1;
pub const COMMIT_HDR: u32 = 1 << 2;
pub const COMMIT_PRIMARY: u32 = 1 << 3;
pub const COMMIT_CURSOR: u32 = 1 << 4;

pub const MAX_PRESENT_RECTS: usize = 16;

// Context / submission engine kinds.
pub const ENGINE_VIRGL_3D: u32 = 1;
pub const ENGINE_VENUS_VK: u32 = 2;
pub const ENGINE_GFX: u32 = 3;
pub const ENGINE_COMPUTE: u32 = 4;
pub const ENGINE_SDMA: u32 = 5;

const CALL_TIMEOUT_NS: u64 = 10_000_000_000;

pub fn query_endpoint() -> Handle {
    svc::endpoint(b"gpu.query")
}

pub fn display_endpoint() -> Handle {
    svc::endpoint(b"gpu.display")
}

pub fn render_endpoint() -> Handle {
    svc::endpoint(b"gpu.render")
}

// ---- Adapter descriptor (`OP_LIST_ADAPTERS`, 128 bytes) -----------------------------------------

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

    pub fn kind_name(&self) -> &'static str {
        match self.kind {
            KIND_GOP => "gop",
            KIND_VIRTIO_GPU => "virtio-gpu",
            KIND_AMD_RDNA => "amdgpu",
            KIND_INTEL_XE => "xe",
            KIND_NVIDIA_GSP => "nvgpu",
            _ => "unknown",
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
        out[40] = self.monitor_len.min(24);
        out[41] = self.name_len.min(40);
        out[44..68].copy_from_slice(&self.monitor);
        out[68..108].copy_from_slice(&self.name);
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.len() < ADAPTER_INFO_BYTES {
            return None;
        }
        let mut monitor = [0u8; 24];
        monitor.copy_from_slice(&b[44..68]);
        let mut name = [0u8; 40];
        name.copy_from_slice(&b[68..108]);
        Some(Self {
            id: u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
            kind: b[4],
            online: b[5] != 0,
            vendor: u16::from_le_bytes([b[6], b[7]]),
            device: u16::from_le_bytes([b[8], b[9]]),
            caps: u32::from_le_bytes([b[12], b[13], b[14], b[15]]),
            width: u32::from_le_bytes([b[16], b[17], b[18], b[19]]),
            height: u32::from_le_bytes([b[20], b[21], b[22], b[23]]),
            vram_mib: u32::from_le_bytes([b[24], b[25], b[26], b[27]]),
            restarts: u32::from_le_bytes([b[28], b[29], b[30], b[31]]),
            frames: u64::from_le_bytes([b[32], b[33], b[34], b[35], b[36], b[37], b[38], b[39]]),
            monitor_len: b[40].min(24),
            name_len: b[41].min(40),
            monitor,
            name,
        })
    }
}

// ---- KMS mode & resource wire descriptors (`OP_KMS_GET_RESOURCES`) ------------------------------

pub const MODE_ENTRY_BYTES: usize = 24;
pub const MODE_FLAG_PREFERRED: u32 = 1 << 0;
pub const MODE_FLAG_CURRENT: u32 = 1 << 1;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ModeEntry {
    pub width: u32,
    pub height: u32,
    pub refresh_mhz: u32,
    pub pixel_clock_khz: u32,
    pub htotal: u16,
    pub vtotal: u16,
    pub flags: u32,
}

impl ModeEntry {
    pub fn encode(&self, out: &mut [u8; MODE_ENTRY_BYTES]) {
        out[0..4].copy_from_slice(&self.width.to_le_bytes());
        out[4..8].copy_from_slice(&self.height.to_le_bytes());
        out[8..12].copy_from_slice(&self.refresh_mhz.to_le_bytes());
        out[12..16].copy_from_slice(&self.pixel_clock_khz.to_le_bytes());
        out[16..18].copy_from_slice(&self.htotal.to_le_bytes());
        out[18..20].copy_from_slice(&self.vtotal.to_le_bytes());
        out[20..24].copy_from_slice(&self.flags.to_le_bytes());
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.len() < MODE_ENTRY_BYTES {
            return None;
        }
        Some(Self {
            width: u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
            height: u32::from_le_bytes([b[4], b[5], b[6], b[7]]),
            refresh_mhz: u32::from_le_bytes([b[8], b[9], b[10], b[11]]),
            pixel_clock_khz: u32::from_le_bytes([b[12], b[13], b[14], b[15]]),
            htotal: u16::from_le_bytes([b[16], b[17]]),
            vtotal: u16::from_le_bytes([b[18], b[19]]),
            flags: u32::from_le_bytes([b[20], b[21], b[22], b[23]]),
        })
    }
}

// KMS resource capability/status flags (`KmsResourcesWire::status_flags`).
pub const KMS_STATUS_CONNECTED: u32 = 1 << 0;
pub const KMS_STATUS_CRTC_ACTIVE: u32 = 1 << 1;
pub const KMS_STATUS_CURSOR_PLANE: u32 = 1 << 2;
pub const KMS_STATUS_OVERLAY_PLANE: u32 = 1 << 3;
pub const KMS_STATUS_VRR_CAPABLE: u32 = 1 << 4;
pub const KMS_STATUS_VRR_ENABLED: u32 = 1 << 5;
pub const KMS_STATUS_HDR_CAPABLE: u32 = 1 << 6;
pub const KMS_STATUS_HDR_ENABLED: u32 = 1 << 7;
pub const KMS_STATUS_DSC_CAPABLE: u32 = 1 << 8;
pub const KMS_STATUS_DSC_ENABLED: u32 = 1 << 9;
pub const KMS_STATUS_FIRMWARE_LOADED: u32 = 1 << 10;
pub const KMS_STATUS_VENDOR_SHIM_OK: u32 = 1 << 11;
pub const KMS_STATUS_REVERT_PENDING: u32 = 1 << 12;

pub const KMS_RESOURCES_HDR_BYTES: usize = 160;

/// Atomic KMS topology & live pipeline state returned by `OP_KMS_GET_RESOURCES` / `DRV_KMS_GET_RESOURCES`.
#[derive(Clone, Copy, Debug)]
pub struct KmsResourcesWire {
    pub adapter_id: u32,
    pub connector_id: u32,
    pub connector_kind: u8,
    pub crtc_id: u32,
    pub pipe: u8,
    pub plane_count: u8,
    pub edid_blocks: u8,
    pub status_flags: u32,
    pub width: u32,
    pub height: u32,
    pub pitch_bytes: u32,
    pub refresh_mhz: u32,
    pub htotal: u16,
    pub vtotal: u16,
    pub dp_lanes: u8,
    pub dp_rate_mbps: u32,
    pub vrr_min_hz: u16,
    pub vrr_max_hz: u16,
    pub vblank_seq: u64,
    pub revert_secs_left: u8,
    pub shim_abi: u32,
    pub monitor_name: [u8; 24],
    pub monitor_len: u8,
    pub driver_note: [u8; 48],
    pub note_len: u8,
}

impl KmsResourcesWire {
    pub const fn empty() -> Self {
        Self {
            adapter_id: 0,
            connector_id: 1,
            connector_kind: 0,
            crtc_id: 1,
            pipe: 0,
            plane_count: 1,
            edid_blocks: 0,
            status_flags: 0,
            width: 0,
            height: 0,
            pitch_bytes: 0,
            refresh_mhz: 0,
            htotal: 0,
            vtotal: 0,
            dp_lanes: 0,
            dp_rate_mbps: 0,
            vrr_min_hz: 0,
            vrr_max_hz: 0,
            vblank_seq: 0,
            revert_secs_left: 0,
            shim_abi: 0,
            monitor_name: [0; 24],
            monitor_len: 0,
            driver_note: [0; 48],
            note_len: 0,
        }
    }

    pub fn connector_kind_str(&self) -> &'static str {
        match self.connector_kind {
            1 => "GOP",
            2 => "Virtual",
            3 => "DP",
            4 => "HDMI-A",
            5 => "eDP",
            _ => "Unknown",
        }
    }

    pub fn monitor_str(&self) -> &str {
        let n = (self.monitor_len as usize).min(self.monitor_name.len());
        core::str::from_utf8(&self.monitor_name[..n]).unwrap_or("")
    }

    pub fn note_str(&self) -> &str {
        let n = (self.note_len as usize).min(self.driver_note.len());
        core::str::from_utf8(&self.driver_note[..n]).unwrap_or("")
    }

    pub fn set_monitor(&mut self, s: &[u8]) {
        let n = s.len().min(self.monitor_name.len());
        self.monitor_name.fill(0);
        self.monitor_name[..n].copy_from_slice(&s[..n]);
        self.monitor_len = n as u8;
    }

    pub fn set_note(&mut self, s: &[u8]) {
        let n = s.len().min(self.driver_note.len());
        self.driver_note.fill(0);
        self.driver_note[..n].copy_from_slice(&s[..n]);
        self.note_len = n as u8;
    }

    pub fn encode(&self, out: &mut [u8; KMS_RESOURCES_HDR_BYTES]) {
        out.fill(0);
        out[0..4].copy_from_slice(&self.adapter_id.to_le_bytes());
        out[4..8].copy_from_slice(&self.connector_id.to_le_bytes());
        out[8..12].copy_from_slice(&self.crtc_id.to_le_bytes());
        out[12] = self.connector_kind;
        out[13] = self.pipe;
        out[14] = self.plane_count;
        out[15] = self.edid_blocks;
        out[16..20].copy_from_slice(&self.status_flags.to_le_bytes());
        out[20..24].copy_from_slice(&self.width.to_le_bytes());
        out[24..28].copy_from_slice(&self.height.to_le_bytes());
        out[28..32].copy_from_slice(&self.pitch_bytes.to_le_bytes());
        out[32..36].copy_from_slice(&self.refresh_mhz.to_le_bytes());
        out[36..38].copy_from_slice(&self.htotal.to_le_bytes());
        out[38..40].copy_from_slice(&self.vtotal.to_le_bytes());
        out[40..44].copy_from_slice(&self.dp_rate_mbps.to_le_bytes());
        out[44] = self.dp_lanes;
        out[45] = self.revert_secs_left;
        out[46] = self.monitor_len.min(24);
        out[47] = self.note_len.min(48);
        out[48..50].copy_from_slice(&self.vrr_min_hz.to_le_bytes());
        out[50..52].copy_from_slice(&self.vrr_max_hz.to_le_bytes());
        out[52..56].copy_from_slice(&self.shim_abi.to_le_bytes());
        out[56..64].copy_from_slice(&self.vblank_seq.to_le_bytes());
        out[64..88].copy_from_slice(&self.monitor_name);
        out[88..136].copy_from_slice(&self.driver_note);
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.len() < KMS_RESOURCES_HDR_BYTES {
            return None;
        }
        let mut monitor_name = [0u8; 24];
        monitor_name.copy_from_slice(&b[64..88]);
        let mut driver_note = [0u8; 48];
        driver_note.copy_from_slice(&b[88..136]);
        Some(Self {
            adapter_id: u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
            connector_id: u32::from_le_bytes([b[4], b[5], b[6], b[7]]),
            crtc_id: u32::from_le_bytes([b[8], b[9], b[10], b[11]]),
            connector_kind: b[12],
            pipe: b[13],
            plane_count: b[14],
            edid_blocks: b[15],
            status_flags: u32::from_le_bytes([b[16], b[17], b[18], b[19]]),
            width: u32::from_le_bytes([b[20], b[21], b[22], b[23]]),
            height: u32::from_le_bytes([b[24], b[25], b[26], b[27]]),
            pitch_bytes: u32::from_le_bytes([b[28], b[29], b[30], b[31]]),
            refresh_mhz: u32::from_le_bytes([b[32], b[33], b[34], b[35]]),
            htotal: u16::from_le_bytes([b[36], b[37]]),
            vtotal: u16::from_le_bytes([b[38], b[39]]),
            dp_rate_mbps: u32::from_le_bytes([b[40], b[41], b[42], b[43]]),
            dp_lanes: b[44],
            revert_secs_left: b[45],
            monitor_len: b[46].min(24),
            note_len: b[47].min(48),
            vrr_min_hz: u16::from_le_bytes([b[48], b[49]]),
            vrr_max_hz: u16::from_le_bytes([b[50], b[51]]),
            shim_abi: u32::from_le_bytes([b[52], b[53], b[54], b[55]]),
            vblank_seq: u64::from_le_bytes([b[56], b[57], b[58], b[59], b[60], b[61], b[62], b[63]]),
            monitor_name,
            driver_note,
        })
    }
}

// ---- Atomic KMS commit wire codec (`OP_KMS_ATOMIC_COMMIT` / `DRV_KMS_ATOMIC_COMMIT`) ------------

pub const ATOMIC_COMMIT_HDR_BYTES: usize = 72;

#[derive(Clone, Copy, Debug)]
pub struct AtomicCommitWire {
    pub flags: u32,
    pub change_mask: u32,
    pub crtc_id: u32,
    pub connector_id: u32,
    pub mode_width: u32,
    pub mode_height: u32,
    pub mode_refresh_mhz: u32,
    pub vrr_enable: bool,
    pub hdr_enable: bool,
    pub primary_fb_id: u32,
    pub cursor_fb_id: u32,
    pub cursor_x: i32,
    pub cursor_y: i32,
    pub cursor_hot_x: u16,
    pub cursor_hot_y: u16,
    pub in_syncobj: u32,
    pub in_point: u64,
    pub out_syncobj: u32,
    pub out_point: u64,
    pub damage: [(u32, u32, u32, u32); MAX_PRESENT_RECTS],
    pub damage_count: usize,
}

impl Default for AtomicCommitWire {
    fn default() -> Self {
        Self {
            flags: 0,
            change_mask: 0,
            crtc_id: 1,
            connector_id: 1,
            mode_width: 0,
            mode_height: 0,
            mode_refresh_mhz: 0,
            vrr_enable: false,
            hdr_enable: false,
            primary_fb_id: 0,
            cursor_fb_id: 0,
            cursor_x: 0,
            cursor_y: 0,
            cursor_hot_x: 0,
            cursor_hot_y: 0,
            in_syncobj: 0,
            in_point: 0,
            out_syncobj: 0,
            out_point: 0,
            damage: [(0, 0, 0, 0); MAX_PRESENT_RECTS],
            damage_count: 0,
        }
    }
}

impl AtomicCommitWire {
    pub fn encode(&self, out: &mut [u8; ATOMIC_COMMIT_HDR_BYTES + MAX_PRESENT_RECTS * 16]) -> usize {
        out.fill(0);
        let cnt = self.damage_count.min(MAX_PRESENT_RECTS);
        out[0..4].copy_from_slice(&self.flags.to_le_bytes());
        out[4..8].copy_from_slice(&self.change_mask.to_le_bytes());
        out[8..12].copy_from_slice(&self.crtc_id.to_le_bytes());
        out[12..16].copy_from_slice(&self.connector_id.to_le_bytes());
        out[16..20].copy_from_slice(&self.mode_width.to_le_bytes());
        out[20..24].copy_from_slice(&self.mode_height.to_le_bytes());
        out[24..28].copy_from_slice(&self.mode_refresh_mhz.to_le_bytes());
        out[28] = u8::from(self.vrr_enable);
        out[29] = u8::from(self.hdr_enable);
        out[30] = cnt as u8;
        out[32..36].copy_from_slice(&self.primary_fb_id.to_le_bytes());
        out[36..40].copy_from_slice(&self.cursor_fb_id.to_le_bytes());
        out[40..44].copy_from_slice(&self.cursor_x.to_le_bytes());
        out[44..48].copy_from_slice(&self.cursor_y.to_le_bytes());
        out[48..50].copy_from_slice(&self.cursor_hot_x.to_le_bytes());
        out[50..52].copy_from_slice(&self.cursor_hot_y.to_le_bytes());
        out[52..56].copy_from_slice(&self.in_syncobj.to_le_bytes());
        out[56..60].copy_from_slice(&self.out_syncobj.to_le_bytes());
        out[60..64].copy_from_slice(&(self.in_point as u32).to_le_bytes());
        out[64..72].copy_from_slice(&self.out_point.to_le_bytes());
        for (i, &(x, y, w, h)) in self.damage.iter().take(cnt).enumerate() {
            let o = ATOMIC_COMMIT_HDR_BYTES + i * 16;
            out[o..o + 4].copy_from_slice(&x.to_le_bytes());
            out[o + 4..o + 8].copy_from_slice(&y.to_le_bytes());
            out[o + 8..o + 12].copy_from_slice(&w.to_le_bytes());
            out[o + 12..o + 16].copy_from_slice(&h.to_le_bytes());
        }
        ATOMIC_COMMIT_HDR_BYTES + cnt * 16
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.len() < ATOMIC_COMMIT_HDR_BYTES {
            return None;
        }
        let cnt = (b[30] as usize)
            .min(MAX_PRESENT_RECTS)
            .min((b.len() - ATOMIC_COMMIT_HDR_BYTES) / 16);
        let mut damage = [(0u32, 0u32, 0u32, 0u32); MAX_PRESENT_RECTS];
        for (i, slot) in damage.iter_mut().take(cnt).enumerate() {
            let o = ATOMIC_COMMIT_HDR_BYTES + i * 16;
            *slot = (
                u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]),
                u32::from_le_bytes([b[o + 4], b[o + 5], b[o + 6], b[o + 7]]),
                u32::from_le_bytes([b[o + 8], b[o + 9], b[o + 10], b[o + 11]]),
                u32::from_le_bytes([b[o + 12], b[o + 13], b[o + 14], b[o + 15]]),
            );
        }
        Some(Self {
            flags: u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
            change_mask: u32::from_le_bytes([b[4], b[5], b[6], b[7]]),
            crtc_id: u32::from_le_bytes([b[8], b[9], b[10], b[11]]),
            connector_id: u32::from_le_bytes([b[12], b[13], b[14], b[15]]),
            mode_width: u32::from_le_bytes([b[16], b[17], b[18], b[19]]),
            mode_height: u32::from_le_bytes([b[20], b[21], b[22], b[23]]),
            mode_refresh_mhz: u32::from_le_bytes([b[24], b[25], b[26], b[27]]),
            vrr_enable: b[28] != 0,
            hdr_enable: b[29] != 0,
            primary_fb_id: u32::from_le_bytes([b[32], b[33], b[34], b[35]]),
            cursor_fb_id: u32::from_le_bytes([b[36], b[37], b[38], b[39]]),
            cursor_x: i32::from_le_bytes([b[40], b[41], b[42], b[43]]),
            cursor_y: i32::from_le_bytes([b[44], b[45], b[46], b[47]]),
            cursor_hot_x: u16::from_le_bytes([b[48], b[49]]),
            cursor_hot_y: u16::from_le_bytes([b[50], b[51]]),
            in_syncobj: u32::from_le_bytes([b[52], b[53], b[54], b[55]]),
            out_syncobj: u32::from_le_bytes([b[56], b[57], b[58], b[59]]),
            in_point: u64::from(u32::from_le_bytes([b[60], b[61], b[62], b[63]])),
            out_point: u64::from_le_bytes([b[64], b[65], b[66], b[67], b[68], b[69], b[70], b[71]]),
            damage,
            damage_count: cnt,
        })
    }
}

/// Pack/unpack `proto::GPU_DEV` announcement header fields.
pub const fn pack_dev_a(kind: u8, vendor: u16, device: u16, vram_mib: u32) -> u64 {
    let vram = if vram_mib > 0xFFFF { 0xFFFF } else { vram_mib };
    (kind as u64)
        | ((vendor as u64) << 16)
        | ((device as u64) << 32)
        | ((vram as u64) << 48)
}

pub const fn unpack_dev_a(a: u64) -> (u8, u16, u16, u32) {
    (
        (a & 0xFF) as u8,
        ((a >> 16) & 0xFFFF) as u16,
        ((a >> 32) & 0xFFFF) as u16,
        ((a >> 48) & 0xFFFF) as u32,
    )
}

pub const fn pack_dev_b(width: u16, height: u16, caps: u32) -> u64 {
    (width as u64) | ((height as u64) << 16) | ((caps as u64) << 32)
}

pub const fn unpack_dev_b(b: u64) -> (u32, u32, u32) {
    ((b & 0xFFFF) as u32, ((b >> 16) & 0xFFFF) as u32, (b >> 32) as u32)
}

// ---- Client IPC helpers -------------------------------------------------------------------------

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
    let count = (h.a as usize).min(out.len()).min(body.len() / ADAPTER_INFO_BYTES);
    for (i, slot) in out.iter_mut().take(count).enumerate() {
        let off = i * ADAPTER_INFO_BYTES;
        if let Some(info) = AdapterInfo::decode(&body[off..off + ADAPTER_INFO_BYTES]) {
            *slot = info;
        }
    }
    Ok(count)
}

/// Query atomic KMS resources, connector/CRTC/plane state, and mode list (`OP_KMS_GET_RESOURCES`).
pub fn kms_get_resources(
    ep: Handle,
    adapter_id: u32,
    modes_out: &mut [ModeEntry],
) -> Result<(KmsResourcesWire, usize), i64> {
    if ep == 0 {
        return Err(sys::ERR_BAD_HANDLE);
    }
    let mut req = [0u8; HEADER];
    Header {
        txid: 0,
        op: OP_KMS_GET_RESOURCES,
        status: 0,
        a: u64::from(adapter_id),
        b: 0,
    }
    .put(&mut req);
    let mut rep = [0u8; HEADER + KMS_RESOURCES_HDR_BYTES + 16 * MODE_ENTRY_BYTES];
    let n = sys::channel_call(ep, &req, &mut rep, CALL_TIMEOUT_NS)? as usize;
    let h = Header::get(&rep[..n]).ok_or(sys::ERR_INVALID_ARGS)?;
    if h.status != 0 {
        return Err(i64::from(h.status));
    }
    let body = &rep[HEADER..n];
    let res = KmsResourcesWire::decode(body).ok_or(sys::ERR_BAD_STATE)?;
    let modes_slice = &body[KMS_RESOURCES_HDR_BYTES..];
    let count = (h.a as usize).min(modes_out.len()).min(modes_slice.len() / MODE_ENTRY_BYTES);
    for (i, slot) in modes_out.iter_mut().take(count).enumerate() {
        let off = i * MODE_ENTRY_BYTES;
        if let Some(m) = ModeEntry::decode(&modes_slice[off..off + MODE_ENTRY_BYTES]) {
            *slot = m;
        }
    }
    Ok((res, count))
}

pub fn get_modes(ep: Handle, adapter_id: u32, out: &mut [ModeEntry]) -> Result<usize, i64> {
    let (_, count) = kms_get_resources(ep, adapter_id, out)?;
    Ok(count)
}

/// Import an existing VMO into the GPU driver's GEM table (`OP_GEM_IMPORT`).
/// Returns `(gem_handle, uuid)`.
pub fn gem_import(ep: Handle, adapter_id: u32, vmo: Handle, size: u64, bo_flags: u32) -> Result<(u32, [u8; 16]), i64> {
    if ep == 0 || vmo == 0 {
        return Err(sys::ERR_BAD_HANDLE);
    }
    let dup = sys::handle_duplicate(vmo, sys::RIGHT_READ | sys::RIGHT_MAP | sys::RIGHT_TRANSFER)?;
    let mut req = [0u8; HEADER];
    Header {
        txid: 0,
        op: OP_GEM_IMPORT,
        status: 0,
        a: u64::from(adapter_id) | (u64::from(bo_flags) << 32),
        b: size,
    }
    .put(&mut req);
    let mut rep = [0u8; HEADER + 16];
    let mut rh = [0 as Handle; 1];
    let (n, _) = sys::channel_call_h(
        ep,
        &req,
        &[MsgHandle { handle: dup, rights: sys::RIGHTS_SAME }],
        &mut rep,
        &mut rh,
        CALL_TIMEOUT_NS,
    )?;
    let h = Header::get(&rep[..n]).ok_or(sys::ERR_INVALID_ARGS)?;
    if h.status != 0 {
        return Err(i64::from(h.status));
    }
    let mut uuid = [0u8; 16];
    if n >= HEADER + 16 {
        uuid.copy_from_slice(&rep[HEADER..HEADER + 16]);
    }
    Ok((h.a as u32, uuid))
}

/// Allocate a driver-managed GEM buffer object on `gpu.render` (`OP_GEM_CREATE`), returning
/// `(gem_handle, vmo_handle, uuid)`.
pub fn gem_create(ep: Handle, adapter_id: u32, size: u64, bo_flags: u32) -> Result<(u32, Handle, [u8; 16]), i64> {
    if ep == 0 {
        return Err(sys::ERR_BAD_HANDLE);
    }
    let mut req = [0u8; HEADER];
    Header {
        txid: 0,
        op: OP_GEM_CREATE,
        status: 0,
        a: u64::from(adapter_id) | (u64::from(bo_flags) << 32),
        b: size,
    }
    .put(&mut req);
    let mut rep = [0u8; HEADER + 16];
    let mut rh = [0 as Handle; 1];
    let (n, nh) = sys::channel_call_h(ep, &req, &[], &mut rep, &mut rh, CALL_TIMEOUT_NS)?;
    let h = Header::get(&rep[..n]).ok_or(sys::ERR_INVALID_ARGS)?;
    let got_vmo = if nh > 0 { rh[0] } else { 0 };
    if h.status != 0 {
        if got_vmo != 0 {
            sys::handle_close(got_vmo);
        }
        return Err(i64::from(h.status));
    }
    let mut uuid = [0u8; 16];
    if n >= HEADER + 16 {
        uuid.copy_from_slice(&rep[HEADER..HEADER + 16]);
    }
    Ok((h.a as u32, got_vmo, uuid))
}

pub fn gem_close(ep: Handle, adapter_id: u32, gem_handle: u32) -> Result<(), i64> {
    if ep == 0 {
        return Err(sys::ERR_BAD_HANDLE);
    }
    let mut req = [0u8; HEADER];
    Header {
        txid: 0,
        op: OP_GEM_CLOSE,
        status: 0,
        a: u64::from(adapter_id),
        b: u64::from(gem_handle),
    }
    .put(&mut req);
    let mut rep = [0u8; HEADER];
    let n = sys::channel_call(ep, &req, &mut rep, CALL_TIMEOUT_NS)? as usize;
    let h = Header::get(&rep[..n]).ok_or(sys::ERR_INVALID_ARGS)?;
    if h.status != 0 {
        return Err(i64::from(h.status));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn kms_create_fb(
    ep: Handle,
    adapter_id: u32,
    gem_handle: u32,
    width: u32,
    height: u32,
    pitch: u32,
    format: u32,
    modifier: u64,
) -> Result<u32, i64> {
    if ep == 0 {
        return Err(sys::ERR_BAD_HANDLE);
    }
    let mut req = [0u8; HEADER + 16];
    Header {
        txid: 0,
        op: OP_KMS_CREATE_FB,
        status: 0,
        a: u64::from(adapter_id) | (u64::from(gem_handle) << 32),
        b: u64::from(width) | (u64::from(height) << 32),
    }
    .put(&mut req);
    req[HEADER..HEADER + 4].copy_from_slice(&pitch.to_le_bytes());
    req[HEADER + 4..HEADER + 8].copy_from_slice(&format.to_le_bytes());
    req[HEADER + 8..HEADER + 16].copy_from_slice(&modifier.to_le_bytes());
    let mut rep = [0u8; HEADER];
    let n = sys::channel_call(ep, &req, &mut rep, CALL_TIMEOUT_NS)? as usize;
    let h = Header::get(&rep[..n]).ok_or(sys::ERR_INVALID_ARGS)?;
    if h.status != 0 {
        return Err(i64::from(h.status));
    }
    Ok(h.a as u32)
}

pub fn kms_destroy_fb(ep: Handle, adapter_id: u32, fb_id: u32) -> Result<(), i64> {
    if ep == 0 {
        return Err(sys::ERR_BAD_HANDLE);
    }
    let mut req = [0u8; HEADER];
    Header {
        txid: 0,
        op: OP_KMS_DESTROY_FB,
        status: 0,
        a: u64::from(adapter_id),
        b: u64::from(fb_id),
    }
    .put(&mut req);
    let mut rep = [0u8; HEADER];
    let n = sys::channel_call(ep, &req, &mut rep, CALL_TIMEOUT_NS)? as usize;
    let h = Header::get(&rep[..n]).ok_or(sys::ERR_INVALID_ARGS)?;
    if h.status != 0 {
        return Err(i64::from(h.status));
    }
    Ok(())
}

/// Submit or test (`ATOMIC_TEST_ONLY`) an atomic KMS state update (`OP_KMS_ATOMIC_COMMIT`).
/// Returns `(vblank_sequence, async_vblank_pending)`.
pub fn kms_atomic_commit(ep: Handle, adapter_id: u32, commit: &AtomicCommitWire) -> Result<(u64, bool), i64> {
    if ep == 0 {
        return Err(sys::ERR_BAD_HANDLE);
    }
    let mut body = [0u8; ATOMIC_COMMIT_HDR_BYTES + MAX_PRESENT_RECTS * 16];
    let blen = commit.encode(&mut body);
    let mut req = [0u8; HEADER + ATOMIC_COMMIT_HDR_BYTES + MAX_PRESENT_RECTS * 16];
    Header {
        txid: 0,
        op: OP_KMS_ATOMIC_COMMIT,
        status: 0,
        a: u64::from(adapter_id),
        b: blen as u64,
    }
    .put(&mut req);
    req[HEADER..HEADER + blen].copy_from_slice(&body[..blen]);
    let mut rep = [0u8; HEADER];
    let n = sys::channel_call(ep, &req[..HEADER + blen], &mut rep, CALL_TIMEOUT_NS)? as usize;
    let h = Header::get(&rep[..n]).ok_or(sys::ERR_INVALID_ARGS)?;
    if h.status != 0 {
        return Err(i64::from(h.status));
    }
    Ok((h.a, h.b != 0))
}

/// Confirm (`confirm = true`) or immediately revert (`confirm = false`) a pending 12s modeset.
pub fn kms_confirm_mode(ep: Handle, adapter_id: u32, confirm: bool) -> Result<(), i64> {
    if ep == 0 {
        return Err(sys::ERR_BAD_HANDLE);
    }
    let mut req = [0u8; HEADER];
    Header {
        txid: 0,
        op: OP_KMS_CONFIRM_MODE,
        status: 0,
        a: u64::from(adapter_id),
        b: u64::from(confirm),
    }
    .put(&mut req);
    let mut rep = [0u8; HEADER];
    let n = sys::channel_call(ep, &req, &mut rep, CALL_TIMEOUT_NS)? as usize;
    let h = Header::get(&rep[..n]).ok_or(sys::ERR_INVALID_ARGS)?;
    if h.status != 0 {
        return Err(i64::from(h.status));
    }
    Ok(())
}

// ---- High-level Atomic KMS convenience wrappers for D-AWMI & tests ------------------------------

/// Import a scanout VMO into GEM and create a KMS framebuffer (`(gem_handle, fb_id)`).
pub fn kms_attach_scanout_vmo(
    ep: Handle,
    adapter_id: u32,
    vmo: Handle,
    width: u32,
    height: u32,
    pitch: u32,
    format: u32,
) -> Result<(u32, u32), i64> {
    let size = u64::from(pitch).saturating_mul(u64::from(height));
    if size == 0 {
        return Err(sys::ERR_INVALID_ARGS);
    }
    let (gem_h, _) = gem_import(ep, adapter_id, vmo, size, BO_SCANOUT)?;
    match kms_create_fb(ep, adapter_id, gem_h, width, height, pitch, format, 0) {
        Ok(fb_id) => Ok((gem_h, fb_id)),
        Err(e) => {
            let _ = gem_close(ep, adapter_id, gem_h);
            Err(e)
        }
    }
}

/// Present `fb_id` on the primary plane with up to `MAX_PRESENT_RECTS` damage clips.
pub fn kms_present_atomic(
    ep: Handle,
    adapter_id: u32,
    fb_id: u32,
    rects: &[(u32, u32, u32, u32)],
) -> Result<(u64, bool), i64> {
    let mut c = AtomicCommitWire {
        flags: ATOMIC_NONBLOCK | ATOMIC_PAGE_FLIP_EVENT,
        change_mask: COMMIT_PRIMARY,
        primary_fb_id: fb_id,
        ..AtomicCommitWire::default()
    };
    let cnt = rects.len().min(MAX_PRESENT_RECTS);
    c.damage[..cnt].copy_from_slice(&rects[..cnt]);
    c.damage_count = cnt;
    kms_atomic_commit(ep, adapter_id, &c)
}

/// Validate (`test_only = true`) or commit (`test_only = false`) an atomic CRTC mode switch.
pub fn kms_modeset_atomic(
    ep: Handle,
    adapter_id: u32,
    width: u32,
    height: u32,
    refresh_mhz: u32,
    test_only: bool,
    require_confirm: bool,
) -> Result<(), i64> {
    let mut flags = ATOMIC_ALLOW_MODESET;
    if test_only {
        flags |= ATOMIC_TEST_ONLY;
    }
    if require_confirm {
        flags |= ATOMIC_REQUIRE_CONFIRM;
    }
    let c = AtomicCommitWire {
        flags,
        change_mask: COMMIT_MODE,
        mode_width: width,
        mode_height: height,
        mode_refresh_mhz: refresh_mhz,
        ..AtomicCommitWire::default()
    };
    kms_atomic_commit(ep, adapter_id, &c).map(|_| ())
}

pub fn kms_set_vrr_atomic(ep: Handle, adapter_id: u32, enable: bool) -> Result<(), i64> {
    let c = AtomicCommitWire {
        flags: ATOMIC_ALLOW_MODESET,
        change_mask: COMMIT_VRR,
        vrr_enable: enable,
        ..AtomicCommitWire::default()
    };
    kms_atomic_commit(ep, adapter_id, &c).map(|_| ())
}

pub fn kms_set_hdr_atomic(ep: Handle, adapter_id: u32, enable: bool) -> Result<(), i64> {
    let c = AtomicCommitWire {
        flags: ATOMIC_ALLOW_MODESET,
        change_mask: COMMIT_HDR,
        hdr_enable: enable,
        ..AtomicCommitWire::default()
    };
    kms_atomic_commit(ep, adapter_id, &c).map(|_| ())
}

pub fn kms_set_cursor_atomic(
    ep: Handle,
    adapter_id: u32,
    cursor_fb_id: u32,
    x: i32,
    y: i32,
    hot_x: u16,
    hot_y: u16,
) -> Result<(), i64> {
    let c = AtomicCommitWire {
        flags: ATOMIC_CURSOR_ONLY,
        change_mask: COMMIT_CURSOR,
        cursor_fb_id,
        cursor_x: x,
        cursor_y: y,
        cursor_hot_x: hot_x,
        cursor_hot_y: hot_y,
        ..AtomicCommitWire::default()
    };
    kms_atomic_commit(ep, adapter_id, &c).map(|_| ())
}

pub fn kms_reset_boot_atomic(ep: Handle, adapter_id: u32) -> Result<(), i64> {
    let c = AtomicCommitWire {
        flags: ATOMIC_ALLOW_MODESET | ATOMIC_RESET_BOOT,
        ..AtomicCommitWire::default()
    };
    kms_atomic_commit(ep, adapter_id, &c).map(|_| ())
}

// ---- `gpu.render`: GPU VM, Timeline Syncobj, & Context Submission helpers -----------------------

pub fn vm_create(ep: Handle, adapter_id: u32) -> Result<u32, i64> {
    if ep == 0 {
        return Err(sys::ERR_BAD_HANDLE);
    }
    let mut req = [0u8; HEADER];
    Header { txid: 0, op: OP_VM_CREATE, status: 0, a: u64::from(adapter_id), b: 0 }.put(&mut req);
    let mut rep = [0u8; HEADER];
    let n = sys::channel_call(ep, &req, &mut rep, CALL_TIMEOUT_NS)? as usize;
    let h = Header::get(&rep[..n]).ok_or(sys::ERR_INVALID_ARGS)?;
    if h.status != 0 {
        return Err(i64::from(h.status));
    }
    Ok(h.a as u32)
}

pub fn vm_destroy(ep: Handle, adapter_id: u32, vm_id: u32) -> Result<(), i64> {
    if ep == 0 {
        return Err(sys::ERR_BAD_HANDLE);
    }
    let mut req = [0u8; HEADER];
    Header { txid: 0, op: OP_VM_DESTROY, status: 0, a: u64::from(adapter_id), b: u64::from(vm_id) }.put(&mut req);
    let mut rep = [0u8; HEADER];
    let n = sys::channel_call(ep, &req, &mut rep, CALL_TIMEOUT_NS)? as usize;
    let h = Header::get(&rep[..n]).ok_or(sys::ERR_INVALID_ARGS)?;
    if h.status != 0 {
        return Err(i64::from(h.status));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn vm_bind(
    ep: Handle,
    adapter_id: u32,
    vm_id: u32,
    gem_handle: u32,
    bo_offset: u64,
    gpu_va: u64,
    size: u64,
    flags: u32,
) -> Result<(), i64> {
    if ep == 0 {
        return Err(sys::ERR_BAD_HANDLE);
    }
    let mut req = [0u8; HEADER + 24];
    Header {
        txid: 0,
        op: OP_VM_BIND,
        status: 0,
        a: u64::from(adapter_id) | (u64::from(vm_id) << 32),
        b: u64::from(gem_handle) | (u64::from(flags) << 32),
    }
    .put(&mut req);
    req[HEADER..HEADER + 8].copy_from_slice(&bo_offset.to_le_bytes());
    req[HEADER + 8..HEADER + 16].copy_from_slice(&gpu_va.to_le_bytes());
    req[HEADER + 16..HEADER + 24].copy_from_slice(&size.to_le_bytes());
    let mut rep = [0u8; HEADER];
    let n = sys::channel_call(ep, &req, &mut rep, CALL_TIMEOUT_NS)? as usize;
    let h = Header::get(&rep[..n]).ok_or(sys::ERR_INVALID_ARGS)?;
    if h.status != 0 {
        return Err(i64::from(h.status));
    }
    Ok(())
}

pub fn vm_unbind(ep: Handle, adapter_id: u32, vm_id: u32, gpu_va: u64, size: u64) -> Result<(), i64> {
    if ep == 0 {
        return Err(sys::ERR_BAD_HANDLE);
    }
    let mut req = [0u8; HEADER + 8];
    Header {
        txid: 0,
        op: OP_VM_UNBIND,
        status: 0,
        a: u64::from(adapter_id) | (u64::from(vm_id) << 32),
        b: gpu_va,
    }
    .put(&mut req);
    req[HEADER..HEADER + 8].copy_from_slice(&size.to_le_bytes());
    let mut rep = [0u8; HEADER];
    let n = sys::channel_call(ep, &req, &mut rep, CALL_TIMEOUT_NS)? as usize;
    let h = Header::get(&rep[..n]).ok_or(sys::ERR_INVALID_ARGS)?;
    if h.status != 0 {
        return Err(i64::from(h.status));
    }
    Ok(())
}

pub fn syncobj_create(ep: Handle, adapter_id: u32, initial_point: u64) -> Result<u32, i64> {
    if ep == 0 {
        return Err(sys::ERR_BAD_HANDLE);
    }
    let mut req = [0u8; HEADER];
    Header {
        txid: 0,
        op: OP_SYNCOBJ_CREATE,
        status: 0,
        a: u64::from(adapter_id),
        b: initial_point,
    }
    .put(&mut req);
    let mut rep = [0u8; HEADER];
    let n = sys::channel_call(ep, &req, &mut rep, CALL_TIMEOUT_NS)? as usize;
    let h = Header::get(&rep[..n]).ok_or(sys::ERR_INVALID_ARGS)?;
    if h.status != 0 {
        return Err(i64::from(h.status));
    }
    Ok(h.a as u32)
}

pub fn syncobj_destroy(ep: Handle, adapter_id: u32, syncobj: u32) -> Result<(), i64> {
    if ep == 0 {
        return Err(sys::ERR_BAD_HANDLE);
    }
    let mut req = [0u8; HEADER];
    Header {
        txid: 0,
        op: OP_SYNCOBJ_DESTROY,
        status: 0,
        a: u64::from(adapter_id),
        b: u64::from(syncobj),
    }
    .put(&mut req);
    let mut rep = [0u8; HEADER];
    let n = sys::channel_call(ep, &req, &mut rep, CALL_TIMEOUT_NS)? as usize;
    let h = Header::get(&rep[..n]).ok_or(sys::ERR_INVALID_ARGS)?;
    if h.status != 0 {
        return Err(i64::from(h.status));
    }
    Ok(())
}

pub fn syncobj_signal(ep: Handle, adapter_id: u32, syncobj: u32, point: u64) -> Result<u64, i64> {
    if ep == 0 {
        return Err(sys::ERR_BAD_HANDLE);
    }
    let mut req = [0u8; HEADER];
    Header {
        txid: 0,
        op: OP_SYNCOBJ_SIGNAL,
        status: 0,
        a: u64::from(adapter_id) | (u64::from(syncobj) << 32),
        b: point,
    }
    .put(&mut req);
    let mut rep = [0u8; HEADER];
    let n = sys::channel_call(ep, &req, &mut rep, CALL_TIMEOUT_NS)? as usize;
    let h = Header::get(&rep[..n]).ok_or(sys::ERR_INVALID_ARGS)?;
    if h.status != 0 {
        return Err(i64::from(h.status));
    }
    Ok(h.a)
}

/// Query / wait on a timeline `syncobj` reaching `point` (`OP_SYNCOBJ_WAIT`).
/// Returns the current signaled timeline value (`Err(ERR_SHOULD_WAIT)` if not reached yet).
pub fn syncobj_wait(ep: Handle, adapter_id: u32, syncobj: u32, point: u64) -> Result<u64, i64> {
    if ep == 0 {
        return Err(sys::ERR_BAD_HANDLE);
    }
    let mut req = [0u8; HEADER];
    Header {
        txid: 0,
        op: OP_SYNCOBJ_WAIT,
        status: 0,
        a: u64::from(adapter_id) | (u64::from(syncobj) << 32),
        b: point,
    }
    .put(&mut req);
    let mut rep = [0u8; HEADER];
    let n = sys::channel_call(ep, &req, &mut rep, CALL_TIMEOUT_NS)? as usize;
    let h = Header::get(&rep[..n]).ok_or(sys::ERR_INVALID_ARGS)?;
    if h.status != 0 {
        return Err(i64::from(h.status));
    }
    Ok(h.a)
}

pub fn ctx_create_ex(ep: Handle, adapter_id: u32, engine: u32, vm_id: u32) -> Result<u32, i64> {
    if ep == 0 {
        return Err(sys::ERR_BAD_HANDLE);
    }
    let mut req = [0u8; HEADER];
    Header {
        txid: 0,
        op: OP_CTX_CREATE,
        status: 0,
        a: u64::from(adapter_id) | (u64::from(engine) << 32),
        b: u64::from(vm_id),
    }
    .put(&mut req);
    let mut rep = [0u8; HEADER];
    let n = sys::channel_call(ep, &req, &mut rep, CALL_TIMEOUT_NS)? as usize;
    let h = Header::get(&rep[..n]).ok_or(sys::ERR_INVALID_ARGS)?;
    if h.status != 0 {
        return Err(i64::from(h.status));
    }
    Ok(h.a as u32)
}

pub fn ctx_create(ep: Handle, adapter_id: u32) -> Result<u32, i64> {
    ctx_create_ex(ep, adapter_id, ENGINE_VIRGL_3D, 0)
}

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
    let h = Header::get(&rep[..n]).ok_or(sys::ERR_INVALID_ARGS)?;
    if h.status != 0 {
        return Err(i64::from(h.status));
    }
    Ok(())
}

/// Submit a command stream to `(ctx_id, engine)` with optional wait & signal timeline `syncobj`s.
#[allow(clippy::too_many_arguments)]
pub fn submit_ex(
    ep: Handle,
    adapter_id: u32,
    ctx_id: u32,
    engine: u32,
    wait_syncobj: u32,
    wait_point: u64,
    signal_syncobj: u32,
    signal_point: u64,
    cmd: &[u8],
) -> Result<u64, i64> {
    if ep == 0 {
        return Err(sys::ERR_BAD_HANDLE);
    }
    if cmd.len() > 2048 {
        return Err(sys::ERR_INVALID_ARGS);
    }
    let mut req = [0u8; HEADER + 24 + 2048];
    Header {
        txid: 0,
        op: OP_SUBMIT,
        status: 0,
        a: u64::from(adapter_id) | (u64::from(ctx_id) << 32),
        b: u64::from(engine) | ((cmd.len() as u64) << 32),
    }
    .put(&mut req);
    req[HEADER..HEADER + 4].copy_from_slice(&wait_syncobj.to_le_bytes());
    req[HEADER + 4..HEADER + 8].copy_from_slice(&signal_syncobj.to_le_bytes());
    req[HEADER + 8..HEADER + 16].copy_from_slice(&wait_point.to_le_bytes());
    req[HEADER + 16..HEADER + 24].copy_from_slice(&signal_point.to_le_bytes());
    req[HEADER + 24..HEADER + 24 + cmd.len()].copy_from_slice(cmd);
    let mut rep = [0u8; HEADER];
    let n = sys::channel_call(ep, &req[..HEADER + 24 + cmd.len()], &mut rep, CALL_TIMEOUT_NS)? as usize;
    let h = Header::get(&rep[..n]).ok_or(sys::ERR_INVALID_ARGS)?;
    if h.status != 0 {
        return Err(i64::from(h.status));
    }
    Ok(h.a)
}

pub fn submit_cmd(ep: Handle, adapter_id: u32, ctx_id: u32, engine: u32, cmd: &[u8]) -> Result<u64, i64> {
    submit_ex(ep, adapter_id, ctx_id, engine, 0, 0, 0, 0, cmd)
}

pub fn crash_driver(ep: Handle, adapter_id: u32) -> Result<(), i64> {
    if ep == 0 {
        return Err(sys::ERR_BAD_HANDLE);
    }
    let mut req = [0u8; HEADER];
    Header {
        txid: 0,
        op: OP_CRASH_DRIVER,
        status: 0,
        a: u64::from(adapter_id),
        b: 0,
    }
    .put(&mut req);
    let mut rep = [0u8; HEADER];
    let n = sys::channel_call(ep, &req, &mut rep, CALL_TIMEOUT_NS)? as usize;
    let h = Header::get(&rep[..n]).ok_or(sys::ERR_INVALID_ARGS)?;
    if h.status != 0 {
        return Err(i64::from(h.status));
    }
    Ok(())
}
