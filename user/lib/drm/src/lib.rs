//! `dosdrm`: D-OS user-space Atomic KMS, GEM/GPU-VM/Syncobj core, EDID/DisplayID parser,
//! VirtIO-GPU 2D/3D/Blob/Venus wire codecs, and Ring-3 vendor driver compatibility shim.
//!
//! All pure protocol, KMS validation, GEM/VM/syncobj state machines, EDID parsing, and pixel
//! blitters compile with `#![forbid(unsafe_code)]` and zero dependencies; the optional `shim`
//! feature adds the Ring-3 `libd` hardware/firmware/FFI glue used by isolated `.ddrv` processes.

#![no_std]
#![cfg_attr(not(feature = "shim"), forbid(unsafe_code))]

pub mod edid;
pub mod gem;
pub mod kms;
#[cfg(feature = "shim")]
pub mod shim;
pub mod virtio;

#[cfg(test)]
extern crate std;
#[cfg(test)]
mod tests;

/// GPU adapter backend kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum AdapterKind {
    Gop = 1,
    VirtioGpu = 2,
    AmdRdna = 3,
    IntelXe = 4,
    NvidiaGsp = 5,
}

impl AdapterKind {
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Gop),
            2 => Some(Self::VirtioGpu),
            3 => Some(Self::AmdRdna),
            4 => Some(Self::IntelXe),
            5 => Some(Self::NvidiaGsp),
            _ => None,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::Gop => "gop",
            Self::VirtioGpu => "virtio-gpu",
            Self::AmdRdna => "amdgpu",
            Self::IntelXe => "xe",
            Self::NvidiaGsp => "nvgpu",
        }
    }
}

/// Capability bitmask advertised by a GPU adapter.
pub mod caps {
    pub const SCANOUT_2D: u32 = 1 << 0;
    pub const HW_CURSOR: u32 = 1 << 1;
    pub const EDID: u32 = 1 << 2;
    pub const VIRGL_3D: u32 = 1 << 3;
    pub const PAGE_FLIP: u32 = 1 << 4;
    pub const CMD_GFX: u32 = 1 << 5;
    pub const CMD_DMA: u32 = 1 << 6;
    pub const IOMMU_CONFINED: u32 = 1 << 7;
    pub const WRITE_COMBINING: u32 = 1 << 8;
    pub const GSP_RPC: u32 = 1 << 9;
    pub const ASYNC_FLIP: u32 = 1 << 10;
    pub const NATIVE_GOP_MATCH: u32 = 1 << 11;
    pub const VRR: u32 = 1 << 12;
    pub const HDR: u32 = 1 << 13;
    pub const DSC: u32 = 1 << 14;
    pub const ATOMIC_KMS: u32 = 1 << 15;
    pub const GEM_VM: u32 = 1 << 16;
    pub const SYNCOBJ_TIMELINE: u32 = 1 << 17;
    pub const VENUS_VK: u32 = 1 << 18;
    pub const SYS_FIRMWARE: u32 = 1 << 19;
}

/// Standard DRM FourCC pixel formats (`drm/drm_fourcc.h`).
pub mod fourcc {
    pub const fn code(a: u8, b: u8, c: u8, d: u8) -> u32 {
        (a as u32) | ((b as u32) << 8) | ((c as u32) << 16) | ((d as u32) << 24)
    }

    pub const XRGB8888: u32 = code(b'X', b'R', b'2', b'4');
    pub const ARGB8888: u32 = code(b'A', b'R', b'2', b'4');
    pub const XBGR8888: u32 = code(b'X', b'B', b'2', b'4');
    pub const ABGR8888: u32 = code(b'A', b'B', b'2', b'4');
    pub const XRGB2101010: u32 = code(b'X', b'R', b'3', b'0');
    pub const ARGB2101010: u32 = code(b'A', b'R', b'3', b'0');

    pub const MOD_LINEAR: u64 = 0;
}

/// Pixel formats supported by KMS planes and WC blitters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum PixelFormat {
    Xrgb8888 = 1,
    Argb8888 = 2,
    Xbgr8888 = 3,
    Argb2101010 = 4,
}

impl PixelFormat {
    /// Accept both compact D-OS format codes (`1..=4`) and standard DRM FourCC codes.
    pub const fn from_u32(v: u32) -> Option<Self> {
        match v {
            1 | fourcc::XRGB8888 => Some(Self::Xrgb8888),
            2 | fourcc::ARGB8888 => Some(Self::Argb8888),
            3 | fourcc::XBGR8888 | fourcc::ABGR8888 => Some(Self::Xbgr8888),
            4 | fourcc::ARGB2101010 | fourcc::XRGB2101010 => Some(Self::Argb2101010),
            _ => None,
        }
    }

    pub const fn to_fourcc(self) -> u32 {
        match self {
            Self::Xrgb8888 => fourcc::XRGB8888,
            Self::Argb8888 => fourcc::ARGB8888,
            Self::Xbgr8888 => fourcc::XBGR8888,
            Self::Argb2101010 => fourcc::ARGB2101010,
        }
    }

    pub const fn bpp(self) -> u32 {
        4
    }

    pub const fn bpc(self) -> u8 {
        match self {
            Self::Argb2101010 => 10,
            Self::Xrgb8888 | Self::Argb8888 | Self::Xbgr8888 => 8,
        }
    }
}

/// A display mode (resolution + refresh rate in millihertz).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DisplayMode {
    pub width: u32,
    pub height: u32,
    pub refresh_mhz: u32,
    pub preferred: bool,
}

impl DisplayMode {
    pub const fn new(width: u32, height: u32, refresh_mhz: u32, preferred: bool) -> Self {
        Self { width, height, refresh_mhz, preferred }
    }

    pub const fn stride_bytes(&self, align: u32) -> Option<u32> {
        if self.width == 0 || self.height == 0 || align < 4 || !align.is_power_of_two() {
            return None;
        }
        let Some(raw) = self.width.checked_mul(4) else {
            return None;
        };
        let mask = align - 1;
        let Some(added) = raw.checked_add(mask) else {
            return None;
        };
        Some(added & !mask)
    }

    pub const fn fb_size(&self, align: u32) -> Option<u64> {
        let Some(stride) = self.stride_bytes(align) else {
            return None;
        };
        (stride as u64).checked_mul(self.height as u64)
    }
}

/// Maximum supported framebuffer dimension (8K UHD).
pub const MAX_DIM: u32 = 7680;
/// Maximum supported single framebuffer size (64 MiB — matches kernel DMA pin limit).
pub const MAX_FB_BYTES: u64 = 64 << 20;

/// Damage rectangle in pixel coordinates.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DamageRect {
    pub x: u32,
    pub y: u32,
    pub w: u32,
    pub h: u32,
}

impl DamageRect {
    pub const EMPTY: Self = Self { x: 0, y: 0, w: 0, h: 0 };

    pub const fn full(width: u32, height: u32) -> Self {
        Self { x: 0, y: 0, w: width, h: height }
    }

    pub const fn is_empty(self) -> bool {
        self.w == 0 || self.h == 0
    }

    pub const fn clip(self, width: u32, height: u32) -> Option<Self> {
        if self.x >= width || self.y >= height || self.w == 0 || self.h == 0 {
            return None;
        }
        let max_w = width - self.x;
        let max_h = height - self.y;
        let w = if self.w < max_w { self.w } else { max_w };
        let h = if self.h < max_h { self.h } else { max_h };
        if w == 0 || h == 0 {
            return None;
        }
        Some(Self { x: self.x, y: self.y, w, h })
    }

    pub const fn intersects_or_touches(self, other: Self) -> bool {
        if self.is_empty() || other.is_empty() {
            return false;
        }
        let ax1 = self.x.saturating_add(self.w);
        let ay1 = self.y.saturating_add(self.h);
        let bx1 = other.x.saturating_add(other.w);
        let by1 = other.y.saturating_add(other.h);
        self.x <= bx1 && other.x <= ax1 && self.y <= by1 && other.y <= ay1
    }

    pub const fn union(self, other: Self) -> Self {
        if self.w == 0 || self.h == 0 {
            return other;
        }
        if other.w == 0 || other.h == 0 {
            return self;
        }
        let x0 = if self.x < other.x { self.x } else { other.x };
        let y0 = if self.y < other.y { self.y } else { other.y };
        let x1_a = self.x.saturating_add(self.w);
        let x1_b = other.x.saturating_add(other.w);
        let x1 = if x1_a > x1_b { x1_a } else { x1_b };
        let y1_a = self.y.saturating_add(self.h);
        let y1_b = other.y.saturating_add(other.h);
        let y1 = if y1_a > y1_b { y1_a } else { y1_b };
        Self { x: x0, y: y0, w: x1.saturating_sub(x0), h: y1.saturating_sub(y0) }
    }

    pub const fn area(self) -> u64 {
        (self.w as u64).saturating_mul(self.h as u64)
    }
}

pub const MAX_AGE_RECTS: usize = 16;
const AGE_HISTORY: usize = 4;
const MAX_AGE_BUFFERS: usize = 4;

#[derive(Clone, Copy, Debug)]
struct FrameDamage {
    rects: [DamageRect; MAX_AGE_RECTS],
    count: usize,
    full: bool,
}

impl FrameDamage {
    const EMPTY: Self = Self { rects: [DamageRect::EMPTY; MAX_AGE_RECTS], count: 0, full: false };
}

/// Tracks per-buffer damage history across double- or triple-buffered scanout chains.
#[derive(Clone, Copy, Debug)]
pub struct BufferAgeTracker {
    buf_count: usize,
    width: u32,
    height: u32,
    frame: u64,
    last_frame: [u64; MAX_AGE_BUFFERS],
    dirty_full: [bool; MAX_AGE_BUFFERS],
    history: [FrameDamage; AGE_HISTORY],
}

impl BufferAgeTracker {
    pub const fn new(buf_count: usize, width: u32, height: u32) -> Self {
        let clamped = if buf_count == 0 {
            1
        } else if buf_count > MAX_AGE_BUFFERS {
            MAX_AGE_BUFFERS
        } else {
            buf_count
        };
        Self {
            buf_count: clamped,
            width,
            height,
            frame: 0,
            last_frame: [0; MAX_AGE_BUFFERS],
            dirty_full: [true; MAX_AGE_BUFFERS],
            history: [FrameDamage::EMPTY; AGE_HISTORY],
        }
    }

    pub fn reset(&mut self, buf_count: usize, width: u32, height: u32) {
        *self = Self::new(buf_count, width, height);
    }

    pub fn mark_all_dirty(&mut self) {
        self.dirty_full = [true; MAX_AGE_BUFFERS];
    }

    pub const fn frame(&self) -> u64 {
        self.frame
    }

    pub const fn buffer_age(&self, buf_idx: usize) -> Option<u64> {
        if buf_idx >= self.buf_count || self.dirty_full[buf_idx] {
            return None;
        }
        Some(self.frame.saturating_sub(self.last_frame[buf_idx]))
    }

    pub fn collect_for_buffer(&self, buf_idx: usize, current_damage: &[DamageRect], out: &mut [DamageRect]) -> usize {
        if out.is_empty() || self.width == 0 || self.height == 0 {
            return 0;
        }
        let full = DamageRect::full(self.width, self.height);
        if buf_idx >= self.buf_count || self.dirty_full[buf_idx] || current_damage.is_empty() {
            out[0] = full;
            return 1;
        }
        let age = self.frame.saturating_sub(self.last_frame[buf_idx]);
        if age as usize >= AGE_HISTORY {
            out[0] = full;
            return 1;
        }
        let mut count = 0usize;
        let mut f = self.last_frame[buf_idx];
        while f < self.frame {
            let slot = &self.history[(f as usize) % AGE_HISTORY];
            if slot.full {
                out[0] = full;
                return 1;
            }
            for &r in &slot.rects[..slot.count] {
                if let Some(c) = r.clip(self.width, self.height) {
                    push_coalesced(out, &mut count, c);
                }
            }
            f += 1;
        }
        for &r in current_damage {
            if let Some(c) = r.clip(self.width, self.height) {
                push_coalesced(out, &mut count, c);
            }
        }
        if count == 0 {
            out[0] = full;
            return 1;
        }
        count
    }

    pub fn commit_buffer(&mut self, buf_idx: usize, current_damage: &[DamageRect]) {
        if buf_idx >= self.buf_count {
            return;
        }
        let slot = &mut self.history[(self.frame as usize) % AGE_HISTORY];
        *slot = FrameDamage::EMPTY;
        if current_damage.is_empty() {
            slot.full = true;
        } else {
            let mut cnt = 0usize;
            for &r in current_damage {
                if let Some(c) = r.clip(self.width, self.height) {
                    push_coalesced(&mut slot.rects, &mut cnt, c);
                }
            }
            if cnt == 0 {
                slot.full = true;
            } else {
                slot.count = cnt;
            }
        }
        self.frame = self.frame.saturating_add(1);
        self.last_frame[buf_idx] = self.frame;
        self.dirty_full[buf_idx] = false;
    }
}

fn push_coalesced(out: &mut [DamageRect], count: &mut usize, mut rect: DamageRect) {
    let mut i = 0;
    while i < *count {
        if out[i].intersects_or_touches(rect) {
            rect = out[i].union(rect);
            *count -= 1;
            out[i] = out[*count];
        } else {
            i += 1;
        }
    }
    if *count < out.len() {
        out[*count] = rect;
        *count += 1;
    } else if !out.is_empty() {
        let mut best_i = 0usize;
        let mut best_area = u64::MAX;
        for (idx, &existing) in out.iter().enumerate() {
            let a = existing.union(rect).area();
            if a < best_area {
                best_area = a;
                best_i = idx;
            }
        }
        out[best_i] = out[best_i].union(rect);
    }
}

/// Command-stream validation failure reason.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CsError {
    Empty,
    TooLarge,
    Unaligned,
    Truncated,
    UnknownOpcode,
    BadArgument,
}

#[inline]
pub const fn convert_pixel(px: u32, src_fmt: PixelFormat, shifts: [u8; 3]) -> u32 {
    let (r, g, b) = match src_fmt {
        PixelFormat::Xrgb8888 | PixelFormat::Argb8888 => ((px >> 16) & 0xFF, (px >> 8) & 0xFF, px & 0xFF),
        PixelFormat::Xbgr8888 => (px & 0xFF, (px >> 8) & 0xFF, (px >> 16) & 0xFF),
        PixelFormat::Argb2101010 => ((px >> 22) & 0xFF, (px >> 12) & 0xFF, (px >> 2) & 0xFF),
    };
    (r << (shifts[0] & 31)) | (g << (shifts[1] & 31)) | (b << (shifts[2] & 31))
}

#[inline]
pub const fn convert_pixel_to_argb2101010(px: u32, src_fmt: PixelFormat) -> u32 {
    match src_fmt {
        PixelFormat::Argb2101010 => px,
        _ => {
            let (r, g, b) = match src_fmt {
                PixelFormat::Xrgb8888 | PixelFormat::Argb8888 => ((px >> 16) & 0xFF, (px >> 8) & 0xFF, px & 0xFF),
                PixelFormat::Xbgr8888 => (px & 0xFF, (px >> 8) & 0xFF, (px >> 16) & 0xFF),
                PixelFormat::Argb2101010 => (0, 0, 0),
            };
            let r10 = (r << 2) | (r >> 6);
            let g10 = (g << 2) | (g >> 6);
            let b10 = (b << 2) | (b >> 6);
            (3 << 30) | (r10 << 20) | (g10 << 10) | b10
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub fn blit_rect_wc<F>(
    src: &[u8],
    src_pitch: u32,
    src_fmt: PixelFormat,
    dst_pitch: u32,
    dst_shifts: [u8; 3],
    width: u32,
    height: u32,
    rect: DamageRect,
    mut write_pixel: F,
) -> usize
where
    F: FnMut(u64, u32),
{
    let Some(r) = rect.clip(width, height) else {
        return 0;
    };
    let fast_identity = matches!(src_fmt, PixelFormat::Xrgb8888 | PixelFormat::Argb8888)
        && dst_shifts == [16, 8, 0];
    let mut pixels = 0usize;
    for row in 0..r.h {
        let y = r.y + row;
        let Some(src_row_off) = (y as usize)
            .checked_mul(src_pitch as usize)
            .and_then(|o| o.checked_add((r.x as usize).checked_mul(4)?))
        else {
            break;
        };
        let Some(row_bytes) = (r.w as usize).checked_mul(4) else {
            break;
        };
        if src_row_off.checked_add(row_bytes).is_none_or(|e| e > src.len()) {
            break;
        }
        let dst_row_base = u64::from(y) * u64::from(dst_pitch) + u64::from(r.x) * 4;
        let slice = &src[src_row_off..src_row_off + row_bytes];
        for (col, chunk) in slice.as_chunks::<4>().0.iter().enumerate() {
            let px = u32::from_le_bytes(*chunk);
            let out = if fast_identity { px } else { convert_pixel(px, src_fmt, dst_shifts) };
            write_pixel(dst_row_base + (col as u64) * 4, out);
            pixels += 1;
        }
    }
    pixels
}

#[allow(clippy::too_many_arguments)]
pub fn blit_rect_wc_10bpc<F>(
    src: &[u8],
    src_pitch: u32,
    src_fmt: PixelFormat,
    dst_pitch: u32,
    width: u32,
    height: u32,
    rect: DamageRect,
    mut write_pixel: F,
) -> usize
where
    F: FnMut(u64, u32),
{
    let Some(r) = rect.clip(width, height) else {
        return 0;
    };
    let mut pixels = 0usize;
    for row in 0..r.h {
        let y = r.y + row;
        let Some(src_row_off) = (y as usize)
            .checked_mul(src_pitch as usize)
            .and_then(|o| o.checked_add((r.x as usize).checked_mul(4)?))
        else {
            break;
        };
        let Some(row_bytes) = (r.w as usize).checked_mul(4) else {
            break;
        };
        if src_row_off.checked_add(row_bytes).is_none_or(|e| e > src.len()) {
            break;
        }
        let dst_row_base = u64::from(y) * u64::from(dst_pitch) + u64::from(r.x) * 4;
        let slice = &src[src_row_off..src_row_off + row_bytes];
        for (col, chunk) in slice.as_chunks::<4>().0.iter().enumerate() {
            let px = u32::from_le_bytes(*chunk);
            write_pixel(dst_row_base + (col as u64) * 4, convert_pixel_to_argb2101010(px, src_fmt));
            pixels += 1;
        }
    }
    pixels
}

#[inline]
pub(crate) fn rd_u16(b: &[u8], off: usize) -> Option<u16> {
    let s = b.get(off..off + 2)?;
    Some(u16::from_le_bytes([s[0], s[1]]))
}

#[inline]
pub(crate) fn rd_u32(b: &[u8], off: usize) -> Option<u32> {
    let s = b.get(off..off + 4)?;
    Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

#[inline]
pub(crate) fn rd_u64(b: &[u8], off: usize) -> Option<u64> {
    let s = b.get(off..off + 8)?;
    Some(u64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]))
}

#[inline]
pub(crate) fn wr_u32(b: &mut [u8], off: usize, v: u32) -> bool {
    if let Some(s) = b.get_mut(off..off + 4) {
        s.copy_from_slice(&v.to_le_bytes());
        true
    } else {
        false
    }
}

#[inline]
pub(crate) fn wr_u64(b: &mut [u8], off: usize, v: u64) -> bool {
    if let Some(s) = b.get_mut(off..off + 8) {
        s.copy_from_slice(&v.to_le_bytes());
        true
    } else {
        false
    }
}
