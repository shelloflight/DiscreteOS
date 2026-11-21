//! `dosgpu`: pure `no_std`, `#![forbid(unsafe_code)]`, zero-dependency GPU & display core.
//!
//! Provides bounds-checked hardware parsers, modesetting math, EDID decoding, dirty-rectangle
//! blitting/format conversion, buffer-age damage tracking, and strict command-stream builders
//! & validators for:
//! - UEFI GOP linear framebuffer baseline
//! - VirtIO-GPU 2D & 3D (VirGL)
//! - AMD RDNA / AMDGPU (RDNA 2/3/4, IP Discovery, DCN 3.0/3.1.5/3.2/4.0.1, DP AUX, IH ring, PM4, SDMA)
//! - Intel Xe / i915 (Gen9/Xe-LP/Xe-HPG/Xe2, GMD_ID, Display Pipes A-D, MI/XY Blitter)
//! - NVIDIA Open-GSP (Turing/Ampere/Ada/Blackwell, PMC_BOOT, Open-GSP RPC framing)

#![no_std]
#![forbid(unsafe_code)]

pub mod amd;
pub mod edid;
pub mod intel;
pub mod nvidia;
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
    /// Asynchronous vsync flip completion notifications (`EVT_FLIP_DONE`).
    pub const ASYNC_FLIP: u32 = 1 << 10;
    /// Native driver verified its active scanout matches the firmware GOP display.
    pub const NATIVE_GOP_MATCH: u32 = 1 << 11;
    /// Variable refresh rate (FreeSync / Adaptive-Sync) supported.
    pub const VRR: u32 = 1 << 12;
    /// 10-bit HDR10 scanout supported.
    pub const HDR: u32 = 1 << 13;
    /// Display Stream Compression (DSC 1.2) supported.
    pub const DSC: u32 = 1 << 14;
}

/// Command submission engine kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum EngineKind {
    Virgl3d = 1,
    AmdPm4 = 2,
    AmdSdma = 3,
    IntelBlit = 4,
    NvidiaGsp = 5,
}

impl EngineKind {
    pub const fn from_u32(v: u32) -> Option<Self> {
        match v {
            1 => Some(Self::Virgl3d),
            2 => Some(Self::AmdPm4),
            3 => Some(Self::AmdSdma),
            4 => Some(Self::IntelBlit),
            5 => Some(Self::NvidiaGsp),
            _ => None,
        }
    }
}

/// Pixel formats for framebuffers and scanouts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum PixelFormat {
    /// 32-bit B, G, R, X in memory (`0x00RRGGBB` as little-endian u32, DRM_FORMAT_XRGB8888 / VirtIO B8G8R8X8).
    Xrgb8888 = 1,
    /// 32-bit B, G, R, A in memory (`0xAARRGGBB` as little-endian u32, DRM_FORMAT_ARGB8888 / VirtIO B8G8R8A8).
    Argb8888 = 2,
    /// 32-bit R, G, B, X in memory (`0x00BBGGRR` as little-endian u32, DRM_FORMAT_XBGR8888 / VirtIO R8G8B8X8).
    Xbgr8888 = 3,
    /// 32-bit 10-bit per channel RGB + 2-bit alpha (`0xAARRRRRRRRRRGGGGGGGGGGBBBBBBBBBB`, HDR10).
    Argb2101010 = 4,
}

impl PixelFormat {
    pub const fn from_u32(v: u32) -> Option<Self> {
        match v {
            1 => Some(Self::Xrgb8888),
            2 => Some(Self::Argb8888),
            3 => Some(Self::Xbgr8888),
            4 => Some(Self::Argb2101010),
            _ => None,
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

    /// Checked stride in bytes for 32bpp, aligned up to `align` bytes (must be power of two >= 4).
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

    /// Checked total framebuffer size in bytes.
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

    /// Clip this rectangle to `[0, width) x [0, height)`. Returns `None` if empty after clipping.
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

    /// True if `self` and `other` overlap or touch along an edge.
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

    /// Bounding union of two non-empty rectangles.
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

    /// Area in pixels (saturating).
    pub const fn area(self) -> u64 {
        (self.w as u64).saturating_mul(self.h as u64)
    }
}

/// Maximum damage rectangles stored per frame in [`BufferAgeTracker`].
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
///
/// For any scanout buffer `buf_idx`, [`Self::collect_for_buffer`] computes the union of
/// `current_damage` with all damage committed to newer frames since `buf_idx` was last shown.
/// That keeps incremental updates tiny (avoiding full-frame copies over PCIe at 240/540 Hz)
/// while guaranteeing every pixel in the flipped buffer is up to date.
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

    /// Number of frames elapsed since `buf_idx` was last committed (`None` if never shown / dirty).
    pub const fn buffer_age(&self, buf_idx: usize) -> Option<u64> {
        if buf_idx >= self.buf_count || self.dirty_full[buf_idx] {
            return None;
        }
        Some(self.frame.saturating_sub(self.last_frame[buf_idx]))
    }

    /// Compute the clipped, coalesced damage rectangles that must be copied into `buf_idx`
    /// before flipping it to display the current frame (`current_damage`; empty = full frame).
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
        // Include damage from frames presented after `buf_idx` was last shown.
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
        // Include current frame's damage.
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

    /// Record that `buf_idx` has been updated with `current_damage` (empty = full frame)
    /// and flipped for the current frame.
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
    // Merge with any existing overlapping/touching rectangle.
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
        // Capacity reached: merge with the rectangle that produces the smallest bounding box.
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
    DisallowedRegister,
    BadArgument,
}

/// Convert one 32-bit pixel from `src_fmt` into a packed 32-bit word with the given RGB bit shifts.
#[inline]
pub const fn convert_pixel(px: u32, src_fmt: PixelFormat, shifts: [u8; 3]) -> u32 {
    let (r, g, b) = match src_fmt {
        PixelFormat::Xrgb8888 | PixelFormat::Argb8888 => ((px >> 16) & 0xFF, (px >> 8) & 0xFF, px & 0xFF),
        PixelFormat::Xbgr8888 => (px & 0xFF, (px >> 8) & 0xFF, (px >> 16) & 0xFF),
        PixelFormat::Argb2101010 => (((px >> 22) & 0xFF), ((px >> 12) & 0xFF), ((px >> 2) & 0xFF)),
    };
    (r << (shifts[0] & 31)) | (g << (shifts[1] & 31)) | (b << (shifts[2] & 31))
}

/// Convert one 8bpc pixel to packed 10bpc `ARGB2101010` (HDR10 scanout format).
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
            // Expand 8-bit channel to 10-bit via `(c << 2) | (c >> 6)` for full [0, 1023] range.
            let r10 = (r << 2) | (r >> 6);
            let g10 = (g << 2) | (g >> 6);
            let b10 = (b << 2) | (b >> 6);
            (3 << 30) | (r10 << 20) | (g10 << 10) | b10
        }
    }
}

/// Blit a clipped damage rectangle from `src` (pitch `src_pitch` bytes) into a destination sink
/// `write_pixel(dst_byte_off, pixel_u32)` with zero destination readback (write-combining safe).
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

/// Blit a clipped damage rectangle converting pixels to 10-bit `ARGB2101010` (HDR10).
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

/// Helper: read little-endian u16 from a byte slice with bounds check.
#[inline]
pub(crate) fn rd_u16(b: &[u8], off: usize) -> Option<u16> {
    let s = b.get(off..off + 2)?;
    Some(u16::from_le_bytes([s[0], s[1]]))
}

/// Helper: read little-endian u32 from a byte slice with bounds check.
#[inline]
pub(crate) fn rd_u32(b: &[u8], off: usize) -> Option<u32> {
    let s = b.get(off..off + 4)?;
    Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

/// Helper: read little-endian u64 from a byte slice with bounds check.
#[inline]
pub(crate) fn rd_u64(b: &[u8], off: usize) -> Option<u64> {
    let s = b.get(off..off + 8)?;
    Some(u64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]))
}

/// Helper: write little-endian u32 into a byte slice with bounds check.
#[inline]
pub(crate) fn wr_u32(b: &mut [u8], off: usize, v: u32) -> bool {
    if let Some(s) = b.get_mut(off..off + 4) {
        s.copy_from_slice(&v.to_le_bytes());
        true
    } else {
        false
    }
}

/// Helper: write little-endian u64 into a byte slice with bounds check.
#[inline]
pub(crate) fn wr_u64(b: &mut [u8], off: usize, v: u64) -> bool {
    if let Some(s) = b.get_mut(off..off + 8) {
        s.copy_from_slice(&v.to_le_bytes());
        true
    } else {
        false
    }
}
