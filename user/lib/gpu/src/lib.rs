//! `dosgpu`: pure `no_std`, `#![forbid(unsafe_code)]`, zero-dependency GPU & display core.
//!
//! Provides bounds-checked hardware parsers, modesetting math, EDID decoding, dirty-rectangle
//! blitting/format conversion, and strict command-stream builders & validators for:
//! - UEFI GOP linear framebuffer baseline
//! - VirtIO-GPU 2D & 3D (VirGL)
//! - AMD RDNA / AMDGPU (RDNA 2/3/4, IP Discovery, DCN, PM4 Type-3, SDMA v5/v6)
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
}

impl PixelFormat {
    pub const fn from_u32(v: u32) -> Option<Self> {
        match v {
            1 => Some(Self::Xrgb8888),
            2 => Some(Self::Argb8888),
            3 => Some(Self::Xbgr8888),
            _ => None,
        }
    }

    pub const fn bpp(self) -> u32 {
        4
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
    pub const fn full(width: u32, height: u32) -> Self {
        Self { x: 0, y: 0, w: width, h: height }
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
    };
    (r << (shifts[0] & 31)) | (g << (shifts[1] & 31)) | (b << (shifts[2] & 31))
}

/// Blit a clipped damage rectangle from `src` (pitch `src_pitch` bytes) into a destination sink
/// `write_row(dst_byte_off, row_u32s)` with zero destination readback (write-combining safe).
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
