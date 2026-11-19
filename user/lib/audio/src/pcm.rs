//! PCM format conversion, channel mapping, stateful linear resampling, mixing, and tone generation.
//!
//! All DSP operates in integer Q1.31-like `i32` stereo headroom (scaled to `[-32768..=32767]`
//! shifted left by 8 -> `[-8_388_608..=8_388_607]` nominal full scale, accumulated in `i64`
//! so mixing many streams never overflows before final clamping).

/// Supported PCM sample formats.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SampleFormat {
    /// Unsigned 8-bit PCM (0..=255, silence = 128).
    U8 = 1,
    /// Signed 16-bit little-endian PCM (native mixer & common hardware format).
    S16Le = 2,
    /// Signed 24-bit little-endian packed (3 bytes per sample).
    S24Le = 3,
    /// Signed 32-bit little-endian PCM (or 24-in-32 MSB-aligned).
    S32Le = 4,
    /// IEEE 754 32-bit float little-endian in `[-1.0, 1.0]`.
    F32Le = 5,
}

impl SampleFormat {
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::U8),
            2 => Some(Self::S16Le),
            3 => Some(Self::S24Le),
            4 => Some(Self::S32Le),
            5 => Some(Self::F32Le),
            _ => None,
        }
    }

    pub const fn bytes_per_sample(self) -> usize {
        match self {
            Self::U8 => 1,
            Self::S16Le => 2,
            Self::S24Le => 3,
            Self::S32Le | Self::F32Le => 4,
        }
    }

    pub const fn bits(self) -> u8 {
        (self.bytes_per_sample() * 8) as u8
    }
}

/// Stream parameters validated against safe limits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StreamParams {
    pub rate: u32,
    pub channels: u8,
    pub format: SampleFormat,
}

pub const MIN_RATE: u32 = 8_000;
pub const MAX_RATE: u32 = 192_000;
pub const MAX_CHANNELS: u8 = 8;

impl StreamParams {
    pub const fn stereo_48k_s16() -> Self {
        Self { rate: 48_000, channels: 2, format: SampleFormat::S16Le }
    }

    pub const fn valid(&self) -> bool {
        self.rate >= MIN_RATE
            && self.rate <= MAX_RATE
            && self.channels >= 1
            && self.channels <= MAX_CHANNELS
    }

    pub const fn frame_bytes(&self) -> usize {
        self.channels as usize * self.format.bytes_per_sample()
    }
}

/// Decode one sample from `src` into signed 24-bit range (`i32` in `[-8_388_608, 8_388_607]`).
#[inline]
pub fn decode_sample(fmt: SampleFormat, src: &[u8]) -> i32 {
    match fmt {
        SampleFormat::U8 => ((src[0] as i32) - 128) << 16,
        SampleFormat::S16Le => (i16::from_le_bytes([src[0], src[1]]) as i32) << 8,
        SampleFormat::S24Le => {
            (src[0] as i32) | ((src[1] as i32) << 8) | (((src[2] as i8) as i32) << 16)
        }
        SampleFormat::S32Le => i32::from_le_bytes([src[0], src[1], src[2], src[3]]) >> 8,
        SampleFormat::F32Le => {
            let f = f32::from_le_bytes([src[0], src[1], src[2], src[3]]);
            if !f.is_finite() {
                return 0;
            }
            let clamped = f.clamp(-1.0, 1.0);
            (clamped * 8_388_607.0) as i32
        }
    }
}

/// Encode one signed 24-bit range sample (`[-8_388_608, 8_388_607]`) into `dst`.
#[inline]
pub fn encode_sample(fmt: SampleFormat, s: i32, dst: &mut [u8]) {
    let s = s.clamp(-8_388_608, 8_388_607);
    match fmt {
        SampleFormat::U8 => {
            dst[0] = ((s >> 16) + 128).clamp(0, 255) as u8;
        }
        SampleFormat::S16Le => {
            let v = (s >> 8).clamp(i16::MIN as i32, i16::MAX as i32) as i16;
            dst[0..2].copy_from_slice(&v.to_le_bytes());
        }
        SampleFormat::S24Le => {
            dst[0] = (s & 0xFF) as u8;
            dst[1] = ((s >> 8) & 0xFF) as u8;
            dst[2] = ((s >> 16) & 0xFF) as u8;
        }
        SampleFormat::S32Le => {
            let v = s << 8;
            dst[0..4].copy_from_slice(&v.to_le_bytes());
        }
        SampleFormat::F32Le => {
            let f = (s as f32) / 8_388_608.0;
            dst[0..4].copy_from_slice(&f.to_le_bytes());
        }
    }
}

/// Decode one frame with arbitrary channels into a canonical stereo `[L, R]` pair (24-bit scale).
/// - 1 ch (mono): `[M, M]`
/// - 2 ch (stereo): `[L, R]`
/// - >= 3 ch: front L/R + center/surround folded gently so no channel is dropped silently.
#[inline]
pub fn decode_frame_stereo(params: StreamParams, frame: &[u8]) -> [i32; 2] {
    let bps = params.format.bytes_per_sample();
    let ch = params.channels as usize;
    if ch == 0 || frame.len() < ch * bps {
        return [0, 0];
    }
    match ch {
        1 => {
            let m = decode_sample(params.format, &frame[..bps]);
            [m, m]
        }
        2 => {
            let l = decode_sample(params.format, &frame[0..bps]);
            let r = decode_sample(params.format, &frame[bps..2 * bps]);
            [l, r]
        }
        _ => {
            let mut l = decode_sample(params.format, &frame[0..bps]) as i64;
            let mut r = decode_sample(params.format, &frame[bps..2 * bps]) as i64;
            if ch >= 3 {
                // Center channel mixed equally into L and R (-3 dB approx -> * 7 / 10).
                let c = decode_sample(params.format, &frame[2 * bps..3 * bps]) as i64;
                let c_mix = (c * 7) / 10;
                l += c_mix;
                r += c_mix;
            }
            // Additional surround pairs (skip LFE at index 3 for 6ch).
            let mut idx = if ch >= 6 { 4 } else { 3 };
            while idx + 1 < ch {
                l += decode_sample(params.format, &frame[idx * bps..(idx + 1) * bps]) as i64 / 2;
                r += decode_sample(params.format, &frame[(idx + 1) * bps..(idx + 2) * bps]) as i64 / 2;
                idx += 2;
            }
            [l.clamp(-8_388_608, 8_388_607) as i32, r.clamp(-8_388_608, 8_388_607) as i32]
        }
    }
}

/// Encode a canonical stereo `[L, R]` pair into a destination frame with `params.channels`.
#[inline]
pub fn encode_frame_from_stereo(params: StreamParams, lr: [i32; 2], dst: &mut [u8]) {
    let bps = params.format.bytes_per_sample();
    let ch = params.channels as usize;
    if ch == 0 || dst.len() < ch * bps {
        return;
    }
    match ch {
        1 => {
            let m = ((lr[0] as i64 + lr[1] as i64) / 2) as i32;
            encode_sample(params.format, m, &mut dst[..bps]);
        }
        2 => {
            encode_sample(params.format, lr[0], &mut dst[0..bps]);
            encode_sample(params.format, lr[1], &mut dst[bps..2 * bps]);
        }
        _ => {
            encode_sample(params.format, lr[0], &mut dst[0..bps]);
            encode_sample(params.format, lr[1], &mut dst[bps..2 * bps]);
            for c in 2..ch {
                encode_sample(params.format, 0, &mut dst[c * bps..(c + 1) * bps]);
            }
        }
    }
}

/// Volume (0..=100) + mute -> fixed-point Q16 gain (`0..=65536`).
/// Uses a mild quadratic-blended curve so 50% feels natural while 100% is exact unity (65536).
#[inline]
pub const fn volume_gain_q16(vol: u8, muted: bool) -> i64 {
    if muted || vol == 0 {
        return 0;
    }
    let v = if vol > 100 { 100 } else { vol } as i64;
    // Exact unity at 100, smooth curve below: (v * v * 65536) / 10000
    (v * v * 65536) / 10_000
}

/// Stateful stereo linear resampler (32.32 fixed-point phase accumulator).
/// Keeps the last input stereo frame so consecutive blocks stitch without discontinuities.
#[derive(Clone, Copy, Debug)]
pub struct Resampler {
    in_rate: u32,
    out_rate: u32,
    /// Fixed-point 32.32 fractional offset within the current input pair `[prev, next]`.
    phase: u64,
    prev: [i32; 2],
    has_prev: bool,
}

impl Resampler {
    pub const fn new(in_rate: u32, out_rate: u32) -> Self {
        Self { in_rate, out_rate, phase: 0, prev: [0, 0], has_prev: false }
    }

    pub fn reset(&mut self, in_rate: u32, out_rate: u32) {
        self.in_rate = in_rate;
        self.out_rate = out_rate;
        self.phase = 0;
        self.prev = [0, 0];
        self.has_prev = false;
    }

    /// Resample encoded input frames from `src` and accumulate into stereo `mix_acc` (`[L, R]` pairs,
    /// length `out_frames * 2`) with Q16 gain `gain_q16`.
    /// Returns `(input_frames_consumed, output_frames_mixed)`.
    pub fn mix_into(
        &mut self,
        src_params: StreamParams,
        src: &[u8],
        mix_acc: &mut [i64],
        gain_q16: i64,
    ) -> (usize, usize) {
        let fb = src_params.frame_bytes();
        let out_frames = mix_acc.len() / 2;
        if fb == 0 || out_frames == 0 || self.in_rate == 0 || self.out_rate == 0 {
            return (0, 0);
        }
        let in_frames = src.len() / fb;
        if in_frames == 0 {
            return (0, 0);
        }

        // Fast path: 1:1 sample rate (no interpolation overhead).
        if self.in_rate == self.out_rate {
            let n = in_frames.min(out_frames);
            for i in 0..n {
                let lr = decode_frame_stereo(src_params, &src[i * fb..(i + 1) * fb]);
                mix_acc[i * 2] += (lr[0] as i64 * gain_q16) >> 16;
                mix_acc[i * 2 + 1] += (lr[1] as i64 * gain_q16) >> 16;
            }
            self.prev = decode_frame_stereo(src_params, &src[(n - 1) * fb..n * fb]);
            self.has_prev = true;
            return (n, n);
        }

        // Step per output frame in 32.32 fixed-point.
        let step: u64 = ((self.in_rate as u64) << 32) / (self.out_rate as u64);
        let mut in_idx: usize = 0;
        let mut out_idx: usize = 0;

        if !self.has_prev {
            self.prev = decode_frame_stereo(src_params, &src[0..fb]);
            self.has_prev = true;
            in_idx = 1;
            self.phase = 0;
        }

        while out_idx < out_frames {
            // Advance input index for any whole integer frames in `phase`.
            let adv = (self.phase >> 32) as usize;
            if adv > 0 {
                if in_idx + adv > in_frames {
                    // Consume what remains and retain the leftover phase relative to the next call.
                    if in_idx < in_frames {
                        self.prev = decode_frame_stereo(src_params, &src[(in_frames - 1) * fb..in_frames * fb]);
                        let used = in_frames - in_idx;
                        self.phase -= (used as u64) << 32;
                        in_idx = in_frames;
                    }
                    break;
                }
                self.prev = decode_frame_stereo(src_params, &src[(in_idx + adv - 1) * fb..(in_idx + adv) * fb]);
                in_idx += adv;
                self.phase &= 0xFFFF_FFFF;
            }
            if in_idx >= in_frames {
                break;
            }
            let next = decode_frame_stereo(src_params, &src[in_idx * fb..(in_idx + 1) * fb]);
            let frac = (self.phase >> 16) as i64; // 0..=65535
            let inv = 65536 - frac;
            let l = ((self.prev[0] as i64 * inv) + (next[0] as i64 * frac)) >> 16;
            let r = ((self.prev[1] as i64 * inv) + (next[1] as i64 * frac)) >> 16;
            mix_acc[out_idx * 2] += (l * gain_q16) >> 16;
            mix_acc[out_idx * 2 + 1] += (r * gain_q16) >> 16;
            out_idx += 1;
            self.phase += step;
        }

        (in_idx, out_idx)
    }

    /// Resample stereo `src_lr` (already decoded 24-bit stereo frames) into encoded `dst` for capture.
    /// Returns `(input_frames_consumed, output_frames_written)`.
    pub fn convert_stereo_to_bytes(
        &mut self,
        src_lr: &[[i32; 2]],
        dst_params: StreamParams,
        dst: &mut [u8],
    ) -> (usize, usize) {
        let fb = dst_params.frame_bytes();
        if fb == 0 || src_lr.is_empty() || self.in_rate == 0 || self.out_rate == 0 {
            return (0, 0);
        }
        let out_cap = dst.len() / fb;
        if out_cap == 0 {
            return (0, 0);
        }
        if self.in_rate == self.out_rate {
            let n = src_lr.len().min(out_cap);
            for (i, &lr) in src_lr.iter().take(n).enumerate() {
                encode_frame_from_stereo(dst_params, lr, &mut dst[i * fb..(i + 1) * fb]);
            }
            self.prev = src_lr[n - 1];
            self.has_prev = true;
            return (n, n);
        }

        let step: u64 = ((self.in_rate as u64) << 32) / (self.out_rate as u64);
        let mut in_idx: usize = 0;
        let mut out_idx: usize = 0;
        if !self.has_prev {
            self.prev = src_lr[0];
            self.has_prev = true;
            in_idx = 1;
            self.phase = 0;
        }
        while out_idx < out_cap {
            let adv = (self.phase >> 32) as usize;
            if adv > 0 {
                if in_idx + adv > src_lr.len() {
                    if in_idx < src_lr.len() {
                        self.prev = src_lr[src_lr.len() - 1];
                        let used = src_lr.len() - in_idx;
                        self.phase -= (used as u64) << 32;
                        in_idx = src_lr.len();
                    }
                    break;
                }
                self.prev = src_lr[in_idx + adv - 1];
                in_idx += adv;
                self.phase &= 0xFFFF_FFFF;
            }
            if in_idx >= src_lr.len() {
                break;
            }
            let next = src_lr[in_idx];
            let frac = (self.phase >> 16) as i64;
            let inv = 65536 - frac;
            let l = (((self.prev[0] as i64 * inv) + (next[0] as i64 * frac)) >> 16) as i32;
            let r = (((self.prev[1] as i64 * inv) + (next[1] as i64 * frac)) >> 16) as i32;
            encode_frame_from_stereo(dst_params, [l, r], &mut dst[out_idx * fb..(out_idx + 1) * fb]);
            out_idx += 1;
            self.phase += step;
        }
        (in_idx, out_idx)
    }
}

/// Apply master volume/mute and encode a stereo `i64` mix accumulator into output device PCM bytes.
pub fn finalize_mix(mix_acc: &[i64], master_gain_q16: i64, dst_params: StreamParams, dst: &mut [u8]) -> usize {
    let fb = dst_params.frame_bytes();
    if fb == 0 {
        return 0;
    }
    let frames = (mix_acc.len() / 2).min(dst.len() / fb);
    for i in 0..frames {
        let l = ((mix_acc[i * 2] * master_gain_q16) >> 16).clamp(-8_388_608, 8_388_607) as i32;
        let r = ((mix_acc[i * 2 + 1] * master_gain_q16) >> 16).clamp(-8_388_608, 8_388_607) as i32;
        encode_frame_from_stereo(dst_params, [l, r], &mut dst[i * fb..(i + 1) * fb]);
    }
    frames * fb
}

/// 65-entry quarter-wave sine table (`sin(i * pi / 128) * 32767`, `i = 0..=64`).
const QUARTER_SINE: [i16; 65] = [
    0, 804, 1608, 2410, 3212, 4011, 4808, 5602,
    6393, 7179, 7962, 8739, 9512, 10278, 11039, 11793,
    12539, 13279, 14010, 14732, 15446, 16151, 16846, 17530,
    18204, 18868, 19519, 20159, 20787, 21403, 22005, 22594,
    23170, 23731, 24279, 24811, 25329, 25832, 26319, 26790,
    27245, 27683, 28105, 28510, 28898, 29268, 29621, 29956,
    30273, 30571, 30852, 31113, 31356, 31580, 31785, 31971,
    32137, 32285, 32412, 32521, 32609, 32678, 32728, 32757,
    32767,
];

/// Fixed-point sine generator (`no_std`, no libm needed) with linear table interpolation.
#[derive(Clone, Copy, Debug)]
pub struct ToneGen {
    phase: u32,
    step: u32,
    amp: i16,
}

impl ToneGen {
    /// Create a sine tone generator for `freq_hz` at `sample_rate` with peak amplitude `amp` (`0..=32767`).
    pub const fn new(freq_hz: u32, sample_rate: u32, amp: i16) -> Self {
        let step = if sample_rate == 0 {
            0
        } else {
            (((freq_hz as u64) << 32) / (sample_rate as u64)) as u32
        };
        Self { phase: 0, step, amp }
    }

    /// Generate the next `i16` sample.
    #[inline]
    pub fn next_i16(&mut self) -> i16 {
        let p = self.phase;
        self.phase = self.phase.wrapping_add(self.step);
        // Top 2 bits = quadrant, next 6 bits = table index (0..63), next 16 bits = interpolation frac.
        let quad = p >> 30;
        let idx = ((p >> 24) & 0x3F) as usize;
        let frac = ((p >> 8) & 0xFFFF) as i32;
        let (a, b) = match quad & 1 {
            0 => (QUARTER_SINE[idx] as i32, QUARTER_SINE[idx + 1] as i32),
            _ => (QUARTER_SINE[64 - idx] as i32, QUARTER_SINE[63 - idx] as i32),
        };
        let mut s = a + (((b - a) * frac) >> 16);
        if quad >= 2 {
            s = -s;
        }
        ((s * self.amp as i32) / 32767) as i16
    }

    /// Fill a PCM buffer (`params`) with `frames` frames of the generated tone.
    pub fn fill(&mut self, params: StreamParams, dst: &mut [u8]) -> usize {
        let fb = params.frame_bytes();
        if fb == 0 {
            return 0;
        }
        let frames = dst.len() / fb;
        for i in 0..frames {
            let s = (self.next_i16() as i32) << 8;
            encode_frame_from_stereo(params, [s, s], &mut dst[i * fb..(i + 1) * fb]);
        }
        frames * fb
    }
}
