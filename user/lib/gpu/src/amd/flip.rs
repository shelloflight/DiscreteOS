//! Tear-free DCN vsync page-flipping state machine, hardware cursor (HUBP + DPP),
//! OSSSYS IH ring vblank/flip interrupt controller, guarded mode-setting (OTG + DCCG DTO +
//! DP MSA + DSC 1.2), VRR (FreeSync), and HDR10 control.

use crate::amd::dp_aux::DpLinkState;
use crate::amd::dcn::{
    DCN_FMT_ARGB2101010, DCN_FMT_ARGB8888, DcnAccess, FbWindow, OtgTiming, RegIo, ScanoutLayout,
    decode_surface_addr, encode_surface_addr, frame_count_diff, read_frame_count,
};
use crate::edid::DetailedTiming;
use crate::{BufferAgeTracker, DamageRect, rd_u32};

// ---- DCN Register Bitfields (from AMD MIT `dcn_4_1_0_sh_mask.h`, `dcn10_hubp.c`, `dcn401_optc.c`) ---

const FLIP_TYPE_IMMEDIATE: u32 = 1 << 1;
const FLIP_PENDING_BIT: u32 = 1 << 8;

const FLIP_INT_MASK_BIT: u32 = 1 << 0;
const FLIP_INT_TYPE_PULSE: u32 = 1 << 1;
const FLIP_INT_CLEAR_BIT: u32 = 1 << 8;

const VINT0_INT_ENABLE: u32 = 1 << 8;
const VINT0_CLEAR: u32 = 1 << 20;
const VINT0_INT_TYPE_PULSE: u32 = 1 << 24;

// OSSSYS IH_RB_CNTL bit positions (identical across OSSSYS 5.0 / 6.0 / 7.0).
const IH_RB_ENABLE: u32 = 1 << 0;
const IH_RB_SIZE_SHIFT: u32 = 1;
const IH_WPTR_WRITEBACK_ENABLE: u32 = 1 << 8;
const IH_WPTR_OVERFLOW_ENABLE: u32 = 1 << 16;
const IH_ENABLE_INTR: u32 = 1 << 17;
const IH_MC_SNOOP: u32 = 1 << 20;
const IH_RPTR_REARM: u32 = 1 << 21;
const IH_MC_SPACE_SHIFT: u32 = 28;
const IH_MC_SPACE_BUS_ADDR: u32 = 2;
const IH_WPTR_OVERFLOW_CLEAR: u32 = 1 << 31;
const IH_CHICKEN_MC_SPACE_GPA_ENABLE: u32 = 1 << 4;

// NBIF BIF_BX0_INTERRUPT_CNTL bits (`nbif_v6_3_1.c`).
const NBIF_IH_DUMMY_RD_OVERRIDE: u32 = 1 << 0;
const NBIF_IH_REQ_NONSNOOP_EN: u32 = 1 << 3;

// SOC15 IH Client & DCN Source IDs (`soc15_ih_clientid.h`, `irqsrcs_dcn_1_0.h`).
pub const IH_CLIENTID_DCE: u8 = 0x04;
pub const DCN_SRCID_HPD1: u8 = 0x09;
pub const DCN_SRCID_OTG_VINT0_BASE: u8 = 0x1E; // 0x1E..=0x23 (pipes 0..5)
pub const DCN_SRCID_OTG_VSTARTUP_BASE: u8 = 0x3C; // 0x3C..=0x41 (pipes 0..5)
pub const DCN_SRCID_HUBP_FLIP_BASE: u8 = 0x4F; // 0x4F..=0x54 (pipes 0..5)
pub const IH_IV_BYTES: usize = 32;

// ---- Tear-Free Flip State Machine ---------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SelfCheckState {
    NotStarted,
    InProgress { target_mc: u64, start_frame: u32 },
    Verified,
    Failed(SelfCheckReason),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SelfCheckReason {
    InvalidAddress,
    NotLatchedWithin3Frames,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlipError {
    NotVerified,
    FlipInFlight,
    InvalidBuffer,
    BadAddress,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlipPoll {
    Idle,
    Pending,
    Completed { buf_idx: usize, frames: u64, late: bool },
}

/// Tear-free vsync flip controller for one DCN pipe.
///
/// Safety invariants:
/// - Never writes into a buffer that is currently on screen (`on_screen_buf`) or has a flip
///   in flight (`pending_buf`).
/// - Always writes `PRIMARY_SURFACE_ADDRESS_HIGH` before `PRIMARY_SURFACE_ADDRESS` with
///   `SURFACE_FLIP_TYPE = 0` (vsync), verifying latch via both `SURFACE_FLIP_PENDING == 0`
///   and `SURFACE_EARLIEST_INUSE`.
/// - Runs a 3-frame self-check showing an identical copy of the live screen before enabling
///   native presentation; restores `orig_mc_addr` immediately on failure, session end, or crash recovery.
#[derive(Clone, Copy, Debug)]
pub struct FlipEngine {
    pub pipe: u8,
    pub fb_win: FbWindow,
    pub layout: ScanoutLayout,
    pub orig_mc_addr: u64,
    pub width: u32,
    pub height: u32,
    pub refresh_mhz: u32,
    pub age: BufferAgeTracker,
    pub self_check: SelfCheckState,
    pub on_screen_buf: Option<usize>,
    pub pending_buf: Option<usize>,
    pub pending_mc: u64,
    pub pending_issue_frame: u32,
    pub pending_issue_ns: u64,
    pub last_flip_ns: u64,
    pub flips_completed: u64,
    pub late_flips: u64,
    pub missed_flips: u64,
}

impl FlipEngine {
    pub fn new(
        pipe: u8,
        fb_win: FbWindow,
        layout: ScanoutLayout,
        orig_mc_addr: u64,
        width: u32,
        height: u32,
        refresh_mhz: u32,
    ) -> Self {
        Self {
            pipe,
            fb_win,
            layout,
            orig_mc_addr,
            width,
            height,
            refresh_mhz: refresh_mhz.clamp(24_000, 1_000_000),
            age: BufferAgeTracker::new(layout.buf_count, width, height),
            self_check: SelfCheckState::NotStarted,
            on_screen_buf: None,
            pending_buf: None,
            pending_mc: 0,
            pending_issue_frame: 0,
            pending_issue_ns: 0,
            last_flip_ns: 0,
            flips_completed: 0,
            late_flips: 0,
            missed_flips: 0,
        }
    }

    pub const fn is_verified(&self) -> bool {
        matches!(self.self_check, SelfCheckState::Verified)
    }

    /// Translate scanout buffer index `buf_idx` into its GPU MC address.
    pub const fn buffer_mc(&self, buf_idx: usize) -> Option<u64> {
        if buf_idx >= self.layout.buf_count {
            return None;
        }
        self.fb_win.vram_to_mc(self.layout.buffers[buf_idx])
    }

    /// Read live `(flip_pending, earliest_inuse_mc)` from HUBPREQ registers.
    pub fn read_hw_status<I: RegIo>(&self, io: &I, dcn: &DcnAccess) -> (bool, u64) {
        let r = dcn.regs;
        let ctl = dcn.r_dcn(io, r.hubp_flip_control(self.pipe)).unwrap_or(0);
        let lo = dcn.r_dcn(io, r.hubp_earliest_inuse(self.pipe)).unwrap_or(0);
        let hi = dcn.r_dcn(io, r.hubp_earliest_inuse_hi(self.pipe)).unwrap_or(0);
        ((ctl & FLIP_PENDING_BIT) != 0, decode_surface_addr(lo, hi))
    }

    /// Low-level vsync surface address write (`SURFACE_FLIP_TYPE = 0`, HIGH then LOW).
    fn write_vsync_addr<I: RegIo>(&self, io: &mut I, dcn: &DcnAccess, mc_addr: u64) {
        let r = dcn.regs;
        let ctl_reg = r.hubp_flip_control(self.pipe);
        let ctl = dcn.r_dcn(io, ctl_reg).unwrap_or(0);
        if (ctl & FLIP_TYPE_IMMEDIATE) != 0 {
            dcn.w_dcn(io, ctl_reg, ctl & !FLIP_TYPE_IMMEDIATE);
        }
        let (lo, hi) = encode_surface_addr(mc_addr);
        // Hardware latches on the LOW write — HIGH must always be written first.
        dcn.w_dcn(io, r.hubp_primary_addr_hi(self.pipe), hi);
        dcn.w_dcn(io, r.hubp_primary_addr(self.pipe), lo);
    }

    /// Detect if a prior crashed driver left one of our own scanout buffers on screen;
    /// if so, restore the original firmware GOP address immediately and return `true`.
    pub fn recover_if_crashed_own_buffer<I: RegIo>(&mut self, io: &mut I, dcn: &DcnAccess) -> bool {
        let (_, earliest) = self.read_hw_status(io, dcn);
        if let Some(vram_off) = self.fb_win.mc_to_vram(earliest)
            && self.layout.is_own_scanout_buffer(vram_off)
        {
            self.restore_original(io, dcn);
            return true;
        }
        false
    }

    /// Restore the original firmware GOP framebuffer scanout address (session end / stop / failure).
    pub fn restore_original<I: RegIo>(&mut self, io: &mut I, dcn: &DcnAccess) {
        if self.orig_mc_addr != 0 {
            self.write_vsync_addr(io, dcn, self.orig_mc_addr);
        }
        self.on_screen_buf = None;
        self.pending_buf = None;
        self.pending_mc = 0;
        self.age.mark_all_dirty();
    }

    /// Begin the pre-use self-check: caller has copied the live GOP screen verbatim into buffer 0,
    /// so flipping to buffer 0 produces zero visible change. Must latch within 3 frames.
    pub fn self_check_start<I: RegIo>(&mut self, io: &mut I, dcn: &DcnAccess) -> SelfCheckState {
        let Some(mc0) = self.buffer_mc(0) else {
            self.self_check = SelfCheckState::Failed(SelfCheckReason::InvalidAddress);
            return self.self_check;
        };
        let start_frame = read_frame_count(io, dcn, self.pipe);
        self.write_vsync_addr(io, dcn, mc0);
        self.self_check = SelfCheckState::InProgress { target_mc: mc0, start_frame };
        self.self_check
    }

    /// Advance the pre-use self-check state machine. Reverts to `orig_mc_addr` automatically if
    /// `SURFACE_EARLIEST_INUSE` does not latch within 3 frames.
    pub fn self_check_poll<I: RegIo>(&mut self, io: &mut I, dcn: &DcnAccess) -> SelfCheckState {
        let SelfCheckState::InProgress { target_mc, start_frame } = self.self_check else {
            return self.self_check;
        };
        let (pending, earliest) = self.read_hw_status(io, dcn);
        if !pending && earliest == target_mc {
            self.on_screen_buf = Some(0);
            self.pending_buf = None;
            self.pending_mc = 0;
            self.age.mark_all_dirty();
            self.self_check = SelfCheckState::Verified;
            return self.self_check;
        }
        let now_frame = read_frame_count(io, dcn, self.pipe);
        if frame_count_diff(now_frame, start_frame) >= 3 {
            self.restore_original(io, dcn);
            self.self_check = SelfCheckState::Failed(SelfCheckReason::NotLatchedWithin3Frames);
        }
        self.self_check
    }

    /// Poll hardware registers to see if an in-flight vsync flip has latched on screen.
    pub fn poll_flip_complete<I: RegIo>(&mut self, io: &I, dcn: &DcnAccess, now_ns: u64) -> FlipPoll {
        let Some(pbuf) = self.pending_buf else {
            return FlipPoll::Idle;
        };
        let (pending, earliest) = self.read_hw_status(io, dcn);
        if !pending && earliest == self.pending_mc {
            self.on_screen_buf = Some(pbuf);
            self.pending_buf = None;
            self.pending_mc = 0;
            self.flips_completed = self.flips_completed.saturating_add(1);
            let now_frame = read_frame_count(io, dcn, self.pipe);
            let df = frame_count_diff(now_frame, self.pending_issue_frame);
            let interval = self.frame_interval_ns();
            let late = df > 1 || (self.last_flip_ns > 0 && now_ns.saturating_sub(self.last_flip_ns) > (interval * 3) / 2);
            if late {
                self.late_flips = self.late_flips.saturating_add(1);
            }
            if df > 1 {
                self.missed_flips = self.missed_flips.saturating_add(u64::from(df - 1));
            }
            self.last_flip_ns = now_ns;
            FlipPoll::Completed { buf_idx: pbuf, frames: self.flips_completed, late }
        } else {
            FlipPoll::Pending
        }
    }

    /// Select a safe idle buffer to draw the next frame into.
    /// Guarantees the returned buffer is NEITHER on screen (`on_screen_buf` / `EARLIEST_INUSE`)
    /// NOR pending (`pending_buf` / `SURFACE_FLIP_PENDING`).
    pub fn pick_draw_buffer<I: RegIo>(&mut self, io: &I, dcn: &DcnAccess, now_ns: u64) -> Result<usize, FlipError> {
        if !self.is_verified() {
            return Err(FlipError::NotVerified);
        }
        // Reap any completed flip first.
        let _ = self.poll_flip_complete(io, dcn, now_ns);
        let (hw_pending, earliest) = self.read_hw_status(io, dcn);
        if self.pending_buf.is_some() || hw_pending {
            // Never queue a second overlapping flip while one is in flight (keeps strict vsync pacing).
            return Err(FlipError::FlipInFlight);
        }
        // Pick the next buffer in round-robin order that is neither `on_screen_buf` nor `earliest`.
        let start = self.on_screen_buf.map_or(0, |b| (b + 1) % self.layout.buf_count);
        for step in 0..self.layout.buf_count {
            let cand = (start + step) % self.layout.buf_count;
            if self.on_screen_buf == Some(cand) || self.pending_buf == Some(cand) {
                continue;
            }
            if let Some(mc) = self.buffer_mc(cand)
                && mc != earliest
            {
                return Ok(cand);
            }
        }
        Err(FlipError::FlipInFlight)
    }

    /// Compute the buffer-age damage rectangles needed for `buf_idx` given `current_damage`.
    pub fn damage_for_buffer(&self, buf_idx: usize, current_damage: &[DamageRect], out: &mut [DamageRect]) -> usize {
        self.age.collect_for_buffer(buf_idx, current_damage, out)
    }

    /// Submit a vsync flip to `buf_idx` after the caller has finished writing damage pixels + Release fence.
    pub fn commit_vsync_flip<I: RegIo>(
        &mut self,
        io: &mut I,
        dcn: &DcnAccess,
        buf_idx: usize,
        current_damage: &[DamageRect],
        now_ns: u64,
    ) -> Result<(), FlipError> {
        if !self.is_verified() {
            return Err(FlipError::NotVerified);
        }
        if buf_idx >= self.layout.buf_count || self.on_screen_buf == Some(buf_idx) || self.pending_buf.is_some() {
            return Err(FlipError::InvalidBuffer);
        }
        let mc = self.buffer_mc(buf_idx).ok_or(FlipError::BadAddress)?;
        self.age.commit_buffer(buf_idx, current_damage);
        self.pending_buf = Some(buf_idx);
        self.pending_mc = mc;
        self.pending_issue_frame = read_frame_count(io, dcn, self.pipe);
        self.pending_issue_ns = now_ns;
        self.write_vsync_addr(io, dcn, mc);
        Ok(())
    }

    /// Nominal frame interval in nanoseconds (`1e12 / refresh_mhz`).
    pub const fn frame_interval_ns(&self) -> u64 {
        1_000_000_000_000u64 / (self.refresh_mhz as u64)
    }

    /// Estimate nanoseconds remaining until the next vblank start from `OTG_STATUS_POSITION`.
    /// Used for high-resolution timer sleeps before/without IH interrupts.
    pub fn ns_until_vblank<I: RegIo>(&self, io: &I, dcn: &DcnAccess, timing: &OtgTiming) -> u64 {
        let interval = self.frame_interval_ns();
        if timing.v_total == 0 {
            return interval / 2;
        }
        let pos = dcn.r_dcn(io, dcn.regs.otg_status_position(self.pipe)).unwrap_or(0);
        let vert = pos & 0x7FFF;
        let target = timing.v_blank_start.min(timing.v_total.saturating_sub(1));
        let lines_left = if vert < target {
            target - vert
        } else {
            // Already inside vblank or past target: wrap to next frame's vblank start.
            timing.v_total.saturating_sub(vert).saturating_add(target)
        };
        let ns = (u128::from(lines_left) * u128::from(interval) / u128::from(timing.v_total)) as u64;
        // Clamp to a practical [100 us .. frame_interval] sleep window.
        ns.clamp(100_000, interval)
    }
}

// ---- Hardware Cursor Controller (HUBP + DPP CNVC/CM_CUR) ----------------------------------------

/// Cursor colour format codes (`enum dc_cursor_color_format` in AMD DC `dcn401_dpp_cm.c`).
pub const CURSOR_MODE_ARGB_PREMUL: u32 = 2;
pub const CURSOR_MODE_ARGB_UNPREMUL: u32 = 3;

/// Supported square hardware cursor sizes (64x64 or 256x256 ARGB8888).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CursorSize {
    Px64,
    Px256,
}

impl CursorSize {
    pub const fn pixels(self) -> u32 {
        match self {
            Self::Px64 => 64,
            Self::Px256 => 256,
        }
    }

    const fn hw_pitch_code(self) -> u32 {
        match self {
            Self::Px64 => 0,  // CURSOR_PITCH_64_PIXELS
            Self::Px256 => 2, // CURSOR_PITCH_256_PIXELS
        }
    }

    const fn lines_per_chunk(self) -> u32 {
        match self {
            Self::Px64 => 3,  // 8 lines per chunk
            Self::Px256 => 1, // 2 lines per chunk
        }
    }
}

/// Hardware cursor state for one DCN pipe (HUBP `CURSOR0_n_*` + DPP `CM_CUR/CNVC_CUR`).
#[derive(Clone, Copy, Debug, Default)]
pub struct HwCursor {
    pub pipe: u8,
    pub mc_addr: u64,
    pub size_px: u32,
    pub hot_x: u32,
    pub hot_y: u32,
    pub x: i32,
    pub y: i32,
    pub enabled: bool,
    pub premultiplied: bool,
}

impl HwCursor {
    pub const fn new(pipe: u8) -> Self {
        Self {
            pipe,
            mc_addr: 0,
            size_px: 64,
            hot_x: 0,
            hot_y: 0,
            x: 0,
            y: 0,
            enabled: false,
            premultiplied: false,
        }
    }

    /// Program HUBP + DPP cursor registers to display the ARGB8888 cursor buffer at `mc_addr`.
    #[allow(clippy::too_many_arguments)]
    pub fn configure<I: RegIo>(
        &mut self,
        io: &mut I,
        dcn: &DcnAccess,
        mc_addr: u64,
        size: CursorSize,
        hot_x: u32,
        hot_y: u32,
        premultiplied: bool,
        screen_w: u32,
        screen_h: u32,
    ) {
        let r = dcn.regs;
        let px = size.pixels();
        self.mc_addr = mc_addr;
        self.size_px = px;
        self.hot_x = hot_x.min(px - 1);
        self.hot_y = hot_y.min(px - 1);
        self.premultiplied = premultiplied;
        self.enabled = true;

        let mode = if premultiplied { CURSOR_MODE_ARGB_PREMUL } else { CURSOR_MODE_ARGB_UNPREMUL };
        let (lo, hi) = encode_surface_addr(mc_addr);

        // HUBP cursor address (HIGH then LOW) and dimensions (`size - 1` encoding in DCN).
        dcn.w_dcn(io, r.cursor_addr_hi(self.pipe), hi);
        dcn.w_dcn(io, r.cursor_addr(self.pipe), lo);
        dcn.w_dcn(io, r.cursor_size(self.pipe), ((px - 1) << 16) | (px - 1));
        dcn.w_dcn(io, r.cursor_hot_spot(self.pipe), (self.hot_x << 16) | self.hot_y);

        // HUBPREQ cursor settings: DST_Y_OFFSET=0, CHUNK_HDL_ADJUST=3 (`dcn10_hubp.c`).
        dcn.w_dcn(io, r.hubp_cursor_settings(self.pipe), 3 << 8);

        // HUBP CURSOR_CONTROL: ENABLE=1, MODE, PITCH, LINES_PER_CHUNK.
        let hubp_cur_ctl = 1u32
            | (mode << 8)
            | (size.hw_pitch_code() << 16)
            | (size.lines_per_chunk() << 24);
        dcn.w_dcn(io, r.cursor_control(self.pipe), hubp_cur_ctl);

        // DPP CM_CUR/CNVC_CUR: CUR0_ENABLE=1 (bit 0), CUR0_MODE (bits 6:4).
        let dpp_cur_ctl = 1u32 | ((mode & 0x7) << 4);
        dcn.w_dcn(io, r.dpp_cursor_control(self.pipe), dpp_cur_ctl);

        // Position immediately.
        self.move_pos(io, dcn, self.x, self.y, screen_w, screen_h);
    }

    /// Immediately move the hardware cursor to `(x, y)` without touching scanout buffers.
    /// Note: `CURSOR_X_POSITION` starts at bit 15 (`0xF`), `CURSOR_Y_POSITION` at bit 0.
    pub fn move_pos<I: RegIo>(&mut self, io: &mut I, dcn: &DcnAccess, x: i32, y: i32, screen_w: u32, screen_h: u32) {
        self.x = x;
        self.y = y;
        if !self.enabled {
            return;
        }
        let r = dcn.regs;
        let visible = x < screen_w as i32
            && y < screen_h as i32
            && x + (self.size_px as i32) > 0
            && y + (self.size_px as i32) > 0;
        let mode = if self.premultiplied { CURSOR_MODE_ARGB_PREMUL } else { CURSOR_MODE_ARGB_UNPREMUL };
        if !visible {
            dcn.w_dcn(io, r.dpp_cursor_control(self.pipe), (mode & 0x7) << 4);
            return;
        }
        let cx = x.max(0) as u32;
        let cy = y.max(0) as u32;
        let hx = if x < 0 { self.hot_x.saturating_add((-x) as u32).min(self.size_px - 1) } else { self.hot_x };
        let hy = if y < 0 { self.hot_y.saturating_add((-y) as u32).min(self.size_px - 1) } else { self.hot_y };

        // CURSOR_POSITION: X at bits [29:15], Y at bits [14:0].
        let pos_reg = ((cx & 0x7FFF) << 15) | (cy & 0x7FFF);
        dcn.w_dcn(io, r.cursor_hot_spot(self.pipe), ((hx & 0x3FFF) << 16) | (hy & 0x3FFF));
        dcn.w_dcn(io, r.cursor_dst_offset(self.pipe), 0);
        dcn.w_dcn(io, r.cursor_position(self.pipe), pos_reg);
        dcn.w_dcn(io, r.dpp_cursor_control(self.pipe), 1u32 | ((mode & 0x7) << 4));
    }

    /// Disable the hardware cursor cleanly on both HUBP and DPP.
    pub fn disable<I: RegIo>(&mut self, io: &mut I, dcn: &DcnAccess) {
        let r = dcn.regs;
        self.enabled = false;
        dcn.w_dcn(io, r.cursor_control(self.pipe), 0);
        dcn.w_dcn(io, r.dpp_cursor_control(self.pipe), 0);
    }
}

// ---- OSSSYS Interrupt Handler (IH) Ring & DCN Vblank/Flip IRQs ----------------------------------

/// Decoded DCN interrupt event from one 32-byte OSSSYS IH ring IV entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IhEvent {
    FlipDone { pipe: u8, timestamp: u64 },
    Vblank { pipe: u8, timestamp: u64 },
    Hpd { idx: u8 },
    Other { client_id: u8, src_id: u8 },
}

/// Decode one 32-byte little-endian OSSSYS IV ring entry (`amdgpu_ih.c`).
pub fn decode_iv(entry: &[u8]) -> Option<IhEvent> {
    if entry.len() < IH_IV_BYTES {
        return None;
    }
    let dw0 = rd_u32(entry, 0)?;
    let dw1 = rd_u32(entry, 4)?;
    let dw2 = rd_u32(entry, 8)?;
    let client_id = (dw0 & 0xFF) as u8;
    let src_id = ((dw0 >> 8) & 0xFF) as u8;
    let timestamp = u64::from(dw1) | (u64::from(dw2 & 0xFFFF) << 32);

    if client_id == IH_CLIENTID_DCE {
        if (DCN_SRCID_HUBP_FLIP_BASE..DCN_SRCID_HUBP_FLIP_BASE + 6).contains(&src_id) {
            return Some(IhEvent::FlipDone { pipe: src_id - DCN_SRCID_HUBP_FLIP_BASE, timestamp });
        }
        if (DCN_SRCID_OTG_VINT0_BASE..DCN_SRCID_OTG_VINT0_BASE + 6).contains(&src_id) {
            return Some(IhEvent::Vblank { pipe: src_id - DCN_SRCID_OTG_VINT0_BASE, timestamp });
        }
        if (DCN_SRCID_OTG_VSTARTUP_BASE..DCN_SRCID_OTG_VSTARTUP_BASE + 6).contains(&src_id) {
            return Some(IhEvent::Vblank { pipe: src_id - DCN_SRCID_OTG_VSTARTUP_BASE, timestamp });
        }
        if src_id == DCN_SRCID_HPD1 {
            let src_data0 = rd_u32(entry, 16).unwrap_or(0);
            return Some(IhEvent::Hpd { idx: (src_data0 & 0x0F) as u8 });
        }
    }
    Some(IhEvent::Other { client_id, src_id })
}

/// Controller for OSSSYS 5.0/6.0/7.0 IH ring DMA + DCN vblank/flip interrupts (no firmware required).
#[derive(Clone, Copy, Debug)]
pub struct IhController {
    pub ring_size: usize,
    pub rptr: u32,
    pub active: bool,
    pub iv_count: u64,
    pub overflows: u64,
}

impl IhController {
    pub const fn new(ring_size: usize) -> Self {
        Self { ring_size, rptr: 0, active: false, iv_count: 0, overflows: 0 }
    }

    /// Initialize OSSSYS IH ring in DMA system memory (`ring_iova`, `wptr_iova`, `dummy_iova`)
    /// and enable MSI/MSI-X delivery via NBIF. Ring size must be power-of-two >= 4096.
    pub fn enable<I: RegIo>(
        &mut self,
        io: &mut I,
        dcn: &DcnAccess,
        ring_iova: u64,
        wptr_iova: u64,
        dummy_iova: u64,
    ) -> bool {
        if !self.ring_size.is_power_of_two() || self.ring_size < 4096 || dcn.osssys.is_none() {
            return false;
        }
        let ih = dcn.regs.ih_regs();

        // Configure NBIF interrupt control for snooped system RAM IH ring (`nbif_v6_3_1.c`).
        if dcn.nbif.is_some() {
            dcn.w_nbif(io, dcn.regs.nbif_interrupt_cntl2(), (dummy_iova >> 8) as u32);
            let mut ic = dcn.r_nbif(io, dcn.regs.nbif_interrupt_cntl()).unwrap_or(0);
            ic &= !(NBIF_IH_DUMMY_RD_OVERRIDE | NBIF_IH_REQ_NONSNOOP_EN);
            dcn.w_nbif(io, dcn.regs.nbif_interrupt_cntl(), ic);
        }

        // Disable IH ring cleanly before reprogramming base/pointers.
        let mut cntl = dcn.r_ih(io, ih.rb_cntl).unwrap_or(0);
        cntl &= !(IH_RB_ENABLE | IH_ENABLE_INTR);
        dcn.w_ih(io, ih.rb_cntl, cntl);

        // Allow GPA/IOVA bus addressing when `MC_SPACE = 2` (`ih_v7_0.c`).
        let chicken = dcn.r_ih(io, ih.ih_chicken).unwrap_or(0);
        dcn.w_ih(io, ih.ih_chicken, chicken | IH_CHICKEN_MC_SPACE_GPA_ENABLE);

        // Program ring base (256-byte shifted), WPTR writeback address, and reset RPTR/WPTR.
        dcn.w_ih(io, ih.rb_base, (ring_iova >> 8) as u32);
        dcn.w_ih(io, ih.rb_base_hi, ((ring_iova >> 40) & 0xFF) as u32);
        dcn.w_ih(io, ih.rb_wptr_addr_lo, wptr_iova as u32);
        dcn.w_ih(io, ih.rb_wptr_addr_hi, ((wptr_iova >> 32) & 0xFFFF) as u32);
        dcn.w_ih(io, ih.rb_rptr, 0);
        dcn.w_ih(io, ih.rb_wptr, 0);
        self.rptr = 0;

        // `RB_SIZE` = log2(ring_size / 4) dwords (`ih_v7_0.c`).
        let rb_bufsz = (self.ring_size / 4).trailing_zeros();
        let rb_cntl = IH_RB_ENABLE
            | ((rb_bufsz & 0x1F) << IH_RB_SIZE_SHIFT)
            | IH_WPTR_WRITEBACK_ENABLE
            | IH_WPTR_OVERFLOW_ENABLE
            | IH_ENABLE_INTR
            | IH_MC_SNOOP
            | IH_RPTR_REARM
            | (IH_MC_SPACE_BUS_ADDR << IH_MC_SPACE_SHIFT);
        dcn.w_ih(io, ih.rb_cntl, rb_cntl);
        self.active = true;
        true
    }

    /// Enable DCN pipe vertical-blank (`VERTICAL_INTERRUPT0` at `v_blank_start`) and HUBP flip interrupts.
    pub fn enable_pipe_irqs<I: RegIo>(&self, io: &mut I, dcn: &DcnAccess, pipe: u8, v_blank_start: u32) {
        let r = dcn.regs;
        // OTG vertical interrupt 0 at `v_blank_start`.
        let line = v_blank_start & 0x7FFF;
        dcn.w_dcn(io, r.otg_vert_int0_pos(pipe), line | (line << 16));
        dcn.w_dcn(io, r.otg_vert_int0_ctrl(pipe), VINT0_INT_ENABLE | VINT0_CLEAR | VINT0_INT_TYPE_PULSE);

        // HUBP surface flip interrupt (pulse mode, unmasked).
        dcn.w_dcn(
            io,
            r.hubp_flip_interrupt(pipe),
            FLIP_INT_MASK_BIT | FLIP_INT_TYPE_PULSE | FLIP_INT_CLEAR_BIT,
        );
    }

    /// Mask DCN pipe vblank and flip interrupts.
    pub fn disable_pipe_irqs<I: RegIo>(&self, io: &mut I, dcn: &DcnAccess, pipe: u8) {
        let r = dcn.regs;
        dcn.w_dcn(io, r.otg_vert_int0_ctrl(pipe), VINT0_CLEAR);
        dcn.w_dcn(io, r.hubp_flip_interrupt(pipe), FLIP_INT_CLEAR_BIT);
    }

    /// Drain all pending 32-byte IV entries from `ring_bytes` up to `wptr_wb` (or register WPTR),
    /// calling `on_event` for each decoded entry, clearing overflow if flagged, and updating `IH_RB_RPTR`.
    pub fn drain<I: RegIo, F: FnMut(IhEvent)>(
        &mut self,
        io: &mut I,
        dcn: &DcnAccess,
        ring_bytes: &[u8],
        wptr_wb: Option<u32>,
        mut on_event: F,
    ) -> usize {
        if !self.active || ring_bytes.len() < self.ring_size {
            return 0;
        }
        let ih = dcn.regs.ih_regs();
        let mask = (self.ring_size - 1) as u32;
        let raw_wptr = wptr_wb.unwrap_or_else(|| dcn.r_ih(io, ih.rb_wptr).unwrap_or(self.rptr));

        // Handle IH overflow bit (bit 31): acknowledge via `WPTR_OVERFLOW_CLEAR`.
        if (raw_wptr & IH_WPTR_OVERFLOW_CLEAR) != 0 {
            self.overflows = self.overflows.saturating_add(1);
            let cntl = dcn.r_ih(io, ih.rb_cntl).unwrap_or(0);
            dcn.w_ih(io, ih.rb_cntl, cntl | IH_WPTR_OVERFLOW_CLEAR);
            dcn.w_ih(io, ih.rb_cntl, cntl & !IH_WPTR_OVERFLOW_CLEAR);
        }

        let wptr = raw_wptr & mask & !31;
        let mut rptr = self.rptr & mask & !31;
        let mut count = 0usize;
        let max_ivs = self.ring_size / IH_IV_BYTES;

        while rptr != wptr && count < max_ivs {
            let off = rptr as usize;
            if let Some(ev) = decode_iv(&ring_bytes[off..off + IH_IV_BYTES]) {
                on_event(ev);
            }
            rptr = (rptr + IH_IV_BYTES as u32) & mask;
            count += 1;
        }

        if count > 0 || (raw_wptr & IH_WPTR_OVERFLOW_CLEAR) != 0 {
            self.rptr = rptr;
            self.iv_count = self.iv_count.saturating_add(count as u64);
            dcn.w_ih(io, ih.rb_rptr, rptr);
        }
        count
    }

    /// Cleanly disable OSSSYS IH ring delivery on driver teardown.
    pub fn disable<I: RegIo>(&mut self, io: &mut I, dcn: &DcnAccess) {
        if !self.active {
            return;
        }
        let ih = dcn.regs.ih_regs();
        let cntl = dcn.r_ih(io, ih.rb_cntl).unwrap_or(0);
        dcn.w_ih(io, ih.rb_cntl, cntl & !(IH_RB_ENABLE | IH_ENABLE_INTR));
        self.active = false;
    }
}

// ---- Mode Setting (OTG + DCCG DP DTO + DP MSA + DSC 1.2) + VRR + HDR10 --------------------------

/// Decision on how a requested mode fits over the DisplayPort link.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModeBandwidthPlan {
    /// Fits within the link the firmware already trained, uncompressed (lowest risk).
    FitsCurrentLink,
    /// Fits within the current link using DSC 1.2 at `target_bpp` bits/pixel.
    NeedsDscOnCurrentLink { target_bpp: u8 },
    /// Requires DP link retraining to `(lanes, rate_code, is_uhbr)` and optional DSC.
    NeedsRetrain { lanes: u8, rate_code: u8, is_uhbr: bool, use_dsc: bool, target_bpp: u8 },
    /// Exceeds even the monitor's maximum link + DSC capacity.
    ExceedsSinkCapacity,
}

/// Evaluate whether `timing` at `bpc` (8 or 10) fits the current DP link, needs DSC, or needs retraining.
pub fn plan_mode_bandwidth(link: &DpLinkState, timing: &DetailedTiming, bpc: u8) -> ModeBandwidthPlan {
    if link.fits_active_uncompressed(timing, bpc) {
        return ModeBandwidthPlan::FitsCurrentLink;
    }
    if link.fits_active_with_dsc(timing, 8) {
        return ModeBandwidthPlan::NeedsDscOnCurrentLink { target_bpp: 8 };
    }
    // Try max sink capabilities (prefer UHBR on DP 2.1 monitors, then HBR3, then DSC).
    let max_lanes = link.max_lanes.clamp(1, 4);
    let candidates: [(u8, u32, bool); 5] = [
        (0x1E, 8_100, false),  // HBR3
        (0x01, 10_000, true),  // UHBR10
        (0x04, 13_500, true),  // UHBR13.5
        (0x02, 20_000, true),  // UHBR20
        (0x14, 5_400, false),  // HBR2
    ];
    let raw_req = timing.raw_bandwidth_kbps(bpc);
    let dsc_req = (timing.pixel_clock_khz as u64).saturating_mul(8);

    // First try uncompressed at a supported sink rate.
    for &(code, mbps, uhbr) in &candidates {
        if mbps > link.max_link_rate_mbps {
            continue;
        }
        let eff = if uhbr {
            u64::from(mbps) * 1000 * u64::from(max_lanes) * 963 / 1000
        } else {
            u64::from(mbps) * 1000 * u64::from(max_lanes) * 800 / 1000
        };
        if raw_req <= eff {
            return ModeBandwidthPlan::NeedsRetrain {
                lanes: max_lanes,
                rate_code: code,
                is_uhbr: uhbr,
                use_dsc: false,
                target_bpp: bpc * 3,
            };
        }
    }
    // Next try DSC 1.2 at 8 bpp (standard for 1440p@540 Hz / 4K@240 Hz).
    if link.dsc_supported {
        for &(code, mbps, uhbr) in &candidates {
            if mbps > link.max_link_rate_mbps {
                continue;
            }
            let eff = if uhbr {
                u64::from(mbps) * 1000 * u64::from(max_lanes) * 963 / 1000
            } else {
                u64::from(mbps) * 1000 * u64::from(max_lanes) * 800 / 1000
            };
            if dsc_req <= eff {
                return ModeBandwidthPlan::NeedsRetrain {
                    lanes: max_lanes,
                    rate_code: code,
                    is_uhbr: uhbr,
                    use_dsc: true,
                    target_bpp: 8,
                };
            }
        }
    }
    ModeBandwidthPlan::ExceedsSinkCapacity
}

/// Encode a VESA DSC 1.2 Picture Parameter Set (128 bytes) for RGB 4:4:4 at `target_bpp` (8..=12 bpp).
pub fn encode_dsc_1_2_pps(width: u32, height: u32, bpc: u8, target_bpp: u8, slices: u8) -> [u8; 128] {
    let mut pps = [0u8; 128];
    let slice_cnt = u32::from(slices.clamp(1, 4));
    let slice_w = width.div_ceil(slice_cnt).max(16);
    let slice_h = if height.is_multiple_of(8) { height / 8 } else { 108 }.max(8);
    let bpp_x16 = u16::from(target_bpp.clamp(8, 16)) * 16;
    let chunk_size = ((slice_w * u32::from(bpp_x16)).div_ceil(16 * 8)) as u16;

    pps[0] = 0x12; // DSC v1.2
    pps[1] = 0x00; // PPS identifier
    pps[3] = ((bpc & 0x0F) << 4) | 0x09; // bpc | linebuf_depth=9
    pps[4] = (1 << 5) | (1 << 4) | ((bpp_x16 >> 8) as u8 & 0x03); // block_pred_enable | convert_rgb | bpp[9:8]
    pps[5] = (bpp_x16 & 0xFF) as u8;
    pps[6..8].copy_from_slice(&(height as u16).to_be_bytes());
    pps[8..10].copy_from_slice(&(width as u16).to_be_bytes());
    pps[10..12].copy_from_slice(&(slice_h as u16).to_be_bytes());
    pps[12..14].copy_from_slice(&(slice_w as u16).to_be_bytes());
    pps[14..16].copy_from_slice(&chunk_size.to_be_bytes());
    // Initial transmission delay = 512, initial dec delay = 526, rc_model_size = 8192.
    pps[16] = 0x02;
    pps[17] = 0x00;
    pps[18..20].copy_from_slice(&526u16.to_be_bytes());
    pps[21] = 32; // initial_scale_value
    pps[38..40].copy_from_slice(&8192u16.to_be_bytes()); // rc_model_size
    pps[40] = 6; // rc_edge_factor
    pps[41] = 11; // rc_quant_incr_limit0
    pps[42] = 11; // rc_quant_incr_limit1
    pps[43] = 0x33; // rc_tgt_offset_hi/lo
    pps
}

/// Snapshot of OTG/DCCG/MSA/DSC registers captured before a guarded mode switch for instant revert.
#[derive(Clone, Copy, Debug, Default)]
pub struct SavedModeRegs {
    pub pipe: u8,
    pub h_total: u32,
    pub h_blank: u32,
    pub h_sync: u32,
    pub h_sync_cntl: u32,
    pub v_total: u32,
    pub v_blank: u32,
    pub v_sync: u32,
    pub v_sync_cntl: u32,
    pub dto_cntl: u32,
    pub dto_phase: u32,
    pub dto_modulo: u32,
    pub pixel_rate_div: Option<u32>,
    pub msa1: u32,
    pub msa2: u32,
    pub msa3: u32,
    pub msa4: u32,
    pub msa_color: u32,
    pub msa_misc: u32,
    pub dp_pix_fmt: u32,
}

impl SavedModeRegs {
    pub fn capture<I: RegIo>(io: &I, dcn: &DcnAccess, pipe: u8) -> Self {
        let r = dcn.regs;
        Self {
            pipe,
            h_total: dcn.r_dcn(io, r.otg_h_total(pipe)).unwrap_or(0),
            h_blank: dcn.r_dcn(io, r.otg_h_blank(pipe)).unwrap_or(0),
            h_sync: dcn.r_dcn(io, r.otg_h_sync_a(pipe)).unwrap_or(0),
            h_sync_cntl: dcn.r_dcn(io, r.otg_h_sync_a_cntl(pipe)).unwrap_or(0),
            v_total: dcn.r_dcn(io, r.otg_v_total(pipe)).unwrap_or(0),
            v_blank: dcn.r_dcn(io, r.otg_v_blank(pipe)).unwrap_or(0),
            v_sync: dcn.r_dcn(io, r.otg_v_sync_a(pipe)).unwrap_or(0),
            v_sync_cntl: dcn.r_dcn(io, r.otg_v_sync_a_cntl(pipe)).unwrap_or(0),
            dto_cntl: dcn.r_dcn(io, r.dccg_otg_pixel_rate_cntl(pipe)).unwrap_or(0),
            dto_phase: dcn.r_dcn(io, r.dccg_dp_dto_phase(pipe)).unwrap_or(0),
            dto_modulo: dcn.r_dcn(io, r.dccg_dp_dto_modulo(pipe)).unwrap_or(0),
            pixel_rate_div: r.dccg_otg_pixel_rate_div().and_then(|reg| dcn.r_dcn(io, reg)),
            msa1: dcn.r_dcn(io, r.dp_msa_timing_param1(pipe)).unwrap_or(0),
            msa2: dcn.r_dcn(io, r.dp_msa_timing_param2(pipe)).unwrap_or(0),
            msa3: dcn.r_dcn(io, r.dp_msa_timing_param3(pipe)).unwrap_or(0),
            msa4: dcn.r_dcn(io, r.dp_msa_timing_param4(pipe)).unwrap_or(0),
            msa_color: dcn.r_dcn(io, r.dp_msa_colorimetry(pipe)).unwrap_or(0),
            msa_misc: dcn.r_dcn(io, r.dp_msa_misc(pipe)).unwrap_or(0),
            dp_pix_fmt: dcn.r_dcn(io, r.dp_pixel_format(pipe)).unwrap_or(0),
        }
    }

    /// Restore all captured OTG/DCCG/MSA registers atomically under `OTG_MASTER_UPDATE_LOCK`.
    pub fn restore<I: RegIo>(&self, io: &mut I, dcn: &DcnAccess) {
        let r = dcn.regs;
        let p = self.pipe;
        dcn.w_dcn(io, r.otg_master_update_lock(p), 1);
        dcn.w_dcn(io, r.otg_h_total(p), self.h_total);
        dcn.w_dcn(io, r.otg_h_blank(p), self.h_blank);
        dcn.w_dcn(io, r.otg_h_sync_a(p), self.h_sync);
        dcn.w_dcn(io, r.otg_h_sync_a_cntl(p), self.h_sync_cntl);
        dcn.w_dcn(io, r.otg_v_total(p), self.v_total);
        dcn.w_dcn(io, r.otg_v_blank(p), self.v_blank);
        dcn.w_dcn(io, r.otg_v_sync_a(p), self.v_sync);
        dcn.w_dcn(io, r.otg_v_sync_a_cntl(p), self.v_sync_cntl);
        if let (Some(reg), Some(val)) = (r.dccg_otg_pixel_rate_div(), self.pixel_rate_div) {
            dcn.w_dcn(io, reg, val);
        }
        dcn.w_dcn(io, r.dccg_dp_dto_phase(p), self.dto_phase);
        dcn.w_dcn(io, r.dccg_dp_dto_modulo(p), self.dto_modulo);
        dcn.w_dcn(io, r.dccg_otg_pixel_rate_cntl(p), self.dto_cntl);
        dcn.w_dcn(io, r.dp_msa_timing_param1(p), self.msa1);
        dcn.w_dcn(io, r.dp_msa_timing_param2(p), self.msa2);
        dcn.w_dcn(io, r.dp_msa_timing_param3(p), self.msa3);
        dcn.w_dcn(io, r.dp_msa_timing_param4(p), self.msa4);
        dcn.w_dcn(io, r.dp_msa_colorimetry(p), self.msa_color);
        dcn.w_dcn(io, r.dp_msa_misc(p), self.msa_misc);
        dcn.w_dcn(io, r.dp_pixel_format(p), self.dp_pix_fmt);
        dcn.w_dcn(io, r.otg_master_update_lock(p), 0);
    }
}

/// Program new OTG timing, DCCG DP pixel-rate DTO, DP MSA, and optional DSC 1.2 PPS registers
/// under `OTG_MASTER_UPDATE_LOCK`. Returns the saved prior register snapshot so callers can verify
/// that OTG keeps scanning and automatically revert if anything stalls.
#[allow(clippy::too_many_arguments)]
pub fn program_mode_regs<I: RegIo>(
    io: &mut I,
    dcn: &DcnAccess,
    pipe: u8,
    timing: &DetailedTiming,
    refclk_khz: u32,
    use_dsc: bool,
    dsc_bpp: u8,
    bpc: u8,
) -> SavedModeRegs {
    let saved = SavedModeRegs::capture(io, dcn, pipe);
    let r = dcn.regs;
    let otg = OtgTiming::from_detailed(timing);

    dcn.w_dcn(io, r.otg_master_update_lock(pipe), 1);

    // 1. OTG horizontal & vertical timing.
    dcn.w_dcn(io, r.otg_h_total(pipe), otg.h_total.saturating_sub(1) & 0x7FFF);
    dcn.w_dcn(io, r.otg_h_blank(pipe), (otg.h_blank_start & 0x7FFF) | ((otg.h_blank_end & 0x7FFF) << 16));
    dcn.w_dcn(io, r.otg_h_sync_a(pipe), (otg.h_sync_width & 0x7FFF) << 16);
    dcn.w_dcn(io, r.otg_h_sync_a_cntl(pipe), u32::from(!otg.h_sync_pos));

    dcn.w_dcn(io, r.otg_v_total(pipe), otg.v_total.saturating_sub(1) & 0x7FFF);
    dcn.w_dcn(io, r.otg_v_blank(pipe), (otg.v_blank_start & 0x7FFF) | ((otg.v_blank_end & 0x7FFF) << 16));
    dcn.w_dcn(io, r.otg_v_sync_a(pipe), (otg.v_sync_width & 0x7FFF) << 16);
    dcn.w_dcn(io, r.otg_v_sync_a_cntl(pipe), u32::from(!otg.v_sync_pos));

    // 2. DCCG DP pixel-rate DTO (`dcn401_dccg.c`).
    let refclk = refclk_khz.max(100_000);
    let dto_int = (timing.pixel_clock_khz / refclk).min(1);
    let dto_phase = timing.pixel_clock_khz % refclk;
    dcn.w_dcn(io, r.dccg_dp_dto_phase(pipe), dto_phase);
    dcn.w_dcn(io, r.dccg_dp_dto_modulo(pipe), refclk);
    if let Some(div_reg) = r.dccg_otg_pixel_rate_div() {
        let mut div = dcn.r_dcn(io, div_reg).unwrap_or(0);
        // DPDTO{0..3}_INT bits sit at shifts 1, 6, 11, 16 (`dcn_4_1_0_sh_mask.h`).
        let shift = 1 + u32::from(pipe.min(3)) * 5;
        div = (div & !(1 << shift)) | ((dto_int & 1) << shift);
        dcn.w_dcn(io, div_reg, div);
    }
    let cntl = dcn.r_dcn(io, r.dccg_otg_pixel_rate_cntl(pipe)).unwrap_or(0);
    dcn.w_dcn(io, r.dccg_otg_pixel_rate_cntl(pipe), cntl | (1 << 4)); // DP_DTO_ENABLE

    // 3. DP Main Stream Attributes (MSA) & pixel format (`dcn401_dio_stream_encoder.c`).
    let h_start = otg.h_blank_end;
    let v_start = otg.v_blank_end;
    dcn.w_dcn(io, r.dp_msa_timing_param1(pipe), ((otg.h_total & 0xFFFF) << 16) | (otg.v_total & 0xFFFF));
    dcn.w_dcn(io, r.dp_msa_timing_param2(pipe), ((h_start & 0xFFFF) << 16) | (v_start & 0xFFFF));
    let msa3 = (otg.v_sync_width & 0x7FFF)
        | (u32::from(!otg.v_sync_pos) << 15)
        | ((otg.h_sync_width & 0x7FFF) << 16)
        | (u32::from(!otg.h_sync_pos) << 31);
    dcn.w_dcn(io, r.dp_msa_timing_param3(pipe), msa3);
    dcn.w_dcn(io, r.dp_msa_timing_param4(pipe), ((otg.h_active & 0xFFFF) << 16) | (otg.v_active & 0xFFFF));

    let depth_code = if bpc >= 10 { 2u32 } else { 1u32 }; // 1 = 8bpc, 2 = 10bpc
    let enc_type = u32::from(use_dsc); // 0 = uncompressed, 1 = DSC compressed
    dcn.w_dcn(io, r.dp_pixel_format(pipe), enc_type | (depth_code << 8));

    // MSA_MISC0: bits[7:5] = bpc (1=8bpc, 2=10bpc), bit 0 = synchronous clock.
    let misc0 = ((if bpc >= 10 { 2u32 } else { 1u32 }) << 5) | 1;
    dcn.w_dcn(io, r.dp_msa_colorimetry(pipe), misc0 << 24);

    // 4. Optional DSC 1.2 PPS programming (`dcn401_dsc.c`).
    if use_dsc {
        let pps = encode_dsc_1_2_pps(otg.h_active, otg.v_active, bpc, dsc_bpp, 4);
        if let Some(cfg0) = r.dscc_config0() {
            dcn.w_dcn(io, cfg0, 1); // enable DSCC
        }
        for i in 0..23u8 {
            if let Some(reg) = r.dscc_pps_config(i) {
                let off = usize::from(i) * 4;
                let w = rd_u32(&pps, off).unwrap_or(0);
                dcn.w_dcn(io, reg, w);
            }
        }
        if let Some(fwd) = r.dsc_forward_config(pipe) {
            dcn.w_dcn(io, fwd, 1);
        }
    }

    dcn.w_dcn(io, r.otg_master_update_lock(pipe), 0);
    saved
}

/// Enable or disable Variable Refresh Rate (FreeSync / Adaptive-Sync) on `pipe` (`dcn401_optc.c`).
#[allow(clippy::too_many_arguments)]
pub fn set_vrr<I: RegIo>(
    io: &mut I,
    dcn: &DcnAccess,
    pipe: u8,
    timing: &OtgTiming,
    nominal_mhz: u32,
    min_hz: u16,
    max_hz: u16,
    enable: bool,
) -> bool {
    let r = dcn.regs;
    if !enable {
        dcn.w_dcn(io, r.otg_v_total_control(pipe), 0);
        return true;
    }
    if min_hz < 24 || max_hz < min_hz || timing.v_total == 0 || nominal_mhz == 0 {
        return false;
    }
    let vtot_min = timing.v_total;
    // Scale V_TOTAL_MAX = v_total * (nominal_hz / min_hz).
    let vtot_max = ((u64::from(timing.v_total) * u64::from(nominal_mhz)) / (u64::from(min_hz) * 1000))
        .clamp(u64::from(vtot_min), 0x7FFF) as u32;

    dcn.w_dcn(io, r.otg_v_total_min(pipe), vtot_min.saturating_sub(1) & 0x7FFF);
    dcn.w_dcn(io, r.otg_v_total_max(pipe), vtot_max.saturating_sub(1) & 0x7FFF);
    // DRR timing double-buffer update mode = 2 (update at VUPDATE).
    let mut dbuf = dcn.r_dcn(io, r.otg_double_buffer_control(pipe)).unwrap_or(0);
    dbuf = (dbuf & !(0x3 << 24)) | (2 << 24);
    dcn.w_dcn(io, r.otg_double_buffer_control(pipe), dbuf);
    // OTG_V_TOTAL_MIN_SEL=1 (bit 0), OTG_V_TOTAL_MAX_SEL=1 (bit 1), SET_V_TOTAL_MIN_MASK=(1<<1) at bit 16.
    dcn.w_dcn(io, r.otg_v_total_control(pipe), 0x3 | ((1 << 1) << 16));
    true
}

/// Enable or disable 10-bit HDR10 scanout format (`ARGB2101010` + 10bpc DP MSA + VSC SDP bit).
pub fn set_hdr<I: RegIo>(io: &mut I, dcn: &DcnAccess, pipe: u8, enable_hdr10: bool) {
    let r = dcn.regs;
    let surf_cfg = dcn.r_dcn(io, r.hubp_surface_config(pipe)).unwrap_or(0);
    let fmt = if enable_hdr10 { DCN_FMT_ARGB2101010 } else { DCN_FMT_ARGB8888 };
    dcn.w_dcn(io, r.hubp_surface_config(pipe), (surf_cfg & !0x7F) | fmt);

    let dp_fmt = dcn.r_dcn(io, r.dp_pixel_format(pipe)).unwrap_or(0);
    let depth = if enable_hdr10 { 2u32 } else { 1u32 };
    dcn.w_dcn(io, r.dp_pixel_format(pipe), (dp_fmt & !(0x7 << 8)) | (depth << 8));

    // MSA_MISC1 bit 6 = use VSC SDP for BT.2020/HDR colorimetry (`dcn401_dio_stream_encoder.c`).
    let mut misc1 = dcn.r_dcn(io, r.dp_msa_misc(pipe)).unwrap_or(0);
    if enable_hdr10 {
        misc1 |= 1 << 6;
    } else {
        misc1 &= !(1 << 6);
    }
    dcn.w_dcn(io, r.dp_msa_misc(pipe), misc1);
}
