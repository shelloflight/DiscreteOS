//! DCN DisplayPort AUX transaction engine (native DPCD & I2C-over-AUX multi-block EDID),
//! DP link state decoding (RBR..HBR3 + DP 2.1 UHBR 10/13.5/20 + DSC caps), and DP link training.
//!
//! Register bit layout matches AMD's MIT-licensed `dce_aux.c` and `dcn_4_1_0_sh_mask.h`.

use crate::amd::dcn::{DcnAccess, RegIo};
use crate::edid::{self, DetailedTiming, EDID_BLOCK_LEN, EdidInfo, MAX_EDID_BLOCKS};

// DP AUX command nibbles (VESA DP 1.4 / 2.1 §2.7.7).
const AUX_CMD_I2C_READ: u8 = 0x1;
const AUX_CMD_I2C_WRITE_MOT: u8 = 0x4;
const AUX_CMD_I2C_READ_MOT: u8 = 0x5;
const AUX_CMD_NATIVE_WRITE: u8 = 0x8;
const AUX_CMD_NATIVE_READ: u8 = 0x9;

// AUX_ARB_CONTROL bits.
const ARB_SW_USE_REQ: u32 = 1 << 16;
const ARB_SW_DONE_USING: u32 = 1 << 17;
const ARB_STATUS_SHIFT: u32 = 2;
const ARB_STATUS_MASK: u32 = 0x3;
const ARB_STATUS_SW_OWNED: u32 = 1;

// AUX_CONTROL bits.
const AUX_EN: u32 = 1 << 0;

// AUX_SW_CONTROL bits.
const AUX_SW_GO: u32 = 1 << 0;
const AUX_SW_WR_BYTES_SHIFT: u32 = 16;

// AUX_INTERRUPT_CONTROL bits.
const AUX_SW_DONE_ACK: u32 = 1 << 1;

// AUX_SW_STATUS bits.
const AUX_SW_DONE: u32 = 1 << 0;
const AUX_SW_RX_TIMEOUT: u32 = 1 << 7;
const AUX_SW_RX_OVERFLOW: u32 = 1 << 8;
const AUX_SW_HPD_DISCON: u32 = 1 << 9;
const AUX_SW_ERROR_MASK: u32 = AUX_SW_RX_OVERFLOW
    | (1 << 10) // RX_PARTIAL_BYTE
    | (1 << 11) // NON_AUX_MODE
    | (1 << 12) // RX_MIN_COUNT_VIOL
    | (1 << 14) // RX_INVALID_STOP
    | (1 << 17) // SYNC_INVALID_L
    | (1 << 18) // SYNC_INVALID_H
    | (1 << 19) // INVALID_START
    | (1 << 20) // RECV_NO_DET
    | (1 << 22) // RECV_INVALID_H
    | (1 << 23); // RECV_INVALID_L
const AUX_SW_REPLY_COUNT_SHIFT: u32 = 24;
const AUX_SW_REPLY_COUNT_MASK: u32 = 0x1F;

// AUX_SW_DATA bits.
const AUX_SW_DATA_READ: u32 = 1 << 0;
const AUX_SW_DATA_SHIFT: u32 = 8;

// Standard DPCD addresses.
pub const DPCD_REV: u32 = 0x0000;
pub const DPCD_DSC_SUPPORT: u32 = 0x0060;
pub const DPCD_LINK_BW_SET: u32 = 0x0100;
pub const DPCD_LANE_COUNT_SET: u32 = 0x0101;
pub const DPCD_TRAINING_PATTERN_SET: u32 = 0x0102;
pub const DPCD_TRAINING_LANE0_SET: u32 = 0x0103;
pub const DPCD_MAIN_LINK_CODING_SET: u32 = 0x0108;
pub const DPCD_DSC_ENABLE: u32 = 0x0160;
pub const DPCD_LANE0_1_STATUS: u32 = 0x0202;
pub const DPCD_ADJUST_REQUEST_LANE0_1: u32 = 0x0206;
pub const DPCD_EXT_CAP_BASE: u32 = 0x2200;
pub const DPCD_UHBR_CAPS: u32 = 0x2215;

// I2C addresses for E-DDC EDID.
const I2C_EDDC_SEGMENT: u32 = 0x30;
const I2C_EDID_ADDR: u32 = 0x50;

const MAX_DEFER_RETRIES: usize = 7;
const MAX_TIMEOUT_RETRIES: usize = 3;
const POLL_LIMIT: usize = 20_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuxError {
    BadArgs,
    ArbBusy,
    Disconnected,
    Timeout,
    Nack,
    DeferExhausted,
    Protocol,
}

/// Execute one low-level DP AUX transaction (native or I2C-over-AUX) with DEFER & timeout retries.
/// `delay_us` is invoked on DEFER/retry (no-op in host tests, real wait in driver).
#[allow(clippy::too_many_arguments)]
fn aux_xfer<I: RegIo, D: FnMut(u32)>(
    io: &mut I,
    dcn: &DcnAccess,
    aux: u8,
    cmd: u8,
    addr: u32,
    tx_data: &[u8],
    rx_data: &mut [u8],
    is_read: bool,
    mut delay_us: D,
) -> Result<usize, AuxError> {
    if aux >= dcn.regs.max_aux() || tx_data.len() > 16 || rx_data.len() > 16 || addr > 0x0F_FFFF {
        return Err(AuxError::BadArgs);
    }
    let r = dcn.regs;
    let arb_reg = r.aux_arb_control(aux);
    let ctrl_reg = r.aux_control(aux);
    let sw_ctrl_reg = r.aux_sw_control(aux);
    let int_reg = r.aux_interrupt_control(aux);
    let status_reg = r.aux_sw_status(aux);
    let data_reg = r.aux_sw_data(aux);

    // Acquire SW AUX arbitration.
    let arb = dcn.r_dcn(io, arb_reg).ok_or(AuxError::Protocol)?;
    if arb == 0xFFFF_FFFF {
        return Err(AuxError::Disconnected);
    }
    dcn.w_dcn(io, arb_reg, arb | ARB_SW_USE_REQ);
    let mut owned = false;
    for _ in 0..1024 {
        let cur = dcn.r_dcn(io, arb_reg).unwrap_or(0);
        if ((cur >> ARB_STATUS_SHIFT) & ARB_STATUS_MASK) == ARB_STATUS_SW_OWNED {
            owned = true;
            break;
        }
    }
    if !owned {
        dcn.w_dcn(io, arb_reg, arb | ARB_SW_DONE_USING);
        return Err(AuxError::ArbBusy);
    }

    // Ensure AUX channel is enabled.
    let ctrl = dcn.r_dcn(io, ctrl_reg).unwrap_or(0);
    if (ctrl & AUX_EN) == 0 {
        dcn.w_dcn(io, ctrl_reg, ctrl | AUX_EN);
    }

    let mut defers = 0usize;
    let mut timeouts = 0usize;
    let result = loop {
        // Clear any stale SW_DONE interrupt status.
        dcn.w_dcn(io, int_reg, AUX_SW_DONE_ACK);

        // Assemble 3- or 4-byte DP AUX header + optional write payload.
        let mut pkt = [0u8; 20];
        pkt[0] = ((cmd & 0x0F) << 4) | (((addr >> 16) & 0x0F) as u8);
        pkt[1] = ((addr >> 8) & 0xFF) as u8;
        pkt[2] = (addr & 0xFF) as u8;
        let payload_len = if is_read { rx_data.len() } else { tx_data.len() };
        let wr_bytes = if payload_len == 0 {
            3usize
        } else {
            pkt[3] = (payload_len - 1) as u8;
            if is_read {
                4usize
            } else {
                pkt[4..4 + tx_data.len()].copy_from_slice(tx_data);
                4 + tx_data.len()
            }
        };

        // Load FIFO via AUX_SW_DATA (explicit index in bits [20:16]).
        for (i, &b) in pkt[..wr_bytes].iter().enumerate() {
            let word = (u32::from(b) << AUX_SW_DATA_SHIFT) | ((i as u32) << 16);
            dcn.w_dcn(io, data_reg, word);
        }

        // Kick transaction.
        dcn.w_dcn(io, sw_ctrl_reg, ((wr_bytes as u32) << AUX_SW_WR_BYTES_SHIFT) | AUX_SW_GO);

        // Poll until AUX_SW_DONE.
        let mut status = 0u32;
        let mut done = false;
        for _ in 0..POLL_LIMIT {
            status = dcn.r_dcn(io, status_reg).unwrap_or(0);
            if (status & AUX_SW_DONE) != 0 {
                done = true;
                break;
            }
        }
        dcn.w_dcn(io, int_reg, AUX_SW_DONE_ACK);

        if !done || (status & AUX_SW_RX_TIMEOUT) != 0 {
            timeouts += 1;
            if timeouts <= MAX_TIMEOUT_RETRIES {
                delay_us(500);
                continue;
            }
            break Err(AuxError::Timeout);
        }
        if (status & AUX_SW_HPD_DISCON) != 0 {
            break Err(AuxError::Disconnected);
        }
        if (status & AUX_SW_ERROR_MASK) != 0 {
            timeouts += 1;
            if timeouts <= MAX_TIMEOUT_RETRIES {
                delay_us(400);
                continue;
            }
            break Err(AuxError::Protocol);
        }

        let reply_count = ((status >> AUX_SW_REPLY_COUNT_SHIFT) & AUX_SW_REPLY_COUNT_MASK) as usize;
        if reply_count == 0 {
            break Err(AuxError::Protocol);
        }

        // Switch FIFO to read mode at index 0.
        dcn.w_dcn(io, data_reg, AUX_SW_DATA_READ);
        let hdr_raw = dcn.r_dcn(io, data_reg).unwrap_or(0);
        let reply_hdr = ((hdr_raw >> AUX_SW_DATA_SHIFT) & 0xFF) as u8;
        let reply_code = reply_hdr >> 4;
        let is_i2c = (cmd & 0x08) == 0;

        // Native: 0=ACK, 1=NACK, 2=DEFER. I2C: 0=ACK, 4=NACK, 8=DEFER (also check native bits).
        let is_defer = if is_i2c {
            (reply_code & 0x0C) == 0x08 || (reply_code & 0x03) == 0x02
        } else {
            (reply_code & 0x03) == 0x02
        };
        let is_nack = if is_i2c {
            (reply_code & 0x0C) == 0x04 || (reply_code & 0x03) == 0x01
        } else {
            (reply_code & 0x03) == 0x01
        };

        if is_defer {
            defers += 1;
            if defers <= MAX_DEFER_RETRIES {
                delay_us(400);
                continue;
            }
            break Err(AuxError::DeferExhausted);
        }
        if is_nack {
            break Err(AuxError::Nack);
        }

        let data_bytes = reply_count.saturating_sub(1).min(rx_data.len());
        for slot in rx_data.iter_mut().take(data_bytes) {
            let w = dcn.r_dcn(io, data_reg).unwrap_or(0);
            *slot = ((w >> AUX_SW_DATA_SHIFT) & 0xFF) as u8;
        }
        break Ok(data_bytes);
    };

    // Release SW AUX arbitration.
    dcn.w_dcn(io, arb_reg, ARB_SW_DONE_USING);
    result
}

/// Read `out.len()` bytes from DPCD starting at `dpcd_addr` (handles multi-chunk >16 byte reads).
/// Strictly a read-only DP AUX operation.
pub fn aux_native_read<I: RegIo, D: FnMut(u32)>(
    io: &mut I,
    dcn: &DcnAccess,
    aux: u8,
    dpcd_addr: u32,
    out: &mut [u8],
    mut delay_us: D,
) -> Result<usize, AuxError> {
    let mut done = 0usize;
    while done < out.len() {
        let chunk = (out.len() - done).min(16);
        let n = aux_xfer(
            io,
            dcn,
            aux,
            AUX_CMD_NATIVE_READ,
            dpcd_addr + done as u32,
            &[],
            &mut out[done..done + chunk],
            true,
            &mut delay_us,
        )?;
        if n == 0 {
            break;
        }
        done += n;
    }
    Ok(done)
}

/// Write `data` to DPCD starting at `dpcd_addr` (used only for mode-set link training / DSC enable).
pub fn aux_native_write<I: RegIo, D: FnMut(u32)>(
    io: &mut I,
    dcn: &DcnAccess,
    aux: u8,
    dpcd_addr: u32,
    data: &[u8],
    mut delay_us: D,
) -> Result<(), AuxError> {
    let mut done = 0usize;
    while done < data.len() {
        let chunk = (data.len() - done).min(16);
        aux_xfer(
            io,
            dcn,
            aux,
            AUX_CMD_NATIVE_WRITE,
            dpcd_addr + done as u32,
            &data[done..done + chunk],
            &mut [],
            false,
            &mut delay_us,
        )?;
        done += chunk;
    }
    Ok(())
}

/// Read one 128-byte EDID block (`block_idx` in `0..4`) over I2C-over-AUX (`0x50` + E-DDC `0x30`).
pub fn aux_read_edid_block<I: RegIo, D: FnMut(u32)>(
    io: &mut I,
    dcn: &DcnAccess,
    aux: u8,
    block_idx: u8,
    out: &mut [u8; EDID_BLOCK_LEN],
    mut delay_us: D,
) -> Result<(), AuxError> {
    let seg = block_idx / 2;
    let offset = (block_idx % 2) * 128;

    // Select E-DDC segment pointer for blocks >= 2 (ignore NACK on sinks without E-DDC).
    if seg > 0 {
        let _ = aux_xfer(io, dcn, aux, AUX_CMD_I2C_WRITE_MOT, I2C_EDDC_SEGMENT, &[seg], &mut [], false, &mut delay_us);
    }
    // Set EDID byte offset at I2C address 0x50 with MOT=1.
    aux_xfer(io, dcn, aux, AUX_CMD_I2C_WRITE_MOT, I2C_EDID_ADDR, &[offset], &mut [], false, &mut delay_us)?;

    // Read 128 bytes in 16-byte chunks with MOT=1, then send address-only STOP (MOT=0).
    let mut pos = 0usize;
    while pos < EDID_BLOCK_LEN {
        let chunk = (EDID_BLOCK_LEN - pos).min(16);
        let n = aux_xfer(
            io,
            dcn,
            aux,
            AUX_CMD_I2C_READ_MOT,
            I2C_EDID_ADDR,
            &[],
            &mut out[pos..pos + chunk],
            true,
            &mut delay_us,
        )?;
        if n == 0 {
            return Err(AuxError::Protocol);
        }
        pos += n;
    }
    // Address-only I2C stop (0 data bytes, MOT=0).
    let _ = aux_xfer(io, dcn, aux, AUX_CMD_I2C_READ, I2C_EDID_ADDR, &[], &mut [], true, &mut delay_us);
    Ok(())
}

// ---- DPCD & Link State Decoding -----------------------------------------------------------------

/// Convert DPCD link rate byte (`0x001` or `0x100`) to per-lane rate in Mbit/s.
pub const fn dpcd_rate_code_to_mbps(code: u8) -> u32 {
    match code {
        0x06 => 1_620,  // RBR (1.62 Gbps)
        0x0A => 2_700,  // HBR (2.70 Gbps)
        0x14 => 5_400,  // HBR2 (5.40 Gbps)
        0x1E => 8_100,  // HBR3 (8.10 Gbps)
        0x01 => 10_000, // UHBR10 (10.0 Gbps, DP 2.1 128b/132b)
        0x04 => 13_500, // UHBR13.5 (13.5 Gbps, DP 2.1 128b/132b)
        0x02 => 20_000, // UHBR20 (20.0 Gbps, DP 2.1 128b/132b)
        _ => 0,
    }
}

/// Convert DPCD rate code to a short human-readable label.
pub const fn dpcd_rate_label(mbps: u32) -> &'static str {
    match mbps {
        1_620 => "RBR",
        2_700 => "HBR",
        5_400 => "HBR2",
        8_100 => "HBR3",
        10_000 => "UHBR10",
        13_500 => "UHBR13.5",
        20_000 => "UHBR20",
        _ => "?",
    }
}

/// Decoded DisplayPort link configuration and sink capabilities from DPCD.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DpLinkState {
    pub dpcd_rev: u8,
    pub max_lanes: u8,
    pub max_link_rate_mbps: u32,
    pub active_lanes: u8,
    pub active_link_rate_mbps: u32,
    pub is_uhbr: bool,
    pub uhbr_caps: u8,
    pub cr_done: bool,
    pub eq_done: bool,
    pub dsc_supported: bool,
    pub dsc_enabled: bool,
    pub dsc_version: u8,
    pub dpcd_000: [u8; 16],
    pub dpcd_060: [u8; 4],
    pub dpcd_100: [u8; 2],
    pub dpcd_202: [u8; 4],
}

impl DpLinkState {
    /// Decode link state from raw DPCD slices (`0x000..=0x00F`, `0x060..=0x063`, `0x100..=0x101`,
    /// `0x202..=0x205`, `0x160`, and optional `0x108` + `0x2215`).
    pub fn decode(
        dpcd_000: [u8; 16],
        dpcd_060: [u8; 4],
        dpcd_100: [u8; 2],
        dpcd_202: [u8; 4],
        dpcd_160: u8,
        dpcd_108: u8,
        uhbr_caps: u8,
    ) -> Self {
        let dpcd_rev = dpcd_000[0];
        let max_lanes = dpcd_000[2] & 0x1F;
        let max_8b10b = dpcd_rate_code_to_mbps(dpcd_000[1]);
        let max_uhbr = if (uhbr_caps & 0x02) != 0 {
            20_000
        } else if (uhbr_caps & 0x04) != 0 {
            13_500
        } else if (uhbr_caps & 0x01) != 0 {
            10_000
        } else {
            0
        };
        let max_link_rate_mbps = if max_uhbr > max_8b10b { max_uhbr } else { max_8b10b };

        let active_lanes = dpcd_100[1] & 0x1F;
        let is_uhbr = (dpcd_108 & 0x02) != 0 || matches!(dpcd_100[0], 0x01 | 0x02 | 0x04);
        let active_link_rate_mbps = dpcd_rate_code_to_mbps(dpcd_100[0]);

        // Check per-lane CR (bit 0) and EQ+SymbolLock (bits 1 & 2) across `active_lanes`.
        let mut cr_done = active_lanes > 0;
        let mut eq_done = active_lanes > 0;
        for lane in 0..usize::from(active_lanes).min(4) {
            let byte = dpcd_202[lane / 2];
            let nib = if lane % 2 == 0 { byte & 0x0F } else { (byte >> 4) & 0x0F };
            if (nib & 0x01) == 0 {
                cr_done = false;
            }
            if (nib & 0x07) != 0x07 {
                eq_done = false;
            }
        }
        if active_lanes > 1 && (dpcd_202[2] & 0x01) == 0 {
            // INTERLANE_ALIGN_DONE (0x204 bit 0).
            eq_done = false;
        }

        let dsc_supported = (dpcd_060[0] & 0x01) != 0;
        let dsc_version = dpcd_060[1];
        let dsc_enabled = (dpcd_160 & 0x01) != 0;

        Self {
            dpcd_rev,
            max_lanes,
            max_link_rate_mbps,
            active_lanes,
            active_link_rate_mbps,
            is_uhbr,
            uhbr_caps,
            cr_done,
            eq_done,
            dsc_supported,
            dsc_enabled,
            dsc_version,
            dpcd_000,
            dpcd_060,
            dpcd_100,
            dpcd_202,
        }
    }

    /// Effective usable payload bandwidth of the active link in kbit/s (accounts for 8b/10b or 128b/132b).
    pub const fn active_bandwidth_kbps(&self) -> u64 {
        let raw_kbps = (self.active_link_rate_mbps as u64)
            .saturating_mul(1_000)
            .saturating_mul(self.active_lanes as u64);
        if self.is_uhbr {
            // 128b/132b coding + ~0.4% FEC/framing overhead ≈ 96.3% effective.
            raw_kbps.saturating_mul(963) / 1000
        } else {
            // 8b/10b coding = 80% effective.
            raw_kbps.saturating_mul(800) / 1000
        }
    }

    /// Maximum usable payload bandwidth supported by the sink in kbit/s.
    pub const fn max_bandwidth_kbps(&self) -> u64 {
        let raw_kbps = (self.max_link_rate_mbps as u64)
            .saturating_mul(1_000)
            .saturating_mul(self.max_lanes as u64);
        if self.max_link_rate_mbps >= 10_000 {
            raw_kbps.saturating_mul(963) / 1000
        } else {
            raw_kbps.saturating_mul(800) / 1000
        }
    }

    /// True if `timing` at `bpc` bits/component (e.g. 8 or 10) fits within the currently trained link uncompressed.
    pub const fn fits_active_uncompressed(&self, timing: &DetailedTiming, bpc: u8) -> bool {
        timing.raw_bandwidth_kbps(bpc) <= self.active_bandwidth_kbps()
    }

    /// True if `timing` fits within the currently trained link using DSC at `target_bpp` bits/pixel (typically 8 or 12).
    pub const fn fits_active_with_dsc(&self, timing: &DetailedTiming, target_bpp: u8) -> bool {
        let req = (timing.pixel_clock_khz as u64).saturating_mul(target_bpp as u64);
        self.dsc_supported && req <= self.active_bandwidth_kbps()
    }
}

/// Complete result of a read-only DP AUX probe on one connector.
#[derive(Clone, Copy, Debug)]
pub struct DpAuxProbe {
    pub aux_idx: u8,
    pub link: DpLinkState,
    pub edid: Option<EdidInfo>,
    pub edid_blocks_read: u8,
}

/// Perform a strictly **read-only** DP AUX probe on connector `aux` (DPCD caps + link state + multi-block EDID).
/// Issues zero DPCD write transactions.
pub fn probe_dp_aux_readonly<I: RegIo, D: FnMut(u32)>(
    io: &mut I,
    dcn: &DcnAccess,
    aux: u8,
    mut delay_us: D,
) -> Result<DpAuxProbe, AuxError> {
    let mut dpcd_000 = [0u8; 16];
    let n0 = aux_native_read(io, dcn, aux, DPCD_REV, &mut dpcd_000, &mut delay_us)?;
    if n0 < 3 || dpcd_000[0] == 0 {
        return Err(AuxError::Disconnected);
    }
    let mut dpcd_060 = [0u8; 4];
    let _ = aux_native_read(io, dcn, aux, DPCD_DSC_SUPPORT, &mut dpcd_060, &mut delay_us);

    let mut dpcd_100 = [0u8; 2];
    let _ = aux_native_read(io, dcn, aux, DPCD_LINK_BW_SET, &mut dpcd_100, &mut delay_us);

    let mut dpcd_108 = [0u8; 1];
    let _ = aux_native_read(io, dcn, aux, DPCD_MAIN_LINK_CODING_SET, &mut dpcd_108, &mut delay_us);

    let mut dpcd_160 = [0u8; 1];
    let _ = aux_native_read(io, dcn, aux, DPCD_DSC_ENABLE, &mut dpcd_160, &mut delay_us);

    let mut dpcd_202 = [0u8; 4];
    let _ = aux_native_read(io, dcn, aux, DPCD_LANE0_1_STATUS, &mut dpcd_202, &mut delay_us);

    // If extended receiver capability field is present (DPCD 0x00E bit 7), read UHBR caps at 0x2215.
    let mut uhbr_caps = 0u8;
    if (dpcd_000[0x0E] & 0x80) != 0 {
        let mut ext_buf = [0u8; 1];
        if aux_native_read(io, dcn, aux, DPCD_UHBR_CAPS, &mut ext_buf, &mut delay_us).is_ok() {
            uhbr_caps = ext_buf[0];
        }
    }

    let link = DpLinkState::decode(dpcd_000, dpcd_060, dpcd_100, dpcd_202, dpcd_160[0], dpcd_108[0], uhbr_caps);

    // Read base EDID block + any CTA-861 / DisplayID extension blocks over I2C-over-AUX.
    let mut edid_raw = [0u8; EDID_BLOCK_LEN * MAX_EDID_BLOCKS];
    let mut blocks_read = 0u8;
    let mut blk0 = [0u8; EDID_BLOCK_LEN];
    if aux_read_edid_block(io, dcn, aux, 0, &mut blk0, &mut delay_us).is_ok() {
        edid_raw[..EDID_BLOCK_LEN].copy_from_slice(&blk0);
        blocks_read = 1;
        let ext_cnt = blk0[126].min((MAX_EDID_BLOCKS - 1) as u8);
        for bidx in 1..=ext_cnt {
            let mut ext = [0u8; EDID_BLOCK_LEN];
            if aux_read_edid_block(io, dcn, aux, bidx, &mut ext, &mut delay_us).is_ok() {
                let off = usize::from(bidx) * EDID_BLOCK_LEN;
                edid_raw[off..off + EDID_BLOCK_LEN].copy_from_slice(&ext);
                blocks_read += 1;
            } else {
                break;
            }
        }
    }
    let edid = if blocks_read > 0 {
        edid::parse_edid(&edid_raw[..usize::from(blocks_read) * EDID_BLOCK_LEN]).ok()
    } else {
        None
    };

    Ok(DpAuxProbe { aux_idx: aux, link, edid, edid_blocks_read: blocks_read })
}

/// Probe all AUX channels (0..max_aux) read-only and return the first connected DisplayPort sink.
pub fn probe_first_connected_aux<I: RegIo, D: FnMut(u32)>(
    io: &mut I,
    dcn: &DcnAccess,
    mut delay_us: D,
) -> Option<DpAuxProbe> {
    for aux in 0..dcn.regs.max_aux() {
        if let Ok(p) = probe_dp_aux_readonly(io, dcn, aux, &mut delay_us) {
            return Some(p);
        }
    }
    None
}

// ---- DP Link Training Engine (for high-refresh mode setting) ------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DpTrainResult {
    pub lanes: u8,
    pub link_rate_mbps: u32,
    pub is_uhbr: bool,
    pub cr_done: bool,
    pub eq_done: bool,
    pub voltage_swing: [u8; 4],
    pub pre_emphasis: [u8; 4],
}

/// Negotiate DisplayPort Clock Recovery (TPS1) and Channel Equalization (TPS2/TPS3/TPS4) over DPCD AUX.
/// Note: used only when a requested high-refresh mode exceeds the firmware's trained link bandwidth.
pub fn train_dp_link<I: RegIo, D: FnMut(u32)>(
    io: &mut I,
    dcn: &DcnAccess,
    aux: u8,
    target_lanes: u8,
    target_rate_code: u8,
    is_uhbr: bool,
    mut delay_us: D,
) -> Result<DpTrainResult, AuxError> {
    let lanes = target_lanes.clamp(1, 4);
    let rate_mbps = dpcd_rate_code_to_mbps(target_rate_code);
    if rate_mbps == 0 {
        return Err(AuxError::BadArgs);
    }

    // Program link coding (0x01 = 8b/10b, 0x02 = 128b/132b UHBR), bandwidth, and lane count (enhanced framing).
    let coding = if is_uhbr { 0x02u8 } else { 0x01u8 };
    let _ = aux_native_write(io, dcn, aux, DPCD_MAIN_LINK_CODING_SET, &[coding], &mut delay_us);
    aux_native_write(io, dcn, aux, DPCD_LINK_BW_SET, &[target_rate_code, lanes | 0x80], &mut delay_us)?;

    let mut vs = [0u8; 4];
    let mut pe = [0u8; 4];
    let mut lane_cfg = [0u8; 4];

    // Phase 1: Clock Recovery (TPS1 = 0x21 with scrambling disabled).
    aux_native_write(io, dcn, aux, DPCD_TRAINING_PATTERN_SET, &[0x21], &mut delay_us)?;
    let mut cr_done = false;
    for _ in 0..5 {
        for i in 0..usize::from(lanes) {
            let max_vs = u8::from(vs[i] >= 3) << 2;
            let max_pe = u8::from(pe[i] >= 3) << 5;
            lane_cfg[i] = (vs[i] & 0x3) | max_vs | ((pe[i] & 0x3) << 3) | max_pe;
        }
        aux_native_write(io, dcn, aux, DPCD_TRAINING_LANE0_SET, &lane_cfg[..usize::from(lanes)], &mut delay_us)?;
        delay_us(400);

        let mut st = [0u8; 6];
        aux_native_read(io, dcn, aux, DPCD_LANE0_1_STATUS, &mut st, &mut delay_us)?;
        let mut all_cr = true;
        for lane in 0..usize::from(lanes) {
            let b = st[lane / 2];
            let nib = if lane % 2 == 0 { b & 0x0F } else { (b >> 4) & 0x0F };
            if (nib & 0x01) == 0 {
                all_cr = false;
            }
            let adj = st[4 + lane / 2];
            let anib = if lane % 2 == 0 { adj & 0x0F } else { (adj >> 4) & 0x0F };
            vs[lane] = anib & 0x03;
            pe[lane] = (anib >> 2) & 0x03;
        }
        if all_cr {
            cr_done = true;
            break;
        }
    }

    // Phase 2: Channel Equalization (TPS4 = 0x07 for HBR3/UHBR, TPS2 = 0x22 otherwise).
    let mut eq_done = false;
    if cr_done {
        let eq_pat = if rate_mbps >= 8_100 { 0x07u8 } else { 0x22u8 };
        aux_native_write(io, dcn, aux, DPCD_TRAINING_PATTERN_SET, &[eq_pat], &mut delay_us)?;
        for _ in 0..6 {
            for i in 0..usize::from(lanes) {
                let max_vs = u8::from(vs[i] >= 3) << 2;
                let max_pe = u8::from(pe[i] >= 3) << 5;
                lane_cfg[i] = (vs[i] & 0x3) | max_vs | ((pe[i] & 0x3) << 3) | max_pe;
            }
            aux_native_write(io, dcn, aux, DPCD_TRAINING_LANE0_SET, &lane_cfg[..usize::from(lanes)], &mut delay_us)?;
            delay_us(400);

            let mut st = [0u8; 6];
            aux_native_read(io, dcn, aux, DPCD_LANE0_1_STATUS, &mut st, &mut delay_us)?;
            let mut all_eq = lanes == 1 || (st[2] & 0x01) != 0;
            for lane in 0..usize::from(lanes) {
                let b = st[lane / 2];
                let nib = if lane % 2 == 0 { b & 0x0F } else { (b >> 4) & 0x0F };
                if (nib & 0x07) != 0x07 {
                    all_eq = false;
                }
                let adj = st[4 + lane / 2];
                let anib = if lane % 2 == 0 { adj & 0x0F } else { (adj >> 4) & 0x0F };
                vs[lane] = anib & 0x03;
                pe[lane] = (anib >> 2) & 0x03;
            }
            if all_eq {
                eq_done = true;
                break;
            }
        }
    }

    // Clear training pattern (normal video transmission).
    let _ = aux_native_write(io, dcn, aux, DPCD_TRAINING_PATTERN_SET, &[0x00], &mut delay_us);

    Ok(DpTrainResult {
        lanes,
        link_rate_mbps: rate_mbps,
        is_uhbr,
        cr_done,
        eq_done,
        voltage_swing: vs,
        pre_emphasis: pe,
    })
}
