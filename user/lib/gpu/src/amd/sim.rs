//! Simulated DCN register file, DP AUX responder, and OSSSYS IH ring DMA writer for host tests.
//!
//! Models real DCN hardware behaviour for all four generations (`Dcn401`, `Dcn315`, `Dcn32`, `Dcn30`):
//! - Latched-at-vblank `SURFACE_EARLIEST_INUSE` + `SURFACE_FLIP_PENDING` clearing on `advance_vblank()`.
//! - Advancing `OTG_STATUS_FRAME_COUNT` and `OTG_STATUS_POSITION`.
//! - Injectable flip latch stall (to test 3-frame self-check failure and automatic revert to GOP).
//! - Simulated DP AUX FIFO handling native DPCD reads/writes, I2C-over-AUX multi-block EDID
//!   (CTA-861 HDR/FreeSync + DisplayID 2.0 240 Hz & 540 Hz timings), injectable DEFER retries,
//!   HPD disconnect, and DP link training CR/EQ status progression.
//! - Simulated OSSSYS IH ring DMA writing real 32-byte IV entries for vblank and flip-done.

use core::cell::Cell;
use std::collections::BTreeMap;
use std::vec;
use std::vec::Vec;

use super::dcn::{
    DCN_FMT_ARGB8888, DcnAccess, DcnVersion, OtgTiming, RegAddr, RegIo, decode_surface_addr, encode_surface_addr,
};
use super::flip::{DCN_SRCID_HUBP_FLIP_BASE, DCN_SRCID_OTG_VINT0_BASE, IH_CLIENTID_DCE, IH_IV_BYTES};
use super::{
    HWID_DCE, HWID_GC, HWID_MMHUB, HWID_NBIO, HWID_OSSSYS, HWID_SDMA0, IP_DISCOVERY_BINARY_SIG,
    IP_DISCOVERY_TABLE_SIG, IpBlock, MAX_IP_BASES, discovery_checksum,
};
use crate::edid::{DetailedTiming, EDID_BLOCK_LEN};

/// Build a valid AMD IP Discovery binary image matching `struct binary_header` + `ip_discovery_header`.
pub fn build_discovery_image(
    ver_maj: u16,
    base_64: bool,
    blocks: &[IpBlock],
    reserved: &[(u64, u64)],
) -> Vec<u8> {
    let mut img = vec![0u8; 2048];
    let tbl_list_off = if ver_maj >= 2 { 16usize } else { 12usize };
    let ip_off = 128usize;
    let die_off = 256usize;

    // Die header at `die_off`: die_id(0), num_ips.
    img[die_off..die_off + 2].copy_from_slice(&0u16.to_le_bytes());
    img[die_off + 2..die_off + 4].copy_from_slice(&(blocks.len() as u16).to_le_bytes());
    let mut cur = die_off + 4;
    for b in blocks {
        img[cur..cur + 2].copy_from_slice(&b.hw_id.to_le_bytes());
        img[cur + 2] = b.instance;
        img[cur + 3] = b.num_bases;
        img[cur + 4] = b.major;
        img[cur + 5] = b.minor;
        img[cur + 6] = b.revision;
        img[cur + 7] = 0;
        cur += 8;
        for &base_val in b.bases.iter().take(usize::from(b.num_bases).min(MAX_IP_BASES)) {
            if base_64 {
                img[cur..cur + 8].copy_from_slice(&u64::from(base_val).to_le_bytes());
                cur += 8;
            } else {
                img[cur..cur + 4].copy_from_slice(&base_val.to_le_bytes());
                cur += 4;
            }
        }
    }

    // `ip_discovery_header` at `ip_off` (96 bytes).
    let ip_size = 96usize;
    img[ip_off..ip_off + 4].copy_from_slice(&IP_DISCOVERY_TABLE_SIG.to_le_bytes());
    img[ip_off + 4..ip_off + 6].copy_from_slice(&2u16.to_le_bytes());
    img[ip_off + 6..ip_off + 8].copy_from_slice(&(ip_size as u16).to_le_bytes());
    img[ip_off + 12..ip_off + 14].copy_from_slice(&1u16.to_le_bytes()); // num_dies = 1
    img[ip_off + 14..ip_off + 16].copy_from_slice(&0u16.to_le_bytes()); // die 0
    img[ip_off + 16..ip_off + 18].copy_from_slice(&(die_off as u16).to_le_bytes());
    if base_64 {
        img[ip_off + 78] = 1; // flags.base_addr_64_bit
    }
    let ip_csum = discovery_checksum(&img[ip_off..ip_off + ip_size]);

    // Optional Table 6 (`MEM_RESERVED_INFO`) at offset 1024.
    let res_off = 1024usize;
    let res_size = 32 + reserved.len() * 16;
    if !reserved.is_empty() {
        for (i, &(off, sz)) in reserved.iter().enumerate() {
            let p = res_off + 32 + i * 16;
            img[p..p + 8].copy_from_slice(&off.to_le_bytes());
            img[p + 8..p + 16].copy_from_slice(&sz.to_le_bytes());
        }
        let res_csum = discovery_checksum(&img[res_off..res_off + res_size]);
        let t6 = tbl_list_off + 6 * 8;
        img[t6..t6 + 2].copy_from_slice(&(res_off as u16).to_le_bytes());
        img[t6 + 2..t6 + 4].copy_from_slice(&res_csum.to_le_bytes());
        img[t6 + 4..t6 + 6].copy_from_slice(&(res_size as u16).to_le_bytes());
    }

    // Binary header at offset 0.
    let bin_size = (res_off + res_size).max(cur).next_multiple_of(16);
    img.truncate(bin_size);
    img[0..4].copy_from_slice(&IP_DISCOVERY_BINARY_SIG.to_le_bytes());
    img[4..6].copy_from_slice(&ver_maj.to_le_bytes());
    img[6..8].copy_from_slice(&0u16.to_le_bytes());
    img[10..12].copy_from_slice(&(bin_size as u16).to_le_bytes());
    if ver_maj >= 2 {
        img[12..14].copy_from_slice(&8u16.to_le_bytes()); // num_tables
    }
    // Table 0: IP_DISCOVERY.
    img[tbl_list_off..tbl_list_off + 2].copy_from_slice(&(ip_off as u16).to_le_bytes());
    img[tbl_list_off + 2..tbl_list_off + 4].copy_from_slice(&ip_csum.to_le_bytes());
    img[tbl_list_off + 4..tbl_list_off + 6].copy_from_slice(&(ip_size as u16).to_le_bytes());

    let bin_csum = discovery_checksum(&img[10..bin_size]);
    img[8..10].copy_from_slice(&bin_csum.to_le_bytes());
    img
}

/// Build a standard multi-block EDID with base block (1920x1080@60 + range limits),
/// CTA-861 extension (HDR10 ST2084 + AMD FreeSync 48..240 Hz + 2560x1440@240 Hz DTD),
/// and DisplayID 2.0 extension (2560x1440@540 Hz Type VII timing).
pub fn build_high_refresh_edid() -> Vec<u8> {
    let mut edid = vec![0u8; EDID_BLOCK_LEN * 3];

    // Block 0: Base EDID 1.4.
    let b0 = &mut edid[0..128];
    b0[0..8].copy_from_slice(&[0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00]);
    b0[8] = 0x04; // "AMD" approx PNP
    b0[9] = 0x24;
    b0[10] = 0x70;
    b0[11] = 0x90;
    b0[18] = 1;
    b0[19] = 4;
    b0[21] = 60;
    b0[22] = 34;
    // DTD 0: 2560x1440 @ 60 Hz (pclk = 241.50 MHz -> 24150, h_blank=160, v_blank=41).
    let write_dtd = |dst: &mut [u8], pclk_10khz: u16, ha: u32, hb: u32, hfp: u32, hsw: u32, va: u32, vb: u32, vfp: u32, vsw: u32| {
        dst[0..2].copy_from_slice(&pclk_10khz.to_le_bytes());
        dst[2] = (ha & 0xFF) as u8;
        dst[3] = (hb & 0xFF) as u8;
        dst[4] = ((((ha >> 8) & 0xF) << 4) | ((hb >> 8) & 0xF)) as u8;
        dst[5] = (va & 0xFF) as u8;
        dst[6] = (vb & 0xFF) as u8;
        dst[7] = ((((va >> 8) & 0xF) << 4) | ((vb >> 8) & 0xF)) as u8;
        dst[8] = (hfp & 0xFF) as u8;
        dst[9] = (hsw & 0xFF) as u8;
        dst[10] = ((((vfp & 0xF) << 4) | (vsw & 0xF)) & 0xFF) as u8;
        dst[11] = ((((hfp >> 8) & 3) << 6) | (((hsw >> 8) & 3) << 4) | (((vfp >> 4) & 3) << 2) | ((vsw >> 4) & 3)) as u8;
        dst[17] = 0x1E; // digital separate, +H +V
    };
    write_dtd(&mut b0[54..72], 24_150, 2560, 160, 48, 32, 1440, 41, 3, 5);
    // Descriptor 1: Monitor name "RX9070-540Hz".
    b0[75] = 0xFC;
    b0[77..89].copy_from_slice(b"RX9070-540Hz");
    b0[89] = 0x0A;
    // Descriptor 2: Range limits (48..540 Hz using EDID 1.4 max offset bit1=1 -> +255? 255+285 exceeds u8; use 48..240 in base + 540 in DisplayID).
    b0[93] = 0xFD;
    b0[94] = 0x00;
    b0[95] = 48;
    b0[96] = 240;
    b0[126] = 2; // 2 extension blocks
    let s0 = b0[..127].iter().fold(0u8, |a, &x| a.wrapping_add(x));
    b0[127] = 0u8.wrapping_sub(s0);

    // Block 1: CTA-861 extension (AMD FreeSync VSDB + HDR10 Static Metadata + 2560x1440@240 Hz DTD?
    // Note: 2560x1440@240 needs ~967 MHz > 655 MHz DTD limit, so put 1920x1080@240 (585 MHz) in CTA DTD
    // and both 2560x1440@240 & 2560x1440@540 in DisplayID 2.0 Type VII!).
    let b1 = &mut edid[128..256];
    b1[0] = 0x02; // CTA-861
    b1[1] = 0x03; // rev 3
    let mut p = 4usize;
    // AMD FreeSync VSDB (tag=3, len=7): OUI 0x1A,0x00,0x00, ver=1, flags=0, min=48, max=240.
    b1[p] = (3 << 5) | 7;
    b1[p + 1..p + 8].copy_from_slice(&[0x1A, 0x00, 0x00, 0x01, 0x00, 48, 240]);
    p += 8;
    // HDR Static Metadata (tag=7, len=4): ext=0x06, eotf=0x04 (ST2084), sm=0x01, max_lum=128 (~800 nits).
    b1[p] = (7 << 5) | 4;
    b1[p + 1..p + 5].copy_from_slice(&[0x06, 0x04, 0x01, 128]);
    p += 5;
    b1[2] = p as u8; // dtd_off
    // CTA DTD: 1920x1080 @ 240 Hz (h_total=2080, v_total=1144, pclk=571.00 MHz -> 57100).
    write_dtd(&mut b1[p..p + 18], 57_100, 1920, 160, 48, 32, 1080, 64, 3, 5);
    let s1 = b1[..127].iter().fold(0u8, |a, &x| a.wrapping_add(x));
    b1[127] = 0u8.wrapping_sub(s1);

    // Block 2: DisplayID 2.0 extension with two Type VII (0x22) timings: 2560x1440@240Hz and 2560x1440@540Hz.
    let b2 = &mut edid[256..384];
    b2[0] = 0x70; // DisplayID extension
    b2[1] = 0x20; // DisplayID 2.0
    b2[2] = 43; // payload length (3 header + 40 bytes of 2 Type VII descriptors)
    b2[3] = 0x00;
    b2[4] = 0x00;
    b2[5] = 0x22; // Type VII Detailed Timing block
    b2[6] = 0x00;
    b2[7] = 40; // 2 * 20 bytes
    let write_did7 = |dst: &mut [u8], pclk_khz: u32, pref: bool, ha: u32, hb: u32, hfp: u32, hsw: u32, va: u32, vb: u32, vfp: u32, vsw: u32| {
        let pc = pclk_khz - 1;
        dst[0] = (pc & 0xFF) as u8;
        dst[1] = ((pc >> 8) & 0xFF) as u8;
        dst[2] = ((pc >> 16) & 0xFF) as u8;
        dst[3] = if pref { 0x80 } else { 0x00 };
        dst[4..6].copy_from_slice(&((ha - 1) as u16).to_le_bytes());
        dst[6..8].copy_from_slice(&((hb - 1) as u16).to_le_bytes());
        dst[8..10].copy_from_slice(&(((hfp - 1) as u16) | 0x8000).to_le_bytes());
        dst[10..12].copy_from_slice(&((hsw - 1) as u16).to_le_bytes());
        dst[12..14].copy_from_slice(&((va - 1) as u16).to_le_bytes());
        dst[14..16].copy_from_slice(&((vb - 1) as u16).to_le_bytes());
        dst[16..18].copy_from_slice(&(((vfp - 1) as u16) | 0x8000).to_le_bytes());
        dst[18..20].copy_from_slice(&((vsw - 1) as u16).to_le_bytes());
    };
    // 2560x1440 @ 240.00 Hz: h_total=2640, v_total=1525, pclk = 966_240 kHz.
    write_did7(&mut b2[8..28], 966_240, true, 2560, 80, 16, 32, 1440, 85, 3, 5);
    // 2560x1440 @ 540.00 Hz: h_total=2640, v_total=1525, pclk = 2_174_040 kHz.
    write_did7(&mut b2[28..48], 2_174_040, false, 2560, 80, 16, 32, 1440, 85, 3, 5);
    let s2 = b2[..127].iter().fold(0u8, |a, &x| a.wrapping_add(x));
    b2[127] = 0u8.wrapping_sub(s2);

    edid
}

/// Default IP blocks matching a real GPU of `version` (distinct non-overlapping segment bases).
pub fn default_ip_blocks(version: DcnVersion) -> Vec<IpBlock> {
    let (dcn_maj, dcn_min, dcn_rev, mm_maj, ih_maj) = match version {
        DcnVersion::Dcn401 => (4, 0, 1, 4, 7),
        DcnVersion::Dcn315 => (3, 1, 5, 3, 6),
        DcnVersion::Dcn32 => (3, 2, 0, 3, 6),
        DcnVersion::Dcn30 => (3, 0, 0, 2, 5),
    };
    vec![
        IpBlock {
            hw_id: HWID_DCE,
            instance: 0,
            major: dcn_maj,
            minor: dcn_min,
            revision: dcn_rev,
            num_bases: 4,
            bases: [0x0000_0040, 0x0000_00C0, 0x0000_34C0, 0x0000_9000, 0, 0, 0, 0],
        },
        IpBlock {
            hw_id: HWID_MMHUB,
            instance: 0,
            major: mm_maj,
            minor: 0,
            revision: 0,
            num_bases: 2,
            bases: [0x0001_A000, 0x0001_C000, 0, 0, 0, 0, 0, 0],
        },
        IpBlock {
            hw_id: HWID_OSSSYS,
            instance: 0,
            major: ih_maj,
            minor: 0,
            revision: 0,
            num_bases: 1,
            bases: [0x0000_10A0, 0, 0, 0, 0, 0, 0, 0],
        },
        IpBlock {
            hw_id: HWID_NBIO,
            instance: 0,
            major: 6,
            minor: 3,
            revision: 1,
            num_bases: 3,
            bases: [0x0000_0000, 0x0000_0014, 0x0000_0D20, 0, 0, 0, 0, 0],
        },
        IpBlock {
            hw_id: HWID_GC,
            instance: 0,
            major: 12,
            minor: 0,
            revision: 1,
            num_bases: 1,
            bases: [0x0000_1260, 0, 0, 0, 0, 0, 0, 0],
        },
        IpBlock {
            hw_id: HWID_SDMA0,
            instance: 0,
            major: 7,
            minor: 0,
            revision: 0,
            num_bases: 1,
            bases: [0x0000_4980, 0, 0, 0, 0, 0, 0, 0],
        },
    ]
}

/// Simulated DCN hardware state for exhaustive host testing of 4a..4f.
pub struct DcnSim {
    pub access: DcnAccess,
    pub regs: BTreeMap<u64, u32>,
    /// If true, flips never latch into `EARLIEST_INUSE` (tests 3-frame self-check revert).
    pub stall_flip_latch: bool,
    /// Simulated DPCD register space (on AUX 0 by default).
    pub dpcd: BTreeMap<u32, u8>,
    /// Simulated EDID ROM (1..=4 blocks) served over I2C-over-AUX 0x50.
    pub edid_rom: Vec<u8>,
    pub edid_segment: u8,
    pub edid_offset: u8,
    /// AUX channel index with a connected monitor (None = disconnected).
    pub connected_aux: Option<u8>,
    /// Remaining synthetic AUX DEFER replies to inject before ACKing.
    pub inject_defers: usize,
    aux_tx_fifo: [u8; 20],
    aux_rx_fifo: [u8; 20],
    aux_rx_len: usize,
    aux_rx_idx: Cell<usize>,
    /// Simulated OSSSYS IH ring buffer (DMA target) + wptr writeback value.
    pub ih_ring: Vec<u8>,
    pub ih_wptr_wb: u32,
}

impl DcnSim {
    pub fn new(version: DcnVersion, fb_base: u64, vram_size: u64) -> Self {
        let blocks = default_ip_blocks(version);
        let dcn = blocks[0];
        let mmhub = Some(blocks[1]);
        let osssys = Some(blocks[2]);
        let nbif = Some(blocks[3]);
        let access = DcnAccess::new(version, dcn, mmhub, osssys, nbif);

        let mut sim = Self {
            access,
            regs: BTreeMap::new(),
            stall_flip_latch: false,
            dpcd: BTreeMap::new(),
            edid_rom: build_high_refresh_edid(),
            edid_segment: 0,
            edid_offset: 0,
            connected_aux: Some(0),
            inject_defers: 0,
            aux_tx_fifo: [0; 20],
            aux_rx_fifo: [0; 20],
            aux_rx_len: 0,
            aux_rx_idx: Cell::new(0),
            ih_ring: vec![0u8; 4096],
            ih_wptr_wb: 0,
        };

        // Program MMHUB FB_LOCATION_BASE / TOP / OFFSET.
        let base_field = ((fb_base >> 24) & 0x00FF_FFFF) as u32;
        let top_field = (((fb_base + vram_size - 1) >> 24) & 0x00FF_FFFF) as u32;
        sim.set_mmhub(access.regs.mmhub_fb_location_base(), base_field);
        sim.set_mmhub(access.regs.mmhub_fb_location_top(), top_field);
        sim.set_mmhub(access.regs.mmhub_fb_offset(), 0);

        // Populate realistic DP 2.1 + DSC sink DPCD (4 lanes HBR3 active, UHBR20 + DSC capable).
        let dpcd_init: &[(u32, u8)] = &[
            (0x000, 0x14), // DP 1.4+
            (0x001, 0x1E), // max HBR3 (8.1 Gbps) in base caps
            (0x002, 0x84), // 4 lanes + enhanced framing
            (0x00E, 0x80), // extended receiver caps present at 0x2200
            (0x060, 0x01), // DSC supported
            (0x061, 0x12), // DSC 1.2
            (0x100, 0x1E), // active link BW = HBR3 (8.1 Gbps)
            (0x101, 0x84), // active 4 lanes
            (0x108, 0x01), // 8b/10b
            (0x160, 0x00), // DSC currently off
            (0x202, 0x77), // lanes 0-1 CR+EQ+SYM locked
            (0x203, 0x77), // lanes 2-3 CR+EQ+SYM locked
            (0x204, 0x01), // interlane align done
            (0x2215, 0x07), // UHBR10 | UHBR20 | UHBR13.5 capable
        ];
        for &(a, v) in dpcd_init {
            sim.dpcd.insert(a, v);
        }

        sim
    }

    fn set_dcn(&mut self, reg: RegAddr, val: u32) {
        if let Some(off) = self.access.dcn.reg_byte(usize::from(reg.base_idx), reg.off) {
            self.regs.insert(off, val);
        }
    }

    fn set_mmhub(&mut self, reg: RegAddr, val: u32) {
        if let Some(off) = self.access.mmhub.and_then(|b| b.reg_byte(usize::from(reg.base_idx), reg.off)) {
            self.regs.insert(off, val);
        }
    }

    /// Configure `pipe` as an active UEFI GOP scanout pipe with exact OTG timing & HUBP surface.
    pub fn setup_active_pipe(&mut self, pipe: u8, timing: &DetailedTiming, pitch_pixels: u32, mc_addr: u64) {
        let r = self.access.regs;
        let otg = OtgTiming::from_detailed(timing);
        self.set_dcn(r.otg_control(pipe), 1 | (1 << 16)); // OTG_MASTER_EN + CURRENT_STATE
        self.set_dcn(r.otg_h_total(pipe), otg.h_total - 1);
        self.set_dcn(r.otg_h_blank(pipe), (otg.h_blank_start & 0x7FFF) | ((otg.h_blank_end & 0x7FFF) << 16));
        self.set_dcn(r.otg_h_sync_a(pipe), (otg.h_sync_width & 0x7FFF) << 16);
        self.set_dcn(r.otg_h_sync_a_cntl(pipe), u32::from(!otg.h_sync_pos));
        self.set_dcn(r.otg_v_total(pipe), otg.v_total - 1);
        self.set_dcn(r.otg_v_blank(pipe), (otg.v_blank_start & 0x7FFF) | ((otg.v_blank_end & 0x7FFF) << 16));
        self.set_dcn(r.otg_v_sync_a(pipe), (otg.v_sync_width & 0x7FFF) << 16);
        self.set_dcn(r.otg_v_sync_a_cntl(pipe), u32::from(!otg.v_sync_pos));
        self.set_dcn(r.otg_status_frame_count(pipe), 10);
        self.set_dcn(r.otg_status_position(pipe), otg.v_active / 2);

        self.set_dcn(r.hubp_cntl(pipe), 0); // HUBP_BLANK_EN = 0 (unblanked)
        self.set_dcn(r.hubp_surface_config(pipe), DCN_FMT_ARGB8888);
        self.set_dcn(r.hubp_viewport_dim(pipe), otg.h_active | (otg.v_active << 16));
        self.set_dcn(r.hubp_surface_pitch(pipe), pitch_pixels.saturating_sub(1));
        self.set_dcn(r.hubp_ret_control(pipe), 0);
        let (lo, hi) = encode_surface_addr(mc_addr);
        self.set_dcn(r.hubp_primary_addr(pipe), lo);
        self.set_dcn(r.hubp_primary_addr_hi(pipe), hi);
        self.set_dcn(r.hubp_earliest_inuse(pipe), lo);
        self.set_dcn(r.hubp_earliest_inuse_hi(pipe), hi);
        self.set_dcn(r.hubp_flip_control(pipe), 0);
    }

    /// Push one 32-byte IV packet into the simulated OSSSYS IH ring if IH is enabled.
    fn push_iv(&mut self, client_id: u8, src_id: u8, ts: u64) {
        let ih = self.access.regs.ih_regs();
        let cntl = self.access.r_ih(self, ih.rb_cntl).unwrap_or(0);
        if (cntl & 1) == 0 || self.ih_ring.len() < IH_IV_BYTES {
            return;
        }
        let mask = (self.ih_ring.len() - 1) as u32;
        let off = (self.ih_wptr_wb & mask & !31) as usize;
        let dw0 = u32::from(client_id) | (u32::from(src_id) << 8);
        let dw1 = ts as u32;
        let dw2 = ((ts >> 32) & 0xFFFF) as u32;
        self.ih_ring[off..off + 4].copy_from_slice(&dw0.to_le_bytes());
        self.ih_ring[off + 4..off + 8].copy_from_slice(&dw1.to_le_bytes());
        self.ih_ring[off + 8..off + 12].copy_from_slice(&dw2.to_le_bytes());
        self.ih_ring[off + 12..off + 32].fill(0);
        self.ih_wptr_wb = (self.ih_wptr_wb + IH_IV_BYTES as u32) & mask;
        if let Some(wreg) = self.access.osssys.and_then(|b| b.reg_byte(usize::from(ih.rb_wptr.base_idx), ih.rb_wptr.off)) {
            self.regs.insert(wreg, self.ih_wptr_wb);
        }
    }

    /// Advance `pipe` by one vblank: increments `OTG_STATUS_FRAME_COUNT`, latches any pending
    /// surface address into `EARLIEST_INUSE` (unless `stall_flip_latch` is set), and emits IH IVs.
    pub fn advance_vblank(&mut self, pipe: u8) {
        let r = self.access.regs;
        let fc = self.access.r_dcn(self, r.otg_status_frame_count(pipe)).unwrap_or(0);
        let next_fc = (fc + 1) & 0x00FF_FFFF;
        self.set_dcn(r.otg_status_frame_count(pipe), next_fc);

        let flip_ctl = self.access.r_dcn(self, r.hubp_flip_control(pipe)).unwrap_or(0);
        let had_flip = (flip_ctl & (1 << 8)) != 0;
        if had_flip && !self.stall_flip_latch {
            let lo = self.access.r_dcn(self, r.hubp_primary_addr(pipe)).unwrap_or(0);
            let hi = self.access.r_dcn(self, r.hubp_primary_addr_hi(pipe)).unwrap_or(0);
            self.set_dcn(r.hubp_earliest_inuse(pipe), lo);
            self.set_dcn(r.hubp_earliest_inuse_hi(pipe), hi);
            self.set_dcn(r.hubp_flip_control(pipe), flip_ctl & !(1 << 8));
            let flip_int = self.access.r_dcn(self, r.hubp_flip_interrupt(pipe)).unwrap_or(0);
            if (flip_int & 1) != 0 {
                self.push_iv(IH_CLIENTID_DCE, DCN_SRCID_HUBP_FLIP_BASE + pipe, u64::from(next_fc) * 1000);
            }
        }
        let vint0 = self.access.r_dcn(self, r.otg_vert_int0_ctrl(pipe)).unwrap_or(0);
        if (vint0 & (1 << 8)) != 0 {
            self.push_iv(IH_CLIENTID_DCE, DCN_SRCID_OTG_VINT0_BASE + pipe, u64::from(next_fc) * 1000 + 1);
        }
    }

    /// Return the currently latched `EARLIEST_INUSE` MC address on `pipe`.
    pub fn latched_mc(&self, pipe: u8) -> u64 {
        let r = self.access.regs;
        let lo = self.access.r_dcn(self, r.hubp_earliest_inuse(pipe)).unwrap_or(0);
        let hi = self.access.r_dcn(self, r.hubp_earliest_inuse_hi(pipe)).unwrap_or(0);
        decode_surface_addr(lo, hi)
    }

    fn execute_aux(&mut self, aux: u8, wr_bytes: usize) {
        let r = self.access.regs;
        let status_reg = r.aux_sw_status(aux);
        if self.connected_aux != Some(aux) {
            self.set_dcn(status_reg, (1 << 0) | (1 << 9)); // DONE | HPD_DISCON
            return;
        }
        if self.inject_defers > 0 {
            self.inject_defers -= 1;
            let cmd = self.aux_tx_fifo[0] >> 4;
            let reply_hdr = if (cmd & 0x08) == 0 { 0x80u8 } else { 0x20u8 }; // I2C DEFER or Native DEFER
            self.aux_rx_fifo[0] = reply_hdr;
            self.aux_rx_len = 1;
            self.aux_rx_idx.set(0);
            self.set_dcn(status_reg, (1 << 0) | (1 << 24));
            return;
        }
        if wr_bytes < 3 {
            self.set_dcn(status_reg, (1 << 0) | (1 << 12));
            return;
        }
        let cmd = self.aux_tx_fifo[0] >> 4;
        let addr = (u32::from(self.aux_tx_fifo[0] & 0x0F) << 16)
            | (u32::from(self.aux_tx_fifo[1]) << 8)
            | u32::from(self.aux_tx_fifo[2]);
        let req_len = if wr_bytes >= 4 { usize::from(self.aux_tx_fifo[3]) + 1 } else { 0 };

        self.aux_rx_fifo[0] = 0x00; // ACK
        self.aux_rx_len = 1;
        self.aux_rx_idx.set(0);

        match cmd {
            0x9 => {
                // Native DPCD read.
                for i in 0..req_len.min(16) {
                    self.aux_rx_fifo[1 + i] = *self.dpcd.get(&(addr + i as u32)).unwrap_or(&0);
                }
                self.aux_rx_len = 1 + req_len.min(16);
            }
            0x8 => {
                // Native DPCD write (also simulates link training CR/EQ status lock).
                for i in 0..req_len.min(16) {
                    if 4 + i < wr_bytes {
                        let a = addr + i as u32;
                        let v = self.aux_tx_fifo[4 + i];
                        self.dpcd.insert(a, v);
                        if a == 0x102 && v != 0 {
                            // Link training pattern active -> mark lanes locked.
                            self.dpcd.insert(0x202, 0x77);
                            self.dpcd.insert(0x203, 0x77);
                            self.dpcd.insert(0x204, 0x01);
                        }
                    }
                }
            }
            0x0 | 0x4 => {
                // I2C write (0x30 = E-DDC segment, 0x50 = EDID byte offset).
                if addr == 0x30 && req_len >= 1 && wr_bytes >= 5 {
                    self.edid_segment = self.aux_tx_fifo[4];
                } else if addr == 0x50 && req_len >= 1 && wr_bytes >= 5 {
                    self.edid_offset = self.aux_tx_fifo[4];
                }
            }
            0x1 | 0x5 => {
                // I2C read from EDID ROM (0x50).
                if addr == 0x50 && req_len > 0 {
                    let base = usize::from(self.edid_segment) * 256 + usize::from(self.edid_offset);
                    for i in 0..req_len.min(16) {
                        self.aux_rx_fifo[1 + i] = *self.edid_rom.get(base + i).unwrap_or(&0);
                    }
                    self.edid_offset = self.edid_offset.wrapping_add(req_len.min(16) as u8);
                    self.aux_rx_len = 1 + req_len.min(16);
                }
                if cmd == 0x1 && req_len == 0 {
                    self.edid_segment = 0;
                    self.edid_offset = 0;
                }
            }
            _ => {
                self.aux_rx_fifo[0] = 0x10; // NACK
            }
        }
        self.set_dcn(status_reg, (1 << 0) | ((self.aux_rx_len as u32) << 24));
    }
}

impl RegIo for DcnSim {
    fn r32(&self, byte_off: u64) -> Option<u32> {
        let r = self.access.regs;
        for aux in 0..r.max_aux() {
            if self.access.dcn.reg_byte(usize::from(r.aux_sw_data(aux).base_idx), r.aux_sw_data(aux).off) == Some(byte_off) {
                let idx = self.aux_rx_idx.get();
                let b = if idx < self.aux_rx_len { self.aux_rx_fifo[idx] } else { 0 };
                self.aux_rx_idx.set(idx + 1);
                return Some(1u32 | (u32::from(b) << 8) | ((idx as u32) << 16));
            }
        }
        Some(*self.regs.get(&byte_off).unwrap_or(&0))
    }

    fn w32(&mut self, byte_off: u64, val: u32) {
        let r = self.access.regs;

        // Check HUBP primary surface address LOW writes: mark flip pending (or latch immediately if FLIP_TYPE=1).
        for pipe in 0..r.max_pipes() {
            let addr_reg = r.hubp_primary_addr(pipe);
            if self.access.dcn.reg_byte(usize::from(addr_reg.base_idx), addr_reg.off) == Some(byte_off) {
                self.regs.insert(byte_off, val);
                let flip_ctl = self.access.r_dcn(self, r.hubp_flip_control(pipe)).unwrap_or(0);
                if (flip_ctl & (1 << 1)) != 0 {
                    // Immediate flip: latch right away unless stalled.
                    if !self.stall_flip_latch {
                        let hi = self.access.r_dcn(self, r.hubp_primary_addr_hi(pipe)).unwrap_or(0);
                        self.set_dcn(r.hubp_earliest_inuse(pipe), val);
                        self.set_dcn(r.hubp_earliest_inuse_hi(pipe), hi);
                    }
                } else {
                    // Vsync flip: set SURFACE_FLIP_PENDING (bit 8) until `advance_vblank(pipe)`.
                    self.set_dcn(r.hubp_flip_control(pipe), flip_ctl | (1 << 8));
                }
                return;
            }
        }

        // Check DP AUX registers.
        for aux in 0..r.max_aux() {
            let arb = r.aux_arb_control(aux);
            if self.access.dcn.reg_byte(usize::from(arb.base_idx), arb.off) == Some(byte_off) {
                if (val & (1 << 16)) != 0 {
                    // Grant SW arbitration: REG_RW_CNTL_STATUS = 1 at bits [3:2].
                    self.regs.insert(byte_off, (val & !0xC) | (1 << 2));
                } else if (val & (1 << 17)) != 0 {
                    self.regs.insert(byte_off, 0);
                } else {
                    self.regs.insert(byte_off, val);
                }
                return;
            }
            let data = r.aux_sw_data(aux);
            if self.access.dcn.reg_byte(usize::from(data.base_idx), data.off) == Some(byte_off) {
                if (val & 1) != 0 {
                    // Switch to read mode at `INDEX`.
                    self.aux_rx_idx.set(((val >> 16) & 0x1F) as usize);
                } else {
                    let idx = ((val >> 16) & 0x1F) as usize;
                    if idx < self.aux_tx_fifo.len() {
                        self.aux_tx_fifo[idx] = ((val >> 8) & 0xFF) as u8;
                    }
                }
                self.regs.insert(byte_off, val);
                return;
            }
            let swc = r.aux_sw_control(aux);
            if self.access.dcn.reg_byte(usize::from(swc.base_idx), swc.off) == Some(byte_off) {
                self.regs.insert(byte_off, val);
                if (val & 1) != 0 {
                    let wr_bytes = ((val >> 16) & 0x1F) as usize;
                    self.execute_aux(aux, wr_bytes);
                }
                return;
            }
        }

        self.regs.insert(byte_off, val);
    }
}
