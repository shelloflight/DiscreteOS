//! Host unit tests, simulated DCN hardware verification, and fuzzers for `dosgpu` (`gpu-host`).

use super::*;
use std::vec;
use std::vec::Vec;

use edid::DetailedTiming;
use amd::dp_aux::{AuxError, dpcd_rate_label, probe_dp_aux_readonly, train_dp_link};
use amd::dcn::{
    ActivePipe, DcnAccess, DcnVersion, FbWindow, GopInfo, RegIo, allocate_scanout_buffers,
    decode_surface_addr, encode_surface_addr, measure_refresh_mhz, probe_active_pipes,
};
use amd::flip::{
    CursorSize, FlipEngine, FlipError, FlipPoll, HwCursor, IhController, IhEvent, ModeBandwidthPlan,
    SelfCheckReason, SelfCheckState, encode_dsc_1_2_pps, plan_mode_bandwidth, program_mode_regs,
    set_hdr, set_vrr,
};
use amd::sim::{DcnSim, build_discovery_image, build_high_refresh_edid, default_ip_blocks};

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn fill(&mut self, buf: &mut [u8]) {
        for b in buf.iter_mut() {
            *b = self.next() as u8;
        }
    }
}

fn make_valid_edid(w: u32, h: u32, name: &[u8]) -> [u8; 128] {
    let mut b = [0u8; 128];
    b[0..8].copy_from_slice(&[0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00]);
    // Manufacturer "DOS": D=4, O=15, S=19 -> (4<<10)|(15<<5)|19 = 0x11F3
    b[8] = 0x11;
    b[9] = 0xF3;
    b[10] = 0x70;
    b[11] = 0x90;
    b[18] = 1;
    b[19] = 4;
    b[21] = 60;
    b[22] = 34;
    // Established timings: 1024x768@60 + 800x600@60
    b[35] = 1;
    b[36] = 1 << 3;
    // DTD 0 at offset 54: pixel clock ~65 MHz (6500 * 10 kHz), h_blank=160, v_blank=30
    let pclk: u16 = 6500;
    b[54..56].copy_from_slice(&pclk.to_le_bytes());
    b[56] = (w & 0xFF) as u8;
    b[57] = 160;
    b[58] = (((w >> 8) & 0xF) << 4) as u8;
    b[59] = (h & 0xFF) as u8;
    b[60] = 30;
    b[61] = (((h >> 8) & 0xF) << 4) as u8;
    // Monitor name descriptor at offset 72
    b[75] = 0xFC;
    let n = name.len().min(13);
    b[77..77 + n].copy_from_slice(&name[..n]);
    if n < 13 {
        b[77 + n] = 0x0A;
    }
    let sum = b[..127].iter().fold(0u8, |a, &x| a.wrapping_add(x));
    b[127] = 0u8.wrapping_sub(sum);
    b
}

#[test]
fn edid_parse_valid_and_high_refresh_extensions() {
    let raw = make_valid_edid(1920, 1080, b"D-OS Monitor");
    let info = edid::parse_edid(&raw).unwrap();
    assert_eq!(info.manufacturer_str(), "DOS");
    assert_eq!(info.name_str(), "D-OS Monitor");
    assert_eq!(info.width_cm, 60);
    assert_eq!(info.height_cm, 34);
    assert!(info.mode_count >= 1);
    assert_eq!((info.modes()[0].width, info.modes()[0].height), (1920, 1080));
    assert!(info.modes()[0].preferred);

    // Multi-block EDID with CTA-861 HDR10 + FreeSync + DisplayID 2.0 240 Hz & 540 Hz timings.
    let hr = build_high_refresh_edid();
    let hr_info = edid::parse_edid(&hr).unwrap();
    assert_eq!(hr_info.name_str(), "RX9070-540Hz");
    assert_eq!(hr_info.ext_blocks, 2);
    assert!(hr_info.hdr_supported);
    assert!(hr_info.hdr_max_nits >= 700);
    assert_eq!((hr_info.vrr_min_hz, hr_info.vrr_max_hz), (48, 240));
    assert!(hr_info.timings().iter().any(|t| t.h_active == 2560 && t.v_active == 1440 && (239_000..=241_000).contains(&t.refresh_mhz)));
    assert!(hr_info.timings().iter().any(|t| t.h_active == 2560 && t.v_active == 1440 && (539_000..=541_000).contains(&t.refresh_mhz)));
    let best = hr_info.highest_refresh_for(2560, 1440).unwrap();
    assert!((539_000..=541_000).contains(&best.refresh_mhz));

    // Bad checksum refused
    let mut bad = raw;
    bad[127] ^= 1;
    assert_eq!(edid::parse_edid(&bad), Err(edid::EdidError::BadChecksum));
    // Bad header refused
    let mut bad_hdr = raw;
    bad_hdr[0] = 0xFF;
    assert_eq!(edid::parse_edid(&bad_hdr), Err(edid::EdidError::BadHeader));
    // Truncated refused
    assert_eq!(edid::parse_edid(&raw[..64]), Err(edid::EdidError::TooShort));
}

#[test]
fn damage_rect_buffer_age_and_blit_wc() {
    let r = DamageRect { x: 50, y: 40, w: 200, h: 100 }.clip(100, 80).unwrap();
    assert_eq!(r, DamageRect { x: 50, y: 40, w: 50, h: 40 });
    assert_eq!(DamageRect { x: 100, y: 0, w: 10, h: 10 }.clip(100, 80), None);
    let u = DamageRect { x: 10, y: 20, w: 30, h: 40 }.union(DamageRect { x: 25, y: 10, w: 50, h: 20 });
    assert_eq!(u, DamageRect { x: 10, y: 10, w: 65, h: 50 });

    // Double-buffered buffer-age tracking: never copies full frame after warmup.
    let mut age = BufferAgeTracker::new(2, 2560, 1440);
    let mut out = [DamageRect::EMPTY; 16];
    let d0 = [DamageRect { x: 10, y: 10, w: 40, h: 40 }];
    // Buffer 0 starts dirty -> full copy once.
    assert_eq!(age.collect_for_buffer(0, &d0, &mut out), 1);
    assert_eq!(out[0], DamageRect::full(2560, 1440));
    age.commit_buffer(0, &d0);

    // Buffer 1 starts dirty -> full copy once.
    let d1 = [DamageRect { x: 100, y: 100, w: 50, h: 50 }];
    assert_eq!(age.collect_for_buffer(1, &d1, &mut out), 1);
    assert_eq!(out[0], DamageRect::full(2560, 1440));
    age.commit_buffer(1, &d1);

    // Now buffer 0 is age 1: needs d1 (frame 1) + d2 (current), NOT full frame!
    let d2 = [DamageRect { x: 500, y: 500, w: 20, h: 20 }];
    let n = age.collect_for_buffer(0, &d2, &mut out);
    assert_eq!(n, 2);
    let total_px: u64 = out[..n].iter().map(|r| r.area()).sum();
    assert_eq!(total_px, 50 * 50 + 20 * 20);
    assert!(total_px < 2560 * 1440 / 100);
    age.commit_buffer(0, &d2);

    // Triple-buffered buffer-age tracking: buffer 0 at age 2 gets union of d1 + d2 + d3.
    let mut age3 = BufferAgeTracker::new(3, 1920, 1080);
    age3.commit_buffer(0, &[DamageRect { x: 0, y: 0, w: 10, h: 10 }]);
    age3.commit_buffer(1, &[DamageRect { x: 50, y: 0, w: 10, h: 10 }]);
    age3.commit_buffer(2, &[DamageRect { x: 100, y: 0, w: 10, h: 10 }]);
    let d3 = [DamageRect { x: 150, y: 0, w: 10, h: 10 }];
    let n3 = age3.collect_for_buffer(0, &d3, &mut out);
    assert_eq!(n3, 3); // frames 1, 2, and current d3

    // 4x2 XRGB8888 source -> BGR shifts [0, 8, 16] and HDR10 ARGB2101010 conversion.
    let mut src = [0u8; 4 * 2 * 4];
    src[0..4].copy_from_slice(&0x0011_2233u32.to_le_bytes()); // R=0x11, G=0x22, B=0x33
    let mut written = Vec::new();
    let n = blit_rect_wc(
        &src,
        16,
        PixelFormat::Xrgb8888,
        16,
        [0, 8, 16],
        4,
        2,
        DamageRect { x: 0, y: 0, w: 1, h: 1 },
        |off, px| written.push((off, px)),
    );
    assert_eq!(n, 1);
    assert_eq!(written, vec![(0, 0x0033_2211)]);

    let hdr_px = convert_pixel_to_argb2101010(0x00FF_8000, PixelFormat::Xrgb8888);
    assert_eq!((hdr_px >> 30) & 3, 3);
    assert_eq!((hdr_px >> 20) & 0x3FF, 1023);
    assert_eq!(hdr_px & 0x3FF, 0);
}

#[test]
fn virtio_gpu_2d_and_virgl_roundtrip() {
    let mut buf = [0u8; 512];
    assert_eq!(virtio::encode_get_display_info(&mut buf), Some(24));
    assert_eq!(virtio::encode_resource_create_2d(&mut buf, 1, virtio::FORMAT_B8G8R8X8_UNORM, 1024, 768), Some(40));
    assert_eq!(virtio::encode_resource_attach_backing(&mut buf, 1, &[(0x10000, 4096), (0x20000, 4096)]), Some(64));
    assert_eq!(virtio::encode_set_scanout(&mut buf, 0, 0, 1024, 768, 0, 1), Some(48));
    assert_eq!(virtio::encode_transfer_to_host_2d(&mut buf, 0, 0, 64, 64, 0, 1), Some(56));
    assert_eq!(virtio::encode_resource_flush(&mut buf, 0, 0, 64, 64, 1), Some(48));
    assert_eq!(virtio::encode_cursor(&mut buf, true, 0, 100, 200, 2, 0, 0), Some(56));

    // Build and validate VirGL 3D command stream
    let mut words = [0u32; 16];
    let n1 = virtio::virgl_cmd_nop(&mut words).unwrap();
    let n2 = virtio::virgl_cmd_clear(&mut words[n1..], 1, [0.1, 0.2, 0.3, 1.0], 1.0, 0).unwrap();
    let mut cs = Vec::new();
    for &w in &words[..n1 + n2] {
        cs.extend_from_slice(&w.to_le_bytes());
    }
    assert_eq!(virtio::validate_virgl_cs(&cs), Ok(2));

    // Reject unknown opcode & bad CLEAR length
    let bad_op = virtio::virgl_hdr(0xFE, 0, 0).to_le_bytes();
    assert_eq!(virtio::validate_virgl_cs(&bad_op), Err(CsError::UnknownOpcode));
    let bad_clr = virtio::virgl_hdr(virtio::VIRGL_CCMD_CLEAR, 0, 2).to_le_bytes();
    let mut bad_clr_buf = Vec::from(bad_clr);
    bad_clr_buf.extend_from_slice(&[0u8; 8]);
    assert_eq!(virtio::validate_virgl_cs(&bad_clr_buf), Err(CsError::BadArgument));
}

#[test]
fn amd_ip_discovery_v1_v2_v4_and_cs_validators() {
    let rx9070 = amd::identify_pci(0x7550);
    assert_eq!(rx9070.family, amd::AmdFamily::Rdna4);
    assert_eq!(rx9070.gfx_major, 12);
    assert_eq!(rx9070.dcn_major, 4);
    assert_eq!(rx9070.dcn_hint(), DcnVersion::Dcn401);
    assert!(rx9070.name.contains("RX 9070"));

    let igpu = amd::identify_pci(0x13C0);
    assert_eq!(igpu.family, amd::AmdFamily::Rdna2);
    assert!(igpu.is_apu);
    assert_eq!(igpu.dcn_hint(), DcnVersion::Dcn315);

    // Real IP Discovery v1 (32-bit bases) and v2 + 64-bit v4 bases + MEM_RESERVED_INFO.
    let blocks = default_ip_blocks(DcnVersion::Dcn401);
    for &(ver_maj, b64) in &[(1u16, false), (2u16, false), (2u16, true)] {
        let img = build_discovery_image(ver_maj, b64, &blocks, &[(0x100_0000, 0x20_0000)]);
        let disc = amd::parse_ip_discovery(&img).unwrap();
        assert_eq!(disc.dcn_version(), Some(DcnVersion::Dcn401));
        let dcn_blk = disc.find(amd::HWID_DCE, 0).unwrap();
        assert_eq!((dcn_blk.major, dcn_blk.minor, dcn_blk.revision), (4, 0, 1));
        assert_eq!(dcn_blk.base(1), Some(0x0000_00C0));
        assert_eq!(dcn_blk.base(2), Some(0x0000_34C0));
        assert_eq!(disc.find(amd::HWID_MMHUB, 0).unwrap().major, 4);
        assert_eq!(disc.find(amd::HWID_OSSSYS, 0).unwrap().major, 7);
        assert_eq!(disc.find(amd::HWID_NBIO, 0).unwrap().base(2), Some(0x0000_0D20));
        assert_eq!(disc.reserved().len(), 1);
        assert_eq!(disc.reserved()[0].offset, 0x100_0000);
        assert_eq!(disc.reserved()[0].size, 0x20_0000);
    }

    // PM4 & SDMA command validation including 2D sub-window GPU composition builder.
    let mut pm4 = [0u32; 12];
    let n1 = amd::pm4_nop(&mut pm4, 0x1234).unwrap();
    let n2 = amd::pm4_release_mem_fence(&mut pm4[n1..], 0x10000, 42).unwrap();
    let mut pm4_bytes = Vec::new();
    for &w in &pm4[..n1 + n2] {
        pm4_bytes.extend_from_slice(&w.to_le_bytes());
    }
    assert_eq!(amd::validate_pm4_cs(&pm4_bytes), Ok(2));

    // Privileged PM4 WRITE_DATA must be refused.
    let bad_pm4 = [amd::pm4_hdr(amd::PM4_WRITE_DATA, 1), 0];
    let mut bad_bytes = Vec::new();
    for w in bad_pm4 {
        bad_bytes.extend_from_slice(&w.to_le_bytes());
    }
    assert_eq!(amd::validate_pm4_cs(&bad_bytes), Err(CsError::UnknownOpcode));

    let mut sdma = [0u32; 64];
    let comp_dw = amd::build_sdma_composite_rects(
        &mut sdma,
        0x1000_0000,
        2560,
        0x2000_0000,
        2560,
        2560,
        1440,
        &[DamageRect { x: 16, y: 32, w: 200, h: 100 }, DamageRect { x: 400, y: 500, w: 64, h: 64 }],
        0x3000_0000,
        9,
    )
    .unwrap();
    let mut sdma_bytes = Vec::new();
    for &w in &sdma[..comp_dw] {
        sdma_bytes.extend_from_slice(&w.to_le_bytes());
    }
    assert_eq!(amd::validate_sdma_cs(&sdma_bytes), Ok(3)); // 2 sub-window copies + 1 fence
}

#[test]
fn dcn_all_generations_probe_mc_vram_and_gop_match() {
    let fb_base = 0x0000_0080_0000_0000u64; // Typical 512 GiB MC aperture base on RDNA 4
    let bar0_phys = 0x0000_00FC_0000_0000u64;
    let vram_size = 16u64 << 30; // 16 GiB RX 9070
    let gop_vram_off = 0x0040_0000u64; // 4 MiB into VRAM
    let gop_mc = fb_base + gop_vram_off;

    let timing = DetailedTiming {
        pixel_clock_khz: 966_240,
        h_active: 2560,
        h_blank: 80,
        h_front_porch: 16,
        h_sync_width: 32,
        v_active: 1440,
        v_blank: 85,
        v_front_porch: 3,
        v_sync_width: 5,
        h_sync_pos: true,
        v_sync_pos: true,
        refresh_mhz: 240_000,
        preferred: true,
    };

    let gop = GopInfo {
        phys_base: bar0_phys + gop_vram_off,
        size: 2560 * 1440 * 4,
        width: 2560,
        height: 1440,
        pitch: 2560 * 4,
        red_shift: 16,
        green_shift: 8,
        blue_shift: 0,
    };

    for ver in [DcnVersion::Dcn401, DcnVersion::Dcn315, DcnVersion::Dcn32, DcnVersion::Dcn30] {
        let mut sim = DcnSim::new(ver, fb_base, vram_size);
        // Active pipe 0 (GOP monitor) + active pipe 2 (secondary monitor, multi-monitor 4f).
        sim.setup_active_pipe(0, &timing, 2560, gop_mc);
        sim.setup_active_pipe(2, &timing, 2560, fb_base + 0x0400_0000);

        let fb_win = FbWindow::read(&sim, &sim.access, vram_size).unwrap();
        assert_eq!(fb_win.fb_base, fb_base);
        assert_eq!(fb_win.mc_to_vram(gop_mc), Some(gop_vram_off));
        assert_eq!(fb_win.vram_to_mc(gop_vram_off), Some(gop_mc));
        assert_eq!(fb_win.mc_to_vram(fb_base - 0x1000), None); // out of window

        let mut pipes = [ActivePipe::default(); 6];
        let n = probe_active_pipes(&sim, &sim.access, Some(fb_win), bar0_phys, Some(&gop), &mut pipes);
        assert_eq!(n, 2, "version {:?}", ver);
        assert_eq!(pipes[0].pipe, 0);
        assert_eq!((pipes[0].width(), pipes[0].height()), (2560, 1440));
        assert_eq!(pipes[0].pitch_bytes, 2560 * 4);
        assert_eq!(pipes[0].vram_off, Some(gop_vram_off));
        assert!(pipes[0].gop_matched);
        assert_eq!(pipes[1].pipe, 2);
        assert!(!pipes[1].gop_matched);

        // Wrong GOP phys_base must NOT match.
        let wrong_gop = GopInfo { phys_base: bar0_phys + 0x0800_0000, ..gop };
        assert!(!pipes[0].check_gop_match(bar0_phys, &wrong_gop));
    }

    // Exact refresh-rate measurement from OTG frame counter.
    assert_eq!(measure_refresh_mhz(24, 100_000_000), Some(240_000));
    assert_eq!(measure_refresh_mhz(54, 100_000_000), Some(540_000));
    assert_eq!(measure_refresh_mhz(6, 100_000_000), Some(60_000));
    assert_eq!(measure_refresh_mhz(0, 100_000_000), None);
}

#[test]
fn dcn_sim_flip_state_machine_self_check_revert_and_crash_recovery() {
    let fb_base = 0x0000_0080_0000_0000u64;
    let vram_size = 16u64 << 30;
    let bar0_size = 16u64 << 30;
    let gop_vram_off = 0x0040_0000u64;
    let gop_mc = fb_base + gop_vram_off;

    let timing = DetailedTiming {
        pixel_clock_khz: 966_240,
        h_active: 2560,
        h_blank: 80,
        h_front_porch: 16,
        h_sync_width: 32,
        v_active: 1440,
        v_blank: 85,
        v_front_porch: 3,
        v_sync_width: 5,
        h_sync_pos: true,
        v_sync_pos: true,
        refresh_mhz: 240_000,
        preferred: true,
    };

    let mut sim = DcnSim::new(DcnVersion::Dcn401, fb_base, vram_size);
    sim.setup_active_pipe(0, &timing, 2560, gop_mc);
    let access = sim.access;
    let fb_win = FbWindow::read(&sim, &access, vram_size).unwrap();

    // Allocate 3 scanout buffers + cursor adjacent to GOP FB, avoiding reserved top VRAM.
    let layout = allocate_scanout_buffers(
        gop_vram_off,
        2560 * 1440 * 4,
        2560 * 4,
        1440,
        bar0_size,
        vram_size,
        &[amd::ReservedMemRegion { offset: 0x0200_0000, size: 0x10_0000 }],
        true,
    )
    .unwrap();
    assert_eq!(layout.buf_count, 3);
    assert!(layout.buffers[0] >= gop_vram_off + 2560 * 1440 * 4);
    assert!(layout.cursor_vram_off + layout.cursor_size_bytes < vram_size - amd::dcn::TOP_VRAM_RESERVE);

    // 1. Self-check failure path: latch stalls -> after 3 frames, must restore GOP MC addr!
    sim.stall_flip_latch = true;
    let mut eng_fail = FlipEngine::new(0, fb_win, layout, gop_mc, 2560, 1440, 240_000);
    assert!(matches!(eng_fail.self_check_start(&mut sim, &access), SelfCheckState::InProgress { .. }));
    sim.advance_vblank(0);
    assert!(matches!(eng_fail.self_check_poll(&mut sim, &access), SelfCheckState::InProgress { .. }));
    sim.advance_vblank(0);
    assert!(matches!(eng_fail.self_check_poll(&mut sim, &access), SelfCheckState::InProgress { .. }));
    sim.advance_vblank(0);
    assert_eq!(
        eng_fail.self_check_poll(&mut sim, &access),
        SelfCheckState::Failed(SelfCheckReason::NotLatchedWithin3Frames)
    );
    // Verify original GOP MC addr was written back to HUBP primary surface address.
    let lo = access.r_dcn(&sim, access.regs.hubp_primary_addr(0)).unwrap();
    let hi = access.r_dcn(&sim, access.regs.hubp_primary_addr_hi(0)).unwrap();
    assert_eq!(decode_surface_addr(lo, hi), gop_mc);

    // 2. Normal self-check pass + strict never-write-pending/on-screen invariant across 20 flips.
    sim.stall_flip_latch = false;
    sim.advance_vblank(0); // settle restored GOP
    assert_eq!(sim.latched_mc(0), gop_mc);

    let mut eng = FlipEngine::new(0, fb_win, layout, gop_mc, 2560, 1440, 240_000);
    eng.self_check_start(&mut sim, &access);
    sim.advance_vblank(0);
    assert_eq!(eng.self_check_poll(&mut sim, &access), SelfCheckState::Verified);
    assert_eq!(eng.on_screen_buf, Some(0));

    let mut dmg_out = [DamageRect::EMPTY; 16];
    for frame in 0..20u32 {
        let now_ns = u64::from(frame + 1) * 4_166_666;
        let b = eng.pick_draw_buffer(&sim, &access, now_ns).unwrap();
        // Hard invariant: never draw into the buffer currently on screen.
        assert_ne!(Some(b), eng.on_screen_buf);
        assert_ne!(eng.buffer_mc(b).unwrap(), sim.latched_mc(0));

        let cur_dmg = [DamageRect { x: (frame * 32) % 2400, y: 100, w: 64, h: 64 }];
        let dn = eng.damage_for_buffer(b, &cur_dmg, &mut dmg_out);
        assert!(dn >= 1);
        if frame >= 3 {
            // After initial buffer warmup, buffer-age damage must NEVER be full screen!
            let px: u64 = dmg_out[..dn].iter().map(|r| r.area()).sum();
            assert!(px < 2560 * 1440 / 50, "expected minimal buffer-age damage, got {} px", px);
        }

        eng.commit_vsync_flip(&mut sim, &access, b, &cur_dmg, now_ns).unwrap();
        // While flip is pending, pick_draw_buffer MUST refuse to start another overlapping flip!
        assert_eq!(eng.pick_draw_buffer(&sim, &access, now_ns), Err(FlipError::FlipInFlight));
        assert_eq!(eng.poll_flip_complete(&sim, &access, now_ns), FlipPoll::Pending);

        // Advance vblank -> flip completes cleanly and latches into EARLIEST_INUSE.
        sim.advance_vblank(0);
        assert_eq!(
            eng.poll_flip_complete(&sim, &access, now_ns + 4_166_666),
            FlipPoll::Completed { buf_idx: b, frames: u64::from(frame + 1), late: false }
        );
        assert_eq!(sim.latched_mc(0), eng.buffer_mc(b).unwrap());
    }

    // 3. Crash recovery: a newly spawned driver finds our own buffer on screen and restores GOP!
    let mut crashed_restart = FlipEngine::new(0, fb_win, layout, gop_mc, 2560, 1440, 240_000);
    assert!(crashed_restart.recover_if_crashed_own_buffer(&mut sim, &access));
    sim.advance_vblank(0);
    assert_eq!(sim.latched_mc(0), gop_mc);
    assert!(!crashed_restart.recover_if_crashed_own_buffer(&mut sim, &access));
}

#[test]
fn dcn_sim_dp_aux_edid_cursor_ih_modeset_vrr_hdr() {
    let fb_base = 0x0000_0080_0000_0000u64;
    let vram_size = 16u64 << 30;
    let mut sim = DcnSim::new(DcnVersion::Dcn401, fb_base, vram_size);
    let access = sim.access;
    let edid_ref = edid::parse_edid(&build_high_refresh_edid()).unwrap();
    let mode_240 = edid_ref.timings().iter().find(|t| (239_000..=241_000).contains(&t.refresh_mhz) && t.h_active == 2560).copied().unwrap();
    let mode_540 = edid_ref.timings().iter().find(|t| (539_000..=541_000).contains(&t.refresh_mhz) && t.h_active == 2560).copied().unwrap();

    sim.setup_active_pipe(0, &mode_240, 2560, fb_base + 0x40_0000);

    // 1. Read-only DP AUX probe with injected DEFER retries.
    sim.inject_defers = 3;
    let probe = probe_dp_aux_readonly(&mut sim, &access, 0, |_| {}).unwrap();
    assert_eq!(probe.link.active_lanes, 4);
    assert_eq!(probe.link.active_link_rate_mbps, 8_100);
    assert_eq!(dpcd_rate_label(probe.link.active_link_rate_mbps), "HBR3");
    assert!(probe.link.dsc_supported);
    assert!(probe.link.cr_done && probe.link.eq_done);
    assert_eq!(probe.edid_blocks_read, 3);
    let parsed_edid = probe.edid.unwrap();
    assert_eq!(parsed_edid.name_str(), "RX9070-540Hz");
    assert!(parsed_edid.hdr_supported);
    // Disconnected AUX channel returns Disconnected.
    assert_eq!(probe_dp_aux_readonly(&mut sim, &access, 1, |_| {}).unwrap_err(), AuxError::Disconnected);

    // 2. Bandwidth planning for 1440p@240 vs 1440p@540 + DSC 1.2 PPS + DP link training.
    assert_eq!(plan_mode_bandwidth(&probe.link, &mode_240, 8), ModeBandwidthPlan::FitsCurrentLink);
    // 1440p@540 Hz @ 24 bpp (~52 Gbps) exceeds HBR3 (25.9 Gbps), fits via DSC on HBR3!
    assert_eq!(
        plan_mode_bandwidth(&probe.link, &mode_540, 8),
        ModeBandwidthPlan::NeedsDscOnCurrentLink { target_bpp: 8 }
    );
    let pps = encode_dsc_1_2_pps(2560, 1440, 8, 8, 4);
    assert_eq!(pps[0], 0x12);
    let train = train_dp_link(&mut sim, &access, 0, 4, 0x02, true, |_| {}).unwrap(); // UHBR20
    assert!(train.cr_done && train.eq_done && train.is_uhbr);
    assert_eq!(train.link_rate_mbps, 20_000);

    // 3. Guarded mode setting (OTG + DCCG DP DTO + MSA + DSC) and clean revert.
    let saved = program_mode_regs(&mut sim, &access, 0, &mode_540, 100_000, true, 8, 8);
    assert_eq!(access.r_dcn(&sim, access.regs.otg_h_total(0)), Some(mode_540.h_total() - 1));
    assert_eq!(access.r_dcn(&sim, access.regs.dp_pixel_format(0)).unwrap() & 1, 1); // DSC enabled
    saved.restore(&mut sim, &access);
    assert_eq!(access.r_dcn(&sim, access.regs.dp_pixel_format(0)).unwrap() & 1, 0);

    // 4. VRR (FreeSync) and HDR10.
    let otg = amd::dcn::OtgTiming::read(&sim, &access, 0).unwrap();
    assert!(set_vrr(&mut sim, &access, 0, &otg, 240_000, 48, 240, true));
    assert_eq!(access.r_dcn(&sim, access.regs.otg_v_total_control(0)).unwrap() & 0x3, 0x3);
    set_hdr(&mut sim, &access, 0, true);
    assert_eq!(access.r_dcn(&sim, access.regs.hubp_surface_config(0)).unwrap() & 0x7F, amd::dcn::DCN_FMT_ARGB2101010);

    // 5. Hardware cursor (HUBP + DPP, bit-15 X position shift, off-screen clipping).
    let mut cur = HwCursor::new(0);
    cur.configure(&mut sim, &access, fb_base + 0x0800_0000, CursorSize::Px64, 4, 4, true, 2560, 1440);
    cur.move_pos(&mut sim, &access, 300, 150, 2560, 1440);
    let pos_reg = access.r_dcn(&sim, access.regs.cursor_position(0)).unwrap();
    assert_eq!((pos_reg >> 15) & 0x7FFF, 300);
    assert_eq!(pos_reg & 0x7FFF, 150);
    assert_eq!(access.r_dcn(&sim, access.regs.dpp_cursor_control(0)).unwrap() & 1, 1);
    cur.move_pos(&mut sim, &access, 3000, 150, 2560, 1440); // off-screen disables DPP cursor
    assert_eq!(access.r_dcn(&sim, access.regs.dpp_cursor_control(0)).unwrap() & 1, 0);

    // 6. OSSSYS 7.0 IH ring setup + vblank & flip-done 32-byte IV decoding.
    let mut ih = IhController::new(4096);
    assert!(ih.enable(&mut sim, &access, 0x1000_0000, 0x1000_1000, 0x1000_2000));
    ih.enable_pipe_irqs(&mut sim, &access, 0, otg.v_blank_start);
    // Trigger a flip and advance vblank -> both FlipDone and Vblank IVs appear in IH ring!
    let (lo, hi) = encode_surface_addr(fb_base + 0x0100_0000);
    access.w_dcn(&mut sim, access.regs.hubp_primary_addr_hi(0), hi);
    access.w_dcn(&mut sim, access.regs.hubp_primary_addr(0), lo);
    sim.advance_vblank(0);
    let ring_copy = sim.ih_ring.clone();
    let wptr_wb = sim.ih_wptr_wb;
    let mut events = Vec::new();
    let drained = ih.drain(&mut sim, &access, &ring_copy, Some(wptr_wb), |ev| events.push(ev));
    assert_eq!(drained, 2);
    assert!(matches!(events[0], IhEvent::FlipDone { pipe: 0, .. }));
    assert!(matches!(events[1], IhEvent::Vblank { pipe: 0, .. }));
    ih.disable(&mut sim, &access);
    assert!(!ih.active);
}

#[test]
fn intel_xe_and_nvidia_gsp_core() {
    assert_eq!(intel::identify_pci(0xE20B).arch, intel::IntelGen::Xe2);
    assert_eq!(intel::identify_pci(0x56A0).arch, intel::IntelGen::XeHpg);
    assert_eq!(intel::decode_pipe_srcsz((1919 << 16) | 1079), (1920, 1080));
    let mut mi = [0u32; 8];
    let m1 = intel::mi_flush_dw(&mut mi).unwrap();
    let m2 = intel::mi_store_data_imm(&mut mi[m1..], 0x10000, 99).unwrap();
    let mut mi_bytes = Vec::new();
    for &w in &mi[..m1 + m2] {
        mi_bytes.extend_from_slice(&w.to_le_bytes());
    }
    assert_eq!(intel::validate_mi_cs(&mi_bytes), Ok(2));

    let ada = nvidia::decode_boot_regs(0, 0x1920_00A1);
    assert_eq!(ada.arch, nvidia::NvidiaArch::Ada);
    assert!(ada.gsp_capable);
    let bw = nvidia::decode_boot_regs(0, 0x1B20_00A1);
    assert_eq!(bw.arch, nvidia::NvidiaArch::Blackwell);

    let mut rpc = [0u8; 128];
    let n = nvidia::encode_gsp_rpc(&mut rpc, 5, nvidia::NV_VGPU_MSG_FUNCTION_NOP, &[1, 2, 3, 4]).unwrap();
    assert_eq!(nvidia::validate_gsp_rpc(&rpc[..n]), Ok((5, nvidia::NV_VGPU_MSG_FUNCTION_NOP)));
    rpc[n - 1] ^= 0xFF;
    assert_eq!(nvidia::validate_gsp_rpc(&rpc[..n]), Err(CsError::BadArgument));
}

/// Arbitrary-register-value fuzzing target implementing `RegIo` for DCN register parsers.
struct FuzzRegs {
    seed: u64,
}
impl RegIo for FuzzRegs {
    fn r32(&self, byte_off: u64) -> Option<u32> {
        let mut x = self.seed ^ byte_off.wrapping_mul(0x9E37_79B9_7F4A_7C15);
        x ^= x >> 30;
        x = x.wrapping_mul(0xBF58_476D_1CE4_E5B9);
        x ^= x >> 27;
        Some(x as u32)
    }
    fn w32(&mut self, _byte_off: u64, val: u32) {
        self.seed ^= u64::from(val);
    }
}

#[test]
fn fuzz_all_gpu_parsers_validators_and_dcn_registers() {
    let mut rng = Rng(0xD056_0055_1234_5678);
    let mut buf = [0u8; 512];

    // 3,000 rounds EDID (1-block & multi-block) fuzzer
    for _ in 0..3_000 {
        let len = (rng.next() as usize) % buf.len();
        rng.fill(&mut buf[..len]);
        let _ = edid::parse_edid(&buf[..len]);
    }
    // 3,000 rounds VirtIO-GPU response + VirGL CS fuzzer
    for _ in 0..3_000 {
        let len = (rng.next() as usize) % buf.len();
        rng.fill(&mut buf[..len]);
        let _ = virtio::decode_display_info(&buf[..len]);
        let _ = virtio::decode_edid_resp(&buf[..len]);
        let _ = virtio::decode_capset_info(&buf[..len]);
        let _ = virtio::validate_virgl_cs(&buf[..len]);
    }
    // 3,000 rounds AMD IP Discovery + PM4 + SDMA + IH IV fuzzer
    for _ in 0..3_000 {
        let len = (rng.next() as usize) % buf.len();
        rng.fill(&mut buf[..len]);
        let _ = amd::parse_ip_discovery(&buf[..len]);
        let _ = amd::validate_pm4_cs(&buf[..len]);
        let _ = amd::validate_sdma_cs(&buf[..len]);
        let _ = amd::flip::decode_iv(&buf[..len]);
    }
    // 2,000 rounds arbitrary DCN/MMHUB/AUX register values fuzzer across all 4 DCN generations
    let vers = [DcnVersion::Dcn401, DcnVersion::Dcn315, DcnVersion::Dcn32, DcnVersion::Dcn30];
    let mut pipes = [ActivePipe::default(); 6];
    for i in 0..2_000 {
        let ver = vers[i % vers.len()];
        let blocks = default_ip_blocks(ver);
        let access = DcnAccess::new(ver, blocks[0], Some(blocks[1]), Some(blocks[2]), Some(blocks[3]));
        let mut fio = FuzzRegs { seed: rng.next() };
        let vram_sz = (rng.next() & 0x3_FFFF_FFFF).max(1 << 20);
        let win = FbWindow::read(&fio, &access, vram_sz);
        let _ = probe_active_pipes(&fio, &access, win, rng.next(), None, &mut pipes);
        let _ = allocate_scanout_buffers(
            rng.next() & 0x0FFF_FFFF,
            (rng.next() & 0x03FF_FFFF).max(4096),
            ((rng.next() as u32) & 0x7FFF).max(64),
            ((rng.next() as u32) & 0x1FFF).max(64),
            vram_sz,
            vram_sz,
            &[],
            (i & 1) == 0,
        );
        let _ = probe_dp_aux_readonly(&mut fio, &access, (i as u8) % access.regs.max_aux(), |_| {});
    }
    // 2,000 rounds Intel MI CS fuzzer
    for _ in 0..2_000 {
        let len = (rng.next() as usize) % buf.len();
        rng.fill(&mut buf[..len]);
        let _ = intel::validate_mi_cs(&buf[..len]);
    }
    // 2,000 rounds NVIDIA Open-GSP RPC fuzzer
    for _ in 0..2_000 {
        let len = (rng.next() as usize) % buf.len();
        rng.fill(&mut buf[..len]);
        let _ = nvidia::validate_gsp_rpc(&buf[..len]);
    }
}

#[test]
fn amd_dccg_dto_source_clock_derivation_and_ip_discovery_v4() {
    use crate::amd::dcn::{DcnAccess, DcnVersion, OtgTiming};
    use crate::amd::flip::{derive_dto_source_clk_khz, program_mode_regs};
    use crate::amd::sim::{DcnSim, build_discovery_image, default_ip_blocks};
    use crate::edid::DetailedTiming;

    // 1. Verify DCCG DTO source clock derivation (e.g. DTBCLK = 1000 MHz driving 2560x1440@60 Hz
    // at 241.5 MHz, then reprogramming to 2560x1440@240 Hz at 966 MHz without assuming 100 MHz refclk).
    let blocks = default_ip_blocks(DcnVersion::Dcn401);
    let dcn = DcnAccess::new(DcnVersion::Dcn401, blocks[0], Some(blocks[1]), Some(blocks[2]), Some(blocks[3]));
    let mut sim = DcnSim::new(DcnVersion::Dcn401, 0x0080_0000_0000, 16 << 30);
    let r = dcn.regs;
    // Simulate firmware programming 241.5 MHz from 1000 MHz DTBCLK (dto_int=0, phase=241_500, mod=1_000_000).
    dcn.w_dcn(&mut sim, r.dccg_dp_dto_phase(0), 241_500);
    dcn.w_dcn(&mut sim, r.dccg_dp_dto_modulo(0), 1_000_000);
    dcn.w_dcn(&mut sim, r.dccg_otg_pixel_rate_cntl(0), 1 << 4);
    let cur = OtgTiming {
        h_active: 2560,
        h_total: 2720,
        h_blank_start: 2560,
        h_blank_end: 80,
        h_front_porch: 48,
        h_sync_width: 32,
        h_sync_pos: true,
        v_active: 1440,
        v_total: 1481,
        v_blank_start: 1440,
        v_blank_end: 38,
        v_front_porch: 3,
        v_sync_width: 5,
        v_sync_pos: false,
    };
    let derived = derive_dto_source_clk_khz(&sim, &dcn, 0, &cur, 59_951, 100_000);
    assert!((995_000..=1_005_000).contains(&derived), "derived DTBCLK={}", derived);

    let mode_240 = DetailedTiming {
        pixel_clock_khz: 966_000,
        h_active: 2560,
        h_blank: 160,
        h_front_porch: 48,
        h_sync_width: 32,
        v_active: 1440,
        v_blank: 41,
        v_front_porch: 3,
        v_sync_width: 5,
        h_sync_pos: true,
        v_sync_pos: false,
        refresh_mhz: 239_803,
        preferred: false,
    };
    let saved = program_mode_regs(&mut sim, &dcn, 0, &mode_240, derived, false, 8, 8);
    assert_eq!(dcn.r_dcn(&sim, r.dccg_dp_dto_modulo(0)), Some(derived));
    assert_eq!(dcn.r_dcn(&sim, r.dccg_dp_dto_phase(0)), Some(966_000));
    saved.restore(&mut sim, &dcn);
    assert_eq!(dcn.r_dcn(&sim, r.dccg_dp_dto_phase(0)), Some(241_500));

    // 2. Verify IP Discovery v4 enables 64-bit base addresses while v2 ignores padding byte 78.
    let img_v4 = build_discovery_image(2, true, &blocks, &[]);
    let parsed_v4 = amd::parse_ip_discovery(&img_v4).expect("v4 64-bit discovery must parse");
    assert!(parsed_v4.find(amd::HWID_DCE, 0).is_some());

    let mut img_v2_pad = build_discovery_image(2, false, &blocks, &[]);
    // Set padding byte 78 inside v2 ip_discovery_header and recompute checksums: must stay 32-bit!
    let ip_off = 128usize;
    let ip_size = 96usize;
    img_v2_pad[ip_off + 78] = 1;
    let ip_csum = amd::discovery_checksum(&img_v2_pad[ip_off..ip_off + ip_size]);
    img_v2_pad[16 + 2..16 + 4].copy_from_slice(&ip_csum.to_le_bytes());
    let bin_csum = amd::discovery_checksum(&img_v2_pad[10..]);
    img_v2_pad[8..10].copy_from_slice(&bin_csum.to_le_bytes());
    let parsed_v2 = amd::parse_ip_discovery(&img_v2_pad).expect("v2 with non-zero pad byte must parse as 32-bit");
    assert_eq!(parsed_v2.find(amd::HWID_DCE, 0).map(|b| b.bases[0]), Some(blocks[0].bases[0]));
}

#[test]
fn cvt_rb_timing_synthesis_edid_vics_and_resolution_mode_switch_revert() {
    use crate::amd::dcn::{
        DcnAccess, DcnVersion, RegAddr, find_pipe_dig_encoder, probe_pipe_dpp_size_regs,
    };
    use crate::amd::flip::program_mode_regs_ex;
    use crate::amd::sim::{DcnSim, default_ip_blocks};
    use crate::edid::DetailedTiming;

    // 1. CVT-RB v2 synthesis produces accurate pixel clocks and refresh rates across common modes.
    for &(w, h, hz_mhz) in &[
        (1920u32, 1080u32, 60_000u32),
        (1920, 1080, 144_000),
        (1920, 1080, 240_000),
        (2560, 1440, 144_000),
        (2560, 1440, 240_000),
        (3840, 2160, 60_000),
        (1280, 800, 60_000),
    ] {
        let t = DetailedTiming::cvt_rb(w, h, hz_mhz).expect("valid CVT-RB timing");
        assert_eq!((t.h_active, t.v_active), (w, h));
        assert!(t.refresh_mhz.abs_diff(hz_mhz) < 500, "{}x{}@{} got {}", w, h, hz_mhz, t.refresh_mhz);
        assert!(t.pixel_clock_khz > 50_000);
    }
    assert!(DetailedTiming::cvt_rb(100, 100, 60_000).is_none());

    // 2. Active DIG encoder lookup + DPP geometry discovery + resolution switch + atomic restore.
    let blocks = default_ip_blocks(DcnVersion::Dcn401);
    let dcn = DcnAccess::new(DcnVersion::Dcn401, blocks[0], Some(blocks[1]), Some(blocks[2]), Some(blocks[3]));
    let mut sim = DcnSim::new(DcnVersion::Dcn401, 0x0080_0000_0000, 16 << 30);
    let r = dcn.regs;
    let boot_mode = DetailedTiming::cvt_rb(1920, 1080, 60_000).unwrap();
    let boot_mc = 0x0080_0010_0000u64;
    sim.setup_active_pipe(0, &boot_mode, 1920, boot_mc);

    // Route pipe 0 to DIG encoder 2 (`DIG_BE_EN = 1`, `DIG_FE source = 0`).
    dcn.w_dcn(&mut sim, r.dig_be_en_cntl(2), 1);
    dcn.w_dcn(&mut sim, r.dig_fe_cntl(2), 0);
    assert_eq!(find_pipe_dig_encoder(&sim, &dcn, 0), 2);

    // Populate simulated DPP DSCL_RECOUT_SIZE and DSCL_MPC_SIZE registers with 1920x1080.
    let dpp_base = r.cnvc_pixel_format(0).base_idx;
    let recout_off = r.cnvc_pixel_format(0).off + 0x40;
    let mpc_off = r.cnvc_pixel_format(0).off + 0x41;
    let dim_1080 = 1920u32 | (1080u32 << 16);
    dcn.w_dcn(&mut sim, RegAddr::new(dpp_base, recout_off), dim_1080);
    dcn.w_dcn(&mut sim, RegAddr::new(dpp_base, mpc_off), dim_1080);

    let (dpp_regs, dpp_n) = probe_pipe_dpp_size_regs(&sim, &dcn, 0, 1920, 1080);
    assert_eq!(dpp_n, 2);
    assert_eq!(&dpp_regs[..2], &[recout_off, mpc_off]);

    // Switch resolution to 2560x1440 @ 144 Hz on encoder 2 with new scanout buffer.
    let target = DetailedTiming::cvt_rb(2560, 1440, 144_000).unwrap();
    let new_mc = 0x0080_0100_0000u64;
    let saved = program_mode_regs_ex(
        &mut sim,
        &dcn,
        0,
        2,
        &target,
        1_000_000,
        false,
        8,
        8,
        Some(2560),
        Some(new_mc),
        &dpp_regs[..dpp_n],
    );
    let dim_1440 = 2560u32 | (1440u32 << 16);
    assert_eq!(dcn.r_dcn(&sim, r.hubp_viewport_dim(0)), Some(dim_1440));
    assert_eq!(dcn.r_dcn(&sim, r.hubp_surface_pitch(0)), Some(2559));
    assert_eq!(dcn.r_dcn(&sim, RegAddr::new(dpp_base, recout_off)), Some(dim_1440));
    assert_eq!(dcn.r_dcn(&sim, RegAddr::new(dpp_base, mpc_off)), Some(dim_1440));
    assert_eq!(dcn.r_dcn(&sim, r.dp_msa_timing_param4(2)), Some((2560 << 16) | 1440));

    // Full restore reverts OTG, MSA (enc 2), HUBP viewport/pitch/surface, and DPP size regs.
    saved.restore(&mut sim, &dcn);
    assert_eq!(dcn.r_dcn(&sim, r.hubp_viewport_dim(0)), Some(dim_1080));
    assert_eq!(dcn.r_dcn(&sim, r.hubp_surface_pitch(0)), Some(1919));
    assert_eq!(dcn.r_dcn(&sim, RegAddr::new(dpp_base, recout_off)), Some(dim_1080));
    assert_eq!(dcn.r_dcn(&sim, RegAddr::new(dpp_base, mpc_off)), Some(dim_1080));

    // A boot-mode snapshot pinned to the untouched GOP surface address always restores GOP
    // even if a native scanout buffer was active when switching modes.
    let native_buf = 0x0080_0200_0000u64;
    let boot_snap = crate::amd::flip::SavedModeRegs::capture_ex(&sim, &dcn, 0, 2, &dpp_regs[..dpp_n], true)
        .with_surface_addr(boot_mc);
    assert_eq!(boot_snap.surface_mc_addr(), boot_mc);
    let _ = program_mode_regs_ex(
        &mut sim,
        &dcn,
        0,
        2,
        &target,
        1_000_000,
        false,
        8,
        8,
        Some(2560),
        Some(native_buf),
        &dpp_regs[..dpp_n],
    );
    assert_eq!(
        crate::amd::dcn::decode_surface_addr(
            dcn.r_dcn(&sim, r.hubp_primary_addr(0)).unwrap(),
            dcn.r_dcn(&sim, r.hubp_primary_addr_hi(0)).unwrap(),
        ),
        native_buf
    );
    boot_snap.restore(&mut sim, &dcn);
    assert_eq!(dcn.r_dcn(&sim, r.hubp_viewport_dim(0)), Some(dim_1080));
    assert_eq!(dcn.r_dcn(&sim, r.hubp_surface_pitch(0)), Some(1919));
    assert_eq!(
        crate::amd::dcn::decode_surface_addr(
            dcn.r_dcn(&sim, r.hubp_primary_addr(0)).unwrap(),
            dcn.r_dcn(&sim, r.hubp_primary_addr_hi(0)).unwrap(),
        ),
        boot_mc
    );

    // 3. Verify DP_VID_M_N_GEN_EN, DP_STEER_FIFO reset pulse, VRR OTG_SET_V_TOTAL_MIN_MASK_EN,
    // and DPCD 0x107 Adaptive-Sync toggling.
    dcn.w_dcn(&mut sim, r.dp_vid_timing(2), 0x100);
    let _s2 = program_mode_regs_ex(
        &mut sim,
        &dcn,
        0,
        2,
        &target,
        1_000_000,
        false,
        8,
        8,
        None,
        None,
        &[],
    );
    assert_eq!(dcn.r_dcn(&sim, r.dp_vid_timing(2)).unwrap() & 1, 1, "DP_VID_M_N_GEN_EN must be set");
    crate::amd::flip::reset_dp_steer_fifo(&mut sim, &dcn, 2, |_| {});
    assert_eq!(dcn.r_dcn(&sim, r.dp_steer_fifo(2)).unwrap() & 1, 0, "DP_STEER_FIFO_RESET must be cleared after pulse");

    let otg = crate::amd::dcn::OtgTiming::from_detailed(&target);
    assert!(crate::amd::flip::set_vrr(&mut sim, &dcn, 0, &otg, 144_000, 48, 144, true));
    let vctl = dcn.r_dcn(&sim, r.otg_v_total_control(0)).unwrap();
    assert_eq!(vctl & 0xF, 0xB, "OTG_V_TOTAL_MIN/MAX_SEL + MIN_MASK_EN must be set");
    assert_eq!((vctl >> 16) & 0xF, 0x2, "HUBP flip mask bit must be set");
    assert!(crate::amd::flip::set_vrr(&mut sim, &dcn, 0, &otg, 144_000, 48, 144, false));
    assert_eq!(dcn.r_dcn(&sim, r.otg_v_total_control(0)), Some(0));
}
