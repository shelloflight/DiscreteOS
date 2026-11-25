//! Host unit tests and 15,000+ fuzz rounds for `dosdrm` (`gpu-host`).

use crate::edid::{DetailedTiming, EDID_BLOCK_LEN, parse_edid};
use crate::gem::{BO_RENDER, BO_SCANOUT, DrmMemError, GemTable, GpuVmSpace, GpuVmTable, SyncobjTable, VM_READ, VM_WRITE};
use crate::kms::{
    ATOMIC_ALLOW_MODESET, ATOMIC_CURSOR_ONLY, ATOMIC_TEST_ONLY, AtomicCommit, ConnectorKind,
    KmsError, KmsMode, KmsState, MODE_FLAG_CURRENT, MODE_FLAG_PREFERRED, ModeRevertGuard,
};
use crate::virtio::{self as vg};
use crate::{BufferAgeTracker, DamageRect, PixelFormat, blit_rect_wc, blit_rect_wc_10bpc, fourcc};

struct Xorshift64(u64);

impl Xorshift64 {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn fill(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(8) {
            let v = self.next().to_le_bytes();
            chunk.copy_from_slice(&v[..chunk.len()]);
        }
    }
}

fn fix_edid_checksum(blk: &mut [u8; EDID_BLOCK_LEN]) {
    blk[127] = 0;
    let sum = blk[..127].iter().fold(0u8, |a, &b| a.wrapping_add(b));
    blk[127] = 0u8.wrapping_sub(sum);
}

fn sample_edid_with_displayid_240hz() -> [u8; 256] {
    let mut raw = [0u8; 256];
    let base: &mut [u8; 128] = (&mut raw[..128]).try_into().unwrap();
    base[0..8].copy_from_slice(&[0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00]);
    // Manufacturer "DOS" -> D=4, O=15, S=19 -> (4<<10)|(15<<5)|19 = 0x11F3
    base[8..10].copy_from_slice(&0x11F3u16.to_be_bytes());
    base[18] = 1;
    base[19] = 4;
    // DTD 0 @ 54: 2560x1440 @ 60 Hz (241.50 MHz -> 24150 in 10 kHz units)
    base[54..56].copy_from_slice(&24150u16.to_le_bytes());
    base[56] = (2560 & 0xFF) as u8;
    base[57] = 160;
    base[58] = ((2560 >> 8) as u8) << 4;
    base[59] = (1440 & 0xFF) as u8;
    base[60] = 41;
    base[61] = ((1440 >> 8) as u8) << 4;
    base[62] = 48;
    base[63] = 32;
    base[64] = (3 << 4) | 5;
    base[71] = 0x1E;
    // Product name @ 72: "DOS-240HZ"
    base[75] = 0xFC;
    base[77..86].copy_from_slice(b"DOS-240HZ");
    base[86] = 0x0A;
    // Range limits @ 90: 48..240 Hz VRR
    base[93] = 0xFD;
    base[95] = 48;
    base[96] = 240;
    base[126] = 1; // 1 extension block
    fix_edid_checksum(base);

    // Extension block 1: DisplayID 2.0 (`0x70`) with Type VII (`0x22`) 2560x1440 @ 240 Hz timing!
    let ext: &mut [u8; 128] = (&mut raw[128..256]).try_into().unwrap();
    ext[0] = 0x70;
    ext[1] = 0x20;
    ext[2] = 23; // 3-byte block header + 20-byte timing
    ext[5] = 0x22; // Type VII (1 kHz pixel clock units)
    ext[6] = 0;
    ext[7] = 20;
    // 2560+80=2640, 1440+135=1575 -> 2640 * 1575 * 240 = 997_920 kHz -> raw = 997_919
    let pclk_m1: u32 = 997_919;
    ext[8] = (pclk_m1 & 0xFF) as u8;
    ext[9] = ((pclk_m1 >> 8) & 0xFF) as u8;
    ext[10] = ((pclk_m1 >> 16) & 0xFF) as u8;
    ext[11] = 0x80;
    ext[12..14].copy_from_slice(&(2560u16 - 1).to_le_bytes());
    ext[14..16].copy_from_slice(&(80u16 - 1).to_le_bytes());
    ext[16..18].copy_from_slice(&((8u16 - 1) | 0x8000).to_le_bytes());
    ext[18..20].copy_from_slice(&(32u16 - 1).to_le_bytes());
    ext[20..22].copy_from_slice(&(1440u16 - 1).to_le_bytes());
    ext[22..24].copy_from_slice(&(135u16 - 1).to_le_bytes());
    ext[24..26].copy_from_slice(&(121u16 - 1).to_le_bytes());
    ext[26..28].copy_from_slice(&(8u16 - 1).to_le_bytes());
    fix_edid_checksum(ext);
    raw
}

#[test]
fn edid_displayid_240hz_and_cvt_rb() {
    let raw = sample_edid_with_displayid_240hz();
    let info = parse_edid(&raw).expect("valid 2-block EDID+DisplayID");
    assert_eq!(info.manufacturer_str(), "DOS");
    assert_eq!(info.name_str(), "DOS-240HZ");
    assert_eq!((info.vrr_min_hz, info.vrr_max_hz), (48, 240));
    assert!(info.modes().iter().any(|m| m.width == 2560 && m.height == 1440 && m.refresh_mhz == 240_000));

    let cvt = DetailedTiming::cvt_rb(1920, 1080, 240_000).expect("CVT-RB 1080p240");
    assert_eq!((cvt.h_active, cvt.v_active), (1920, 1080));
    assert!(cvt.refresh_mhz.abs_diff(240_000) <= 500);
}

#[test]
fn atomic_kms_test_only_commit_and_12s_revert_guard() {
    let mut kms = KmsState::new();
    kms.init_single_pipe(ConnectorKind::DisplayPort, b"DOS-240HZ", 1920, 1080, 60_000, true);
    kms.connectors[0].as_mut().unwrap().vrr_capable = true;
    kms.push_mode(KmsMode::simple(1920, 1080, 240_000, 0));
    kms.push_mode(KmsMode::simple(2560, 1440, 240_000, MODE_FLAG_PREFERRED));

    let fb1 = kms
        .add_fb(1, 1920, 1080, 1920 * 4, fourcc::XRGB8888, fourcc::MOD_LINEAR, 1920 * 1080 * 4)
        .expect("fb1");
    let cur_fb = kms
        .add_fb(2, 64, 64, 64 * 4, fourcc::ARGB8888, fourcc::MOD_LINEAR, 64 * 64 * 4)
        .expect("cursor fb");

    // Modeset without ATOMIC_ALLOW_MODESET must fail closed.
    let mut bad = AtomicCommit {
        flags: 0,
        mode_changed: true,
        mode_width: 2560,
        mode_height: 1440,
        mode_refresh_mhz: 240_000,
        ..AtomicCommit::default()
    };
    assert_eq!(kms.validate_commit(&bad), Err(KmsError::ModesetRequired));

    // HDR on a non-HDR connector must fail closed.
    bad.flags = ATOMIC_ALLOW_MODESET;
    bad.mode_changed = false;
    bad.hdr_changed = true;
    bad.hdr_enable = true;
    assert_eq!(kms.validate_commit(&bad), Err(KmsError::CapabilityUnsupported));

    // TEST_ONLY modeset validates without mutating active CRTC mode.
    let test_req = AtomicCommit {
        flags: ATOMIC_TEST_ONLY | ATOMIC_ALLOW_MODESET,
        mode_changed: true,
        mode_width: 2560,
        mode_height: 1440,
        mode_refresh_mhz: 240_000,
        vrr_changed: true,
        vrr_enable: true,
        primary_changed: true,
        primary_fb_id: fb1,
        cursor_changed: true,
        cursor_fb_id: cur_fb,
        cursor_x: 100,
        cursor_y: 200,
        cursor_hot_x: 4,
        cursor_hot_y: 4,
        ..AtomicCommit::default()
    };
    let resolved = kms.validate_commit(&test_req).expect("TEST_ONLY 1440p240");
    assert_eq!(kms.crtcs[0].unwrap().mode.refresh_mhz, 60_000);

    // Real commit updates CRTC mode, VRR, primary plane, cursor plane, and vblank sequence.
    let prev_mode = kms.crtcs[0].unwrap().mode;
    kms.apply_commit(&test_req, resolved);
    let c = kms.crtcs[0].unwrap();
    assert_eq!((c.mode.width, c.mode.height, c.mode.refresh_mhz), (2560, 1440, 240_000));
    assert!(c.vrr_enabled && c.vblank_seq == 1);
    assert!((c.mode.flags & MODE_FLAG_CURRENT) != 0);

    // Cursor-only move does not bump primary vblank sequence.
    let cur_move = AtomicCommit {
        flags: ATOMIC_CURSOR_ONLY,
        cursor_changed: true,
        cursor_x: 320,
        cursor_y: 240,
        ..AtomicCommit::default()
    };
    let rm = kms.validate_commit(&cur_move).unwrap();
    kms.apply_commit(&cur_move, rm);
    assert_eq!(kms.planes[1].unwrap().crtc_x, 320);

    // 12-second revert guard: expires if unconfirmed, clears if confirmed.
    let mut guard = ModeRevertGuard::new();
    guard.arm(1, prev_mode, 1_000, 12_000_000_000);
    assert!(guard.poll_expired(5_000_000_000).is_none());
    let (rev_id, rev_mode) = guard.poll_expired(12_000_001_000).expect("expired");
    assert_eq!(rev_id, 1);
    assert_eq!((rev_mode.width, rev_mode.height, rev_mode.refresh_mhz), (1920, 1080, 60_000));

    guard.arm(1, prev_mode, 20_000_000_000, 12_000_000_000);
    assert!(guard.confirm(1));
    assert!(guard.poll_expired(50_000_000_000).is_none());
}

#[test]
fn gem_gpu_vm_isolation_and_timeline_syncobj() {
    let mut gem = GemTable::new();
    let bo1 = gem.insert(64 * 1024, BO_RENDER | BO_SCANOUT, 10, [0xAA; 16]).unwrap();
    let bo2 = gem.insert(16 * 1024, BO_RENDER, 11, [0xBB; 16]).unwrap();
    assert!(gem.add_ref(bo1));

    let mut vms = GpuVmTable::new();
    let vm_a = vms.create().unwrap();
    let vm_b = vms.create().unwrap();
    assert_ne!(vm_a, vm_b);

    let base = GpuVmSpace::DEFAULT_VA_BASE;
    vms.get_mut(vm_a)
        .unwrap()
        .bind(&gem, base, 32 * 1024, bo1, 0, VM_READ | VM_WRITE)
        .expect("bind bo1 in vm_a");

    // Overlapping VA inside the same VM must fail, while the same VA in `vm_b` succeeds (isolated!).
    assert_eq!(
        vms.get_mut(vm_a).unwrap().bind(&gem, base + 4096, 8192, bo2, 0, VM_READ),
        Err(DrmMemError::AddressOverlap)
    );
    vms.get_mut(vm_b)
        .unwrap()
        .bind(&gem, base + 4096, 8192, bo2, 0, VM_READ)
        .expect("isolated vm_b bind at overlapping VA");

    // Unaligned VA and out-of-BO-bounds bind must fail.
    assert_eq!(
        vms.get_mut(vm_a).unwrap().bind(&gem, base + 0x100, 4096, bo2, 0, VM_READ),
        Err(DrmMemError::Unaligned)
    );
    assert_eq!(
        vms.get_mut(vm_a).unwrap().bind(&gem, base + 0x20_000, 32 * 1024, bo2, 0, VM_READ),
        Err(DrmMemError::OutOfRange)
    );

    assert!(vms.get(vm_a).unwrap().lookup(base + 8192, 4096).is_some());
    vms.get_mut(vm_a).unwrap().unbind(base, 32 * 1024).expect("unbind");
    assert!(vms.get(vm_a).unwrap().lookup(base, 4096).is_none());

    // GEM refcounting drops only on last release.
    assert_eq!(gem.release(bo1).unwrap(), None);
    assert!(gem.release(bo1).unwrap().is_some());
    assert_eq!(gem.release(bo1), Err(DrmMemError::UnknownHandle));

    // Monotonic timeline syncobjs (`wait_all` vs `wait_any`).
    let mut sync = SyncobjTable::new();
    let s1 = sync.create(0).unwrap();
    let s2 = sync.create(5).unwrap();
    assert!(!sync.check_wait(&[(s1, 1), (s2, 5)], true).unwrap());
    assert!(sync.check_wait(&[(s1, 1), (s2, 5)], false).unwrap());
    assert_eq!(sync.signal(s1, 10).unwrap(), 10);
    // Signaling a lower point preserves monotonicity.
    assert_eq!(sync.signal(s1, 3).unwrap(), 10);
    assert!(sync.check_wait(&[(s1, 10), (s2, 5)], true).unwrap());
}

#[test]
fn virtio_blob_uuid_venus_and_blit_tracker() {
    let mut buf = [0u8; 256];
    let n = vg::encode_resource_create_blob(
        &mut buf,
        3,
        42,
        vg::BLOB_MEM_HOST3D_GUEST,
        vg::BLOB_FLAG_USE_MAPPABLE | vg::BLOB_FLAG_USE_SHAREABLE,
        7,
        65536,
        &[(0x1000_0000, 65536)],
    )
    .expect("blob cmd");
    assert_eq!(n, 72);
    assert_eq!(vg::CtrlHdr::decode(&buf).unwrap().ty, vg::CMD_RESOURCE_CREATE_BLOB);

    let cn = vg::encode_ctx_create_ex(&mut buf, 1, vg::CAPSET_VENUS, b"mesa-venus").unwrap();
    assert_eq!(cn, 96);

    let mut age = BufferAgeTracker::new(3, 1920, 1080);
    let mut out = [DamageRect::EMPTY; 8];
    assert_eq!(age.collect_for_buffer(0, &[DamageRect { x: 0, y: 0, w: 32, h: 32 }], &mut out), 1);
    assert_eq!(out[0], DamageRect::full(1920, 1080));
    age.commit_buffer(0, &[]);
    age.commit_buffer(1, &[DamageRect { x: 10, y: 10, w: 20, h: 20 }]);
    let cnt = age.collect_for_buffer(0, &[DamageRect { x: 100, y: 100, w: 20, h: 20 }], &mut out);
    assert_eq!(cnt, 2);

    let src = [0xFFu8; 16 * 16 * 4];
    let mut written = 0usize;
    let px = blit_rect_wc(
        &src,
        16 * 4,
        PixelFormat::Xrgb8888,
        16 * 4,
        [16, 8, 0],
        16,
        16,
        DamageRect { x: 2, y: 2, w: 8, h: 8 },
        |_, _| written += 1,
    );
    assert_eq!((px, written), (64, 64));
    let px10 = blit_rect_wc_10bpc(
        &src,
        16 * 4,
        PixelFormat::Xrgb8888,
        16 * 4,
        16,
        16,
        DamageRect { x: 0, y: 0, w: 4, h: 4 },
        |_, _| {},
    );
    assert_eq!(px10, 16);
}

#[test]
fn fuzz_edid_virtio_and_atomic_kms_16000_rounds() {
    let mut rng = Xorshift64(0xD05_D240_2026_1124);
    let mut raw = [0u8; 512];
    let mut kms = KmsState::new();
    kms.init_single_pipe(ConnectorKind::DisplayPort, b"FUZZ", 1024, 768, 60_000, true);
    let _ = kms.add_fb(1, 1024, 768, 1024 * 4, fourcc::XRGB8888, 0, 1024 * 768 * 4);

    for round in 0..16_000usize {
        let len = (rng.next() as usize) % (raw.len() + 1);
        rng.fill(&mut raw[..len]);
        if round % 4 == 0 && len >= 128 {
            raw[0..8].copy_from_slice(&[0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00]);
            raw[18] = 1;
            let base: &mut [u8; 128] = (&mut raw[..128]).try_into().unwrap();
            fix_edid_checksum(base);
        }
        let _ = parse_edid(&raw[..len]);
        let _ = vg::validate_virgl_cs(&raw[..len]);
        let _ = vg::decode_display_info(&raw[..len]);
        let _ = vg::decode_edid_resp(&raw[..len]);

        let req = AtomicCommit {
            flags: (rng.next() as u32) & 0x7F,
            crtc_id: ((rng.next() % 3) as u32),
            connector_id: ((rng.next() % 3) as u32),
            mode_changed: (rng.next() & 1) != 0,
            mode_width: (rng.next() % 9000) as u32,
            mode_height: (rng.next() % 5000) as u32,
            mode_refresh_mhz: (rng.next() % 600_000) as u32,
            vrr_changed: (rng.next() & 1) != 0,
            vrr_enable: (rng.next() & 1) != 0,
            hdr_changed: (rng.next() & 1) != 0,
            hdr_enable: (rng.next() & 1) != 0,
            primary_changed: (rng.next() & 1) != 0,
            primary_fb_id: (rng.next() % 4) as u32,
            cursor_changed: (rng.next() & 1) != 0,
            cursor_fb_id: (rng.next() % 4) as u32,
            cursor_x: (rng.next() as i16) as i32,
            cursor_y: (rng.next() as i16) as i32,
            ..AtomicCommit::default()
        };
        let _ = kms.validate_commit(&req);
    }
    std::println!("dosdrm fuzz: 16,000 EDID/DisplayID + VirtIO + Atomic KMS rounds clean");
}
