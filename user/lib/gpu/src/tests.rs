//! Host unit tests and 13,000-round fuzzers for `dosgpu` (`gpu-host`).

use super::*;
use std::vec;
use std::vec::Vec;

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
fn edid_parse_valid_and_invalid() {
    let raw = make_valid_edid(1920, 1080, b"D-OS Monitor");
    let info = edid::parse_edid(&raw).unwrap();
    assert_eq!(info.manufacturer_str(), "DOS");
    assert_eq!(info.name_str(), "D-OS Monitor");
    assert_eq!(info.width_cm, 60);
    assert_eq!(info.height_cm, 34);
    assert!(info.mode_count >= 1);
    assert_eq!((info.modes()[0].width, info.modes()[0].height), (1920, 1080));
    assert!(info.modes()[0].preferred);

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
fn damage_rect_and_blit_wc() {
    let r = DamageRect { x: 50, y: 40, w: 200, h: 100 }.clip(100, 80).unwrap();
    assert_eq!(r, DamageRect { x: 50, y: 40, w: 50, h: 40 });
    assert_eq!(DamageRect { x: 100, y: 0, w: 10, h: 10 }.clip(100, 80), None);
    let u = DamageRect { x: 10, y: 20, w: 30, h: 40 }.union(DamageRect { x: 25, y: 10, w: 50, h: 20 });
    assert_eq!(u, DamageRect { x: 10, y: 10, w: 65, h: 50 });

    // 4x2 XRGB8888 source -> BGR shifts [0, 8, 16]
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
fn amd_rdna_rx9070_discovery_pm4_sdma() {
    let rx9070 = amd::identify_pci(0x7550);
    assert_eq!(rx9070.family, amd::AmdFamily::Rdna4);
    assert_eq!(rx9070.gfx_major, 12);
    assert_eq!(rx9070.dcn_major, 4);
    assert!(rx9070.name.contains("RX 9070"));

    let igpu = amd::identify_pci(0x13C0);
    assert_eq!(igpu.family, amd::AmdFamily::Rdna2);
    assert!(igpu.is_apu);

    // Construct a synthetic valid AMD IP Discovery binary image with GC + DCN + SDMA0.
    let mut img = vec![0u8; 256];
    // Die table at offset 128: die_id=0, num_ips=3
    let die_off = 128usize;
    img[die_off..die_off + 2].copy_from_slice(&0u16.to_le_bytes());
    img[die_off + 2..die_off + 4].copy_from_slice(&3u16.to_le_bytes());
    let mut cur = die_off + 4;
    for (hwid, major, minor, base) in [
        (amd::HWID_GC, 12u8, 0u8, 0x1260u32),
        (amd::HWID_DCE, 4, 0, 0x0040),
        (amd::HWID_SDMA0, 7, 0, 0x4980),
    ] {
        img[cur..cur + 2].copy_from_slice(&hwid.to_le_bytes());
        img[cur + 2] = 0; // instance
        img[cur + 3] = 1; // 1 base
        img[cur + 4] = major;
        img[cur + 5] = minor;
        img[cur + 6] = 1;
        img[cur + 8..cur + 12].copy_from_slice(&base.to_le_bytes());
        cur += 12;
    }
    // IP discovery table at offset 64 (size 32)
    let ip_off = 64usize;
    let ip_size = 32usize;
    img[ip_off..ip_off + 4].copy_from_slice(&amd::IP_DISCOVERY_TABLE_SIG.to_le_bytes());
    img[ip_off + 10..ip_off + 12].copy_from_slice(&1u16.to_le_bytes()); // num_dies=1
    img[ip_off + 12..ip_off + 14].copy_from_slice(&0u16.to_le_bytes()); // die 0
    img[ip_off + 14..ip_off + 16].copy_from_slice(&(die_off as u16).to_le_bytes());
    let ip_csum = amd::discovery_checksum(&img[ip_off..ip_off + ip_size]);

    // Binary header at offset 0
    let img_len = img.len() as u16;
    img[0..4].copy_from_slice(&amd::IP_DISCOVERY_BINARY_SIG.to_le_bytes());
    img[4..6].copy_from_slice(&2u16.to_le_bytes());
    img[6..8].copy_from_slice(&img_len.to_le_bytes());
    img[12..14].copy_from_slice(&(ip_off as u16).to_le_bytes());
    img[14..16].copy_from_slice(&ip_csum.to_le_bytes());
    img[16..18].copy_from_slice(&(ip_size as u16).to_le_bytes());
    let bin_csum = amd::discovery_checksum(&img[12..]);
    img[10..12].copy_from_slice(&bin_csum.to_le_bytes());

    let disc = amd::parse_ip_discovery(&img).unwrap();
    assert_eq!(disc.find(amd::HWID_GC, 0).unwrap().major, 12);
    assert_eq!(disc.find(amd::HWID_DCE, 0).unwrap().base_dword, 0x0040);
    assert_eq!(disc.find(amd::HWID_SDMA0, 0).unwrap().major, 7);

    // PM4 & SDMA command validation
    let mut pm4 = [0u32; 12];
    let n1 = amd::pm4_nop(&mut pm4, 0x1234).unwrap();
    let n2 = amd::pm4_release_mem_fence(&mut pm4[n1..], 0x10000, 42).unwrap();
    let mut pm4_bytes = Vec::new();
    for &w in &pm4[..n1 + n2] {
        pm4_bytes.extend_from_slice(&w.to_le_bytes());
    }
    assert_eq!(amd::validate_pm4_cs(&pm4_bytes), Ok(2));

    // Privileged PM4 WRITE_DATA must be refused
    let bad_pm4 = [amd::pm4_hdr(amd::PM4_WRITE_DATA, 1), 0];
    let mut bad_bytes = Vec::new();
    for w in bad_pm4 {
        bad_bytes.extend_from_slice(&w.to_le_bytes());
    }
    assert_eq!(amd::validate_pm4_cs(&bad_bytes), Err(CsError::UnknownOpcode));

    let mut sdma = [0u32; 16];
    let s1 = amd::sdma_const_fill(&mut sdma, 0x20000, 0x00FF_0000, 4096).unwrap();
    let s2 = amd::sdma_fence(&mut sdma[s1..], 0x10000, 7).unwrap();
    let mut sdma_bytes = Vec::new();
    for &w in &sdma[..s1 + s2] {
        sdma_bytes.extend_from_slice(&w.to_le_bytes());
    }
    assert_eq!(amd::validate_sdma_cs(&sdma_bytes), Ok(2));
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

#[test]
fn fuzz_all_gpu_parsers_and_validators() {
    let mut rng = Rng(0xD056_0055_1234_5678);
    let mut buf = [0u8; 512];

    // 3,000 rounds EDID fuzzer
    for _ in 0..3_000 {
        let len = (rng.next() as usize) % 256;
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
    // 3,000 rounds AMD IP Discovery + PM4 + SDMA CS fuzzer
    for _ in 0..3_000 {
        let len = (rng.next() as usize) % buf.len();
        rng.fill(&mut buf[..len]);
        let _ = amd::parse_ip_discovery(&buf[..len]);
        let _ = amd::validate_pm4_cs(&buf[..len]);
        let _ = amd::validate_sdma_cs(&buf[..len]);
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
