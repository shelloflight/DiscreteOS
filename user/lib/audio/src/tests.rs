use std::vec;
use std::vec::Vec;

use crate::hda_graph::{AudioPath, MAX_PATHS, PinDefault, Widget, discover_paths, parse_eld};
use crate::pcm::{
    Resampler, SampleFormat, StreamParams, ToneGen, decode_sample, encode_sample, finalize_mix,
    volume_gain_q16,
};
use crate::route::{
    DeviceKind, FLAG_CAPTURE, FLAG_ELD_VALID, FLAG_INTERNAL, FLAG_PLAYBACK, FLAG_PLUGGED,
    RouteDevice, select_input, select_output,
};
use crate::uac::{UacVersion, parse_config};

#[test]
fn pcm_format_roundtrips() {
    let sample = 12_345i32 << 8;
    for fmt in [
        SampleFormat::U8,
        SampleFormat::S16Le,
        SampleFormat::S24Le,
        SampleFormat::S32Le,
        SampleFormat::F32Le,
    ] {
        let mut buf = [0u8; 4];
        encode_sample(fmt, sample, &mut buf[..fmt.bytes_per_sample()]);
        let out = decode_sample(fmt, &buf[..fmt.bytes_per_sample()]);
        let tol = if fmt == SampleFormat::U8 { 1 << 16 } else { 512 };
        assert!(
            (out - sample).abs() <= tol,
            "format {:?}: got {}, expected {}",
            fmt,
            out,
            sample
        );
    }
    // NaN / Inf in F32 must decode safely to 0.
    assert_eq!(decode_sample(SampleFormat::F32Le, &f32::NAN.to_le_bytes()), 0);
    assert_eq!(decode_sample(SampleFormat::F32Le, &f32::INFINITY.to_le_bytes()), 0);
}

#[test]
fn tone_resampler_and_mixer_preserve_frequency_and_clamp() {
    // Generate a 440 Hz mono 24 kHz S16 tone and resample to 48 kHz stereo S16.
    let src_params = StreamParams { rate: 24_000, channels: 1, format: SampleFormat::S16Le };
    let dst_params = StreamParams::stereo_48k_s16();
    let mut tone = ToneGen::new(440, 24_000, 16_000);
    let mut src = vec![0u8; 2400 * 2]; // 100 ms
    tone.fill(src_params, &mut src);

    let mut resampler = Resampler::new(24_000, 48_000);
    let mut acc = vec![0i64; 4800 * 2];
    let (consumed, mixed) = resampler.mix_into(src_params, &src, &mut acc, volume_gain_q16(100, false));
    assert!(consumed >= 2390);
    assert!(mixed >= 4780);

    let mut out = vec![0u8; mixed * 4];
    finalize_mix(&acc[..mixed * 2], volume_gain_q16(100, false), dst_params, &mut out);

    // Measure zero-crossings on left channel: 440 Hz for ~0.1 s = ~88 crossings.
    let mut crossings = 0usize;
    let mut prev = 0i16;
    let mut peak = 0i32;
    for i in 0..mixed {
        let l = i16::from_le_bytes([out[i * 4], out[i * 4 + 1]]);
        let r = i16::from_le_bytes([out[i * 4 + 2], out[i * 4 + 3]]);
        assert_eq!(l, r, "mono upmix must duplicate L/R");
        peak = peak.max((l as i32).abs());
        if (prev < 0 && l >= 0) || (prev > 0 && l <= 0) {
            crossings += 1;
        }
        prev = l;
    }
    assert!(peak > 12_000 && peak <= 16_500, "unexpected peak {}", peak);
    assert!((80..=96).contains(&crossings), "expected ~88 crossings, got {}", crossings);

    // Saturation check: mixing two full-scale streams must saturate cleanly without wraparound.
    let mut hot = vec![0i64; 8];
    hot.fill(12_000_000);
    let mut clipped = [0u8; 16];
    finalize_mix(&hot, volume_gain_q16(100, false), dst_params, &mut clipped);
    let s0 = i16::from_le_bytes([clipped[0], clipped[1]]);
    assert_eq!(s0, i16::MAX);
}

#[test]
fn output_switching_priority_order() {
    let spk = RouteDevice { id: 1, kind: DeviceKind::Speaker, flags: FLAG_PLAYBACK | FLAG_INTERNAL | FLAG_PLUGGED, online: true };
    let hdmi = RouteDevice { id: 2, kind: DeviceKind::HdmiDp, flags: FLAG_PLAYBACK | FLAG_PLUGGED | FLAG_ELD_VALID, online: true };
    let usb = RouteDevice { id: 3, kind: DeviceKind::UsbAudio, flags: FLAG_PLAYBACK | FLAG_PLUGGED, online: true };
    let mut hp = RouteDevice { id: 4, kind: DeviceKind::Headphones, flags: FLAG_PLAYBACK, online: true }; // unplugged

    // Without headphones plugged: USB wins over HDMI and Speakers.
    assert_eq!(select_output(&[spk, hdmi, usb, hp], None), Some(3));
    // Plug headphones in -> Headphones wins!
    hp.flags |= FLAG_PLUGGED;
    assert_eq!(select_output(&[spk, hdmi, usb, hp], None), Some(4));
    // Manual override to speaker overrides auto.
    assert_eq!(select_output(&[spk, hdmi, usb, hp], Some(1)), Some(1));
    // Unplug headphones & remove USB -> HDMI wins over Speaker.
    hp.flags &= !FLAG_PLUGGED;
    assert_eq!(select_output(&[spk, hdmi, hp], None), Some(2));
    // Unplug HDMI -> Speaker wins.
    let hdmi_unplugged = RouteDevice { flags: FLAG_PLAYBACK, ..hdmi };
    assert_eq!(select_output(&[spk, hdmi_unplugged, hp], None), Some(1));

    // Input selection: USB mic > external mic > internal mic.
    let mic_int = RouteDevice { id: 10, kind: DeviceKind::Microphone, flags: FLAG_CAPTURE | FLAG_INTERNAL | FLAG_PLUGGED, online: true };
    let mic_usb = RouteDevice { id: 11, kind: DeviceKind::UsbAudio, flags: FLAG_CAPTURE | FLAG_PLUGGED, online: true };
    assert_eq!(select_input(&[mic_int, mic_usb], None), Some(11));
    assert_eq!(select_input(&[mic_int], None), Some(10));
}

#[test]
fn hda_dynamic_graph_discovery() {
    // Realistic multi-pin codec (analog HP + Speaker + HDMI + Mic, no board table).
    let mut ws = [Widget::empty(); 10];
    // NID 2: Analog DAC 0
    ws[0] = Widget { nid: 2, wcaps: 0x0000_0401, ..Widget::empty() };
    // NID 3: Analog DAC 1
    ws[1] = Widget { nid: 3, wcaps: 0x0000_0401, ..Widget::empty() };
    // NID 4: Digital HDMI DAC
    ws[2] = Widget { nid: 4, wcaps: 0x0000_0601, ..Widget::empty() }; // bit 9 digital
    // NID 5: Mixer fed by DAC 2 & 3
    let mut m = Widget { nid: 5, wcaps: 0x0020_0106, conn_len: 2, ..Widget::empty() };
    m.conns[0] = 2;
    m.conns[1] = 3;
    ws[3] = m;
    // NID 6: Headphone Pin (jack, presence detect, HP drive)
    let mut hp = Widget {
        nid: 6,
        wcaps: 0x0040_0184,
        pin_caps: (1 << 2) | (1 << 3) | (1 << 4),
        pin_default: PinDefault::new(0x0221_4010), // Jack, HP Out (2)
        conn_len: 1,
        ..Widget::empty()
    };
    hp.conns[0] = 5;
    ws[4] = hp;
    // NID 7: Internal Speaker Pin (fixed, EAPD)
    let mut spk = Widget {
        nid: 7,
        wcaps: 0x0040_0104,
        pin_caps: (1 << 4) | (1 << 16),
        pin_default: PinDefault::new(0x9017_0120), // Fixed (2), Speaker (1)
        conn_len: 1,
        ..Widget::empty()
    };
    spk.conns[0] = 5;
    ws[5] = spk;
    // NID 8: HDMI Pin (digital, HDMI cap)
    let mut hdmi = Widget {
        nid: 8,
        wcaps: 0x0040_0384,
        pin_caps: (1 << 2) | (1 << 4) | (1 << 7),
        pin_default: PinDefault::new(0x1856_0030), // Jack, Digital Out (5), Digital conn (6)
        conn_len: 1,
        ..Widget::empty()
    };
    hdmi.conns[0] = 4;
    ws[6] = hdmi;
    // NID 9: Mic Pin
    ws[7] = Widget {
        nid: 9,
        wcaps: 0x0040_0182,
        pin_caps: (1 << 2) | (1 << 5),
        pin_default: PinDefault::new(0x02A1_9040), // Jack, Mic In (0xA)
        ..Widget::empty()
    };
    // NID 10: ADC connected to Mic Pin 9
    let mut adc = Widget { nid: 10, wcaps: 0x0010_0102, conn_len: 1, ..Widget::empty() };
    adc.conns[0] = 9;
    ws[8] = adc;

    let mut paths = [AudioPath::empty(); MAX_PATHS];
    let n = discover_paths(&ws, &mut paths);
    assert_eq!(n, 4, "expected HP, Speaker, HDMI, Mic paths");
    assert_eq!(paths[0].kind, DeviceKind::Headphones);
    assert!(paths[0].hp_amp && paths[0].jack_detect);
    assert_eq!(paths[0].converter_nid, 2);
    assert_eq!(paths[1].kind, DeviceKind::Speaker);
    assert!(paths[1].eapd && !paths[1].jack_detect);
    assert_eq!(paths[1].converter_nid, 3); // preferred unused DAC 3 over shared DAC 2!
    assert_eq!(paths[2].kind, DeviceKind::HdmiDp);
    assert!(paths[2].is_hdmi_dp && paths[2].converter_nid == 4);
    assert_eq!(paths[3].kind, DeviceKind::Microphone);
    assert!(!paths[3].is_output && paths[3].converter_nid == 10 && paths[3].pin_nid == 9);
}

#[test]
fn eld_parser_valid_and_fuzz() {
    // Valid ELD v2 with monitor name "DELL U2723QE" (12 B) + 1 LPCM SAD (3 B)
    let mut eld = vec![0u8; 40];
    eld[0] = 2 << 3; // version 2
    eld[2] = 9; // 9 DWORDs = 36 bytes baseline
    eld[4] = 12; // MNL = 12
    eld[5] = (1 << 4) | (1 << 2) | 1; // 1 SAD, DisplayPort (1), HDCP
    eld[20..32].copy_from_slice(b"DELL U2723QE");
    eld[32] = (1 << 3) | 1; // LPCM (1), 2 channels
    eld[33] = 0x07; // 32 / 44.1 / 48 kHz
    eld[34] = 0x07; // 16 / 20 / 24 bit

    let info = parse_eld(&eld).expect("valid ELD");
    assert_eq!(info.monitor_name(), "DELL U2723QE");
    assert_eq!(info.conn_type, 1);
    assert!(info.hdcp);
    assert!(info.supports_lpcm_48k_stereo_16());

    // Deterministic fuzzer over ELD parser: never panics on any input.
    let mut rng = 0x9E37_79B9_7F4A_7C15u64;
    let mut next = || {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        rng
    };
    let mut buf = [0u8; 128];
    let mut valid = 0u32;
    for _ in 0..4000 {
        let len = (next() as usize) % buf.len();
        for b in &mut buf[..len] {
            *b = (next() & 0xFF) as u8;
        }
        if let Some(p) = parse_eld(&buf[..len]) {
            let _ = p.monitor_name();
            let _ = p.supports_lpcm_48k_stereo_16();
            valid += 1;
        }
    }
    let _ = valid;
}

#[test]
fn uac1_and_uac2_parser_and_fuzz() {
    // Minimal UAC 1.0 configuration descriptor matching QEMU usb-audio (48 kHz 2ch S16_LE).
    #[rustfmt::skip]
    let uac1: Vec<u8> = vec![
        // Config (9 B)
        9, 0x02, 0, 0, 2, 1, 0, 0x80, 50,
        // Interface 0: AC (UAC 1.0, proto 0)
        9, 0x04, 0, 0, 0, 0x01, 0x01, 0x00, 0,
        // CS_INTERFACE HEADER
        9, 0x24, 0x01, 0x00, 0x01, 30, 0, 1, 1,
        // INPUT_TERMINAL (id 1, USB streaming)
        12, 0x24, 0x02, 1, 0x01, 0x01, 0, 2, 0x03, 0x00, 0, 0,
        // FEATURE_UNIT (id 2, src 1)
        9, 0x24, 0x06, 2, 1, 1, 0x03, 0x00, 0,
        // OUTPUT_TERMINAL (id 3, Speaker, src 2)
        9, 0x24, 0x03, 3, 0x01, 0x03, 0, 2, 0,
        // Interface 1 alt 0: zero-bandwidth AS
        9, 0x04, 1, 0, 0, 0x01, 0x02, 0x00, 0,
        // Interface 1 alt 1: active AS
        9, 0x04, 1, 1, 1, 0x01, 0x02, 0x00, 0,
        // AS_GENERAL (link 1, PCM = 0x0001)
        7, 0x24, 0x01, 1, 1, 0x01, 0x00,
        // FORMAT_TYPE I (2ch, 2B subslot, 16-bit, 1 discrete rate: 48000 = 0x00BB80)
        11, 0x24, 0x02, 1, 2, 2, 16, 1, 0x80, 0xBB, 0x00,
        // Endpoint 0x01 OUT Isoch, maxPacket = 192, interval = 1
        9, 0x05, 0x01, 0x01, 192, 0, 1, 0, 0,
        // CS_ENDPOINT (sampling freq ctrl = 0)
        7, 0x25, 0x01, 0x00, 0, 0, 0,
    ];
    let mut uac1 = uac1;
    let total = uac1.len() as u16;
    uac1[2..4].copy_from_slice(&total.to_le_bytes());

    let cfg = parse_config(&uac1).expect("parse UAC 1.0");
    assert_eq!(cfg.version, UacVersion::Uac1);
    let s = cfg.best_stream(true).expect("playback stream");
    assert_eq!(s.iface, 1);
    assert_eq!(s.alt, 1);
    assert_eq!(s.ep_addr, 0x01);
    assert_eq!(s.max_packet, 192);
    assert_eq!(s.channels, 2);
    assert_eq!(s.format, SampleFormat::S16Le);
    assert_eq!(s.choose_rate(48_000), 48_000);
    assert_eq!(s.feature_unit_id, 2);

    // Minimal UAC 2.0 configuration descriptor (proto 0x20, Clock Source + 24/32-bit or 16-bit PCM).
    #[rustfmt::skip]
    let mut uac2: Vec<u8> = vec![
        9, 0x02, 0, 0, 2, 1, 0, 0x80, 50,
        // AC interface (UAC 2.0, proto 0x20)
        9, 0x04, 0, 0, 0, 0x01, 0x01, 0x20, 0,
        // CLOCK_SOURCE (id 10)
        8, 0x24, 0x0A, 10, 0x01, 0x03, 0, 0,
        // INPUT_TERMINAL (id 1, clock 10)
        17, 0x24, 0x02, 1, 0x01, 0x01, 0, 10, 2, 0, 0, 0, 0, 0, 0, 0, 0,
        // AS interface 1 alt 1 (UAC 2.0)
        9, 0x04, 1, 1, 1, 0x01, 0x02, 0x20, 0,
        // AS_GENERAL (link 1, fmtType 1, bmFormats PCM=1, 2ch)
        16, 0x24, 0x01, 1, 0, 1, 1, 0, 0, 0, 2, 0, 0, 0, 0, 0,
        // FORMAT_TYPE I (subslot 2, 16-bit)
        6, 0x24, 0x02, 1, 2, 16,
        // Endpoint 0x02 OUT Isoch, maxPacket 200
        7, 0x05, 0x02, 0x05, 200, 0, 1,
    ];
    let t2 = uac2.len() as u16;
    uac2[2..4].copy_from_slice(&t2.to_le_bytes());
    let cfg2 = parse_config(&uac2).expect("parse UAC 2.0");
    assert_eq!(cfg2.version, UacVersion::Uac2);
    let s2 = cfg2.best_stream(true).expect("UAC2 playback");
    assert_eq!(s2.clock_source_id, 10);
    assert_eq!(s2.format, SampleFormat::S16Le);
    assert_eq!(s2.channels, 2);

    // Deterministic fuzzer over UAC parser: never panics on random bytes.
    let mut rng = 0xD1B5_4A32_D192_ED03u64;
    let mut next = || {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        rng
    };
    let mut buf = [0u8; 256];
    for _ in 0..4000 {
        let len = (next() as usize) % buf.len();
        for b in &mut buf[..len] {
            *b = (next() & 0xFF) as u8;
        }
        let _ = parse_config(&buf[..len]);
    }
}
