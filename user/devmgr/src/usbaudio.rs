//! Isolated USB Audio Class 1.0 / 2.0 driver (`usbaudio.ddrv`).
//!
//! Runs in its own process spawned by `devmgr` whenever `xhci.ddrv` discovers a USB Audio Class
//! device (`bInterfaceClass == 0x01`). Communicates with `xhci.ddrv` over `proto::TAG_USB_BUS`
//! (control requests + xHCI isochronous `IoRing`) and with `audio.dsvc` via `devmgr` using the
//! standard D-OS audio driver protocol (`AUDIO_DEV`, `AUDIO_ATTACH`, `DRV_OPEN`, `IoRing`).

use dosaudio::pcm::SampleFormat;
use dosaudio::route::{DeviceKind, FLAG_CAPTURE, FLAG_PLAYBACK, FLAG_PLUGGED};
use dosaudio::uac::{UacVersion, UsbAudioStream, parse_config};
use libd::audio::{self, FMT_F32_LE, FMT_S16_LE, FMT_S24_LE, FMT_S32_LE, FMT_U8, RING_READ, RING_WRITE};
use libd::proto::{self, HEADER, Header};
use libd::ring::{Cqe, IoRing, Sqe};
use libd::sys::{self, Handle, MsgHandle};
use libd::{Port, Startup, println};

const MS: u64 = 1_000_000;
const KEY_CTL: u64 = 1;
const KEY_BUS: u64 = 2;
const KEY_OUT_CH: u64 = 10;
const KEY_IN_CH: u64 = 11;

const PERIOD_PACKETS: u32 = 10; // 10 ms at 1 ms USB frame interval
const ISOC_RING_SLOTS: u32 = 8;
const ISOC_SLOT_BYTES: u32 = 4096;

fn fmt_to_wire(f: SampleFormat) -> u8 {
    match f {
        SampleFormat::U8 => FMT_U8,
        SampleFormat::S16Le => FMT_S16_LE,
        SampleFormat::S24Le => FMT_S24_LE,
        SampleFormat::S32Le => FMT_S32_LE,
        SampleFormat::F32Le => FMT_F32_LE,
    }
}

struct ActiveStream {
    unit: usize,
    stream: UsbAudioStream,
    svc_ring: IoRing,
    isoc_ring: IoRing,
    next_slot: u32,
    in_flight: [Option<(u32, u32, u32)>; 8], // (svc_sqe_id, svc_buf_off, svc_buf_len)
    frames_done: u64,
}

struct UsbAudio {
    ctl: Handle,
    bus: Handle,
    port: Port,
    ac_iface: u8,
    play_desc: Option<UsbAudioStream>,
    cap_desc: Option<UsbAudioStream>,
    play_ch: Handle,
    cap_ch: Handle,
    active: Option<ActiveStream>,
    bus_closed: bool,
}

impl UsbAudio {
    fn usb_ctrl(&self, bm: u8, bq: u8, wv: u16, wi: u16, data: &[u8]) -> Result<(), i64> {
        let mut req = [0u8; HEADER + 64];
        let wl = data.len().min(64) as u16;
        let a = u64::from(bm)
            | (u64::from(bq) << 8)
            | (u64::from(wv) << 16)
            | (u64::from(wi) << 32)
            | (u64::from(wl) << 48);
        Header { txid: 0, op: audio::USB_CTRL, status: 0, a, b: 0 }.put(&mut req);
        req[HEADER..HEADER + usize::from(wl)].copy_from_slice(&data[..usize::from(wl)]);
        let mut rep = [0u8; HEADER + 64];
        let n = sys::channel_call(self.bus, &req[..HEADER + usize::from(wl)], &mut rep, 2_000 * MS)? as usize;
        let h = Header::get(&rep[..n]).ok_or(sys::ERR_INVALID_ARGS)?;
        if h.status != 0 {
            return Err(i64::from(h.status));
        }
        Ok(())
    }

    /// Select alt-setting, set sample rate (UAC 1.0 endpoint or UAC 2.0 clock source), and open xHCI isoc pipe.
    fn open_stream(&mut self, unit: usize, capture: bool, ring_vmo: Handle) -> Result<(u32, u8, u8, u32), i32> {
        let desc = match (unit, capture) {
            (0, false) => self.play_desc,
            (1, true) => self.cap_desc,
            _ => None,
        };
        let Some(stream) = desc else {
            sys::handle_close(ring_vmo);
            return Err(sys::ERR_BAD_STATE as i32);
        };
        let svc_ring = IoRing::attach(ring_vmo).map_err(|e| e as i32)?;
        self.stop_active();

        // Activate streaming interface alt-setting (`SET_INTERFACE`, standard request 11).
        if self.usb_ctrl(0x01, 11, u16::from(stream.alt), u16::from(stream.iface), &[]).is_err() {
            println!("usbaudio: SET_INTERFACE(iface={}, alt={}) failed", stream.iface, stream.alt);
            return Err(proto::ERR_IO);
        }

        let rate = stream.choose_rate(48_000);
        // Set sample rate if supported.
        match stream.version {
            UacVersion::Uac1 if stream.ep_freq_ctrl => {
                let r = [rate as u8, (rate >> 8) as u8, (rate >> 16) as u8];
                let _ = self.usb_ctrl(0x22, 0x01, 0x0100, u16::from(stream.ep_addr), &r);
            }
            UacVersion::Uac2 if stream.clock_source_id != 0 => {
                let r = rate.to_le_bytes();
                let wi = (u16::from(stream.clock_source_id) << 8) | u16::from(self.ac_iface);
                let _ = self.usb_ctrl(0x21, 0x01, 0x0100, wi, &r);
            }
            _ => {}
        }
        // Unmute Feature Unit if present (UAC 1.0/2.0: CS=0x01 MUTE_CONTROL, CN=0).
        if stream.feature_unit_id != 0 {
            let wi = (u16::from(stream.feature_unit_id) << 8) | u16::from(self.ac_iface);
            let _ = self.usb_ctrl(0x21, 0x01, 0x0100, wi, &[0u8]);
        }

        let frame_bytes = u32::from(stream.channels) * u32::from(stream.subslot_bytes);
        let frames_per_ms = (rate / 1000).max(1);
        let packet_bytes = (frames_per_ms * frame_bytes).min(u32::from(stream.max_packet)) as u16;
        let period_frames = frames_per_ms * PERIOD_PACKETS;

        let isoc_ring = IoRing::create(ISOC_RING_SLOTS, ISOC_RING_SLOTS * ISOC_SLOT_BYTES).map_err(|e| e as i32)?;
        let dup = sys::handle_duplicate(
            isoc_ring.vmo(),
            sys::RIGHT_READ | sys::RIGHT_WRITE | sys::RIGHT_MAP | sys::RIGHT_INSPECT | sys::RIGHT_TRANSFER,
        )
        .map_err(|e| e as i32)?;
        let a = u64::from(stream.ep_addr)
            | (u64::from(stream.max_packet) << 8)
            | (u64::from(stream.interval) << 24)
            | (u64::from(stream.mult) << 32)
            | (u64::from(packet_bytes) << 40);
        let mut req = [0u8; HEADER];
        Header { txid: 0, op: audio::USB_ISOC_OPEN, status: 0, a, b: u64::from(PERIOD_PACKETS) }.put(&mut req);
        let mut rep = [0u8; HEADER];
        let mut rh = [0 as Handle; 1];
        let res = sys::channel_call_h(
            self.bus,
            &req,
            &[MsgHandle { handle: dup, rights: sys::RIGHTS_SAME }],
            &mut rep,
            &mut rh,
            2_000 * MS,
        );
        if let Ok((n, nh)) = res {
            if nh > 0 && rh[0] != 0 {
                sys::handle_close(rh[0]);
            }
            let h = Header::get(&rep[..n]).ok_or(proto::ERR_IO)?;
            if h.status != 0 {
                return Err(h.status);
            }
        } else {
            return Err(proto::ERR_IO);
        }

        self.active = Some(ActiveStream {
            unit,
            stream,
            svc_ring,
            isoc_ring,
            next_slot: 0,
            in_flight: [None; 8],
            frames_done: 0,
        });
        self.pump_rings();
        Ok((rate, stream.channels, fmt_to_wire(stream.format), period_frames))
    }

    fn stop_active(&mut self) {
        if let Some(st) = self.active.take() {
            let mut req = [0u8; HEADER];
            Header { txid: 0, op: audio::USB_ISOC_STOP, status: 0, a: 0, b: 0 }.put(&mut req);
            let mut rep = [0u8; HEADER];
            let _ = sys::channel_call(self.bus, &req, &mut rep, 1_000 * MS);
            // Return interface to zero-bandwidth alt-setting 0.
            let _ = self.usb_ctrl(0x01, 11, 0, u16::from(st.stream.iface), &[]);
        }
    }

    /// Bridge SQEs/CQEs between `audio.dsvc`'s `IoRing` and `xhci`'s isochronous `IoRing`.
    fn pump_rings(&mut self) {
        let Some(st) = self.active.as_mut() else { return };
        let capture = !st.stream.is_output;
        let frame_bytes = (u32::from(st.stream.channels) * u32::from(st.stream.subslot_bytes)).max(1);
        let mut completed_any = false;

        // 1. Drain completions from xHCI isoc ring -> forward to `audio.dsvc`.
        while let Some(cqe) = st.isoc_ring.pop_cq() {
            let slot = (cqe.id as usize) % (ISOC_RING_SLOTS as usize);
            if let Some((svc_id, svc_off, svc_len)) = st.in_flight[slot].take() {
                if capture && cqe.status == 0 {
                    let got = (cqe.a as u32).min(svc_len).min(ISOC_SLOT_BYTES);
                    let src_off = (slot as u32) * ISOC_SLOT_BYTES;
                    let mut tmp = [0u8; ISOC_SLOT_BYTES as usize];
                    if let Some(src) = st.isoc_ring.data(src_off, got) {
                        tmp[..got as usize].copy_from_slice(src);
                    }
                    if let Some(dst) = st.svc_ring.data_mut(svc_off, got) {
                        dst.copy_from_slice(&tmp[..got as usize]);
                    }
                    st.svc_ring.push_cq(Cqe { id: svc_id, status: 0, a: u64::from(got) });
                    st.frames_done += u64::from(got / frame_bytes);
                } else {
                    st.svc_ring.push_cq(Cqe { id: svc_id, status: cqe.status, a: cqe.a });
                    if cqe.status == 0 {
                        st.frames_done += cqe.a / u64::from(frame_bytes);
                    }
                }
                completed_any = true;
            }
        }

        // 2. Forward new SQEs from `audio.dsvc` -> xHCI isoc ring.
        let mut pushed = false;
        for _ in 0..ISOC_RING_SLOTS {
            let slot = (st.next_slot % ISOC_RING_SLOTS) as usize;
            if st.in_flight[slot].is_some() {
                break;
            }
            let Some(sqe) = st.svc_ring.pop_sq() else { break };
            let want_op = if capture { RING_READ } else { RING_WRITE };
            if sqe.op != want_op {
                st.svc_ring.push_cq(Cqe { id: sqe.id, status: sys::ERR_INVALID_ARGS as i32, a: 0 });
                completed_any = true;
                continue;
            }
            let len = sqe.buf_len.min(ISOC_SLOT_BYTES);
            let dst_off = (slot as u32) * ISOC_SLOT_BYTES;
            if !capture {
                let mut tmp = [0u8; ISOC_SLOT_BYTES as usize];
                let Some(src) = st.svc_ring.data(sqe.buf_off, len) else {
                    st.svc_ring.push_cq(Cqe { id: sqe.id, status: sys::ERR_INVALID_ARGS as i32, a: 0 });
                    completed_any = true;
                    continue;
                };
                tmp[..len as usize].copy_from_slice(src);
                if let Some(dst) = st.isoc_ring.data_mut(dst_off, len) {
                    dst.copy_from_slice(&tmp[..len as usize]);
                }
            }
            if st.isoc_ring.push_sq(Sqe {
                id: slot as u32,
                op: want_op,
                a: 0,
                b: 0,
                buf_off: dst_off,
                buf_len: len,
            }) {
                st.in_flight[slot] = Some((sqe.id, sqe.buf_off, len));
                st.next_slot = st.next_slot.wrapping_add(1);
                pushed = true;
            }
        }
        if pushed {
            proto::send(self.bus, audio::USB_ISOC_KICK, 0, 0);
        }
        let unit = st.unit;
        let frames_done = st.frames_done;
        let svc_ch = if unit == 0 { self.play_ch } else { self.cap_ch };
        if completed_any && svc_ch != 0 {
            proto::send(svc_ch, audio::DRV_EVENT, frames_done, 0);
        }
    }

    fn handle_bus(&mut self) {
        let mut buf = [0u8; HEADER + 64];
        loop {
            match sys::channel_read(self.bus, &mut buf, 0) {
                Ok(n) => {
                    if let Some(h) = Header::get(&buf[..n as usize])
                        && h.op == audio::USB_ISOC_EVENT
                    {
                        self.pump_rings();
                    }
                }
                Err(sys::ERR_SHOULD_WAIT) => {
                    self.port.arm(self.bus, sys::READABLE | sys::PEER_CLOSED, KEY_BUS);
                    return;
                }
                Err(_) => {
                    // USB device unplugged!
                    self.bus_closed = true;
                    return;
                }
            }
        }
    }

    fn handle_ctl(&mut self) {
        let mut buf = [0u8; HEADER + 64];
        loop {
            let mut hs = [0 as Handle; 1];
            match sys::channel_read_h(self.ctl, &mut buf, &mut hs, 0) {
                Ok((n, nh)) => {
                    let hnd = if nh > 0 { hs[0] } else { 0 };
                    let Some(h) = Header::get(&buf[..n]) else {
                        if hnd != 0 {
                            sys::handle_close(hnd);
                        }
                        continue;
                    };
                    match h.op {
                        proto::AUDIO_ATTACH if hnd != 0 => match h.a {
                            0 => {
                                if self.play_ch != 0 {
                                    sys::handle_close(self.play_ch);
                                }
                                self.play_ch = hnd;
                                self.port.arm(hnd, sys::READABLE | sys::PEER_CLOSED, KEY_OUT_CH);
                            }
                            1 => {
                                if self.cap_ch != 0 {
                                    sys::handle_close(self.cap_ch);
                                }
                                self.cap_ch = hnd;
                                self.port.arm(hnd, sys::READABLE | sys::PEER_CLOSED, KEY_IN_CH);
                            }
                            _ => {
                                sys::handle_close(hnd);
                            }
                        },
                        proto::TEST_CRASH => {
                            if hnd != 0 {
                                sys::handle_close(hnd);
                            }
                            println!("usbaudio: intentional crash requested");
                            sys::process_exit(sys::EXIT_FAULT);
                        }
                        _ => {
                            if hnd != 0 {
                                sys::handle_close(hnd);
                            }
                        }
                    }
                }
                Err(sys::ERR_SHOULD_WAIT) => {
                    self.port.arm(self.ctl, sys::READABLE | sys::PEER_CLOSED, KEY_CTL);
                    return;
                }
                Err(_) => return,
            }
        }
    }

    fn handle_unit(&mut self, unit: usize) {
        let mut buf = [0u8; HEADER + 64];
        loop {
            let ch = if unit == 0 { self.play_ch } else { self.cap_ch };
            if ch == 0 {
                return;
            }
            let mut hs = [0 as Handle; 1];
            match sys::channel_read_h(ch, &mut buf, &mut hs, 0) {
                Ok((n, nh)) => {
                    let hnd = if nh > 0 { hs[0] } else { 0 };
                    let Some(h) = Header::get(&buf[..n]) else {
                        if hnd != 0 {
                            sys::handle_close(hnd);
                        }
                        continue;
                    };
                    match h.op {
                        audio::DRV_OPEN => {
                            let (capture, _, _, _) = audio::unpack_drv_open(h.a);
                            let mut rep = [0u8; HEADER];
                            if hnd == 0 {
                                Header { txid: h.txid, op: h.op, status: sys::ERR_INVALID_ARGS as i32, a: 0, b: 0 }.put(&mut rep);
                            } else {
                                match self.open_stream(unit, capture, hnd) {
                                    Ok((rate, chs, fmt, pf)) => {
                                        Header {
                                            txid: h.txid,
                                            op: h.op,
                                            status: 0,
                                            a: audio::pack_params(rate, chs, fmt),
                                            b: u64::from(pf),
                                        }
                                        .put(&mut rep);
                                    }
                                    Err(st) => {
                                        Header { txid: h.txid, op: h.op, status: st, a: 0, b: 0 }.put(&mut rep);
                                    }
                                }
                            }
                            let _ = sys::channel_write(ch, &rep);
                        }
                        audio::DRV_KICK => {
                            if hnd != 0 {
                                sys::handle_close(hnd);
                            }
                            self.pump_rings();
                        }
                        audio::DRV_STOP => {
                            if hnd != 0 {
                                sys::handle_close(hnd);
                            }
                            if self.active.as_ref().is_some_and(|s| s.unit == unit) {
                                self.stop_active();
                            }
                            let mut rep = [0u8; HEADER];
                            Header { txid: h.txid, op: h.op, status: 0, a: 0, b: 0 }.put(&mut rep);
                            let _ = sys::channel_write(ch, &rep);
                        }
                        audio::DRV_SET_VOL => {
                            if hnd != 0 {
                                sys::handle_close(hnd);
                            }
                            let mut rep = [0u8; HEADER];
                            Header { txid: h.txid, op: h.op, status: 0, a: 0, b: 0 }.put(&mut rep);
                            let _ = sys::channel_write(ch, &rep);
                        }
                        audio::DRV_TEST_CRASH => {
                            if hnd != 0 {
                                sys::handle_close(hnd);
                            }
                            println!("usbaudio: intentional crash requested (audio crash recovery test)");
                            sys::process_exit(sys::EXIT_FAULT);
                        }
                        _ => {
                            if hnd != 0 {
                                sys::handle_close(hnd);
                            }
                        }
                    }
                }
                Err(sys::ERR_SHOULD_WAIT) => {
                    let key = if unit == 0 { KEY_OUT_CH } else { KEY_IN_CH };
                    self.port.arm(ch, sys::READABLE | sys::PEER_CLOSED, key);
                    return;
                }
                Err(_) => {
                    if self.active.as_ref().is_some_and(|s| s.unit == unit) {
                        self.stop_active();
                    }
                    if unit == 0 {
                        sys::handle_close(self.play_ch);
                        self.play_ch = 0;
                    } else {
                        sys::handle_close(self.cap_ch);
                        self.cap_ch = 0;
                    }
                    return;
                }
            }
        }
    }
}

pub fn main(s: *const Startup) -> i32 {
    // SAFETY: `s` is the startup block pointer the kernel passed to the entry point.
    if !unsafe { libd::init(s, "usbaudio") } {
        return -1;
    }
    let ctl = libd::startup_handle(proto::TAG_CONTROL);
    let bus = libd::startup_handle(proto::TAG_USB_BUS);
    if ctl == 0 || bus == 0 {
        println!("usbaudio: missing control or USB bus handle");
        return 1;
    }

    // Fetch raw USB configuration descriptor from `xhci.ddrv`.
    let mut req = [0u8; HEADER];
    Header { txid: 0, op: audio::USB_GET_DESC, status: 0, a: 0, b: 0 }.put(&mut req);
    let mut rep = [0u8; HEADER + 2048];
    let Ok(n) = sys::channel_call(bus, &req, &mut rep, 3_000 * MS) else {
        println!("usbaudio: USB_GET_DESC failed");
        return 1;
    };
    let n = n as usize;
    let Some(h) = Header::get(&rep[..n]) else {
        println!("usbaudio: malformed USB_GET_DESC reply");
        return 1;
    };
    let vid = (h.a & 0xFFFF) as u16;
    let pid = ((h.a >> 16) & 0xFFFF) as u16;
    let desc_bytes = &rep[HEADER..n];
    let Some(cfg) = parse_config(desc_bytes) else {
        println!("usbaudio: {:04x}:{:04x} has no usable UAC 1/2 PCM stream", vid, pid);
        return 1;
    };
    let play_desc = cfg.best_stream(true);
    let cap_desc = cfg.best_stream(false);
    if play_desc.is_none() && cap_desc.is_none() {
        println!("usbaudio: {:04x}:{:04x} has no playback or capture endpoint", vid, pid);
        return 1;
    }

    let Ok(port) = Port::new(32) else {
        println!("usbaudio: cannot create port");
        return 1;
    };

    let mut ua = UsbAudio {
        ctl,
        bus,
        port,
        ac_iface: cfg.ac_iface,
        play_desc,
        cap_desc,
        play_ch: 0,
        cap_ch: 0,
        active: None,
        bus_closed: false,
    };

    let ver_str = match cfg.version {
        UacVersion::Uac1 => "UAC 1.0",
        UacVersion::Uac2 => "UAC 2.0",
    };
    let mut count = 0u64;
    if let Some(p) = play_desc {
        let rate = p.choose_rate(48_000);
        println!(
            "usbaudio: {:04x}:{:04x} {} playback ready (if={} alt={} ep={:#04x} {}Hz {}ch {:?} mps={})",
            vid, pid, ver_str, p.iface, p.alt, p.ep_addr, rate, p.channels, p.format, p.max_packet
        );
        let a = ((DeviceKind::UsbAudio as u64) << 16) | ((u64::from(FLAG_PLAYBACK | FLAG_PLUGGED)) << 32);
        let b = u64::from(rate) | (u64::from(p.channels) << 32) | (u64::from(fmt_to_wire(p.format)) << 40);
        let name = b"USB Audio Output";
        let mut msg = [0u8; HEADER + 32];
        Header { txid: 0, op: proto::AUDIO_DEV, status: 0, a, b }.put(&mut msg);
        msg[HEADER..HEADER + name.len()].copy_from_slice(name);
        let _ = sys::channel_write(ctl, &msg[..HEADER + name.len()]);
        count += 1;
    }
    if let Some(c) = cap_desc {
        let rate = c.choose_rate(48_000);
        println!(
            "usbaudio: {:04x}:{:04x} {} capture ready (if={} alt={} ep={:#04x} {}Hz {}ch {:?} mps={})",
            vid, pid, ver_str, c.iface, c.alt, c.ep_addr, rate, c.channels, c.format, c.max_packet
        );
        let a = 1u64 | ((DeviceKind::UsbAudio as u64) << 16) | ((u64::from(FLAG_CAPTURE | FLAG_PLUGGED)) << 32);
        let b = u64::from(rate) | (u64::from(c.channels) << 32) | (u64::from(fmt_to_wire(c.format)) << 40);
        let name = b"USB Audio Mic";
        let mut msg = [0u8; HEADER + 32];
        Header { txid: 0, op: proto::AUDIO_DEV, status: 0, a, b }.put(&mut msg);
        msg[HEADER..HEADER + name.len()].copy_from_slice(name);
        let _ = sys::channel_write(ctl, &msg[..HEADER + name.len()]);
        count += 1;
    }

    ua.port.arm(ctl, sys::READABLE | sys::PEER_CLOSED, KEY_CTL);
    ua.port.arm(bus, sys::READABLE | sys::PEER_CLOSED, KEY_BUS);
    proto::send(ctl, proto::READY, count, 0);

    while !ua.bus_closed {
        let wait_ns = if ua.active.is_some() { 10 * MS } else { 250 * MS };
        if let Some((key, _)) = ua.port.wait(wait_ns) {
            match key {
                KEY_CTL => ua.handle_ctl(),
                KEY_BUS => ua.handle_bus(),
                KEY_OUT_CH => ua.handle_unit(0),
                KEY_IN_CH => ua.handle_unit(1),
                _ => {}
            }
        }
        if ua.active.is_some() {
            ua.pump_rings();
        }
    }

    // Device unplugged cleanly: notify devmgr and exit 0 so devmgr does not restart us.
    if play_desc.is_some() {
        proto::send(ctl, proto::AUDIO_GONE, 0, 0);
    }
    if cap_desc.is_some() {
        proto::send(ctl, proto::AUDIO_GONE, 1, 0);
    }
    println!("usbaudio: {:04x}:{:04x} unplugged, exiting cleanly", vid, pid);
    0
}
