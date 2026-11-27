//! D-OS audio service (`audio.dsvc`).
//!
//! - Connects to `devmgr.audio` to discover IOMMU-confined audio drivers (`hda.ddrv`,
//!   `usbaudio.ddrv`, `virtio-snd.ddrv`) and receives live jack/ELD/hotplug updates.
//! - Provides three capability-separated endpoints:
//!   - `audio.playback`: playback streams (zero-copy `IoRing`), never permitted to capture.
//!   - `audio.capture`: microphone capture streams (requires explicit manifest grant + policy).
//!   - `audio.control`: device listing, per-device volume/mute, manual/auto routing, mic policy.
//! - Drives `terminal.indicator` so any active microphone capture displays a visible `[MIC LIVE]`
//!   badge that clears automatically when capture ends, is revoked, or the client disconnects.
//! - Mixes concurrent playback streams with format/channel/rate conversion (`dosaudio::pcm`) and
//!   automatically switches output (`Headphones` -> `USB Audio` -> `HDMI/DP` -> `Speakers`),
//!   seamlessly recovering playback across audio driver crashes and restarts.

#![no_std]

extern crate alloc;

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use dosaudio::pcm::{
    Resampler, SampleFormat, StreamParams, decode_frame_stereo, finalize_mix, volume_gain_q16,
};
use dosaudio::route::{
    DeviceKind, FLAG_PLAYBACK, FLAG_PLUGGED, RouteDevice, select_input, select_output,
};
use dosid::AudioSettings;
use libd::audio::{
    self, DEVICE_ENTRY_BYTES, DeviceEntry, FMT_F32_LE, FMT_S16_LE, FMT_S24_LE, FMT_S32_LE, FMT_U8,
    RING_READ, RING_WRITE,
};
use libd::fs as fp;
use libd::proto::{self, HEADER, Header};
use libd::ring::{Cqe, IoRing, Sqe};
use libd::sys::{self, Handle, MsgHandle};
use libd::{Port, Startup, println, svc, term};

libd::entry!(dsvc_audio, main);

const MS: u64 = 1_000_000;
const KEY_CTL: u64 = 1;
const KEY_DEVMGR: u64 = 2;
const KEY_HW_OUT: u64 = 3;
const KEY_HW_IN: u64 = 4;
const KEY_CLIENT_BASE: u64 = 100;

const HW_RING_SLOTS: u32 = 8;
const HW_RING_SLOT_BYTES: u32 = 4096;
const HW_MAX_IN_FLIGHT: u32 = 4;
const HOME_CFG_DIR: &[u8] = b".dos";
const HOME_AUDIO_FILE: &[u8] = b".dos/audio.toml";
const HOME_AUDIO_TMP: &[u8] = b".dos/audio.tmp";

fn load_audio_settings() -> Option<AudioSettings> {
    let ns = fp::Namespace::get();
    let (dir, _) = ns.resolve(b"/home")?;
    let d = fp::Node::from(dir);
    let parsed = (|| {
        let (f, _, size) = d.open(HOME_AUDIO_FILE, 0, fp::R_READ).ok()?;
        let size = usize::try_from(size).ok()?;
        if size == 0 || size > 16 * 1024 {
            return None;
        }
        let mut buf = vec![0u8; size];
        let n = f.read(0, &mut buf).ok()?;
        AudioSettings::from_toml(&buf[..n]).ok()
    })();
    let _ = d.into_handle();
    parsed
}

fn save_audio_settings(cfg: &AudioSettings) {
    let ns = fp::Namespace::get();
    let Some((dir, _)) = ns.resolve(b"/home") else {
        return;
    };
    let d = fp::Node::from(dir);
    if d.stat().is_ok_and(|st| st.rights & fp::R_WRITE != 0) {
        let text = cfg.to_toml();
        let _ = d.open(HOME_CFG_DIR, fp::O_DIRECTORY | fp::O_CREATE, fp::R_READ | fp::R_WRITE);
        if let Ok((f, _, _)) = d.open(HOME_AUDIO_TMP, fp::O_CREATE | fp::O_TRUNCATE, fp::R_READ | fp::R_WRITE)
            && f.write(0, text.as_bytes()).is_ok()
        {
            drop(f);
            if d.rename(HOME_AUDIO_TMP, HOME_AUDIO_FILE, true).is_err()
                && let Ok((f2, _, _)) = d.open(HOME_AUDIO_FILE, fp::O_CREATE | fp::O_TRUNCATE, fp::R_READ | fp::R_WRITE)
            {
                let _ = f2.write(0, text.as_bytes());
            }
            let _ = d.sync();
        }
    }
    let _ = d.into_handle();
}

fn wire_to_fmt(v: u8) -> Option<SampleFormat> {
    match v {
        FMT_U8 => Some(SampleFormat::U8),
        FMT_S16_LE => Some(SampleFormat::S16Le),
        FMT_S24_LE => Some(SampleFormat::S24Le),
        FMT_S32_LE => Some(SampleFormat::S32Le),
        FMT_F32_LE => Some(SampleFormat::F32Le),
        _ => None,
    }
}

fn fmt_to_wire(f: SampleFormat) -> u8 {
    match f {
        SampleFormat::U8 => FMT_U8,
        SampleFormat::S16Le => FMT_S16_LE,
        SampleFormat::S24Le => FMT_S24_LE,
        SampleFormat::S32Le => FMT_S32_LE,
        SampleFormat::F32Le => FMT_F32_LE,
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Role {
    Playback,
    Capture,
    Control,
}

struct Backend {
    id: u32,
    dev_key: u16,
    kind: DeviceKind,
    flags: u32,
    params: StreamParams,
    name: String,
    ch: Handle,
    online: bool,
    volume: u8,
    saved_volume: u8,
    muted: bool,
}

struct HwPipe {
    dev_id: u32,
    ch: Handle,
    ring: IoRing,
    params: StreamParams,
    period_frames: usize,
    next_slot: u32,
    in_flight: u32,
    next_id: u32,
}

impl HwPipe {
    fn open(dev: &Backend, capture: bool) -> Result<Self, i64> {
        let ring = IoRing::create(HW_RING_SLOTS, HW_RING_SLOTS * HW_RING_SLOT_BYTES)?;
        let dup = sys::handle_duplicate(
            ring.vmo(),
            sys::RIGHT_READ | sys::RIGHT_WRITE | sys::RIGHT_MAP | sys::RIGHT_INSPECT | sys::RIGHT_TRANSFER,
        )?;
        let req_period = (dev.params.rate / 100).clamp(128, 960); // ~10 ms
        let mut req = [0u8; HEADER];
        Header {
            txid: 0,
            op: audio::DRV_OPEN,
            status: 0,
            a: audio::pack_drv_open(capture, dev.params.rate, dev.params.channels, fmt_to_wire(dev.params.format)),
            b: u64::from(req_period),
        }
        .put(&mut req);
        let mut rep = [0u8; HEADER];
        let mut rh = [0 as Handle; 1];
        let (n, nh) = sys::channel_call_h(
            dev.ch,
            &req,
            &[MsgHandle { handle: dup, rights: sys::RIGHTS_SAME }],
            &mut rep,
            &mut rh,
            3_000 * MS,
        )?;
        if nh > 0 && rh[0] != 0 {
            sys::handle_close(rh[0]);
        }
        let h = Header::get(&rep[..n]).ok_or(sys::ERR_INVALID_ARGS)?;
        if h.status != 0 {
            return Err(i64::from(h.status));
        }
        let (rate, chs, fmt_wire) = audio::unpack_params(h.a);
        let format = wire_to_fmt(fmt_wire).unwrap_or(SampleFormat::S16Le);
        let params = StreamParams {
            rate: rate.clamp(8_000, 192_000),
            channels: chs.clamp(1, 8),
            format,
        };
        let period_frames = ((h.b as usize).clamp(64, 1024))
            .min(HW_RING_SLOT_BYTES as usize / params.frame_bytes().max(1));
        Ok(Self {
            dev_id: dev.id,
            ch: dev.ch,
            ring,
            params,
            period_frames,
            next_slot: 0,
            in_flight: 0,
            next_id: 1,
        })
    }

    fn stop(&self) {
        if self.ch != 0 {
            let mut req = [0u8; HEADER];
            Header { txid: 0, op: audio::DRV_STOP, status: 0, a: 0, b: 0 }.put(&mut req);
            let mut rep = [0u8; HEADER];
            let _ = sys::channel_call(self.ch, &req, &mut rep, 500 * MS);
        }
    }
}

struct ClientConn {
    id: u64,
    role: Role,
    ch: Handle,
}

#[derive(Clone, Copy)]
struct PendingSqe {
    sqe: Sqe,
    offset: usize,
}

struct ClientStream {
    id: u64,
    client_id: u64,
    is_capture: bool,
    params: StreamParams,
    ring: IoRing,
    resampler: Resampler,
    volume: u8,
    muted: bool,
    pending: Option<PendingSqe>,
    label: String,
}

struct AudioSvc {
    port: Port,
    ctl: Handle,
    devmgr: Handle,
    indicator: Handle,
    test_mode: bool,
    stop: bool,
    backends: Vec<Backend>,
    next_dev_id: u32,
    manual_out: Option<u32>,
    active_out_id: Option<u32>,
    active_in_id: Option<u32>,
    hw_out: Option<HwPipe>,
    hw_in: Option<HwPipe>,
    clients: Vec<ClientConn>,
    next_client_id: u64,
    streams: Vec<ClientStream>,
    next_stream_id: u64,
    mic_allowed: bool,
    mic_ind_on: bool,
    driver_restarts: u32,
    last_silent_pace_ns: u64,
    saved: AudioSettings,
}

impl AudioSvc {
    fn persist_settings(&self) {
        if !self.test_mode {
            save_audio_settings(&self.saved);
        }
    }
    fn route_snapshot(&self) -> Vec<RouteDevice> {
        self.backends
            .iter()
            .map(|b| RouteDevice { id: b.id, kind: b.kind, flags: b.flags, online: b.online && b.ch != 0 })
            .collect()
    }

    fn backend_by_id(&self, id: u32) -> Option<&Backend> {
        self.backends.iter().find(|b| b.id == id)
    }

    fn backend_by_id_mut(&mut self, id: u32) -> Option<&mut Backend> {
        self.backends.iter_mut().find(|b| b.id == id)
    }

    fn client_ch(&self, client_id: u64) -> Handle {
        self.clients.iter().find(|c| c.id == client_id).map_or(0, |c| c.ch)
    }

    fn update_mic_indicator(&mut self) {
        let active_cap = self.streams.iter().find(|s| s.is_capture);
        let want = active_cap.is_some();
        if want == self.mic_ind_on {
            return;
        }
        self.mic_ind_on = want;
        let label = active_cap.map_or("", |s| s.label.as_str());
        if want {
            println!("audio: microphone active ({})", if label.is_empty() { "client" } else { label });
        } else {
            println!("audio: microphone inactive");
        }
        if self.indicator != 0 {
            let mut msg = [0u8; HEADER + 32];
            let flags = if want { term::IND_MIC_ACTIVE } else { 0 };
            let n = label.len().min(32);
            Header { txid: 0, op: term::INDICATOR, status: 0, a: flags, b: 0 }.put(&mut msg);
            msg[HEADER..HEADER + n].copy_from_slice(&label.as_bytes()[..n]);
            let _ = sys::channel_write(self.indicator, &msg[..HEADER + n]);
        }
    }

    /// Re-evaluate automatic output & input routing and open/switch hardware streams as needed.
    fn reconcile_routing(&mut self) {
        let snap = self.route_snapshot();
        let want_out = select_output(&snap, self.manual_out);
        let want_in = select_input(&snap, None);

        if want_out != self.active_out_id {
            self.active_out_id = want_out;
            if let Some(id) = want_out
                && let Some(b) = self.backend_by_id(id)
            {
                println!(
                    "audio: output switched to '{}' (id {}, {}, plugged={})",
                    b.name,
                    b.id,
                    b.kind.label(),
                    (b.flags & FLAG_PLUGGED) != 0
                );
            }
        }
        self.active_in_id = want_in;

        let has_play = self.streams.iter().any(|s| !s.is_capture);
        let has_cap = self.streams.iter().any(|s| s.is_capture);

        // Reconcile hardware output pipe.
        let need_out_switch = match (&self.hw_out, want_out, has_play) {
            (Some(hw), Some(want), true) => hw.dev_id != want,
            (Some(_), _, false) | (Some(_), None, true) => true,
            _ => false,
        };
        if need_out_switch
            && let Some(old) = self.hw_out.take()
        {
            old.stop();
        }
        if has_play
            && self.hw_out.is_none()
            && let Some(id) = want_out
            && let Some(pos) = self.backends.iter().position(|b| b.id == id && b.online && b.ch != 0)
        {
            let dev_name = self.backends[pos].name.clone();
            match HwPipe::open(&self.backends[pos], false) {
                Ok(hw) => {
                    let out_rate = hw.params.rate;
                    let (bvol, bmuted) = (self.backends[pos].volume, self.backends[pos].muted);
                    if bmuted {
                        let mut dreq = [0u8; HEADER];
                        Header { txid: 0, op: audio::DRV_SET_VOL, status: 0, a: u64::from(bvol), b: 1 }
                            .put(&mut dreq);
                        let mut drep = [0u8; HEADER];
                        let _ = sys::channel_call(hw.ch, &dreq, &mut drep, 500_000_000);
                    }
                    self.port.arm(hw.ch, sys::READABLE | sys::PEER_CLOSED, KEY_HW_OUT);
                    self.hw_out = Some(hw);
                    for s in self.streams.iter_mut().filter(|s| !s.is_capture) {
                        s.resampler.reset(s.params.rate, out_rate);
                    }
                    println!("audio: opened playback stream on '{}' ({} Hz)", dev_name, out_rate);
                }
                Err(e) => {
                    println!("audio: failed to open playback on '{}': {}", dev_name, sys::status(e));
                }
            }
        }

        // Reconcile hardware input pipe.
        let need_in_switch = match (&self.hw_in, want_in, has_cap) {
            (Some(hw), Some(want), true) => hw.dev_id != want,
            (Some(_), _, false) | (Some(_), None, true) => true,
            _ => false,
        };
        if need_in_switch
            && let Some(old) = self.hw_in.take()
        {
            old.stop();
        }
        if has_cap
            && self.hw_in.is_none()
            && let Some(id) = want_in
            && let Some(pos) = self.backends.iter().position(|b| b.id == id && b.online && b.ch != 0)
        {
            let dev_name = self.backends[pos].name.clone();
            match HwPipe::open(&self.backends[pos], true) {
                Ok(hw) => {
                    let in_rate = hw.params.rate;
                    self.port.arm(hw.ch, sys::READABLE | sys::PEER_CLOSED, KEY_HW_IN);
                    self.hw_in = Some(hw);
                    for s in self.streams.iter_mut().filter(|s| s.is_capture) {
                        s.resampler.reset(in_rate, s.params.rate);
                    }
                    println!("audio: opened capture stream on '{}' ({} Hz)", dev_name, in_rate);
                    self.submit_hw_in();
                }
                Err(e) => {
                    println!("audio: failed to open capture on '{}': {}", dev_name, sys::status(e));
                }
            }
        }

        self.update_mic_indicator();
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
                    let ep = &buf[HEADER..n];
                    match h.op {
                        svc::CONNECT if hnd != 0 => match ep {
                            b"devmgr.audio" => {
                                if self.devmgr != 0 {
                                    sys::handle_close(self.devmgr);
                                }
                                self.devmgr = hnd;
                                self.port.arm(hnd, sys::READABLE | sys::PEER_CLOSED, KEY_DEVMGR);
                            }
                            b"terminal.indicator" => {
                                if self.indicator != 0 {
                                    sys::handle_close(self.indicator);
                                }
                                self.indicator = hnd;
                                let was = self.mic_ind_on;
                                self.mic_ind_on = !was; // force resend
                                self.update_mic_indicator();
                            }
                            b"playback" | b"capture" | b"control" => {
                                let role = match ep {
                                    b"playback" => Role::Playback,
                                    b"capture" => Role::Capture,
                                    _ => Role::Control,
                                };
                                let id = self.next_client_id;
                                self.next_client_id += 1;
                                self.clients.push(ClientConn { id, role, ch: hnd });
                                self.port.arm(hnd, sys::READABLE | sys::PEER_CLOSED, KEY_CLIENT_BASE + id);
                            }
                            _ => {
                                sys::handle_close(hnd);
                            }
                        },
                        svc::SHUTDOWN => {
                            if hnd != 0 {
                                sys::handle_close(hnd);
                            }
                            self.stop = true;
                            return;
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

    fn handle_devmgr(&mut self) {
        let mut buf = [0u8; HEADER + 64];
        loop {
            if self.devmgr == 0 {
                return;
            }
            let mut hs = [0 as Handle; 1];
            match sys::channel_read_h(self.devmgr, &mut buf, &mut hs, 0) {
                Ok((n, nh)) => {
                    let hnd = if nh > 0 { hs[0] } else { 0 };
                    let Some(h) = Header::get(&buf[..n]) else {
                        if hnd != 0 {
                            sys::handle_close(hnd);
                        }
                        continue;
                    };
                    match h.op {
                        audio::BACKEND_ADD if hnd != 0 => {
                            let dev_key = (h.a & 0xFFFF) as u16;
                            let kind = DeviceKind::from_u8(((h.a >> 16) & 0xFF) as u8);
                            let flags = (h.a >> 32) as u32;
                            let (rate, chs, fmt_w) = audio::unpack_params(h.b);
                            let params = StreamParams {
                                rate: rate.clamp(8_000, 192_000),
                                channels: chs.clamp(1, 8),
                                format: wire_to_fmt(fmt_w).unwrap_or(SampleFormat::S16Le),
                            };
                            let name = String::from_utf8_lossy(&buf[HEADER..n]).into_owned();
                            if let Some(existing) = self.backends.iter_mut().find(|b| b.dev_key == dev_key) {
                                // Restarted driver reattached! Replace handle and restore playback.
                                let old_ch = existing.ch;
                                let existing_id = existing.id;
                                existing.ch = hnd;
                                existing.online = true;
                                existing.flags = flags;
                                existing.kind = kind;
                                existing.params = params;
                                existing.name = name.clone();
                                if self.hw_out.as_ref().is_some_and(|hw| hw.dev_id == existing_id) {
                                    self.hw_out = None;
                                }
                                if self.hw_in.as_ref().is_some_and(|hw| hw.dev_id == existing_id) {
                                    self.hw_in = None;
                                }
                                if old_ch != 0 {
                                    sys::handle_close(old_ch);
                                }
                                println!("audio: backend '{}' (id {}) reconnected", name, existing_id);
                            } else {
                                let id = self.next_dev_id;
                                self.next_dev_id += 1;
                                println!(
                                    "audio: backend '{}' registered (id {}, {}, {} Hz {} ch, flags={:#x})",
                                    name,
                                    id,
                                    kind.label(),
                                    params.rate,
                                    params.channels,
                                    flags
                                );
                                let init_vol = self.saved.volume.min(100);
                                let init_muted = self.saved.muted;
                                let match_default = !self.saved.default_output.is_empty()
                                    && self.saved.default_output == name
                                    && (flags & FLAG_PLAYBACK) != 0;
                                self.backends.push(Backend {
                                    id,
                                    dev_key,
                                    kind,
                                    flags,
                                    params,
                                    name,
                                    ch: hnd,
                                    online: true,
                                    volume: init_vol,
                                    saved_volume: init_vol,
                                    muted: init_muted,
                                });
                                if match_default && self.manual_out.is_none() {
                                    self.manual_out = Some(id);
                                }
                            }
                            self.reconcile_routing();
                        }
                        audio::BACKEND_JACK => {
                            if hnd != 0 {
                                sys::handle_close(hnd);
                            }
                            let dev_key = (h.a & 0xFFFF) as u16;
                            let flags = h.b as u32;
                            let new_name = &buf[HEADER..n];
                            if let Some(b) = self.backends.iter_mut().find(|b| b.dev_key == dev_key) {
                                b.flags = flags;
                                if !new_name.is_empty() {
                                    b.name = String::from_utf8_lossy(new_name).into_owned();
                                }
                                println!(
                                    "audio: jack event on '{}' (id {}, plugged={})",
                                    b.name,
                                    b.id,
                                    (flags & FLAG_PLUGGED) != 0
                                );
                            }
                            self.reconcile_routing();
                        }
                        audio::BACKEND_GONE => {
                            if hnd != 0 {
                                sys::handle_close(hnd);
                            }
                            let dev_key = (h.a & 0xFFFF) as u16;
                            if let Some(pos) = self.backends.iter().position(|b| b.dev_key == dev_key) {
                                let b = self.backends.remove(pos);
                                println!("audio: backend '{}' (id {}) removed", b.name, b.id);
                                if self.hw_out.as_ref().is_some_and(|hw| hw.dev_id == b.id) {
                                    self.hw_out = None;
                                }
                                if self.hw_in.as_ref().is_some_and(|hw| hw.dev_id == b.id) {
                                    self.hw_in = None;
                                }
                                if b.ch != 0 {
                                    sys::handle_close(b.ch);
                                }
                                if self.manual_out == Some(b.id) {
                                    self.manual_out = None;
                                }
                            }
                            self.reconcile_routing();
                        }
                        _ => {
                            if hnd != 0 {
                                sys::handle_close(hnd);
                            }
                        }
                    }
                }
                Err(sys::ERR_SHOULD_WAIT) => {
                    self.port.arm(self.devmgr, sys::READABLE | sys::PEER_CLOSED, KEY_DEVMGR);
                    return;
                }
                Err(_) => {
                    sys::handle_close(self.devmgr);
                    self.devmgr = 0;
                    return;
                }
            }
        }
    }

    fn handle_hw_out(&mut self) {
        let mut buf = [0u8; HEADER];
        loop {
            let Some(hw) = self.hw_out.as_mut() else { return };
            let ch = hw.ch;
            match sys::channel_read(ch, &mut buf, 0) {
                Ok(_) => {
                    while hw.ring.pop_cq().is_some() {
                        hw.in_flight = hw.in_flight.saturating_sub(1);
                    }
                }
                Err(sys::ERR_SHOULD_WAIT) => {
                    while hw.ring.pop_cq().is_some() {
                        hw.in_flight = hw.in_flight.saturating_sub(1);
                    }
                    self.port.arm(ch, sys::READABLE | sys::PEER_CLOSED, KEY_HW_OUT);
                    return;
                }
                Err(_) => {
                    // Output driver crashed or closed! Mark offline, drop hw_out, keep client streams alive!
                    let dev_id = hw.dev_id;
                    self.hw_out = None;
                    self.driver_restarts += 1;
                    if let Some(b) = self.backend_by_id_mut(dev_id) {
                        println!("audio: output backend '{}' disconnected (driver restart pending)", b.name);
                        if b.ch != 0 {
                            sys::handle_close(b.ch);
                            b.ch = 0;
                        }
                        b.online = false;
                    }
                    self.reconcile_routing();
                    return;
                }
            }
        }
    }

    fn handle_hw_in(&mut self) {
        let mut buf = [0u8; HEADER];
        let mut got_cqe = false;
        loop {
            let Some(hw) = self.hw_in.as_mut() else { return };
            let ch = hw.ch;
            match sys::channel_read(ch, &mut buf, 0) {
                Ok(_) => got_cqe = true,
                Err(sys::ERR_SHOULD_WAIT) => {
                    self.port.arm(ch, sys::READABLE | sys::PEER_CLOSED, KEY_HW_IN);
                    break;
                }
                Err(_) => {
                    let dev_id = hw.dev_id;
                    self.hw_in = None;
                    if let Some(b) = self.backend_by_id_mut(dev_id) {
                        println!("audio: capture backend '{}' disconnected", b.name);
                        if b.ch != 0 {
                            sys::handle_close(b.ch);
                            b.ch = 0;
                        }
                        b.online = false;
                    }
                    self.reconcile_routing();
                    return;
                }
            }
        }
        let _ = got_cqe;
        self.drain_hw_in();
        self.submit_hw_in();
    }

    fn submit_hw_in(&mut self) {
        let Some(hw) = self.hw_in.as_mut() else { return };
        let period_bytes = (hw.period_frames * hw.params.frame_bytes()).min(HW_RING_SLOT_BYTES as usize) as u32;
        let mut pushed = false;
        while hw.in_flight < HW_MAX_IN_FLIGHT {
            let slot = hw.next_slot % HW_RING_SLOTS;
            let off = slot * HW_RING_SLOT_BYTES;
            let sqe = Sqe {
                id: slot,
                op: RING_READ,
                a: 0,
                b: 0,
                buf_off: off,
                buf_len: period_bytes,
            };
            if !hw.ring.push_sq(sqe) {
                break;
            }
            hw.next_slot = hw.next_slot.wrapping_add(1);
            hw.in_flight += 1;
            pushed = true;
        }
        if pushed {
            proto::send(hw.ch, audio::DRV_KICK, 0, 0);
        }
    }

    fn drain_hw_in(&mut self) {
        let Some(hw) = self.hw_in.as_mut() else { return };
        let mut decoded_blocks: Vec<Vec<[i32; 2]>> = Vec::new();
        while let Some(cqe) = hw.ring.pop_cq() {
            hw.in_flight = hw.in_flight.saturating_sub(1);
            if cqe.status != 0 {
                continue;
            }
            let slot = cqe.id % HW_RING_SLOTS;
            let off = slot * HW_RING_SLOT_BYTES;
            let len = (cqe.a as usize).min(HW_RING_SLOT_BYTES as usize);
            let fb = hw.params.frame_bytes();
            if fb == 0 || len < fb {
                continue;
            }
            if let Some(raw) = hw.ring.data(off, len as u32) {
                let nframes = len / fb;
                let mut lr = Vec::with_capacity(nframes);
                for i in 0..nframes {
                    lr.push(decode_frame_stereo(hw.params, &raw[i * fb..(i + 1) * fb]));
                }
                decoded_blocks.push(lr);
            }
        }
        if decoded_blocks.is_empty() {
            return;
        }
        for lr in &decoded_blocks {
            let mut notify_clients: Vec<(u64, u64)> = Vec::new();
            for s in self.streams.iter_mut().filter(|s| s.is_capture) {
                if let Some(sqe) = s.ring.pop_sq() {
                    if sqe.op == RING_READ {
                        let params = s.params;
                        let fb = params.frame_bytes();
                        if let Some(dst) = s.ring.data_mut(sqe.buf_off, sqe.buf_len) {
                            let (_, written_frames) = s.resampler.convert_stereo_to_bytes(lr, params, dst);
                            s.ring.push_cq(Cqe { id: sqe.id, status: 0, a: (written_frames * fb) as u64 });
                            notify_clients.push((s.client_id, s.id));
                        } else {
                            s.ring.push_cq(Cqe { id: sqe.id, status: sys::ERR_INVALID_ARGS as i32, a: 0 });
                        }
                    } else {
                        s.ring.push_cq(Cqe { id: sqe.id, status: sys::ERR_INVALID_ARGS as i32, a: 0 });
                    }
                }
            }
            for (cid, sid) in notify_clients {
                let ch = self.client_ch(cid);
                if ch != 0 {
                    proto::send(ch, audio::OP_DRAINED, sid, 0);
                }
            }
        }
    }

    fn handle_client(&mut self, client_id: u64) {
        let mut buf = [0u8; HEADER + 64];
        loop {
            let Some(pos) = self.clients.iter().position(|c| c.id == client_id) else {
                return;
            };
            let (ch, role) = (self.clients[pos].ch, self.clients[pos].role);
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
                    let payload = &buf[HEADER..n];
                    self.dispatch_client(client_id, ch, role, h, payload, hnd);
                }
                Err(sys::ERR_SHOULD_WAIT) => {
                    self.port.arm(ch, sys::READABLE | sys::PEER_CLOSED, KEY_CLIENT_BASE + client_id);
                    return;
                }
                Err(_) => {
                    // Client disconnected: remove all of its streams and update mic indicator!
                    self.clients.remove(pos);
                    sys::handle_close(ch);
                    self.streams.retain(|s| s.client_id != client_id);
                    self.reconcile_routing();
                    return;
                }
            }
        }
    }

    fn reply(ch: Handle, h: Header, status: i32, a: u64, b: u64) {
        let mut rep = [0u8; HEADER];
        Header { txid: h.txid, op: h.op, status, a, b }.put(&mut rep);
        let _ = sys::channel_write(ch, &rep);
    }

    fn dispatch_client(&mut self, client_id: u64, ch: Handle, role: Role, h: Header, payload: &[u8], hnd: Handle) {
        let close_hnd = || {
            if hnd != 0 {
                sys::handle_close(hnd);
            }
        };
        match h.op {
            audio::OP_OPEN_PLAY => {
                if role != Role::Playback {
                    close_hnd();
                    println!("audio: refused playback on non-playback endpoint");
                    Self::reply(ch, h, sys::ERR_ACCESS_DENIED as i32, 0, 0);
                    return;
                }
                if hnd == 0 {
                    Self::reply(ch, h, sys::ERR_INVALID_ARGS as i32, 0, 0);
                    return;
                }
                let (rate, chs, fmt_w) = audio::unpack_params(h.a);
                let Some(fmt) = wire_to_fmt(fmt_w) else {
                    close_hnd();
                    Self::reply(ch, h, sys::ERR_INVALID_ARGS as i32, 0, 0);
                    return;
                };
                let params = StreamParams { rate, channels: chs, format: fmt };
                if !params.valid() {
                    close_hnd();
                    Self::reply(ch, h, sys::ERR_INVALID_ARGS as i32, 0, 0);
                    return;
                }
                let ring = match IoRing::attach(hnd) {
                    Ok(r) => r,
                    Err(e) => {
                        Self::reply(ch, h, e as i32, 0, 0);
                        return;
                    }
                };
                if h.b != 0 {
                    self.manual_out = Some(h.b as u32);
                }
                let out_rate = self.hw_out.as_ref().map_or(48_000, |hw| hw.params.rate);
                let sid = self.next_stream_id;
                self.next_stream_id += 1;
                self.streams.push(ClientStream {
                    id: sid,
                    client_id,
                    is_capture: false,
                    params,
                    ring,
                    resampler: Resampler::new(params.rate, out_rate),
                    volume: 100,
                    muted: false,
                    pending: None,
                    label: String::new(),
                });
                self.reconcile_routing();
                let pf = self.hw_out.as_ref().map_or(480, |hw| hw.period_frames) as u64;
                Self::reply(ch, h, 0, sid, pf);
            }
            audio::OP_OPEN_CAPTURE => {
                if role != Role::Capture {
                    close_hnd();
                    println!("audio: refused capture on non-capture endpoint (explicit microphone grant required)");
                    Self::reply(ch, h, sys::ERR_ACCESS_DENIED as i32, 0, 0);
                    return;
                }
                if !self.mic_allowed {
                    close_hnd();
                    println!("audio: refused capture (microphone policy revoked)");
                    Self::reply(ch, h, sys::ERR_ACCESS_DENIED as i32, 0, 0);
                    return;
                }
                if hnd == 0 {
                    Self::reply(ch, h, sys::ERR_INVALID_ARGS as i32, 0, 0);
                    return;
                }
                let (rate, chs, fmt_w) = audio::unpack_params(h.a);
                let Some(fmt) = wire_to_fmt(fmt_w) else {
                    close_hnd();
                    Self::reply(ch, h, sys::ERR_INVALID_ARGS as i32, 0, 0);
                    return;
                };
                let params = StreamParams { rate, channels: chs, format: fmt };
                if !params.valid() {
                    close_hnd();
                    Self::reply(ch, h, sys::ERR_INVALID_ARGS as i32, 0, 0);
                    return;
                }
                let snap = self.route_snapshot();
                if select_input(&snap, None).is_none() {
                    close_hnd();
                    Self::reply(ch, h, sys::ERR_BAD_STATE as i32, 0, 0);
                    return;
                }
                let ring = match IoRing::attach(hnd) {
                    Ok(r) => r,
                    Err(e) => {
                        Self::reply(ch, h, e as i32, 0, 0);
                        return;
                    }
                };
                let sid = self.next_stream_id;
                self.next_stream_id += 1;
                let label = String::from_utf8_lossy(payload).into_owned();
                let in_rate = self.hw_in.as_ref().map_or(48_000, |hw| hw.params.rate);
                self.streams.push(ClientStream {
                    id: sid,
                    client_id,
                    is_capture: true,
                    params,
                    ring,
                    resampler: Resampler::new(in_rate, params.rate),
                    volume: 100,
                    muted: false,
                    pending: None,
                    label,
                });
                self.reconcile_routing();
                let pf = self.hw_in.as_ref().map_or(480, |hw| hw.period_frames) as u64;
                Self::reply(ch, h, 0, sid, pf);
            }
            audio::OP_KICK => {
                close_hnd();
                self.pump_mixer();
            }
            audio::OP_CLOSE_STREAM => {
                close_hnd();
                self.streams.retain(|s| !(s.id == h.a && s.client_id == client_id));
                self.reconcile_routing();
                Self::reply(ch, h, 0, 0, 0);
            }
            audio::OP_SET_STREAM_VOL => {
                close_hnd();
                let vol = (h.b & 0xFF).min(100) as u8;
                let muted = ((h.b >> 8) & 1) != 0;
                if let Some(s) = self.streams.iter_mut().find(|s| s.id == h.a && s.client_id == client_id) {
                    s.volume = vol;
                    s.muted = muted;
                    Self::reply(ch, h, 0, 0, 0);
                } else {
                    Self::reply(ch, h, sys::ERR_BAD_STATE as i32, 0, 0);
                }
            }
            audio::OP_LIST_DEVICES => {
                close_hnd();
                let count = self.backends.len().min(16);
                let mut rep = vec![0u8; HEADER + count * DEVICE_ENTRY_BYTES];
                Header { txid: h.txid, op: h.op, status: 0, a: count as u64, b: 0 }.put(&mut rep);
                for (i, b) in self.backends.iter().take(count).enumerate() {
                    let mut entry = DeviceEntry::empty();
                    entry.id = b.id;
                    entry.kind = b.kind as u8;
                    entry.volume = b.volume;
                    entry.muted = b.muted;
                    entry.active_out = self.active_out_id == Some(b.id);
                    entry.active_in = self.active_in_id == Some(b.id);
                    entry.online = b.online;
                    entry.flags = b.flags;
                    entry.rate = b.params.rate;
                    entry.channels = b.params.channels;
                    entry.format = fmt_to_wire(b.params.format);
                    let nb = b.name.as_bytes();
                    let nl = nb.len().min(40);
                    entry.name[..nl].copy_from_slice(&nb[..nl]);
                    entry.name_len = nl as u8;
                    let mut raw = [0u8; DEVICE_ENTRY_BYTES];
                    entry.encode(&mut raw);
                    rep[HEADER + i * DEVICE_ENTRY_BYTES..HEADER + (i + 1) * DEVICE_ENTRY_BYTES].copy_from_slice(&raw);
                }
                let _ = sys::channel_write(ch, &rep);
            }
            audio::OP_SET_VOL => {
                close_hnd();
                if role != Role::Control {
                    Self::reply(ch, h, sys::ERR_ACCESS_DENIED as i32, 0, 0);
                    return;
                }
                let target = if h.a == 0 { self.active_out_id } else { Some(h.a as u32) };
                let mute_only = (h.b & audio::VOL_FLAG_MUTE_ONLY) != 0;
                let vol = (h.b & 0xFF).min(100) as u8;
                let muted = ((h.b >> 8) & 1) != 0;
                if let Some(id) = target
                    && let Some(b) = self.backend_by_id_mut(id)
                {
                    if mute_only {
                        if muted {
                            if !b.muted {
                                b.saved_volume = b.volume;
                            }
                            b.muted = true;
                        } else {
                            if b.muted {
                                b.volume = b.saved_volume;
                            }
                            b.muted = false;
                        }
                    } else {
                        b.volume = vol;
                        b.saved_volume = vol;
                        b.muted = muted;
                    }
                    let out_vol = b.volume;
                    let out_muted = b.muted;
                    let bch = if b.online { b.ch } else { 0 };
                    println!("audio: volume on '{}' set to {}%{}", b.name, out_vol, if out_muted { " (muted)" } else { "" });
                    if bch != 0 {
                        let mut dreq = [0u8; HEADER];
                        Header { txid: 0, op: audio::DRV_SET_VOL, status: 0, a: u64::from(out_vol), b: u64::from(out_muted) }
                            .put(&mut dreq);
                        let mut drep = [0u8; HEADER];
                        let _ = sys::channel_call(bch, &dreq, &mut drep, 500_000_000);
                    }
                    self.saved.volume = out_vol;
                    self.saved.muted = out_muted;
                    self.persist_settings();
                    Self::reply(ch, h, 0, u64::from(id), u64::from(out_vol));
                } else {
                    Self::reply(ch, h, sys::ERR_BAD_STATE as i32, 0, 0);
                }
            }
            audio::OP_SET_DEFAULT => {
                close_hnd();
                if role != Role::Control {
                    Self::reply(ch, h, sys::ERR_ACCESS_DENIED as i32, 0, 0);
                    return;
                }
                if h.a == 0 {
                    self.manual_out = None;
                    self.saved.default_output.clear();
                    self.persist_settings();
                    println!("audio: output routing set to automatic");
                    self.reconcile_routing();
                    Self::reply(ch, h, 0, u64::from(self.active_out_id.unwrap_or(0)), 0);
                } else {
                    let id = h.a as u32;
                    if let Some(bname) = self
                        .backends
                        .iter()
                        .find(|b| b.id == id && (b.flags & FLAG_PLAYBACK) != 0)
                        .map(|b| b.name.clone())
                    {
                        self.manual_out = Some(id);
                        self.saved.default_output = bname;
                        self.persist_settings();
                        self.reconcile_routing();
                        Self::reply(ch, h, 0, u64::from(id), 0);
                    } else {
                        Self::reply(ch, h, sys::ERR_BAD_STATE as i32, 0, 0);
                    }
                }
            }
            audio::OP_SET_MIC_GRANT => {
                close_hnd();
                if role != Role::Control {
                    Self::reply(ch, h, sys::ERR_ACCESS_DENIED as i32, 0, 0);
                    return;
                }
                let allow = h.a != 0;
                self.mic_allowed = allow;
                self.saved.mic_allowed = allow;
                self.persist_settings();
                println!("audio: microphone policy set to {}", if allow { "allowed" } else { "revoked" });
                if !allow {
                    // Immediately revoke all active capture streams and clear `[MIC LIVE]`.
                    self.streams.retain(|s| !s.is_capture);
                    self.reconcile_routing();
                }
                Self::reply(ch, h, 0, u64::from(allow), 0);
            }
            audio::OP_STATUS => {
                close_hnd();
                let a = u64::from(self.active_out_id.unwrap_or(0)) | (u64::from(self.active_in_id.unwrap_or(0)) << 32);
                let play_cnt = self.streams.iter().filter(|s| !s.is_capture).count() as u64;
                let cap_cnt = self.streams.iter().filter(|s| s.is_capture).count() as u64;
                let b = (cap_cnt.min(255))
                    | (u64::from(self.mic_allowed) << 8)
                    | ((play_cnt.min(255)) << 16)
                    | (u64::from(self.driver_restarts) << 32)
                    | (u64::from(self.manual_out.is_none()) << 48);
                Self::reply(ch, h, 0, a, b);
            }
            audio::OP_CRASH_DRIVER => {
                close_hnd();
                if role != Role::Control || !self.test_mode {
                    Self::reply(ch, h, sys::ERR_ACCESS_DENIED as i32, 0, 0);
                    return;
                }
                if let Some(id) = self.active_out_id
                    && let Some(b) = self.backend_by_id(id)
                    && b.ch != 0
                {
                    println!("audio: requesting crash on active output backend '{}' (test)", b.name);
                    proto::send(b.ch, audio::DRV_TEST_CRASH, 0, 0);
                    Self::reply(ch, h, 0, u64::from(id), 0);
                } else {
                    Self::reply(ch, h, sys::ERR_BAD_STATE as i32, 0, 0);
                }
            }
            _ => {
                close_hnd();
                Self::reply(ch, h, sys::ERR_NOT_SUPPORTED as i32, 0, 0);
            }
        }
    }

    fn has_queued_playback_data(&self) -> bool {
        self.streams.iter().any(|s| !s.is_capture && s.pending.is_some())
            || self.streams.iter().any(|s| {
                !s.is_capture && {
                    // Peek indirectly by letting pump pop when needed; assume active playback stream may have SQEs.
                    let _ = s.id;
                    true
                }
            })
    }

    /// Pull PCM from all active playback clients, convert/resample, mix, and submit periods to `hw_out`.
    fn pump_mixer(&mut self) {
        let has_play = self.streams.iter().any(|s| !s.is_capture);
        if !has_play {
            return;
        }
        // Drain any completed hardware CQEs first.
        if let Some(hw) = self.hw_out.as_mut() {
            while hw.ring.pop_cq().is_some() {
                hw.in_flight = hw.in_flight.saturating_sub(1);
            }
        } else {
            // Hardware output is temporarily absent (e.g., driver crash/restart in flight or no device).
            // Pace client rings at 10 ms so apps stay responsive and resume seamlessly once driver returns.
            let now = sys::clock_ns();
            if now.saturating_sub(self.last_silent_pace_ns) < 10 * MS {
                return;
            }
            self.last_silent_pace_ns = now;
            let mut wake: Vec<(u64, u64)> = Vec::new();
            for s in self.streams.iter_mut().filter(|s| !s.is_capture) {
                if let Some(p) = s.pending.take() {
                    s.ring.push_cq(Cqe { id: p.sqe.id, status: 0, a: u64::from(p.sqe.buf_len) });
                    wake.push((s.client_id, s.id));
                } else if let Some(sqe) = s.ring.pop_sq() {
                    s.ring.push_cq(Cqe { id: sqe.id, status: 0, a: u64::from(sqe.buf_len) });
                    wake.push((s.client_id, s.id));
                }
            }
            for (cid, sid) in wake {
                let ch = self.client_ch(cid);
                if ch != 0 {
                    proto::send(ch, audio::OP_DRAINED, sid, 0);
                }
            }
            return;
        }

        let Some(dev_id) = self.hw_out.as_ref().map(|hw| hw.dev_id) else { return };
        let (master_vol, master_muted) = self
            .backend_by_id(dev_id)
            .map_or((100, false), |b| (b.volume, b.muted));
        let master_gain = volume_gain_q16(master_vol, master_muted);

        let mut kicked = false;
        let mut wake_clients: Vec<(u64, u64)> = Vec::new();

        loop {
            let (period_frames, hw_params) = match self.hw_out.as_ref() {
                Some(hw) if hw.in_flight < HW_MAX_IN_FLIGHT => (hw.period_frames, hw.params),
                _ => break,
            };

            // Ensure every playback stream tries to pull an SQE if it doesn't hold one.
            let mut any_data = false;
            for s in self.streams.iter_mut().filter(|s| !s.is_capture) {
                if s.pending.is_none()
                    && let Some(sqe) = s.ring.pop_sq()
                {
                    if sqe.op == RING_WRITE && sqe.buf_len > 0 {
                        s.pending = Some(PendingSqe { sqe, offset: 0 });
                    } else {
                        s.ring.push_cq(Cqe {
                            id: sqe.id,
                            status: if sqe.op == RING_WRITE { 0 } else { sys::ERR_INVALID_ARGS as i32 },
                            a: 0,
                        });
                        wake_clients.push((s.client_id, s.id));
                    }
                }
                if s.pending.is_some() {
                    any_data = true;
                }
            }
            if !any_data {
                break;
            }

            let mut mix_acc = vec![0i64; period_frames * 2];
            for s in self.streams.iter_mut().filter(|s| !s.is_capture) {
                let gain = volume_gain_q16(s.volume, s.muted);
                let fb = s.params.frame_bytes();
                if fb == 0 {
                    continue;
                }
                let mut out_pos = 0usize;
                while out_pos < period_frames {
                    let Some(mut cur) = s.pending.take() else {
                        if let Some(sqe) = s.ring.pop_sq() {
                            if sqe.op == RING_WRITE && sqe.buf_len > 0 {
                                s.pending = Some(PendingSqe { sqe, offset: 0 });
                                continue;
                            }
                            s.ring.push_cq(Cqe { id: sqe.id, status: 0, a: 0 });
                            wake_clients.push((s.client_id, s.id));
                        }
                        break;
                    };
                    let total_len = cur.sqe.buf_len as usize;
                    if cur.offset >= total_len {
                        s.ring.push_cq(Cqe { id: cur.sqe.id, status: 0, a: u64::from(cur.sqe.buf_len) });
                        wake_clients.push((s.client_id, s.id));
                        continue;
                    }
                    let rem_off = cur.sqe.buf_off.saturating_add(cur.offset as u32);
                    let rem_len = (total_len - cur.offset) as u32;
                    let (consumed_frames, mixed_frames) = if let Some(src) = s.ring.data(rem_off, rem_len) {
                        s.resampler.mix_into(s.params, src, &mut mix_acc[out_pos * 2..], gain)
                    } else {
                        s.ring.push_cq(Cqe { id: cur.sqe.id, status: sys::ERR_INVALID_ARGS as i32, a: 0 });
                        wake_clients.push((s.client_id, s.id));
                        continue;
                    };
                    cur.offset += consumed_frames * fb;
                    out_pos += mixed_frames;
                    if cur.offset + fb > total_len {
                        s.ring.push_cq(Cqe { id: cur.sqe.id, status: 0, a: u64::from(cur.sqe.buf_len) });
                        wake_clients.push((s.client_id, s.id));
                    } else {
                        s.pending = Some(cur);
                        if mixed_frames == 0 {
                            break;
                        }
                    }
                }
            }

            // Encode mixed stereo accumulator into `hw_out`'s IoRing slot and submit.
            let Some(hw) = self.hw_out.as_mut() else { break };
            let slot = hw.next_slot % HW_RING_SLOTS;
            let off = slot * HW_RING_SLOT_BYTES;
            let period_bytes = (period_frames * hw_params.frame_bytes()).min(HW_RING_SLOT_BYTES as usize);
            if let Some(dst) = hw.ring.data_mut(off, period_bytes as u32) {
                let written = finalize_mix(&mix_acc, master_gain, hw_params, dst);
                let sqe = Sqe {
                    id: hw.next_id,
                    op: RING_WRITE,
                    a: 0,
                    b: 0,
                    buf_off: off,
                    buf_len: written as u32,
                };
                if hw.ring.push_sq(sqe) {
                    hw.next_id = hw.next_id.wrapping_add(1);
                    hw.next_slot = hw.next_slot.wrapping_add(1);
                    hw.in_flight += 1;
                    kicked = true;
                }
            }
        }

        if kicked
            && let Some(hw) = self.hw_out.as_ref()
        {
            proto::send(hw.ch, audio::DRV_KICK, 0, 0);
        }
        for (cid, sid) in wake_clients {
            let ch = self.client_ch(cid);
            if ch != 0 {
                proto::send(ch, audio::OP_DRAINED, sid, 0);
            }
        }
    }
}

fn main(s: *const Startup) -> i32 {
    // SAFETY: `s` is the startup block pointer the kernel passed to the entry point.
    if !unsafe { libd::init(s, "audio") } {
        return -1;
    }
    let test_mode = libd::args().starts_with(b"test");
    let Ok(port) = Port::new(128) else {
        println!("audio: cannot create port");
        return 1;
    };
    let ctl = libd::startup_handle(proto::TAG_CONTROL);
    let devmgr = svc::endpoint(b"devmgr.audio");
    let indicator = svc::endpoint(b"terminal.indicator");

    if ctl != 0 {
        port.arm(ctl, sys::READABLE | sys::PEER_CLOSED, KEY_CTL);
    }
    if devmgr != 0 {
        port.arm(devmgr, sys::READABLE | sys::PEER_CLOSED, KEY_DEVMGR);
    }

    let saved = if test_mode { AudioSettings::default() } else { load_audio_settings().unwrap_or_default() };
    let init_mic = saved.mic_allowed;
    let mut svc_state = AudioSvc {
        port,
        ctl,
        devmgr,
        indicator,
        test_mode,
        stop: false,
        backends: Vec::new(),
        next_dev_id: 1,
        manual_out: None,
        active_out_id: None,
        active_in_id: None,
        hw_out: None,
        hw_in: None,
        clients: Vec::new(),
        next_client_id: 1,
        streams: Vec::new(),
        next_stream_id: 1,
        mic_allowed: init_mic,
        mic_ind_on: false,
        driver_restarts: 0,
        last_silent_pace_ns: 0,
        saved,
    };

    println!("audio: ready (mixer, routing, capability-gated playback & capture)");

    while !svc_state.stop {
        let active = !svc_state.streams.is_empty();
        let wait_ns = if active { 5 * MS } else { 250 * MS };
        if let Some((key, _)) = svc_state.port.wait(wait_ns) {
            match key {
                KEY_CTL => svc_state.handle_ctl(),
                KEY_DEVMGR => svc_state.handle_devmgr(),
                KEY_HW_OUT => svc_state.handle_hw_out(),
                KEY_HW_IN => svc_state.handle_hw_in(),
                k if k >= KEY_CLIENT_BASE => svc_state.handle_client(k - KEY_CLIENT_BASE),
                _ => {}
            }
        }
        if svc_state.has_queued_playback_data() {
            svc_state.pump_mixer();
        }
        if svc_state.hw_in.is_some() {
            svc_state.drain_hw_in();
            svc_state.submit_hw_in();
        }
    }

    if let Some(hw) = svc_state.hw_out.take() {
        hw.stop();
    }
    if let Some(hw) = svc_state.hw_in.take() {
        hw.stop();
    }
    svc_state.streams.clear();
    svc_state.update_mic_indicator();
    println!("audio: shutdown");
    0
}
