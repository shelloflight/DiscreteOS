//! Audio service, driver, and USB-audio IPC protocol and client helpers (`libd::audio`).
//!
//! Zero-copy PCM audio flows over `libd::ring::IoRing` VMOs in both hops:
//! `app` <--IoRing--> `audio.dsvc` <--IoRing--> `hda.ddrv` / `usbaudio.ddrv` / `virtio-snd.ddrv`.

use crate::proto::{HEADER, Header};
use crate::ring::{IoRing, Sqe};
use crate::svc;
use crate::sys::{self, Handle, MsgHandle};

// ---- Backend registration (devmgr -> audio.dsvc on `devmgr.audio`) --------------------------

pub const BACKEND_ADD: u32 = 600;
pub const BACKEND_JACK: u32 = 601;
pub const BACKEND_GONE: u32 = 602;

// ---- Audio driver direct protocol (audio.dsvc <-> audio driver unit channel) ----------------

pub const DRV_OPEN: u32 = 610;
pub const DRV_KICK: u32 = 611;
pub const DRV_STOP: u32 = 612;
pub const DRV_SET_VOL: u32 = 613;
pub const DRV_EVENT: u32 = 614;
pub const DRV_TEST_CRASH: u32 = 615;

// ---- Shared IoRing SQE ops ------------------------------------------------------------------

pub const RING_WRITE: u32 = 1;
pub const RING_READ: u32 = 2;

// ---- USB Audio bus protocol (usbaudio.ddrv <-> xhci.ddrv on `proto::TAG_USB_BUS`) -----------

pub const USB_GET_DESC: u32 = 620;
pub const USB_CTRL: u32 = 621;
pub const USB_ISOC_OPEN: u32 = 622;
pub const USB_ISOC_KICK: u32 = 623;
pub const USB_ISOC_STOP: u32 = 624;
pub const USB_ISOC_EVENT: u32 = 625;

// ---- Client <-> audio.dsvc protocol (`audio.playback`, `audio.capture`, `audio.control`) ----

pub const OP_OPEN_PLAY: u32 = 630;
pub const OP_OPEN_CAPTURE: u32 = 631;
pub const OP_KICK: u32 = 632;
pub const OP_CLOSE_STREAM: u32 = 633;
pub const OP_SET_STREAM_VOL: u32 = 634;
pub const OP_DRAINED: u32 = 635;
pub const OP_LIST_DEVICES: u32 = 636;
pub const OP_SET_VOL: u32 = 637;
pub const OP_SET_DEFAULT: u32 = 638;
pub const OP_SET_MIC_GRANT: u32 = 639;
pub const OP_STATUS: u32 = 640;
pub const OP_CRASH_DRIVER: u32 = 641;

// ---- Format & flag mirrors (matching `dosaudio`) --------------------------------------------

pub const FMT_U8: u8 = 1;
pub const FMT_S16_LE: u8 = 2;
pub const FMT_S24_LE: u8 = 3;
pub const FMT_S32_LE: u8 = 4;
pub const FMT_F32_LE: u8 = 5;

pub const FLAG_PLAYBACK: u32 = 1 << 0;
pub const FLAG_CAPTURE: u32 = 1 << 1;
pub const FLAG_PLUGGED: u32 = 1 << 2;
pub const FLAG_ELD_VALID: u32 = 1 << 3;
pub const FLAG_INTERNAL: u32 = 1 << 4;

/// Fixed-size binary device descriptor returned by `OP_LIST_DEVICES` (64 bytes each).
#[derive(Clone, Copy, Debug)]
pub struct DeviceEntry {
    pub id: u32,
    pub kind: u8,
    pub volume: u8,
    pub muted: bool,
    pub active_out: bool,
    pub active_in: bool,
    pub online: bool,
    pub flags: u32,
    pub rate: u32,
    pub channels: u8,
    pub format: u8,
    pub name: [u8; 40],
    pub name_len: u8,
}

pub const DEVICE_ENTRY_BYTES: usize = 64;

impl DeviceEntry {
    pub const fn empty() -> Self {
        Self {
            id: 0,
            kind: 0,
            volume: 100,
            muted: false,
            active_out: false,
            active_in: false,
            online: false,
            flags: 0,
            rate: 48_000,
            channels: 2,
            format: FMT_S16_LE,
            name: [0; 40],
            name_len: 0,
        }
    }

    pub fn name_str(&self) -> &str {
        let n = (self.name_len as usize).min(self.name.len());
        core::str::from_utf8(&self.name[..n]).unwrap_or("?")
    }

    pub fn encode(&self, out: &mut [u8; DEVICE_ENTRY_BYTES]) {
        out.fill(0);
        out[0..4].copy_from_slice(&self.id.to_le_bytes());
        out[4] = self.kind;
        out[5] = self.volume;
        out[6] = (u8::from(self.muted))
            | (u8::from(self.active_out) << 1)
            | (u8::from(self.active_in) << 2)
            | (u8::from(self.online) << 3);
        out[7] = self.channels;
        out[8..12].copy_from_slice(&self.flags.to_le_bytes());
        out[12..16].copy_from_slice(&self.rate.to_le_bytes());
        out[16] = self.format;
        let n = (self.name_len as usize).min(40);
        out[17] = n as u8;
        out[24..24 + n].copy_from_slice(&self.name[..n]);
    }

    pub fn decode(src: &[u8]) -> Option<Self> {
        if src.len() < DEVICE_ENTRY_BYTES {
            return None;
        }
        let id = u32::from_le_bytes([src[0], src[1], src[2], src[3]]);
        let kind = src[4];
        let volume = src[5];
        let bits = src[6];
        let channels = src[7];
        let flags = u32::from_le_bytes([src[8], src[9], src[10], src[11]]);
        let rate = u32::from_le_bytes([src[12], src[13], src[14], src[15]]);
        let format = src[16];
        let name_len = src[17].min(40);
        let mut name = [0u8; 40];
        name[..name_len as usize].copy_from_slice(&src[24..24 + name_len as usize]);
        Some(Self {
            id,
            kind,
            volume,
            muted: (bits & 1) != 0,
            active_out: (bits & 2) != 0,
            active_in: (bits & 4) != 0,
            online: (bits & 8) != 0,
            flags,
            rate,
            channels,
            format,
            name,
            name_len,
        })
    }
}

/// Pack `(rate, channels, format)` into `Header::a` for `OP_OPEN_PLAY` / `OP_OPEN_CAPTURE`.
pub const fn pack_params(rate: u32, channels: u8, format: u8) -> u64 {
    (rate as u64) | ((channels as u64) << 32) | ((format as u64) << 40)
}

/// Unpack `(rate, channels, format)` from `Header::a`.
pub const fn unpack_params(a: u64) -> (u32, u8, u8) {
    (a as u32, ((a >> 32) & 0xFF) as u8, ((a >> 40) & 0xFF) as u8)
}

/// Pack `(dir, rate, channels, format)` into `Header::a` for `DRV_OPEN`.
pub const fn pack_drv_open(capture: bool, rate: u32, channels: u8, format: u8) -> u64 {
    (if capture { 1 } else { 0 }) | ((rate as u64) << 8) | ((channels as u64) << 40) | ((format as u64) << 48)
}

/// Unpack `(capture, rate, channels, format)` from `DRV_OPEN`'s `Header::a`.
pub const fn unpack_drv_open(a: u64) -> (bool, u32, u8, u8) {
    ((a & 1) != 0, ((a >> 8) & 0xFFFF_FFFF) as u32, ((a >> 40) & 0xFF) as u8, ((a >> 48) & 0xFF) as u8)
}

const CALL_TIMEOUT_NS: u64 = 5_000_000_000;

/// Look up the granted `audio.playback` endpoint handle (0 if not granted).
pub fn playback_endpoint() -> Handle {
    svc::endpoint(b"audio.playback")
}

/// Look up the granted `audio.capture` endpoint handle (0 if not granted).
pub fn capture_endpoint() -> Handle {
    svc::endpoint(b"audio.capture")
}

/// Look up the granted `audio.control` endpoint handle (0 if not granted).
pub fn control_endpoint() -> Handle {
    svc::endpoint(b"audio.control")
}

/// Client handle to an open playback stream backed by a zero-copy `IoRing`.
pub struct PlaybackStream {
    ch: Handle,
    pub stream_id: u64,
    pub period_frames: u32,
    pub frame_bytes: usize,
    ring: IoRing,
    slots: u32,
    slot_bytes: u32,
    next_slot: u32,
    in_flight: u32,
    next_id: u32,
}

impl PlaybackStream {
    /// Open a playback stream on `ch` (an `audio.playback` endpoint handle).
    /// Returns `ERR_ACCESS_DENIED` if `ch == 0`.
    pub fn open(ch: Handle, rate: u32, channels: u8, format: u8, device_id: u32) -> Result<Self, i64> {
        if ch == 0 {
            return Err(sys::ERR_ACCESS_DENIED);
        }
        let bps: usize = match format {
            FMT_U8 => 1,
            FMT_S16_LE => 2,
            FMT_S24_LE => 3,
            FMT_S32_LE | FMT_F32_LE => 4,
            _ => return Err(sys::ERR_INVALID_ARGS),
        };
        let frame_bytes = (channels as usize).saturating_mul(bps);
        if frame_bytes == 0 {
            return Err(sys::ERR_INVALID_ARGS);
        }
        let slots: u32 = 8;
        let slot_bytes: u32 = 8192;
        let ring = IoRing::create(slots, slots * slot_bytes)?;
        let dup = sys::handle_duplicate(
            ring.vmo(),
            sys::RIGHT_READ | sys::RIGHT_WRITE | sys::RIGHT_MAP | sys::RIGHT_INSPECT | sys::RIGHT_TRANSFER,
        )?;

        let mut req = [0u8; HEADER];
        Header {
            txid: 0,
            op: OP_OPEN_PLAY,
            status: 0,
            a: pack_params(rate, channels, format),
            b: u64::from(device_id),
        }
        .put(&mut req);
        let mut rep = [0u8; HEADER];
        let mut rh = [0 as Handle; 1];
        let (n, nh) = sys::channel_call_h(
            ch,
            &req,
            &[MsgHandle { handle: dup, rights: sys::RIGHTS_SAME }],
            &mut rep,
            &mut rh,
            CALL_TIMEOUT_NS,
        )?;
        if nh > 0 && rh[0] != 0 {
            sys::handle_close(rh[0]);
        }
        let h = Header::get(&rep[..n]).ok_or(sys::ERR_INVALID_ARGS)?;
        if h.status != 0 {
            return Err(i64::from(h.status));
        }
        Ok(Self {
            ch,
            stream_id: h.a,
            period_frames: (h.b as u32).max(64),
            frame_bytes,
            ring,
            slots,
            slot_bytes,
            next_slot: 0,
            in_flight: 0,
            next_id: 1,
        })
    }

    fn drain_completions(&mut self) {
        // Also drain any OP_DRAINED wakeups from the channel without blocking.
        let mut tmp = [0u8; HEADER];
        while sys::channel_read(self.ch, &mut tmp, 0).is_ok() {}
        while self.ring.pop_cq().is_some() {
            self.in_flight = self.in_flight.saturating_sub(1);
        }
    }

    /// Write raw PCM bytes into the playback ring, waiting if all ring slots are full.
    pub fn write(&mut self, mut pcm: &[u8]) -> Result<usize, i64> {
        let mut total = 0usize;
        while !pcm.is_empty() {
            self.drain_completions();
            if self.in_flight >= self.slots {
                // Wait for `audio.dsvc` to consume a slot.
                let _ = sys::object_wait(self.ch, sys::READABLE | sys::PEER_CLOSED, 50_000_000);
                self.drain_completions();
                if self.in_flight >= self.slots {
                    if sys::object_wait(self.ch, sys::PEER_CLOSED, 0).is_ok() {
                        return Err(sys::ERR_PEER_CLOSED);
                    }
                    continue;
                }
            }
            let max_chunk = (self.slot_bytes as usize / self.frame_bytes) * self.frame_bytes;
            let n = pcm.len().min(max_chunk);
            if n == 0 {
                break;
            }
            let slot = self.next_slot % self.slots;
            let off = slot * self.slot_bytes;
            if let Some(dst) = self.ring.data_mut(off, n as u32) {
                dst.copy_from_slice(&pcm[..n]);
            }
            let sqe = Sqe {
                id: self.next_id,
                op: RING_WRITE,
                a: self.stream_id,
                b: 0,
                buf_off: off,
                buf_len: n as u32,
            };
            if !self.ring.push_sq(sqe) {
                continue;
            }
            self.next_id = self.next_id.wrapping_add(1);
            self.next_slot = self.next_slot.wrapping_add(1);
            self.in_flight += 1;
            let mut kick = [0u8; HEADER];
            Header { txid: 0, op: OP_KICK, status: 0, a: self.stream_id, b: 0 }.put(&mut kick);
            let _ = sys::channel_write(self.ch, &kick);
            pcm = &pcm[n..];
            total += n;
        }
        Ok(total)
    }

    /// Wait until all submitted buffers have been consumed by `audio.dsvc` (up to `timeout_ns`).
    pub fn drain(&mut self, timeout_ns: u64) {
        let deadline = sys::clock_ns().saturating_add(timeout_ns);
        while self.in_flight > 0 && sys::clock_ns() < deadline {
            self.drain_completions();
            if self.in_flight > 0 {
                let rem = deadline.saturating_sub(sys::clock_ns()).min(20_000_000);
                let _ = sys::object_wait(self.ch, sys::READABLE | sys::PEER_CLOSED, rem);
            }
        }
    }

    /// Explicitly close the stream on `audio.dsvc`.
    pub fn close(mut self) {
        self.close_inner();
    }

    fn close_inner(&mut self) {
        if self.stream_id == 0 {
            return;
        }
        let mut req = [0u8; HEADER];
        Header { txid: 0, op: OP_CLOSE_STREAM, status: 0, a: self.stream_id, b: 0 }.put(&mut req);
        let mut rep = [0u8; HEADER];
        let _ = sys::channel_call(self.ch, &req, &mut rep, 1_000_000_000);
        self.stream_id = 0;
    }
}

impl Drop for PlaybackStream {
    fn drop(&mut self) {
        self.close_inner();
    }
}

/// Client handle to an open microphone capture stream backed by a zero-copy `IoRing`.
pub struct CaptureStream {
    ch: Handle,
    pub stream_id: u64,
    pub period_frames: u32,
    ring: IoRing,
    slot_bytes: u32,
    next_id: u32,
}

impl CaptureStream {
    /// Open a capture stream on `ch` (requires `audio.capture` grant; `audio.playback` will return `ERR_ACCESS_DENIED`).
    pub fn open(ch: Handle, rate: u32, channels: u8, format: u8, device_id: u32, client_name: &[u8]) -> Result<Self, i64> {
        if ch == 0 {
            return Err(sys::ERR_ACCESS_DENIED);
        }
        let slots: u32 = 8;
        let slot_bytes: u32 = 4096;
        let ring = IoRing::create(slots, slots * slot_bytes)?;
        let dup = sys::handle_duplicate(
            ring.vmo(),
            sys::RIGHT_READ | sys::RIGHT_WRITE | sys::RIGHT_MAP | sys::RIGHT_INSPECT | sys::RIGHT_TRANSFER,
        )?;

        let mut req = [0u8; HEADER + 32];
        let nlen = client_name.len().min(32);
        Header {
            txid: 0,
            op: OP_OPEN_CAPTURE,
            status: 0,
            a: pack_params(rate, channels, format),
            b: u64::from(device_id),
        }
        .put(&mut req);
        req[HEADER..HEADER + nlen].copy_from_slice(&client_name[..nlen]);
        let mut rep = [0u8; HEADER];
        let mut rh = [0 as Handle; 1];
        let (n, nh) = sys::channel_call_h(
            ch,
            &req[..HEADER + nlen],
            &[MsgHandle { handle: dup, rights: sys::RIGHTS_SAME }],
            &mut rep,
            &mut rh,
            CALL_TIMEOUT_NS,
        )?;
        if nh > 0 && rh[0] != 0 {
            sys::handle_close(rh[0]);
        }
        let h = Header::get(&rep[..n]).ok_or(sys::ERR_INVALID_ARGS)?;
        if h.status != 0 {
            return Err(i64::from(h.status));
        }
        Ok(Self {
            ch,
            stream_id: h.a,
            period_frames: (h.b as u32).max(64),
            ring,
            slot_bytes,
            next_id: 1,
        })
    }

    /// Read one period of captured PCM into `dst` (up to `timeout_ns`).
    pub fn read(&mut self, dst: &mut [u8], timeout_ns: u64) -> Result<usize, i64> {
        let len = dst.len().min(self.slot_bytes as usize) as u32;
        if len == 0 {
            return Ok(0);
        }
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        let sqe = Sqe { id, op: RING_READ, a: self.stream_id, b: 0, buf_off: 0, buf_len: len };
        if !self.ring.push_sq(sqe) {
            return Err(sys::ERR_SHOULD_WAIT);
        }
        let mut kick = [0u8; HEADER];
        Header { txid: 0, op: OP_KICK, status: 0, a: self.stream_id, b: 0 }.put(&mut kick);
        let _ = sys::channel_write(self.ch, &kick);

        let deadline = sys::clock_ns().saturating_add(timeout_ns);
        loop {
            let mut tmp = [0u8; HEADER];
            while sys::channel_read(self.ch, &mut tmp, 0).is_ok() {}
            if let Some(cqe) = self.ring.pop_cq() {
                if cqe.status != 0 {
                    return Err(i64::from(cqe.status));
                }
                let got = (cqe.a as usize).min(dst.len()).min(self.slot_bytes as usize);
                if let Some(src) = self.ring.data(0, got as u32) {
                    dst[..got].copy_from_slice(src);
                }
                return Ok(got);
            }
            let now = sys::clock_ns();
            if now >= deadline {
                return Err(sys::ERR_TIMED_OUT);
            }
            if sys::object_wait(self.ch, sys::PEER_CLOSED, 0).is_ok() {
                return Err(sys::ERR_PEER_CLOSED);
            }
            let _ = sys::object_wait(self.ch, sys::READABLE | sys::PEER_CLOSED, (deadline - now).min(20_000_000));
        }
    }

    pub fn close(mut self) {
        self.close_inner();
    }

    fn close_inner(&mut self) {
        if self.stream_id == 0 {
            return;
        }
        let mut req = [0u8; HEADER];
        Header { txid: 0, op: OP_CLOSE_STREAM, status: 0, a: self.stream_id, b: 0 }.put(&mut req);
        let mut rep = [0u8; HEADER];
        let _ = sys::channel_call(self.ch, &req, &mut rep, 1_000_000_000);
        self.stream_id = 0;
    }
}

impl Drop for CaptureStream {
    fn drop(&mut self) {
        self.close_inner();
    }
}

/// Query devices from an `audio.control` or `audio.playback` channel into `out`.
pub fn list_devices(ch: Handle, out: &mut [DeviceEntry]) -> Result<usize, i64> {
    if ch == 0 {
        return Err(sys::ERR_ACCESS_DENIED);
    }
    let mut req = [0u8; HEADER];
    Header { txid: 0, op: OP_LIST_DEVICES, status: 0, a: 0, b: 0 }.put(&mut req);
    let mut rep = [0u8; HEADER + 16 * DEVICE_ENTRY_BYTES];
    let n = sys::channel_call(ch, &req, &mut rep, CALL_TIMEOUT_NS)? as usize;
    let h = Header::get(&rep[..n]).ok_or(sys::ERR_INVALID_ARGS)?;
    if h.status != 0 {
        return Err(i64::from(h.status));
    }
    let body = &rep[HEADER..n];
    let mut count = 0usize;
    for chunk in body.as_chunks::<DEVICE_ENTRY_BYTES>().0 {
        if count >= out.len() {
            break;
        }
        if let Some(e) = DeviceEntry::decode(chunk) {
            out[count] = e;
            count += 1;
        }
    }
    Ok(count)
}

/// Send a simple control call (`OP_SET_VOL`, `OP_SET_DEFAULT`, `OP_SET_MIC_GRANT`, `OP_CRASH_DRIVER`).
pub fn control_call(ch: Handle, op: u32, a: u64, b: u64) -> Result<Header, i64> {
    if ch == 0 {
        return Err(sys::ERR_ACCESS_DENIED);
    }
    let mut req = [0u8; HEADER];
    Header { txid: 0, op, status: 0, a, b }.put(&mut req);
    let mut rep = [0u8; HEADER];
    let n = sys::channel_call(ch, &req, &mut rep, CALL_TIMEOUT_NS)? as usize;
    let h = Header::get(&rep[..n]).ok_or(sys::ERR_INVALID_ARGS)?;
    if h.status != 0 {
        return Err(i64::from(h.status));
    }
    Ok(h)
}
