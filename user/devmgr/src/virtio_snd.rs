//! VirtIO Sound driver (`virtio-snd.ddrv`, VirtIO 1.2 §5.14, PCI 0x1AF4:0x1059).
//!
//! Supports playback (`txq`) and capture (`rxq`) streams over IOMMU-confined DMA buffers
//! bridged to `audio.dsvc` via shared-memory `IoRing`. Handles devices with fewer MSI-X vectors
//! than virtqueues (e.g., QEMU's default `vectors=2` across 4 queues).

use core::sync::atomic::{Ordering, fence};

use dosaudio::route::{DeviceKind, FLAG_CAPTURE, FLAG_PLAYBACK, FLAG_PLUGGED};
use libd::audio::{self, FMT_S16_LE, RING_READ, RING_WRITE};
use libd::proto::{self, HEADER, Header};
use libd::ring::{Cqe, IoRing};
use libd::sys::{self, Handle};
use libd::{Dma, Port, Startup, println};

use crate::virtio::{DESC_NEXT, DESC_WRITE, Queue, Virtio};

const MS: u64 = 1_000_000;
const PAGE: u64 = 4096;

// VirtIO Sound control request codes (§5.14.6)
const R_PCM_INFO: u32 = 0x0100;
const R_PCM_SET_PARAMS: u32 = 0x0101;
const R_PCM_PREPARE: u32 = 0x0102;
const R_PCM_RELEASE: u32 = 0x0103;
const R_PCM_START: u32 = 0x0104;
const R_PCM_STOP: u32 = 0x0105;
const S_OK: u32 = 0x8000;

const D_OUTPUT: u8 = 0;
const D_INPUT: u8 = 1;
const PCM_FMT_S16: u8 = 5;
const PCM_RATE_48000: u8 = 7;

// Event codes
const EVT_JACK_CONNECTED: u32 = 0x1000;
const EVT_JACK_DISCONNECTED: u32 = 0x1001;

const PERIOD_FRAMES: usize = 480; // 10 ms at 48 kHz
const PERIOD_BYTES: usize = PERIOD_FRAMES * 4; // stereo S16_LE = 1920 bytes
const SLOTS: usize = 4; // 4 in-flight transfers * 3 descriptors = 12 <= QSIZE (16)
const MAX_STREAMS: usize = 8;

// DMA page layout (10 pages):
//   Page 0: control req (0..256), control resp (256..1024), event buffers (1024..1152),
//           tx xfer/status headers (1536..1792), rx xfer/status headers (1792..2048)
//   Pages 1..5: TX period buffers (4 pages, 1 per slot)
//   Pages 5..9: RX period buffers (4 pages, 1 per slot)
const PG_META: u64 = 0;
const PG_TX: u64 = 1;
const PG_RX: u64 = 5;
const DMA_PAGES: u64 = 9;

const OFF_CTL_REQ: u64 = 0;
const OFF_CTL_RSP: u64 = 256;
const OFF_EVT: u64 = 1024; // 8 events * 8 B
const OFF_TX_XFER: u64 = 1536; // SLOTS * 16 B (8B xfer + 8B status)
const OFF_RX_XFER: u64 = 1792; // SLOTS * 16 B (8B xfer + 8B status)
const EVT_COUNT: usize = 8;

// Port keys
const KEY_CTL: u64 = 1;
const KEY_IRQ_BASE: u64 = 2; // up to 4 IRQs: 2..6
const KEY_UNIT_BASE: u64 = 16;

#[derive(Clone, Copy)]
struct StreamDesc {
    stream_id: u32,
    is_output: bool,
    ch: Handle,
}

#[derive(Clone, Copy)]
struct PendingSlot {
    in_flight: bool,
    sqe_id: u32,
    buf_off: u32,
    buf_len: u32,
}

impl PendingSlot {
    const fn empty() -> Self {
        Self { in_flight: false, sqe_id: 0, buf_off: 0, buf_len: 0 }
    }
}

struct ActiveIo {
    unit: usize,
    stream_id: u32,
    ring: IoRing,
    slots: [PendingSlot; SLOTS],
    frames_done: u64,
}

struct VirtioSnd {
    v: Virtio,
    dma: Dma,
    ctl: Handle,
    port: Port,
    controlq: Queue,
    eventq: Queue,
    txq: Queue,
    rxq: Queue,
    irqs: [Handle; 4],
    streams: [Option<StreamDesc>; MAX_STREAMS],
    stream_count: usize,
    tx: Option<ActiveIo>,
    rx: Option<ActiveIo>,
}

impl VirtioSnd {
    /// Send a synchronous command on `controlq` (req_len bytes at OFF_CTL_REQ, rsp_len at OFF_CTL_RSP).
    fn control_cmd(&mut self, req_len: u32, rsp_len: u32) -> Result<u32, &'static str> {
        let base = self.dma.dev_addr(PG_META);
        self.controlq.desc(0, base + OFF_CTL_REQ, req_len, DESC_NEXT, 1);
        self.controlq.desc(1, base + OFF_CTL_RSP, rsp_len, DESC_WRITE, 0);
        self.controlq.push(0);
        self.v.notify(&self.controlq);

        let dl = sys::clock_ns() + 2_000 * MS;
        loop {
            if let Some((_id, _len)) = self.controlq.pop() {
                fence(Ordering::Acquire);
                let code = self.dma.map.r32(OFF_CTL_RSP);
                return Ok(code);
            }
            if sys::clock_ns() >= dl {
                return Err("controlq timeout");
            }
            let irq = self.controlq.irq;
            if irq != 0 {
                let _ = sys::object_wait(irq, sys::SIGNALED, 20 * MS);
                let _ = sys::interrupt_ack(irq);
            } else {
                libd::handle::sleep(MS);
            }
        }
    }

    fn query_pcm_info(&mut self, count: u32) {
        let n = count.min(MAX_STREAMS as u32);
        if n == 0 {
            return;
        }
        // virtio_snd_query_info: code, start_id, count, size=32
        self.dma.map.w32(OFF_CTL_REQ, R_PCM_INFO);
        self.dma.map.w32(OFF_CTL_REQ + 4, 0);
        self.dma.map.w32(OFF_CTL_REQ + 8, n);
        self.dma.map.w32(OFF_CTL_REQ + 12, 32);
        let rsp_len = 4 + n * 32;
        if self.control_cmd(16, rsp_len) != Ok(S_OK) {
            println!("virtio-snd: R_PCM_INFO failed");
            return;
        }
        for i in 0..n as usize {
            let off = OFF_CTL_RSP + 4 + (i as u64) * 32;
            let dir = self.dma.map.r8(off + 24);
            let is_output = dir == D_OUTPUT;
            if !is_output && dir != D_INPUT {
                continue;
            }
            let u = self.stream_count;
            if u >= MAX_STREAMS {
                break;
            }
            self.streams[u] = Some(StreamDesc { stream_id: i as u32, is_output, ch: 0 });
            self.stream_count += 1;

            let kind = if is_output { DeviceKind::Virtual } else { DeviceKind::Microphone };
            let flags = FLAG_PLUGGED | if is_output { FLAG_PLAYBACK } else { FLAG_CAPTURE };
            let name: &[u8] = if is_output { b"VirtIO Sound Out" } else { b"VirtIO Sound Mic" };
            let a = (u as u64) | ((kind as u64) << 16) | ((flags as u64) << 32);
            let b = 48_000u64 | (2u64 << 32) | (u64::from(FMT_S16_LE) << 40);
            let mut msg = [0u8; HEADER + 40];
            Header { txid: 0, op: proto::AUDIO_DEV, status: 0, a, b }.put(&mut msg);
            msg[HEADER..HEADER + name.len()].copy_from_slice(name);
            let _ = sys::channel_write(self.ctl, &msg[..HEADER + name.len()]);
            println!(
                "virtio-snd: unit {} {} (stream {})",
                u,
                core::str::from_utf8(name).unwrap_or("?"),
                i
            );
        }
    }

    fn post_events(&mut self) {
        let base = self.dma.dev_addr(PG_META);
        for i in 0..EVT_COUNT as u16 {
            self.eventq.desc(i, base + OFF_EVT + u64::from(i) * 8, 8, DESC_WRITE, 0);
            self.eventq.push(i);
        }
        self.v.notify(&self.eventq);
    }

    fn drain_events(&mut self) {
        let base = self.dma.dev_addr(PG_META);
        let mut reposted = false;
        while let Some((id, _len)) = self.eventq.pop() {
            let idx = (id as usize) % EVT_COUNT;
            let ty = self.dma.map.r32(OFF_EVT + (idx as u64) * 8);
            let data = self.dma.map.r32(OFF_EVT + (idx as u64) * 8 + 4);
            if ty == EVT_JACK_CONNECTED || ty == EVT_JACK_DISCONNECTED {
                let flags = FLAG_PLAYBACK | if ty == EVT_JACK_CONNECTED { FLAG_PLUGGED } else { 0 };
                proto::send(self.ctl, proto::AUDIO_JACK, u64::from(data), u64::from(flags));
            }
            self.eventq.desc(id, base + OFF_EVT + (idx as u64) * 8, 8, DESC_WRITE, 0);
            self.eventq.push(id);
            reposted = true;
        }
        if reposted {
            self.v.notify(&self.eventq);
        }
    }

    fn pcm_simple_cmd(&mut self, code: u32, stream_id: u32) -> Result<(), i32> {
        self.dma.map.w32(OFF_CTL_REQ, code);
        self.dma.map.w32(OFF_CTL_REQ + 4, stream_id);
        match self.control_cmd(8, 4) {
            Ok(S_OK) => Ok(()),
            _ => Err(proto::ERR_IO),
        }
    }

    fn open_stream(&mut self, unit: usize, capture: bool, ring_vmo: Handle) -> Result<(), i32> {
        let Some(desc) = self.streams[unit] else {
            sys::handle_close(ring_vmo);
            return Err(sys::ERR_BAD_STATE as i32);
        };
        if desc.is_output == capture {
            sys::handle_close(ring_vmo);
            return Err(sys::ERR_INVALID_ARGS as i32);
        }
        let ring = IoRing::attach(ring_vmo).map_err(|e| e as i32)?;

        // Stop any prior stream on this direction.
        self.stop_dir(capture);

        // R_PCM_SET_PARAMS (24 bytes)
        self.dma.map.w32(OFF_CTL_REQ, R_PCM_SET_PARAMS);
        self.dma.map.w32(OFF_CTL_REQ + 4, desc.stream_id);
        self.dma.map.w32(OFF_CTL_REQ + 8, (SLOTS * PERIOD_BYTES) as u32);
        self.dma.map.w32(OFF_CTL_REQ + 12, PERIOD_BYTES as u32);
        self.dma.map.w32(OFF_CTL_REQ + 16, 0); // features
        self.dma.map.w8(OFF_CTL_REQ + 20, 2); // stereo
        self.dma.map.w8(OFF_CTL_REQ + 21, PCM_FMT_S16);
        self.dma.map.w8(OFF_CTL_REQ + 22, PCM_RATE_48000);
        self.dma.map.w8(OFF_CTL_REQ + 23, 0);
        if self.control_cmd(24, 4) != Ok(S_OK) {
            return Err(proto::ERR_IO);
        }
        self.pcm_simple_cmd(R_PCM_PREPARE, desc.stream_id)?;
        self.pcm_simple_cmd(R_PCM_START, desc.stream_id)?;

        let io = ActiveIo {
            unit,
            stream_id: desc.stream_id,
            ring,
            slots: [PendingSlot::empty(); SLOTS],
            frames_done: 0,
        };
        if capture {
            self.rx = Some(io);
            self.pump_rx();
        } else {
            self.tx = Some(io);
            self.pump_tx();
        }
        Ok(())
    }

    fn stop_dir(&mut self, capture: bool) {
        let old = if capture { self.rx.take() } else { self.tx.take() };
        if let Some(io) = old {
            let _ = self.pcm_simple_cmd(R_PCM_STOP, io.stream_id);
            let _ = self.pcm_simple_cmd(R_PCM_RELEASE, io.stream_id);
        }
    }

    fn pump_tx(&mut self) {
        let Some(tx) = self.tx.as_mut() else { return };
        let mut completed_any = false;
        while let Some((head, _used_len)) = self.txq.pop() {
            let slot = (head as usize) / 3;
            if slot < SLOTS && tx.slots[slot].in_flight {
                let st = tx.slots[slot];
                tx.slots[slot].in_flight = false;
                let dev_status = self.dma.map.r32(OFF_TX_XFER + (slot as u64) * 16 + 8);
                let code = if dev_status == S_OK { 0 } else { proto::ERR_IO };
                tx.ring.push_cq(Cqe { id: st.sqe_id, status: code, a: u64::from(st.buf_len) });
                tx.frames_done += u64::from(st.buf_len) / 4;
                completed_any = true;
            }
        }

        let meta_da = self.dma.dev_addr(PG_META);
        let mut submitted = false;
        for slot in 0..SLOTS {
            if tx.slots[slot].in_flight {
                continue;
            }
            let Some(sqe) = tx.ring.pop_sq() else { break };
            if sqe.op != RING_WRITE {
                tx.ring.push_cq(Cqe { id: sqe.id, status: sys::ERR_INVALID_ARGS as i32, a: 0 });
                completed_any = true;
                continue;
            }
            let Some(data) = tx.ring.data(sqe.buf_off, sqe.buf_len) else {
                tx.ring.push_cq(Cqe { id: sqe.id, status: sys::ERR_INVALID_ARGS as i32, a: 0 });
                completed_any = true;
                continue;
            };
            let len = data.len().min(PERIOD_BYTES);
            let pg = PG_TX + slot as u64;
            let dst_base = pg * PAGE;
            let mut i = 0;
            while i + 4 <= len {
                let w = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
                self.dma.map.w32(dst_base + i as u64, w);
                i += 4;
            }
            while i < len {
                self.dma.map.w8(dst_base + i as u64, data[i]);
                i += 1;
            }
            while i < PERIOD_BYTES {
                self.dma.map.w8(dst_base + i as u64, 0);
                i += 1;
            }

            let hdr_off = OFF_TX_XFER + (slot as u64) * 16;
            self.dma.map.w32(hdr_off, tx.stream_id);
            self.dma.map.w32(hdr_off + 4, 0);
            self.dma.map.w32(hdr_off + 8, 0);
            self.dma.map.w32(hdr_off + 12, 0);
            fence(Ordering::Release);

            let d0 = (slot * 3) as u16;
            self.txq.desc(d0, meta_da + hdr_off, 8, DESC_NEXT, d0 + 1);
            self.txq.desc(d0 + 1, self.dma.dev_addr(pg * PAGE), PERIOD_BYTES as u32, DESC_NEXT, d0 + 2);
            self.txq.desc(d0 + 2, meta_da + hdr_off + 8, 8, DESC_WRITE, 0);
            self.txq.push(d0);
            tx.slots[slot] = PendingSlot { in_flight: true, sqe_id: sqe.id, buf_off: sqe.buf_off, buf_len: len as u32 };
            submitted = true;
        }
        if submitted {
            self.v.notify(&self.txq);
        }
        let unit = tx.unit;
        let frames_done = tx.frames_done;
        if completed_any
            && let Some(desc) = self.streams[unit]
            && desc.ch != 0
        {
            proto::send(desc.ch, audio::DRV_EVENT, frames_done, 0);
        }
    }

    fn pump_rx(&mut self) {
        let Some(rx) = self.rx.as_mut() else { return };
        let mut completed_any = false;
        while let Some((head, _used_len)) = self.rxq.pop() {
            let slot = (head as usize) / 3;
            if slot < SLOTS && rx.slots[slot].in_flight {
                let st = rx.slots[slot];
                rx.slots[slot].in_flight = false;
                fence(Ordering::Acquire);
                let dev_status = self.dma.map.r32(OFF_RX_XFER + (slot as u64) * 16 + 8);
                if dev_status == S_OK {
                    let len = (st.buf_len as usize).min(PERIOD_BYTES);
                    let src_base = (PG_RX + slot as u64) * PAGE;
                    if let Some(dst) = rx.ring.data_mut(st.buf_off, len as u32) {
                        for (i, b) in dst.iter_mut().enumerate() {
                            *b = self.dma.map.r8(src_base + i as u64);
                        }
                    }
                    rx.ring.push_cq(Cqe { id: st.sqe_id, status: 0, a: len as u64 });
                    rx.frames_done += (len / 4) as u64;
                } else {
                    rx.ring.push_cq(Cqe { id: st.sqe_id, status: proto::ERR_IO, a: 0 });
                }
                completed_any = true;
            }
        }

        let meta_da = self.dma.dev_addr(PG_META);
        let mut submitted = false;
        for slot in 0..SLOTS {
            if rx.slots[slot].in_flight {
                continue;
            }
            let Some(sqe) = rx.ring.pop_sq() else { break };
            if sqe.op != RING_READ {
                rx.ring.push_cq(Cqe { id: sqe.id, status: sys::ERR_INVALID_ARGS as i32, a: 0 });
                completed_any = true;
                continue;
            }
            let len = (sqe.buf_len as usize).min(PERIOD_BYTES);
            let hdr_off = OFF_RX_XFER + (slot as u64) * 16;
            self.dma.map.w32(hdr_off, rx.stream_id);
            self.dma.map.w32(hdr_off + 4, 0);
            self.dma.map.w32(hdr_off + 8, 0);
            self.dma.map.w32(hdr_off + 12, 0);
            fence(Ordering::Release);

            let d0 = (slot * 3) as u16;
            self.rxq.desc(d0, meta_da + hdr_off, 8, DESC_NEXT, d0 + 1);
            self.rxq.desc(d0 + 1, self.dma.dev_addr((PG_RX + slot as u64) * PAGE), PERIOD_BYTES as u32, DESC_WRITE | DESC_NEXT, d0 + 2);
            self.rxq.desc(d0 + 2, meta_da + hdr_off + 8, 8, DESC_WRITE, 0);
            self.rxq.push(d0);
            rx.slots[slot] = PendingSlot { in_flight: true, sqe_id: sqe.id, buf_off: sqe.buf_off, buf_len: len as u32 };
            submitted = true;
        }
        if submitted {
            self.v.notify(&self.rxq);
        }
        let unit = rx.unit;
        let frames_done = rx.frames_done;
        if completed_any
            && let Some(desc) = self.streams[unit]
            && desc.ch != 0
        {
            proto::send(desc.ch, audio::DRV_EVENT, frames_done, 0);
        }
    }

    fn handle_irq(&mut self, idx: usize) {
        let h = self.irqs[idx];
        if h != 0 {
            let _ = sys::interrupt_ack(h);
            self.port.arm(h, sys::SIGNALED, KEY_IRQ_BASE + idx as u64);
        }
        self.drain_events();
        self.pump_tx();
        self.pump_rx();
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
                        proto::AUDIO_ATTACH if hnd != 0 => {
                            let u = h.a as usize;
                            if u < self.stream_count
                                && let Some(desc) = self.streams[u].as_mut()
                            {
                                if desc.ch != 0 {
                                    sys::handle_close(desc.ch);
                                }
                                desc.ch = hnd;
                                self.port.arm(hnd, sys::READABLE | sys::PEER_CLOSED, KEY_UNIT_BASE + u as u64);
                            } else {
                                sys::handle_close(hnd);
                            }
                        }
                        proto::TEST_CRASH => {
                            if hnd != 0 {
                                sys::handle_close(hnd);
                            }
                            println!("virtio-snd: intentional crash requested");
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

    fn handle_unit_msg(&mut self, u: usize) {
        let mut buf = [0u8; HEADER + 64];
        loop {
            let ch = match self.streams[u] {
                Some(d) if d.ch != 0 => d.ch,
                _ => return,
            };
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
                            let (capture, _rate, _ch, _fmt) = audio::unpack_drv_open(h.a);
                            let mut rep = [0u8; HEADER];
                            if hnd == 0 {
                                Header { txid: h.txid, op: h.op, status: sys::ERR_INVALID_ARGS as i32, a: 0, b: 0 }.put(&mut rep);
                            } else {
                                match self.open_stream(u, capture, hnd) {
                                    Ok(()) => {
                                        let a = audio::pack_params(48_000, 2, FMT_S16_LE);
                                        Header { txid: h.txid, op: h.op, status: 0, a, b: PERIOD_FRAMES as u64 }.put(&mut rep);
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
                            self.pump_tx();
                            self.pump_rx();
                        }
                        audio::DRV_STOP => {
                            if hnd != 0 {
                                sys::handle_close(hnd);
                            }
                            if self.tx.as_ref().is_some_and(|s| s.unit == u) {
                                self.stop_dir(false);
                            }
                            if self.rx.as_ref().is_some_and(|s| s.unit == u) {
                                self.stop_dir(true);
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
                            println!("virtio-snd: intentional crash requested (audio crash recovery test)");
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
                    self.port.arm(ch, sys::READABLE | sys::PEER_CLOSED, KEY_UNIT_BASE + u as u64);
                    return;
                }
                Err(_) => {
                    if self.tx.as_ref().is_some_and(|s| s.unit == u) {
                        self.stop_dir(false);
                    }
                    if self.rx.as_ref().is_some_and(|s| s.unit == u) {
                        self.stop_dir(true);
                    }
                    if let Some(d) = self.streams[u].as_mut() {
                        sys::handle_close(d.ch);
                        d.ch = 0;
                    }
                    return;
                }
            }
        }
    }
}

pub fn main(s: *const Startup) -> i32 {
    // SAFETY: `s` is the startup block pointer the kernel passed to the entry point.
    if !unsafe { libd::init(s, "virtio-snd") } {
        return -1;
    }
    let dev = libd::startup_handle(sys::TAG_DEVICE);
    let ctl = libd::startup_handle(proto::TAG_CONTROL);
    let Ok(info) = sys::device_info(dev) else {
        println!("virtio-snd: device_info failed");
        return 1;
    };
    let v = match Virtio::open(dev) {
        Ok(v) => v,
        Err(why) => {
            println!("virtio-snd: {}", why);
            return 1;
        }
    };
    let Some(cfg) = v.devcfg else {
        println!("virtio-snd: missing device config");
        return 1;
    };
    let jacks = v.r32(cfg, 0);
    let streams = v.r32(cfg, 4);
    let chmaps = v.r32(cfg, 8);

    // Respect available MSI-X vectors (QEMU defaults to vectors=2 across 4 virtqueues).
    let nvec = info.irqs.clamp(1, 4);
    let mut vec_bound = [false; 4];
    let mut bind_q = |qi: u16| -> Result<Queue, &'static str> {
        let vec = qi % nvec;
        let first = !vec_bound[vec as usize];
        vec_bound[vec as usize] = true;
        v.queue_with_vector(qi, vec, first)
    };
    let (Ok(controlq), Ok(eventq), Ok(txq), Ok(rxq)) = (bind_q(0), bind_q(1), bind_q(2), bind_q(3)) else {
        println!("virtio-snd: failed to configure 4 virtqueues");
        return 1;
    };
    let Ok(dma) = Dma::new(dev, DMA_PAGES * PAGE, sys::DMA_DEVICE_READ | sys::DMA_DEVICE_WRITE) else {
        println!("virtio-snd: cannot pin DMA buffers");
        return 1;
    };
    let Ok(port) = Port::new(64) else {
        println!("virtio-snd: cannot create port");
        return 1;
    };
    v.driver_ok();

    let irqs = [controlq.irq, eventq.irq, txq.irq, rxq.irq];
    let mut snd = VirtioSnd {
        v,
        dma,
        ctl,
        port,
        controlq,
        eventq,
        txq,
        rxq,
        irqs,
        streams: [None; MAX_STREAMS],
        stream_count: 0,
        tx: None,
        rx: None,
    };

    println!("virtio-snd: ready on {} (jacks={}, streams={}, chmaps={}, vectors={})", info.name(), jacks, streams, chmaps, nvec);
    snd.query_pcm_info(streams);
    snd.post_events();

    snd.port.arm(ctl, sys::READABLE | sys::PEER_CLOSED, KEY_CTL);
    for (i, &h) in snd.irqs.iter().enumerate() {
        if h != 0 {
            snd.port.arm(h, sys::SIGNALED, KEY_IRQ_BASE + i as u64);
        }
    }
    proto::send(ctl, proto::READY, snd.stream_count as u64, 0);

    loop {
        let wait_ns = if snd.tx.is_some() || snd.rx.is_some() { 10 * MS } else { 250 * MS };
        if let Some((key, _)) = snd.port.wait(wait_ns) {
            match key {
                KEY_CTL => snd.handle_ctl(),
                k if (KEY_IRQ_BASE..KEY_IRQ_BASE + 4).contains(&k) => snd.handle_irq((k - KEY_IRQ_BASE) as usize),
                k if k >= KEY_UNIT_BASE => snd.handle_unit_msg((k - KEY_UNIT_BASE) as usize),
                _ => {}
            }
        }
        snd.drain_events();
        snd.pump_tx();
        snd.pump_rx();
    }
}
