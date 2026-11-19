//! xHCI isochronous transfer support and USB Audio device bridge (`xhci.ddrv` <-> `usbaudio.ddrv`).
//!
//! When xHCI enumerates a USB Audio Class (`bInterfaceClass == 0x01`) device, it keeps the slot
//! configured and creates a dedicated IPC channel (`TAG_USB_BUS`) handed to an isolated
//! `usbaudio.ddrv` process via `devmgr`. `usbaudio.ddrv` parses the UAC 1.0/2.0 descriptors and
//! drives control transfers (`SET_INTERFACE`, `SET_CUR`) and isochronous PCM streams over a
//! shared-memory `IoRing` backed by xHCI Isoch TRBs (`T_ISOCH = 5`).

use core::sync::atomic::{Ordering, fence};

use libd::audio::{self, RING_READ, RING_WRITE};
use libd::proto::{self, HEADER, Header};
use libd::ring::{Cqe, IoRing};
use libd::sys::{self, Handle, MsgHandle};
use libd::{Dma, Port, println};

use super::{
    CC_SHORT, CC_SUCCESS, E_TRANSFER, Ident, Loc, PG_DESC, PG_IN, RING_TRBS, T_CONFIGURE_EP,
    T_LINK, T_SET_TR_DEQ, TRB_IOC, TRB_TC, Trb, Xhci,
};

pub const MAX_AUDIO_DEVS: usize = 2;
pub const KEY_AUDIO: u64 = 32;

const T_ISOCH: u32 = 5;
const TRB_SIA: u32 = 1 << 31;
const CC_RING_UNDERRUN: u32 = 15;
const CC_RING_OVERRUN: u32 = 16;
const CC_MISSED_SERVICE: u32 = 23;

const ISOC_SLOTS: usize = 4;
const ISOC_DMA_PAGES: u64 = 1 + ISOC_SLOTS as u64; // Page 0 = ring, Pages 1..5 = 4 period buffers
const MAX_CFG_DESC: usize = 2048;

#[derive(Clone, Copy)]
struct PendingPeriod {
    in_flight: bool,
    sqe_id: u32,
    buf_off: u32,
    buf_len: u32,
    last_trb_da: u64,
}

impl PendingPeriod {
    const fn empty() -> Self {
        Self { in_flight: false, sqe_id: 0, buf_off: 0, buf_len: 0, last_trb_da: 0 }
    }
}

struct IsocPipe {
    dci: u32,
    is_in: bool,
    max_packet: u32,
    packet_bytes: u32,
    period_packets: u32,
    dma: Dma,
    ring_enq: u32,
    ring_cycle: u32,
    io_ring: IoRing,
    slots: [PendingPeriod; ISOC_SLOTS],
}

impl IsocPipe {
    fn enq_trb(&mut self, t: Trb) -> u64 {
        let i = self.ring_enq;
        let da = self.dma.dev_addr(0) + u64::from(i) * 16;
        let off = u64::from(i) * 16;
        self.dma.map.w64(off, t.param);
        self.dma.map.w32(off + 8, t.status);
        fence(Ordering::SeqCst);
        self.dma.map.w32(off + 12, t.control | self.ring_cycle);
        self.ring_enq += 1;
        if self.ring_enq == RING_TRBS - 1 {
            let link_off = u64::from(RING_TRBS - 1) * 16;
            self.dma.map.w64(link_off, self.dma.dev_addr(0));
            self.dma.map.w32(link_off + 8, 0);
            fence(Ordering::SeqCst);
            self.dma.map.w32(link_off + 12, (T_LINK << 10) | TRB_TC | self.ring_cycle);
            self.ring_enq = 0;
            self.ring_cycle ^= 1;
        }
        da
    }
}

pub struct UsbAudioDev {
    pub idx: usize,
    pub slot: u32,
    pub loc: Loc,
    pub id: Ident,
    pub ch: Handle,
    pub cfg_desc: [u8; MAX_CFG_DESC],
    pub cfg_len: usize,
    pub restarts: u32,
    pipe: Option<IsocPipe>,
}

impl UsbAudioDev {
    pub fn active_dci(&self) -> Option<u32> {
        self.pipe.as_ref().map(|p| p.dci)
    }
}

fn isoc_interval_exp(speed: u32, interval: u8) -> u32 {
    if speed <= 2 {
        // Full Speed: bInterval is 1..=16 representing 2^(bInterval-1) frames (1 ms = 2^3 microframes).
        (u32::from(interval.clamp(1, 16)) - 1 + 3).clamp(3, 18)
    } else {
        // High / Super Speed: bInterval is 1..=16 representing 2^(bInterval-1) microframes.
        (u32::from(interval.clamp(1, 16)) - 1).min(15)
    }
}

impl Xhci {
    /// Set up a USB Audio Class device: apply SET_CONFIGURATION, copy raw configuration descriptor,
    /// and attach a dedicated USB-bus channel to `devmgr` to spawn `usbaudio.ddrv`.
    pub(super) fn setup_audio(
        &mut self,
        slot: u32,
        loc: Loc,
        cfg_value: u8,
        id: Ident,
        cfg_len: usize,
    ) -> Result<super::Found, &'static str> {
        let Some(idx) = self.audios.iter().position(|a| a.is_none()) else {
            return Err("too many USB audio devices");
        };
        let copy_len = cfg_len.min(MAX_CFG_DESC);
        let mut cfg_desc = [0u8; MAX_CFG_DESC];
        for (i, dst) in cfg_desc.iter_mut().take(copy_len).enumerate() {
            *dst = self.desc(i as u64);
        }
        self.control(slot, [0x00, 9, cfg_value, 0, 0, 0, 0, 0], 0)
            .map_err(|_| "SET_CONFIGURATION failed")?;

        let Ok((mine, theirs)) = sys::channel_pair() else {
            return Err("out of handles for USB audio");
        };
        let a = u64::from(id.vid)
            | (u64::from(id.pid) << 16)
            | (u64::from(loc.speed) << 32)
            | (u64::from(slot) << 40);
        let mut msg = [0u8; HEADER];
        Header { txid: 0, op: proto::USB_AUDIO_ATTACH, status: 0, a, b: u64::from(loc.root) }.put(&mut msg);
        if sys::channel_write_h(self.ctl, &msg, &[MsgHandle { handle: theirs, rights: sys::RIGHTS_SAME }]) < 0 {
            sys::handle_close(mine);
            return Err("cannot attach USB audio to devmgr");
        }
        Ok(super::Found::Audio(UsbAudioDev {
            idx,
            slot,
            loc,
            id,
            ch: mine,
            cfg_desc,
            cfg_len: copy_len,
            restarts: 0,
            pipe: None,
        }))
    }

    /// Configure an xHCI Isochronous endpoint on `slot` and attach `io_ring`.
    #[allow(clippy::too_many_arguments)]
    fn open_isoc_pipe(
        &mut self,
        idx: usize,
        ep_addr: u8,
        max_packet: u16,
        interval: u8,
        mult: u8,
        packet_bytes: u16,
        period_packets: u32,
        ring_vmo: Handle,
    ) -> Result<(), i32> {
        let Some(au) = self.audios[idx].as_ref() else {
            sys::handle_close(ring_vmo);
            return Err(sys::ERR_BAD_STATE as i32);
        };
        let slot = au.slot;
        let loc = au.loc;
        let old_dci = au.pipe.as_ref().map(|p| p.dci).unwrap_or(0);
        let ep_num = u32::from(ep_addr & 0x0F);
        if ep_num == 0 || max_packet == 0 || packet_bytes == 0 || period_packets == 0 || period_packets > 20 {
            sys::handle_close(ring_vmo);
            return Err(sys::ERR_INVALID_ARGS as i32);
        }
        let is_in = (ep_addr & 0x80) != 0;
        let dci = ep_num * 2 + u32::from(is_in);
        let io_ring = IoRing::attach(ring_vmo).map_err(|e| e as i32)?;
        let Ok(dma) = Dma::new(self.dev, ISOC_DMA_PAGES * 4096, sys::DMA_DEVICE_READ | sys::DMA_DEVICE_WRITE) else {
            return Err(sys::ERR_NO_MEMORY as i32);
        };
        // Zero ring page.
        for o in (0..4096).step_by(8) {
            dma.map.w64(o, 0);
        }

        // Build Input Context for Configure Endpoint (Isoch OUT = 1, Isoch IN = 5, CErr = 0!).
        self.clear_page(PG_IN);
        if old_dci != 0 && old_dci != dci {
            self.ctx_w(PG_IN, 0, 0, 1u32 << old_dci);
        }
        self.ctx_w(PG_IN, 0, 1, 1 | (1u32 << dci));
        self.slot_ctx(&loc, dci, 0, 0);
        let e = u64::from(dci) + 1;
        let exp = isoc_interval_exp(loc.speed, interval);
        let ep_type = if is_in { 5u32 } else { 1u32 };
        let burst = u32::from(mult.min(2));
        let mps = u32::from(max_packet);
        let esit = mps * (burst + 1);
        let avg = u32::from(packet_bytes).max(mps);
        self.ctx_w(PG_IN, e, 0, exp << 16);
        // CErr = 0 (bits 2:1) is mandatory for Isochronous endpoints per xHCI §4.14.1!
        self.ctx_w(PG_IN, e, 1, (ep_type << 3) | (burst << 8) | (mps << 16));
        let ring_da = dma.dev_addr(0) | 1;
        self.ctx_w(PG_IN, e, 2, ring_da as u32);
        self.ctx_w(PG_IN, e, 3, (ring_da >> 32) as u32);
        self.ctx_w(PG_IN, e, 4, avg | (esit << 16));

        let cmd = Trb {
            param: self.addr(PG_IN, 0),
            status: 0,
            control: (T_CONFIGURE_EP << 10) | (slot << 24),
        };
        if self.command(cmd).is_err() {
            println!("xhci: Configure Endpoint (isoc dci {}) failed (cc={})", dci, self.last_cc);
            return Err(proto::ERR_IO);
        }

        if let Some(au) = self.audios[idx].as_mut() {
            au.pipe = Some(IsocPipe {
                dci,
                is_in,
                max_packet: mps,
                packet_bytes: u32::from(packet_bytes),
                period_packets,
                dma,
                ring_enq: 0,
                ring_cycle: 1,
                io_ring,
                slots: [PendingPeriod::empty(); ISOC_SLOTS],
            });
        }
        self.pump_isoc(idx);
        Ok(())
    }

    fn stop_isoc_pipe(&mut self, idx: usize) {
        let Some((slot, dci)) = self.audios[idx].as_ref().and_then(|a| a.pipe.as_ref().map(|p| (a.slot, p.dci))) else {
            return;
        };
        let loc = self.audios[idx].as_ref().map(|a| a.loc).unwrap_or_default();
        if let Some(au) = self.audios[idx].as_mut() {
            au.pipe = None;
        }
        self.clear_page(PG_IN);
        self.ctx_w(PG_IN, 0, 0, 1u32 << dci); // drop old isoc endpoint
        self.ctx_w(PG_IN, 0, 1, 1);
        self.slot_ctx(&loc, 1, 0, 0);
        let cmd = Trb {
            param: self.addr(PG_IN, 0),
            status: 0,
            control: (T_CONFIGURE_EP << 10) | (slot << 24),
        };
        let _ = self.command(cmd);
    }

    /// Submit available SQEs from `usbaudio.ddrv`'s `IoRing` onto the xHCI isochronous ring.
    pub(super) fn pump_isoc(&mut self, idx: usize) {
        let Some(au) = self.audios[idx].as_mut() else { return };
        let slot = au.slot;
        let Some(p) = au.pipe.as_mut() else { return };
        let mut submitted = false;
        let pkt_bytes = p.packet_bytes as usize;
        let max_period_bytes = (p.period_packets as usize * pkt_bytes).min(4096);

        for s in 0..ISOC_SLOTS {
            if p.slots[s].in_flight {
                continue;
            }
            let Some(sqe) = p.io_ring.pop_sq() else { break };
            let want_op = if p.is_in { RING_READ } else { RING_WRITE };
            if sqe.op != want_op {
                p.io_ring.push_cq(Cqe { id: sqe.id, status: sys::ERR_INVALID_ARGS as i32, a: 0 });
                continue;
            }
            let total_len = (sqe.buf_len as usize).min(max_period_bytes);
            if total_len == 0 {
                p.io_ring.push_cq(Cqe { id: sqe.id, status: 0, a: 0 });
                continue;
            }
            let pg = 1 + s as u64;
            let dst_base = pg * 4096;
            if !p.is_in {
                let Some(src) = p.io_ring.data(sqe.buf_off, total_len as u32) else {
                    p.io_ring.push_cq(Cqe { id: sqe.id, status: sys::ERR_INVALID_ARGS as i32, a: 0 });
                    continue;
                };
                let mut i = 0;
                while i + 4 <= total_len {
                    let w = u32::from_le_bytes([src[i], src[i + 1], src[i + 2], src[i + 3]]);
                    p.dma.map.w32(dst_base + i as u64, w);
                    i += 4;
                }
                while i < total_len {
                    p.dma.map.w8(dst_base + i as u64, src[i]);
                    i += 1;
                }
            }
            fence(Ordering::Release);

            // Split the period into 1-ms (or 1-interval) Isoch TRBs, setting IOC on the last packet.
            let pg_da = p.dma.dev_addr(pg * 4096);
            let mut off = 0usize;
            let mut last_da = 0u64;
            while off < total_len {
                let chunk = (total_len - off).min(pkt_bytes).min(p.max_packet as usize);
                let is_last = off + chunk >= total_len;
                let ctrl = (T_ISOCH << 10) | TRB_SIA | if is_last { TRB_IOC } else { 0 };
                last_da = p.enq_trb(Trb {
                    param: pg_da + off as u64,
                    status: chunk as u32,
                    control: ctrl,
                });
                off += chunk;
            }
            p.slots[s] = PendingPeriod {
                in_flight: true,
                sqe_id: sqe.id,
                buf_off: sqe.buf_off,
                buf_len: total_len as u32,
                last_trb_da: last_da,
            };
            submitted = true;
        }
        let dci = p.dci;
        if submitted {
            self.ring_doorbell(slot, dci);
        }
    }

    /// Handle an xHCI transfer event belonging to a USB audio isochronous endpoint.
    pub(super) fn on_isoc_event(&mut self, e: &Trb) -> bool {
        let at = (e.slot(), e.endpoint());
        let Some(idx) = self.audios.iter().position(|a| {
            a.as_ref().is_some_and(|a| a.slot == at.0 && a.active_dci() == Some(at.1))
        }) else {
            return false;
        };
        let cc = e.code();
        let mut completed = false;
        let mut need_kick = false;
        let mut ch = 0 as Handle;
        if let Some(au) = self.audios[idx].as_mut() {
            ch = au.ch;
            if let Some(p) = au.pipe.as_mut() {
                // Find the matching period slot (or oldest in-flight slot on underrun/missed-service).
                let matched = p
                    .slots
                    .iter()
                    .position(|s| s.in_flight && s.last_trb_da == e.param)
                    .or_else(|| {
                        if matches!(cc, CC_RING_UNDERRUN | CC_RING_OVERRUN | CC_MISSED_SERVICE) {
                            p.slots.iter().position(|s| s.in_flight)
                        } else {
                            None
                        }
                    });
                if let Some(si) = matched {
                    let st = p.slots[si];
                    p.slots[si].in_flight = false;
                    let ok = matches!(cc, CC_SUCCESS | CC_SHORT | CC_RING_UNDERRUN | CC_RING_OVERRUN);
                    if ok && p.is_in {
                        fence(Ordering::Acquire);
                        let src_base = (1 + si as u64) * 4096;
                        if let Some(dst) = p.io_ring.data_mut(st.buf_off, st.buf_len) {
                            for (i, b) in dst.iter_mut().enumerate() {
                                *b = p.dma.map.r8(src_base + i as u64);
                            }
                        }
                    }
                    p.io_ring.push_cq(Cqe {
                        id: st.sqe_id,
                        status: if ok { 0 } else { proto::ERR_IO },
                        a: if ok { u64::from(st.buf_len) } else { 0 },
                    });
                    completed = true;
                    need_kick = true;
                } else if matches!(cc, CC_RING_UNDERRUN | CC_RING_OVERRUN) {
                    need_kick = true;
                }
            }
        }
        if need_kick {
            self.pump_isoc(idx);
        }
        if completed && ch != 0 {
            proto::send(ch, audio::USB_ISOC_EVENT, 0, 0);
        }
        let _ = (E_TRANSFER, T_SET_TR_DEQ);
        true
    }

    /// Serve messages from `usbaudio.ddrv` on its USB-bus channel (`KEY_AUDIO + idx`).
    pub(super) fn serve_audio(&mut self, idx: usize, port: &Port) {
        let mut buf = [0u8; HEADER + 256];
        loop {
            let ch = match self.audios[idx].as_ref() {
                Some(a) if a.ch != 0 => a.ch,
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
                        audio::USB_GET_DESC => {
                            if hnd != 0 {
                                sys::handle_close(hnd);
                            }
                            if let Some(au) = self.audios[idx].as_ref() {
                                let mut rep = [0u8; HEADER + MAX_CFG_DESC];
                                let a = u64::from(au.id.vid)
                                    | (u64::from(au.id.pid) << 16)
                                    | (u64::from(au.loc.speed) << 32);
                                Header { txid: h.txid, op: h.op, status: 0, a, b: u64::from(au.loc.root) }.put(&mut rep);
                                rep[HEADER..HEADER + au.cfg_len].copy_from_slice(&au.cfg_desc[..au.cfg_len]);
                                let _ = sys::channel_write(ch, &rep[..HEADER + au.cfg_len]);
                            }
                        }
                        audio::USB_CTRL => {
                            if hnd != 0 {
                                sys::handle_close(hnd);
                            }
                            let slot = self.audios[idx].as_ref().map_or(0, |a| a.slot);
                            let bm = (h.a & 0xFF) as u8;
                            let bq = ((h.a >> 8) & 0xFF) as u8;
                            let wv = ((h.a >> 16) & 0xFFFF) as u16;
                            let wi = ((h.a >> 32) & 0xFFFF) as u16;
                            let wl = ((h.a >> 48) & 0xFFFF) as u16;
                            let setup = [
                                bm,
                                bq,
                                wv as u8,
                                (wv >> 8) as u8,
                                wi as u8,
                                (wi >> 8) as u8,
                                wl as u8,
                                (wl >> 8) as u8,
                            ];
                            let is_in = (bm & 0x80) != 0;
                            let payload = &buf[HEADER..n];
                            if !is_in && wl > 0 {
                                let cp = usize::from(wl).min(payload.len()).min(256);
                                for (i, &b) in payload.iter().take(cp).enumerate() {
                                    self.mem.map.w8(PG_DESC * 4096 + i as u64, b);
                                }
                            }
                            let mut rep = [0u8; HEADER + 256];
                            match self.control(slot, setup, wl) {
                                Ok(got) => {
                                    let rlen = if is_in { (got as usize).min(256) } else { 0 };
                                    for (i, dst) in rep[HEADER..HEADER + rlen].iter_mut().enumerate() {
                                        *dst = self.desc(i as u64);
                                    }
                                    Header { txid: h.txid, op: h.op, status: 0, a: u64::from(got), b: 0 }.put(&mut rep);
                                    let _ = sys::channel_write(ch, &rep[..HEADER + rlen]);
                                }
                                Err(cc) => {
                                    Header { txid: h.txid, op: h.op, status: proto::ERR_IO, a: u64::from(cc), b: 0 }.put(&mut rep);
                                    let _ = sys::channel_write(ch, &rep[..HEADER]);
                                }
                            }
                        }
                        audio::USB_ISOC_OPEN => {
                            let ep_addr = (h.a & 0xFF) as u8;
                            let max_packet = ((h.a >> 8) & 0xFFFF) as u16;
                            let interval = ((h.a >> 24) & 0xFF) as u8;
                            let mult = ((h.a >> 32) & 0xFF) as u8;
                            let packet_bytes = ((h.a >> 40) & 0xFFFF) as u16;
                            let period_packets = h.b as u32;
                            let mut rep = [0u8; HEADER];
                            if hnd == 0 {
                                Header { txid: h.txid, op: h.op, status: sys::ERR_INVALID_ARGS as i32, a: 0, b: 0 }.put(&mut rep);
                            } else {
                                let st = match self.open_isoc_pipe(
                                    idx,
                                    ep_addr,
                                    max_packet,
                                    interval,
                                    mult,
                                    packet_bytes,
                                    period_packets,
                                    hnd,
                                ) {
                                    Ok(()) => 0,
                                    Err(e) => e,
                                };
                                Header { txid: h.txid, op: h.op, status: st, a: 0, b: 0 }.put(&mut rep);
                            }
                            let _ = sys::channel_write(ch, &rep);
                        }
                        audio::USB_ISOC_KICK => {
                            if hnd != 0 {
                                sys::handle_close(hnd);
                            }
                            self.pump_isoc(idx);
                        }
                        audio::USB_ISOC_STOP => {
                            if hnd != 0 {
                                sys::handle_close(hnd);
                            }
                            self.stop_isoc_pipe(idx);
                            let mut rep = [0u8; HEADER];
                            Header { txid: h.txid, op: h.op, status: 0, a: 0, b: 0 }.put(&mut rep);
                            let _ = sys::channel_write(ch, &rep);
                        }
                        _ => {
                            if hnd != 0 {
                                sys::handle_close(hnd);
                            }
                        }
                    }
                }
                Err(sys::ERR_SHOULD_WAIT) => {
                    port.arm(ch, sys::READABLE | sys::PEER_CLOSED, KEY_AUDIO + idx as u64);
                    return;
                }
                Err(_) => {
                    // `usbaudio.ddrv` exited or crashed while the USB device is still plugged in!
                    // Stop the isoc pipe, close old channel, and re-attach a fresh `usbaudio.ddrv`
                    // (up to 3 times) so audio recovers seamlessly after a driver crash.
                    self.stop_isoc_pipe(idx);
                    if let Some(au) = self.audios[idx].as_mut() {
                        sys::handle_close(au.ch);
                        au.ch = 0;
                        if au.restarts < 3
                            && let Ok((mine, theirs)) = sys::channel_pair()
                        {
                            au.restarts += 1;
                            au.ch = mine;
                            let a = u64::from(au.id.vid)
                                | (u64::from(au.id.pid) << 16)
                                | (u64::from(au.loc.speed) << 32)
                                | (u64::from(au.slot) << 40);
                            let mut msg = [0u8; HEADER];
                            Header { txid: 0, op: proto::USB_AUDIO_ATTACH, status: 0, a, b: u64::from(au.loc.root) }.put(&mut msg);
                            if sys::channel_write_h(self.ctl, &msg, &[MsgHandle { handle: theirs, rights: sys::RIGHTS_SAME }]) == 0 {
                                port.arm(mine, sys::READABLE | sys::PEER_CLOSED, KEY_AUDIO + idx as u64);
                            } else {
                                sys::handle_close(mine);
                                au.ch = 0;
                            }
                        }
                    }
                    return;
                }
            }
        }
    }
}
