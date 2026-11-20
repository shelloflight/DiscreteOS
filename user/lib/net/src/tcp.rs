//! RFC 9293 TCP connection state machine (`no_std`, zero-unsafe, bounded buffers).

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use crate::Ipv4Addr;
use crate::wire::{TCP_ACK, TCP_FIN, TCP_PSH, TCP_RST, TCP_SYN, TcpSegment};

pub const DEFAULT_MSS: u16 = 1460;
pub const MAX_BUF: usize = 32_768;
const INIT_RTO_MS: u64 = 300;
const MAX_RTO_MS: u64 = 4_000;
const MAX_RETRIES: u8 = 8;

#[inline]
pub fn seq_lt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

#[inline]
pub fn seq_le(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) <= 0
}

#[inline]
pub fn seq_gt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) > 0
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TcpState {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
}

/// Outbound TCP segment produced by [`TcpConn`].
#[derive(Clone, Debug)]
pub struct OutSegment {
    pub dst_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub window: u16,
    pub mss: Option<u16>,
    pub payload: Vec<u8>,
}

pub struct TcpConn {
    pub id: u32,
    pub state: TcpState,
    pub local_port: u16,
    pub remote_ip: Ipv4Addr,
    pub remote_port: u16,
    pub snd_una: u32,
    pub snd_nxt: u32,
    pub snd_wnd: u16,
    pub rcv_nxt: u32,
    pub peer_mss: u16,
    pub tx_buf: VecDeque<u8>,
    pub rx_buf: VecDeque<u8>,
    pub fin_queued: bool,
    pub fin_sent: bool,
    pub peer_closed: bool,
    pub reset: bool,
    pub rto_ms: u64,
    pub last_tx_ms: u64,
    pub retries: u8,
    pub time_wait_until: u64,
}

impl TcpConn {
    pub fn new_client(
        id: u32,
        local_port: u16,
        remote_ip: Ipv4Addr,
        remote_port: u16,
        iss: u32,
    ) -> Self {
        Self {
            id,
            state: TcpState::SynSent,
            local_port,
            remote_ip,
            remote_port,
            snd_una: iss,
            snd_nxt: iss,
            snd_wnd: 65535,
            rcv_nxt: 0,
            peer_mss: DEFAULT_MSS,
            tx_buf: VecDeque::new(),
            rx_buf: VecDeque::new(),
            fin_queued: false,
            fin_sent: false,
            peer_closed: false,
            reset: false,
            rto_ms: INIT_RTO_MS,
            last_tx_ms: 0,
            retries: 0,
            time_wait_until: 0,
        }
    }

    pub fn new_listen(id: u32, local_port: u16) -> Self {
        Self {
            id,
            state: TcpState::Listen,
            local_port,
            remote_ip: [0; 4],
            remote_port: 0,
            snd_una: 0,
            snd_nxt: 0,
            snd_wnd: 65535,
            rcv_nxt: 0,
            peer_mss: DEFAULT_MSS,
            tx_buf: VecDeque::new(),
            rx_buf: VecDeque::new(),
            fin_queued: false,
            fin_sent: false,
            peer_closed: false,
            reset: false,
            rto_ms: INIT_RTO_MS,
            last_tx_ms: 0,
            retries: 0,
            time_wait_until: 0,
        }
    }

    fn rcv_window(&self) -> u16 {
        MAX_BUF.saturating_sub(self.rx_buf.len()).min(65535) as u16
    }

    fn seg(&self, seq: u32, flags: u8, mss: Option<u16>, payload: Vec<u8>) -> OutSegment {
        OutSegment {
            dst_ip: self.remote_ip,
            src_port: self.local_port,
            dst_port: self.remote_port,
            seq,
            ack: if (flags & TCP_ACK) != 0 { self.rcv_nxt } else { 0 },
            flags,
            window: self.rcv_window(),
            mss,
            payload,
        }
    }

    /// Emit initial SYN for an active open.
    pub fn start_connect(&mut self, now_ms: u64) -> OutSegment {
        self.state = TcpState::SynSent;
        let seq = self.snd_una;
        self.snd_nxt = seq.wrapping_add(1);
        self.last_tx_ms = now_ms;
        self.retries = 0;
        self.rto_ms = INIT_RTO_MS;
        self.seg(seq, TCP_SYN, Some(DEFAULT_MSS), Vec::new())
    }

    /// Queue application data for transmission; returns bytes accepted.
    pub fn enqueue_tx(&mut self, data: &[u8]) -> usize {
        if !matches!(self.state, TcpState::Established | TcpState::CloseWait) || self.fin_queued {
            return 0;
        }
        let avail = MAX_BUF.saturating_sub(self.tx_buf.len());
        let take = data.len().min(avail);
        self.tx_buf.extend(&data[..take]);
        take
    }

    /// Read received application data into `out`; returns bytes copied.
    pub fn read_rx(&mut self, out: &mut [u8]) -> usize {
        let take = out.len().min(self.rx_buf.len());
        for slot in out.iter_mut().take(take) {
            *slot = self.rx_buf.pop_front().unwrap_or(0);
        }
        take
    }

    /// Initiate graceful FIN close.
    pub fn close(&mut self, now_ms: u64, out: &mut Vec<OutSegment>) {
        match self.state {
            TcpState::Closed | TcpState::Listen => {
                self.state = TcpState::Closed;
            }
            TcpState::SynSent => {
                self.state = TcpState::Closed;
            }
            TcpState::SynReceived | TcpState::Established => {
                self.fin_queued = true;
                self.flush_tx(now_ms, out);
            }
            TcpState::CloseWait => {
                self.fin_queued = true;
                self.flush_tx(now_ms, out);
            }
            _ => {}
        }
    }

    /// Flush unsent bytes (and queued FIN) up to the peer's receive window.
    pub fn flush_tx(&mut self, now_ms: u64, out: &mut Vec<OutSegment>) {
        if !matches!(
            self.state,
            TcpState::Established | TcpState::CloseWait | TcpState::FinWait1 | TcpState::LastAck
        ) {
            return;
        }
        let mss = usize::from(self.peer_mss.clamp(536, DEFAULT_MSS));
        loop {
            let in_flight = self.snd_nxt.wrapping_sub(self.snd_una) as usize;
            let wnd = usize::from(self.snd_wnd).max(mss);
            if in_flight >= self.tx_buf.len() || in_flight >= wnd {
                break;
            }
            let rem_buf = self.tx_buf.len() - in_flight;
            let rem_wnd = wnd - in_flight;
            let chunk_len = rem_buf.min(rem_wnd).min(mss);
            if chunk_len == 0 {
                break;
            }
            let mut payload = Vec::with_capacity(chunk_len);
            for i in 0..chunk_len {
                if let Some(&b) = self.tx_buf.get(in_flight + i) {
                    payload.push(b);
                }
            }
            let seq = self.snd_nxt;
            self.snd_nxt = self.snd_nxt.wrapping_add(payload.len() as u32);
            let mut flags = TCP_ACK | TCP_PSH;
            if self.fin_queued && !self.fin_sent && (self.snd_nxt.wrapping_sub(self.snd_una) as usize) == self.tx_buf.len() {
                flags |= TCP_FIN;
                self.fin_sent = true;
                self.snd_nxt = self.snd_nxt.wrapping_add(1);
                self.state = match self.state {
                    TcpState::CloseWait => TcpState::LastAck,
                    _ => TcpState::FinWait1,
                };
            }
            if self.last_tx_ms == 0 {
                self.last_tx_ms = now_ms;
            }
            out.push(self.seg(seq, flags, None, payload));
        }

        if self.fin_queued
            && !self.fin_sent
            && (self.snd_nxt.wrapping_sub(self.snd_una) as usize) == self.tx_buf.len()
        {
            let seq = self.snd_nxt;
            self.fin_sent = true;
            self.snd_nxt = self.snd_nxt.wrapping_add(1);
            self.state = match self.state {
                TcpState::CloseWait => TcpState::LastAck,
                _ => TcpState::FinWait1,
            };
            self.last_tx_ms = now_ms;
            out.push(self.seg(seq, TCP_FIN | TCP_ACK, None, Vec::new()));
        }
    }

    /// Handle an incoming TCP segment matching this connection.
    pub fn on_segment(&mut self, src_ip: Ipv4Addr, seg: &TcpSegment<'_>, iss: u32, now_ms: u64, out: &mut Vec<OutSegment>) {
        if let Some(m) = seg.mss {
            self.peer_mss = m.clamp(536, DEFAULT_MSS);
        }

        if self.state == TcpState::Listen {
            if (seg.flags & TCP_RST) != 0 || (seg.flags & TCP_ACK) != 0 {
                return;
            }
            if (seg.flags & TCP_SYN) != 0 {
                self.remote_ip = src_ip;
                self.remote_port = seg.src_port;
                self.rcv_nxt = seg.seq.wrapping_add(1);
                self.snd_una = iss;
                self.snd_nxt = iss.wrapping_add(1);
                self.snd_wnd = seg.window;
                self.state = TcpState::SynReceived;
                self.last_tx_ms = now_ms;
                self.retries = 0;
                self.rto_ms = INIT_RTO_MS;
                out.push(self.seg(iss, TCP_SYN | TCP_ACK, Some(DEFAULT_MSS), Vec::new()));
            }
            return;
        }

        if (seg.flags & TCP_RST) != 0 {
            if self.state == TcpState::SynSent {
                if (seg.flags & TCP_ACK) != 0 && seg.ack == self.snd_nxt {
                    self.reset = true;
                    self.state = TcpState::Closed;
                }
            } else if seq_le(self.rcv_nxt, seg.seq)
                && seq_lt(seg.seq, self.rcv_nxt.wrapping_add(self.rcv_window().max(1) as u32))
            {
                self.reset = true;
                self.state = TcpState::Closed;
            }
            return;
        }

        if self.state == TcpState::SynSent {
            if (seg.flags & (TCP_SYN | TCP_ACK)) == (TCP_SYN | TCP_ACK) && seg.ack == self.snd_nxt {
                self.snd_una = seg.ack;
                self.snd_wnd = seg.window;
                self.rcv_nxt = seg.seq.wrapping_add(1);
                self.state = TcpState::Established;
                self.last_tx_ms = 0;
                self.retries = 0;
                self.rto_ms = INIT_RTO_MS;
                out.push(self.seg(self.snd_nxt, TCP_ACK, None, Vec::new()));
                self.flush_tx(now_ms, out);
            }
            return;
        }

        // Process ACK for all synchronized states.
        if (seg.flags & TCP_ACK) != 0 {
            if seq_gt(seg.ack, self.snd_una) && seq_le(seg.ack, self.snd_nxt) {
                let mut acked = seg.ack.wrapping_sub(self.snd_una) as usize;
                self.snd_una = seg.ack;
                self.retries = 0;
                self.rto_ms = INIT_RTO_MS;
                if self.state == TcpState::SynReceived {
                    self.state = TcpState::Established;
                    acked = acked.saturating_sub(1); // SYN consumed 1 seq
                }
                let drain = acked.min(self.tx_buf.len());
                for _ in 0..drain {
                    self.tx_buf.pop_front();
                }
                self.last_tx_ms = if self.snd_una == self.snd_nxt { 0 } else { now_ms };

                // Did the ACK cover our FIN?
                if self.fin_sent && self.snd_una == self.snd_nxt {
                    match self.state {
                        TcpState::FinWait1 => self.state = TcpState::FinWait2,
                        TcpState::Closing => {
                            self.state = TcpState::TimeWait;
                            self.time_wait_until = now_ms.saturating_add(2_000);
                        }
                        TcpState::LastAck => self.state = TcpState::Closed,
                        _ => {}
                    }
                }
            }
            self.snd_wnd = seg.window;
        }

        // Process incoming payload (in-order, trimming any already-received overlap).
        let mut need_ack = false;
        if !seg.payload.is_empty() {
            let seg_end = seg.seq.wrapping_add(seg.payload.len() as u32);
            if seq_le(seg.seq, self.rcv_nxt) && seq_gt(seg_end, self.rcv_nxt) {
                let skip = self.rcv_nxt.wrapping_sub(seg.seq) as usize;
                let fresh = &seg.payload[skip..];
                let space = MAX_BUF.saturating_sub(self.rx_buf.len());
                let take = fresh.len().min(space);
                self.rx_buf.extend(&fresh[..take]);
                self.rcv_nxt = self.rcv_nxt.wrapping_add(take as u32);
                need_ack = true;
            } else {
                // Out-of-order or duplicate: send duplicate ACK with expected rcv_nxt.
                need_ack = true;
            }
        }

        // Process FIN (only when its sequence number aligns with rcv_nxt).
        let fin_seq = seg.seq.wrapping_add(seg.payload.len() as u32);
        if (seg.flags & TCP_FIN) != 0 && fin_seq == self.rcv_nxt {
            self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
            self.peer_closed = true;
            need_ack = true;
            match self.state {
                TcpState::SynReceived | TcpState::Established => self.state = TcpState::CloseWait,
                TcpState::FinWait1 => self.state = TcpState::Closing,
                TcpState::FinWait2 => {
                    self.state = TcpState::TimeWait;
                    self.time_wait_until = now_ms.saturating_add(2_000);
                }
                _ => {}
            }
        }

        let before = out.len();
        self.flush_tx(now_ms, out);
        if need_ack && out.len() == before {
            out.push(self.seg(self.snd_nxt, TCP_ACK, None, Vec::new()));
        }
    }

    /// Periodic timer tick for retransmissions and TIME-WAIT expiry.
    pub fn tick(&mut self, now_ms: u64, out: &mut Vec<OutSegment>) {
        if self.state == TcpState::TimeWait && now_ms >= self.time_wait_until {
            self.state = TcpState::Closed;
            return;
        }
        if self.last_tx_ms == 0 || self.snd_una == self.snd_nxt {
            return;
        }
        if now_ms.saturating_sub(self.last_tx_ms) < self.rto_ms {
            return;
        }
        if self.retries >= MAX_RETRIES {
            self.reset = true;
            self.state = TcpState::Closed;
            return;
        }
        self.retries += 1;
        self.rto_ms = (self.rto_ms * 2).min(MAX_RTO_MS);
        self.last_tx_ms = now_ms;

        match self.state {
            TcpState::SynSent => {
                out.push(self.seg(self.snd_una, TCP_SYN, Some(DEFAULT_MSS), Vec::new()));
            }
            TcpState::SynReceived => {
                out.push(self.seg(self.snd_una, TCP_SYN | TCP_ACK, Some(DEFAULT_MSS), Vec::new()));
            }
            TcpState::Established | TcpState::FinWait1 | TcpState::CloseWait | TcpState::LastAck | TcpState::Closing => {
                let mss = usize::from(self.peer_mss.clamp(536, DEFAULT_MSS));
                if !self.tx_buf.is_empty() {
                    let take = self.tx_buf.len().min(mss);
                    let mut payload = Vec::with_capacity(take);
                    for i in 0..take {
                        if let Some(&b) = self.tx_buf.get(i) {
                            payload.push(b);
                        }
                    }
                    let mut flags = TCP_ACK | TCP_PSH;
                    if self.fin_sent && take == self.tx_buf.len() {
                        flags |= TCP_FIN;
                    }
                    out.push(self.seg(self.snd_una, flags, None, payload));
                } else if self.fin_sent {
                    out.push(self.seg(self.snd_una, TCP_FIN | TCP_ACK, None, Vec::new()));
                }
            }
            _ => {}
        }
    }
}
