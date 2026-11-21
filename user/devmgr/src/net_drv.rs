//! Shared NIC driver <-> `net.dsvc` `IoRing` bridge used by `virtio-net.ddrv`, `e1000e.ddrv`,
//! and `r8169.ddrv`. Eliminates protocol duplication across NIC drivers.

use libd::net;
use libd::proto::{self, HEADER, Header};
use libd::ring::{Cqe, IoRing};
use libd::sys::{self, Handle};
use libd::{Port, println};

pub const KEY_CTL: u64 = 1;
pub const KEY_SVC: u64 = 2;
pub const KEY_IRQ0: u64 = 3;
pub const KEY_IRQ1: u64 = 4;

pub const MAX_FRAME: usize = 1522;

pub struct NetBridge {
    pub svc_ch: Handle,
    pub tx_ring: Option<IoRing>,
    pub rx_ring: Option<IoRing>,
    pub tx_frames: u64,
    pub rx_frames: u64,
    /// Frames received while the network service had no buffer posted (dropped).
    pub rx_dropped: u64,
}

impl NetBridge {
    pub const fn new() -> Self {
        Self {
            svc_ch: 0,
            tx_ring: None,
            rx_ring: None,
            tx_frames: 0,
            rx_frames: 0,
            rx_dropped: 0,
        }
    }

    /// Announce this NIC to `devmgr` on the control channel (`proto::NET_DEV`).
    pub fn announce(ctl: Handle, mac: [u8; 6], link_up: bool, mtu: u16, name: &str) {
        let mut msg = [0u8; HEADER + 40];
        let a = net::pack_mac(mac) | (u64::from(link_up) << 48);
        let nb = name.as_bytes();
        let nl = nb.len().min(40);
        Header { txid: 0, op: proto::NET_DEV, status: 0, a, b: u64::from(mtu) }.put(&mut msg);
        msg[HEADER..HEADER + nl].copy_from_slice(&nb[..nl]);
        let _ = sys::channel_write(ctl, &msg[..HEADER + nl]);
    }

    /// Notify `devmgr` (and `net.dsvc`) when carrier link state changes (`proto::NET_LINK`).
    pub fn send_link(ctl: Handle, link_up: bool) {
        proto::send(ctl, proto::NET_LINK, u64::from(link_up), 0);
    }

    /// Drain messages on `ctl` from `devmgr` (`NET_ATTACH`, `STATS`, `TEST_CRASH`).
    /// Returns `false` if the control channel closed (driver should exit).
    pub fn poll_ctl(&mut self, ctl: Handle, port: &Port, irqs: u64) -> bool {
        let mut buf = [0u8; HEADER + 64];
        loop {
            let mut hs = [0 as Handle; 1];
            match sys::channel_read_h(ctl, &mut buf, &mut hs, 0) {
                Ok((n, nh)) => {
                    let hnd = if nh > 0 { hs[0] } else { 0 };
                    let Some(h) = Header::get(&buf[..n]) else {
                        if hnd != 0 {
                            sys::handle_close(hnd);
                        }
                        continue;
                    };
                    match h.op {
                        proto::NET_ATTACH if hnd != 0 => {
                            if self.svc_ch != 0 {
                                sys::handle_close(self.svc_ch);
                            }
                            self.tx_ring = None;
                            self.rx_ring = None;
                            self.svc_ch = hnd;
                            port.arm(hnd, sys::READABLE | sys::PEER_CLOSED, KEY_SVC);
                        }
                        proto::STATS => {
                            if hnd != 0 {
                                sys::handle_close(hnd);
                            }
                            let mut rep = [0u8; HEADER];
                            Header {
                                txid: h.txid,
                                op: proto::STATS,
                                status: 0,
                                a: irqs,
                                b: self.tx_frames + self.rx_frames,
                            }
                            .put(&mut rep);
                            let _ = sys::channel_write(ctl, &rep);
                        }
                        proto::TEST_CRASH => {
                            if hnd != 0 {
                                sys::handle_close(hnd);
                            }
                            panic!("intentional test crash");
                        }
                        _ => {
                            if hnd != 0 {
                                sys::handle_close(hnd);
                            }
                        }
                    }
                }
                Err(sys::ERR_SHOULD_WAIT) => {
                    port.arm(ctl, sys::READABLE | sys::PEER_CLOSED, KEY_CTL);
                    return true;
                }
                Err(_) => return false,
            }
        }
    }

    /// Drain messages on `svc_ch` from `net.dsvc` (`DRV_SETUP_RINGS`, `DRV_TX_KICK`, `DRV_STOP`).
    /// Returns `true` if TX kick was received.
    pub fn poll_svc(&mut self, port: &Port) -> bool {
        if self.svc_ch == 0 {
            return false;
        }
        let mut kicked = false;
        let mut buf = [0u8; HEADER + 32];
        loop {
            let mut hs = [0 as Handle; 2];
            match sys::channel_read_h(self.svc_ch, &mut buf, &mut hs, 0) {
                Ok((n, nh)) => {
                    let Some(h) = Header::get(&buf[..n]) else {
                        for &x in &hs[..nh] {
                            if x != 0 {
                                sys::handle_close(x);
                            }
                        }
                        continue;
                    };
                    match h.op {
                        net::DRV_SETUP_RINGS if nh == 2 => {
                            let status = match (IoRing::attach(hs[0]), IoRing::attach(hs[1])) {
                                (Ok(tx), Ok(rx)) => {
                                    self.tx_ring = Some(tx);
                                    self.rx_ring = Some(rx);
                                    0
                                }
                                (Err(e), _) | (_, Err(e)) => e as i32,
                            };
                            let mut rep = [0u8; HEADER];
                            Header { txid: h.txid, op: h.op, status, a: 0, b: 0 }.put(&mut rep);
                            let _ = sys::channel_write(self.svc_ch, &rep);
                        }
                        net::DRV_TX_KICK => {
                            for &x in &hs[..nh] {
                                if x != 0 {
                                    sys::handle_close(x);
                                }
                            }
                            kicked = true;
                        }
                        net::DRV_STOP => {
                            for &x in &hs[..nh] {
                                if x != 0 {
                                    sys::handle_close(x);
                                }
                            }
                            self.tx_ring = None;
                            self.rx_ring = None;
                            let mut rep = [0u8; HEADER];
                            Header { txid: h.txid, op: h.op, status: 0, a: 0, b: 0 }.put(&mut rep);
                            let _ = sys::channel_write(self.svc_ch, &rep);
                        }
                        _ => {
                            for &x in &hs[..nh] {
                                if x != 0 {
                                    sys::handle_close(x);
                                }
                            }
                        }
                    }
                }
                Err(sys::ERR_SHOULD_WAIT) => {
                    port.arm(self.svc_ch, sys::READABLE | sys::PEER_CLOSED, KEY_SVC);
                    return kicked;
                }
                Err(_) => {
                    sys::handle_close(self.svc_ch);
                    self.svc_ch = 0;
                    self.tx_ring = None;
                    self.rx_ring = None;
                    return kicked;
                }
            }
        }
    }

    /// Deliver one received Ethernet frame into `net.dsvc`'s `rx_ring`.
    pub fn deliver_rx(&mut self, frame: &[u8]) {
        if frame.len() < 14 || frame.len() > MAX_FRAME {
            return;
        }
        let Some(rx) = self.rx_ring.as_mut() else { return };
        let Some(sqe) = rx.pop_sq() else {
            // The network service is behind: the frame is lost. Said once, then every 1000.
            self.rx_dropped += 1;
            if self.rx_dropped == 1 || self.rx_dropped.is_multiple_of(1000) {
                println!("net driver: {} received frame(s) dropped (no receive buffer from the network service)", self.rx_dropped);
            }
            return;
        };
        if sqe.op != net::DRV_RING_FRAME || (sqe.buf_len as usize) < frame.len() {
            rx.push_cq(Cqe { id: sqe.id, status: sys::ERR_INVALID_ARGS as i32, a: 0 });
            return;
        }
        if let Some(dst) = rx.data_mut(sqe.buf_off, frame.len() as u32) {
            dst.copy_from_slice(frame);
            rx.push_cq(Cqe { id: sqe.id, status: 0, a: frame.len() as u64 });
            self.rx_frames += 1;
            if self.svc_ch != 0 {
                proto::send(self.svc_ch, net::DRV_RX_READY, 1, 0);
            }
        } else {
            rx.push_cq(Cqe { id: sqe.id, status: sys::ERR_INVALID_ARGS as i32, a: 0 });
        }
    }

    /// Drain pending outbound frames from `tx_ring`, invoking `tx_fn(frame) -> bool` for each.
    pub fn drain_tx<F: FnMut(&[u8]) -> bool>(&mut self, mut tx_fn: F) {
        let Some(tx) = self.tx_ring.as_mut() else { return };
        while let Some(sqe) = tx.pop_sq() {
            let ok = if sqe.op == net::DRV_RING_FRAME
                && sqe.buf_len >= 14
                && (sqe.buf_len as usize) <= MAX_FRAME
                && let Some(src) = tx.data(sqe.buf_off, sqe.buf_len)
            {
                tx_fn(src)
            } else {
                false
            };
            if ok {
                self.tx_frames += 1;
            }
            tx.push_cq(Cqe {
                id: sqe.id,
                status: if ok { 0 } else { proto::ERR_IO },
                a: if ok { u64::from(sqe.buf_len) } else { 0 },
            });
        }
    }
}
