//! Network service, NIC driver, and client socket IPC protocol (`libd::net`).
//!
//! Zero-copy packet and stream I/O flows over `libd::ring::IoRing` shared-memory VMOs:
//! - `net.dsvc` <--IoRing (TX + RX)--> `virtio-net.ddrv` / `e1000e.ddrv` / `r8169.ddrv`
//! - `app`      <--IoRing (TCP/UDP)--> `net.dsvc`
//!
//! Capability separation:
//! - `net.client`: DNS resolution, TCP connections, UDP sockets, interface status.
//! - `net.icmp`:   ICMP echo (`ping`), DNS resolution, interface status.
//! - `net.control`: interface status and DNS configuration.
//! - `net.status`:  interface status only (read-only; the desktop's network indicator).
//!
//! An application without `grants.net` receives no endpoints and cannot access the network.

use crate::proto::{HEADER, Header};
use crate::ring::{IoRing, Sqe};
use crate::svc;
use crate::sys::{self, Handle, MsgHandle};

// ---- Backend registration (devmgr -> net.dsvc on `devmgr.net`) ----------------------------------

pub const BACKEND_ADD: u32 = 700;
pub const BACKEND_LINK: u32 = 701;
pub const BACKEND_GONE: u32 = 702;

// ---- NIC driver direct protocol (net.dsvc <-> NIC driver channel) -------------------------------

pub const DRV_SETUP_RINGS: u32 = 710;
pub const DRV_TX_KICK: u32 = 711;
pub const DRV_RX_READY: u32 = 712;
pub const DRV_STOP: u32 = 713;
pub const DRV_RING_FRAME: u32 = 1;

// ---- Client <-> net.dsvc protocol (`net.client`, `net.icmp`, `net.control`) ---------------------

pub const OP_STATUS: u32 = 720;
pub const OP_SET_DNS: u32 = 721;
pub const OP_DNS_RESOLVE: u32 = 722;
pub const OP_PING: u32 = 723;
pub const OP_TCP_CONNECT: u32 = 724;
pub const OP_SOCK_KICK: u32 = 725;
pub const OP_SOCK_EVENT: u32 = 726;
pub const OP_SOCK_CLOSE: u32 = 727;
pub const OP_UDP_OPEN: u32 = 728;
pub const OP_SET_CONFIG: u32 = 729;

// Client socket IoRing SQE ops.
pub const RING_SEND: u32 = 1;
pub const RING_RECV: u32 = 2;

const CALL_TIMEOUT_NS: u64 = 10_000_000_000;
const MS: u64 = 1_000_000;

/// Pack 4 IPv4 octets into low 32 bits of a `u64` (network order).
pub const fn pack_ipv4(ip: [u8; 4]) -> u64 {
    ((ip[0] as u64) << 24) | ((ip[1] as u64) << 16) | ((ip[2] as u64) << 8) | (ip[3] as u64)
}

/// Unpack 4 IPv4 octets from low 32 bits of a `u64`.
pub const fn unpack_ipv4(v: u64) -> [u8; 4] {
    [
        ((v >> 24) & 0xFF) as u8,
        ((v >> 16) & 0xFF) as u8,
        ((v >> 8) & 0xFF) as u8,
        (v & 0xFF) as u8,
    ]
}

/// Pack 6 MAC bytes into bits 0..47 of a `u64`.
pub const fn pack_mac(mac: [u8; 6]) -> u64 {
    (mac[0] as u64)
        | ((mac[1] as u64) << 8)
        | ((mac[2] as u64) << 16)
        | ((mac[3] as u64) << 24)
        | ((mac[4] as u64) << 32)
        | ((mac[5] as u64) << 40)
}

/// Unpack 6 MAC bytes from bits 0..47 of a `u64`.
pub const fn unpack_mac(v: u64) -> [u8; 6] {
    [
        (v & 0xFF) as u8,
        ((v >> 8) & 0xFF) as u8,
        ((v >> 16) & 0xFF) as u8,
        ((v >> 24) & 0xFF) as u8,
        ((v >> 32) & 0xFF) as u8,
        ((v >> 40) & 0xFF) as u8,
    ]
}

/// Look up the granted `net.client` endpoint handle (0 if not granted).
pub fn client_endpoint() -> Handle {
    svc::endpoint(b"net.client")
}

/// Look up the granted `net.icmp` endpoint handle (0 if not granted).
pub fn icmp_endpoint() -> Handle {
    svc::endpoint(b"net.icmp")
}

/// Look up the granted `net.control` endpoint handle (0 if not granted).
pub fn control_endpoint() -> Handle {
    svc::endpoint(b"net.control")
}

/// Look up the granted read-only `net.status` endpoint handle (0 if not granted).
pub fn status_endpoint() -> Handle {
    svc::endpoint(b"net.status")
}

/// Fixed-size network interface status snapshot returned by `OP_STATUS` (128 bytes).
pub const NET_STATUS_BYTES: usize = 128;

#[derive(Clone, Copy, Debug)]
pub struct NetStatus {
    pub mac: [u8; 6],
    pub link_up: bool,
    pub dhcp_bound: bool,
    pub static_mode: bool,
    pub dns_fallback: bool,
    pub ip: [u8; 4],
    pub netmask: [u8; 4],
    pub gateway: [u8; 4],
    pub dns: [u8; 4],
    pub dns2: [u8; 4],
    pub dns_port: u16,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub name: [u8; 32],
    pub name_len: u8,
    pub bootfile: [u8; 48],
    pub bootfile_len: u8,
}

impl NetStatus {
    pub const fn empty() -> Self {
        Self {
            mac: [0; 6],
            link_up: false,
            dhcp_bound: false,
            static_mode: false,
            dns_fallback: true,
            ip: [0; 4],
            netmask: [0; 4],
            gateway: [0; 4],
            dns: [0; 4],
            dns2: [0; 4],
            dns_port: 53,
            rx_packets: 0,
            tx_packets: 0,
            name: [0; 32],
            name_len: 0,
            bootfile: [0; 48],
            bootfile_len: 0,
        }
    }

    pub fn name_str(&self) -> &str {
        let n = (self.name_len as usize).min(self.name.len());
        core::str::from_utf8(&self.name[..n]).unwrap_or("?")
    }

    pub fn bootfile_str(&self) -> &str {
        let n = (self.bootfile_len as usize).min(self.bootfile.len());
        core::str::from_utf8(&self.bootfile[..n]).unwrap_or("")
    }

    pub fn encode(&self, out: &mut [u8; NET_STATUS_BYTES]) {
        out.fill(0);
        out[0..6].copy_from_slice(&self.mac);
        out[6] = u8::from(self.link_up)
            | (u8::from(self.dhcp_bound) << 1)
            | (u8::from(self.static_mode) << 2)
            | (u8::from(self.dns_fallback) << 3);
        out[8..12].copy_from_slice(&self.ip);
        out[12..16].copy_from_slice(&self.netmask);
        out[16..20].copy_from_slice(&self.gateway);
        out[20..24].copy_from_slice(&self.dns);
        out[24..26].copy_from_slice(&self.dns_port.to_le_bytes());
        out[26] = (self.name_len as usize).min(32) as u8;
        out[27] = (self.bootfile_len as usize).min(48) as u8;
        out[28..32].copy_from_slice(&self.dns2);
        out[32..40].copy_from_slice(&self.rx_packets.to_le_bytes());
        out[40..48].copy_from_slice(&self.tx_packets.to_le_bytes());
        let nl = (self.name_len as usize).min(32);
        out[48..48 + nl].copy_from_slice(&self.name[..nl]);
        let bl = (self.bootfile_len as usize).min(48);
        out[80..80 + bl].copy_from_slice(&self.bootfile[..bl]);
    }

    pub fn decode(src: &[u8]) -> Option<Self> {
        if src.len() < NET_STATUS_BYTES {
            return None;
        }
        let mut s = Self::empty();
        s.mac.copy_from_slice(&src[0..6]);
        s.link_up = (src[6] & 1) != 0;
        s.dhcp_bound = (src[6] & 2) != 0;
        s.static_mode = (src[6] & 4) != 0;
        s.dns_fallback = (src[6] & 8) != 0;
        s.ip.copy_from_slice(&src[8..12]);
        s.netmask.copy_from_slice(&src[12..16]);
        s.gateway.copy_from_slice(&src[16..20]);
        s.dns.copy_from_slice(&src[20..24]);
        s.dns_port = u16::from_le_bytes([src[24], src[25]]);
        s.name_len = src[26].min(32);
        s.bootfile_len = src[27].min(48);
        s.dns2.copy_from_slice(&src[28..32]);
        s.rx_packets = u64::from_le_bytes([
            src[32], src[33], src[34], src[35], src[36], src[37], src[38], src[39],
        ]);
        s.tx_packets = u64::from_le_bytes([
            src[40], src[41], src[42], src[43], src[44], src[45], src[46], src[47],
        ]);
        s.name[..s.name_len as usize].copy_from_slice(&src[48..48 + s.name_len as usize]);
        s.bootfile[..s.bootfile_len as usize]
            .copy_from_slice(&src[80..80 + s.bootfile_len as usize]);
        Some(s)
    }
}

/// Fixed-size network interface configuration payload for `OP_SET_CONFIG` (24 bytes).
pub const NET_CONFIG_BYTES: usize = 24;

/// Interface IPv4 & DNS configuration (`net.control` required).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetConfig {
    /// True = automatic DHCPv4 lease (with optional custom DNS overrides if non-zero).
    /// False = manual static IPv4 (`ip`, `netmask`, `gateway`, `dns1`, `dns2`).
    pub dhcp: bool,
    pub ip: [u8; 4],
    pub netmask: [u8; 4],
    pub gateway: [u8; 4],
    pub dns1: [u8; 4],
    pub dns2: [u8; 4],
    pub dns_port: u16,
    pub dns_fallback: bool,
}

impl NetConfig {
    pub const fn encode(&self) -> [u8; NET_CONFIG_BYTES] {
        let mut out = [0u8; NET_CONFIG_BYTES];
        out[0] = (if self.dhcp { 1 } else { 0 }) | (if self.dns_fallback { 2 } else { 0 });
        let p = self.dns_port.to_le_bytes();
        out[2] = p[0];
        out[3] = p[1];
        out[4] = self.ip[0];
        out[5] = self.ip[1];
        out[6] = self.ip[2];
        out[7] = self.ip[3];
        out[8] = self.netmask[0];
        out[9] = self.netmask[1];
        out[10] = self.netmask[2];
        out[11] = self.netmask[3];
        out[12] = self.gateway[0];
        out[13] = self.gateway[1];
        out[14] = self.gateway[2];
        out[15] = self.gateway[3];
        out[16] = self.dns1[0];
        out[17] = self.dns1[1];
        out[18] = self.dns1[2];
        out[19] = self.dns1[3];
        out[20] = self.dns2[0];
        out[21] = self.dns2[1];
        out[22] = self.dns2[2];
        out[23] = self.dns2[3];
        out
    }

    pub fn decode(src: &[u8]) -> Option<Self> {
        if src.len() < NET_CONFIG_BYTES {
            return None;
        }
        Some(Self {
            dhcp: (src[0] & 1) != 0,
            dns_fallback: (src[0] & 2) != 0,
            dns_port: u16::from_le_bytes([src[2], src[3]]),
            ip: [src[4], src[5], src[6], src[7]],
            netmask: [src[8], src[9], src[10], src[11]],
            gateway: [src[12], src[13], src[14], src[15]],
            dns1: [src[16], src[17], src[18], src[19]],
            dns2: [src[20], src[21], src[22], src[23]],
        })
    }
}

/// Apply full IPv4 & DNS configuration (DHCP or Static) on `net.control`.
pub fn set_config(ch: Handle, cfg: &NetConfig) -> Result<(), i64> {
    if ch == 0 {
        return Err(sys::ERR_ACCESS_DENIED);
    }
    let mut req = [0u8; HEADER + NET_CONFIG_BYTES];
    Header { txid: 0, op: OP_SET_CONFIG, status: 0, a: 0, b: 0 }.put(&mut req);
    req[HEADER..HEADER + NET_CONFIG_BYTES].copy_from_slice(&cfg.encode());
    let mut rep = [0u8; HEADER];
    let n = sys::channel_call(ch, &req, &mut rep, CALL_TIMEOUT_NS)? as usize;
    let h = Header::get(&rep[..n]).ok_or(sys::ERR_INVALID_ARGS)?;
    if h.status != 0 {
        return Err(i64::from(h.status));
    }
    Ok(())
}

/// Query network interface status from `net.status`, `net.control`, `net.client`, or `net.icmp`.
pub fn status(ch: Handle) -> Result<NetStatus, i64> {
    if ch == 0 {
        return Err(sys::ERR_ACCESS_DENIED);
    }
    let mut req = [0u8; HEADER];
    Header { txid: 0, op: OP_STATUS, status: 0, a: 0, b: 0 }.put(&mut req);
    let mut rep = [0u8; HEADER + NET_STATUS_BYTES];
    let n = sys::channel_call(ch, &req, &mut rep, CALL_TIMEOUT_NS)? as usize;
    let h = Header::get(&rep[..n]).ok_or(sys::ERR_INVALID_ARGS)?;
    if h.status != 0 {
        return Err(i64::from(h.status));
    }
    NetStatus::decode(&rep[HEADER..n]).ok_or(sys::ERR_INVALID_ARGS)
}

/// Configure DNS server IP and port on `net.control`.
pub fn set_dns(ch: Handle, ip: [u8; 4], port: u16) -> Result<(), i64> {
    if ch == 0 {
        return Err(sys::ERR_ACCESS_DENIED);
    }
    let mut req = [0u8; HEADER];
    Header {
        txid: 0,
        op: OP_SET_DNS,
        status: 0,
        a: pack_ipv4(ip) | (u64::from(port) << 32),
        b: 0,
    }
    .put(&mut req);
    let mut rep = [0u8; HEADER];
    let n = sys::channel_call(ch, &req, &mut rep, CALL_TIMEOUT_NS)? as usize;
    let h = Header::get(&rep[..n]).ok_or(sys::ERR_INVALID_ARGS)?;
    if h.status != 0 {
        return Err(i64::from(h.status));
    }
    Ok(())
}

/// Resolve a hostname (or IPv4 literal) via `net.client` or `net.icmp`.
pub fn resolve(ch: Handle, host: &str) -> Result<[u8; 4], i64> {
    if ch == 0 {
        return Err(sys::ERR_ACCESS_DENIED);
    }
    let hb = host.as_bytes();
    if hb.is_empty() || hb.len() > 253 {
        return Err(sys::ERR_INVALID_ARGS);
    }
    let mut req = [0u8; HEADER + 256];
    Header { txid: 0, op: OP_DNS_RESOLVE, status: 0, a: 0, b: 0 }.put(&mut req);
    req[HEADER..HEADER + hb.len()].copy_from_slice(hb);
    let mut rep = [0u8; HEADER];
    let n = sys::channel_call(ch, &req[..HEADER + hb.len()], &mut rep, CALL_TIMEOUT_NS)? as usize;
    let h = Header::get(&rep[..n]).ok_or(sys::ERR_INVALID_ARGS)?;
    if h.status != 0 {
        return Err(i64::from(h.status));
    }
    Ok(unpack_ipv4(h.a))
}

/// Send one ICMP echo request via `net.icmp` and return `(rtt_ms, ttl)`.
pub fn ping(ch: Handle, ip: [u8; 4], seq: u16, timeout_ms: u32) -> Result<(u32, u8), i64> {
    if ch == 0 {
        return Err(sys::ERR_ACCESS_DENIED);
    }
    let mut req = [0u8; HEADER];
    Header {
        txid: 0,
        op: OP_PING,
        status: 0,
        a: pack_ipv4(ip) | (u64::from(seq) << 32),
        b: u64::from(timeout_ms),
    }
    .put(&mut req);
    let mut rep = [0u8; HEADER];
    let wait = u64::from(timeout_ms).saturating_add(2_000) * MS;
    let n = sys::channel_call(ch, &req, &mut rep, wait)? as usize;
    let h = Header::get(&rep[..n]).ok_or(sys::ERR_INVALID_ARGS)?;
    if h.status != 0 {
        return Err(i64::from(h.status));
    }
    Ok((h.a as u32, ((h.a >> 32) & 0xFF) as u8))
}

// ---- Zero-copy IoRing TCP stream ----------------------------------------------------------------

const SOCK_RING_SLOTS: u32 = 8;
const SOCK_SLOT_BYTES: u32 = 4096;

pub struct TcpStream {
    ch: Handle,
    pub sock_id: u32,
    ring: IoRing,
    next_id: u32,
    /// Active in-flight `RING_RECV` SQE id (0 if none). Reused across timed-out `read()` calls.
    recv_id: u32,
    /// Completed RX result received while waiting for a `RING_SEND` CQE (full-duplex safety).
    stashed_rx: Option<Result<usize, i64>>,
}

impl TcpStream {
    /// Open a TCP connection to `(ip, port)` via `net.client`.
    pub fn connect(ch: Handle, ip: [u8; 4], port: u16, timeout_ms: u32) -> Result<Self, i64> {
        if ch == 0 {
            return Err(sys::ERR_ACCESS_DENIED);
        }
        let ring = IoRing::create(SOCK_RING_SLOTS, SOCK_RING_SLOTS * SOCK_SLOT_BYTES)?;
        let dup = sys::handle_duplicate(
            ring.vmo(),
            sys::RIGHT_READ | sys::RIGHT_WRITE | sys::RIGHT_MAP | sys::RIGHT_INSPECT | sys::RIGHT_TRANSFER,
        )?;
        let mut req = [0u8; HEADER];
        Header {
            txid: 0,
            op: OP_TCP_CONNECT,
            status: 0,
            a: pack_ipv4(ip) | (u64::from(port) << 32),
            b: u64::from(timeout_ms),
        }
        .put(&mut req);
        let mut rep = [0u8; HEADER];
        let mut rh = [0 as Handle; 1];
        let wait = u64::from(timeout_ms).saturating_add(2_000) * MS;
        let (n, nh) = sys::channel_call_h(
            ch,
            &req,
            &[MsgHandle { handle: dup, rights: sys::RIGHTS_SAME }],
            &mut rep,
            &mut rh,
            wait,
        )?;
        if nh > 0 && rh[0] != 0 {
            sys::handle_close(rh[0]);
        }
        let h = Header::get(&rep[..n]).ok_or(sys::ERR_INVALID_ARGS)?;
        if h.status != 0 {
            return Err(i64::from(h.status));
        }
        Ok(Self { ch, sock_id: h.a as u32, ring, next_id: 1, recv_id: 0, stashed_rx: None })
    }

    fn drain_events(&self) {
        let mut tmp = [0u8; HEADER];
        while sys::channel_read(self.ch, &mut tmp, 0).is_ok() {}
    }

    fn kick(&self) {
        let mut m = [0u8; HEADER];
        Header { txid: 0, op: OP_SOCK_KICK, status: 0, a: u64::from(self.sock_id), b: 0 }.put(&mut m);
        let _ = sys::channel_write(self.ch, &m);
    }

    /// Write bytes to the TCP stream via the shared-memory `IoRing`.
    pub fn write(&mut self, data: &[u8]) -> Result<usize, i64> {
        if data.is_empty() {
            return Ok(0);
        }
        let n = data.len().min(SOCK_SLOT_BYTES as usize);
        if let Some(dst) = self.ring.data_mut(0, n as u32) {
            dst.copy_from_slice(&data[..n]);
        } else {
            return Err(sys::ERR_INVALID_ARGS);
        }
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        let sqe = Sqe { id, op: RING_SEND, a: u64::from(self.sock_id), b: 0, buf_off: 0, buf_len: n as u32 };
        if !self.ring.push_sq(sqe) {
            return Err(sys::ERR_SHOULD_WAIT);
        }
        self.kick();

        let dl = sys::clock_ns().saturating_add(5_000 * MS);
        loop {
            self.drain_events();
            while let Some(cqe) = self.ring.pop_cq() {
                if self.recv_id != 0 && cqe.id == self.recv_id {
                    self.recv_id = 0;
                    self.stashed_rx = Some(if cqe.status != 0 {
                        Err(i64::from(cqe.status))
                    } else {
                        Ok((cqe.a as usize).min(SOCK_SLOT_BYTES as usize))
                    });
                    continue;
                }
                if cqe.id == id {
                    if cqe.status != 0 {
                        return Err(i64::from(cqe.status));
                    }
                    return Ok(cqe.a as usize);
                }
            }
            let now = sys::clock_ns();
            if now >= dl {
                return Err(sys::ERR_TIMED_OUT);
            }
            let _ = sys::object_wait(self.ch, sys::READABLE | sys::PEER_CLOSED, (dl - now).min(20 * MS));
        }
    }

    pub fn write_all(&mut self, mut data: &[u8]) -> Result<(), i64> {
        while !data.is_empty() {
            let n = self.write(data)?;
            if n == 0 {
                return Err(sys::ERR_PEER_CLOSED);
            }
            data = &data[n..];
        }
        Ok(())
    }

    /// Read received TCP bytes into `dst` (up to `timeout_ms`). Returns `Ok(0)` on clean EOF.
    pub fn read(&mut self, dst: &mut [u8], timeout_ms: u32) -> Result<usize, i64> {
        if dst.is_empty() {
            return Ok(0);
        }
        let off = SOCK_SLOT_BYTES; // slot 1 for RX
        if let Some(res) = self.stashed_rx.take() {
            let got = res?.min(dst.len()).min(SOCK_SLOT_BYTES as usize);
            if got > 0
                && let Some(src) = self.ring.data(off, got as u32)
            {
                dst[..got].copy_from_slice(src);
            }
            return Ok(got);
        }
        if self.recv_id == 0 {
            let want = dst.len().min(SOCK_SLOT_BYTES as usize) as u32;
            let id = self.next_id.max(1);
            self.next_id = id.wrapping_add(1).max(1);
            let sqe = Sqe { id, op: RING_RECV, a: u64::from(self.sock_id), b: 0, buf_off: off, buf_len: want };
            if !self.ring.push_sq(sqe) {
                return Err(sys::ERR_SHOULD_WAIT);
            }
            self.recv_id = id;
            self.kick();
        }

        let dl = sys::clock_ns().saturating_add(u64::from(timeout_ms) * MS);
        loop {
            self.drain_events();
            while let Some(cqe) = self.ring.pop_cq() {
                if cqe.id == self.recv_id {
                    self.recv_id = 0;
                    if cqe.status != 0 {
                        return Err(i64::from(cqe.status));
                    }
                    let got = (cqe.a as usize).min(dst.len()).min(SOCK_SLOT_BYTES as usize);
                    if got > 0
                        && let Some(src) = self.ring.data(off, got as u32)
                    {
                        dst[..got].copy_from_slice(src);
                    }
                    return Ok(got);
                }
            }
            let now = sys::clock_ns();
            if now >= dl {
                return Err(sys::ERR_TIMED_OUT);
            }
            if sys::object_wait(self.ch, sys::PEER_CLOSED, 0).is_ok() {
                return Err(sys::ERR_PEER_CLOSED);
            }
            let _ = sys::object_wait(self.ch, sys::READABLE | sys::PEER_CLOSED, (dl - now).min(20 * MS));
        }
    }

    pub fn close(mut self) {
        self.close_inner();
    }

    fn close_inner(&mut self) {
        if self.sock_id == 0 {
            return;
        }
        let mut req = [0u8; HEADER];
        Header { txid: 0, op: OP_SOCK_CLOSE, status: 0, a: u64::from(self.sock_id), b: 0 }.put(&mut req);
        let mut rep = [0u8; HEADER];
        let _ = sys::channel_call(self.ch, &req, &mut rep, 1_000 * MS);
        self.sock_id = 0;
    }
}

impl Drop for TcpStream {
    fn drop(&mut self) {
        self.close_inner();
    }
}

// ---- Zero-copy IoRing UDP socket ----------------------------------------------------------------

pub struct UdpSocket {
    ch: Handle,
    pub sock_id: u32,
    ring: IoRing,
    next_id: u32,
}

impl UdpSocket {
    pub fn open(ch: Handle, bind_port: u16) -> Result<Self, i64> {
        if ch == 0 {
            return Err(sys::ERR_ACCESS_DENIED);
        }
        let ring = IoRing::create(SOCK_RING_SLOTS, SOCK_RING_SLOTS * SOCK_SLOT_BYTES)?;
        let dup = sys::handle_duplicate(
            ring.vmo(),
            sys::RIGHT_READ | sys::RIGHT_WRITE | sys::RIGHT_MAP | sys::RIGHT_INSPECT | sys::RIGHT_TRANSFER,
        )?;
        let mut req = [0u8; HEADER];
        Header { txid: 0, op: OP_UDP_OPEN, status: 0, a: u64::from(bind_port), b: 0 }.put(&mut req);
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
        Ok(Self { ch, sock_id: h.a as u32, ring, next_id: 1 })
    }

    pub fn send_to(&mut self, ip: [u8; 4], port: u16, data: &[u8]) -> Result<usize, i64> {
        let n = data.len().min(1472);
        if let Some(dst) = self.ring.data_mut(0, n as u32) {
            dst.copy_from_slice(&data[..n]);
        }
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        let sqe = Sqe {
            id,
            op: RING_SEND,
            a: u64::from(self.sock_id),
            b: pack_ipv4(ip) | (u64::from(port) << 32),
            buf_off: 0,
            buf_len: n as u32,
        };
        if !self.ring.push_sq(sqe) {
            return Err(sys::ERR_SHOULD_WAIT);
        }
        let mut m = [0u8; HEADER];
        Header { txid: 0, op: OP_SOCK_KICK, status: 0, a: u64::from(self.sock_id), b: 0 }.put(&mut m);
        let _ = sys::channel_write(self.ch, &m);
        let dl = sys::clock_ns().saturating_add(2_000 * MS);
        loop {
            let mut tmp = [0u8; HEADER];
            while sys::channel_read(self.ch, &mut tmp, 0).is_ok() {}
            if let Some(cqe) = self.ring.pop_cq() {
                if cqe.status != 0 {
                    return Err(i64::from(cqe.status));
                }
                return Ok(cqe.a as usize);
            }
            if sys::clock_ns() >= dl {
                return Err(sys::ERR_TIMED_OUT);
            }
            let _ = sys::object_wait(self.ch, sys::READABLE | sys::PEER_CLOSED, 20 * MS);
        }
    }

    pub fn recv_from(&mut self, dst: &mut [u8], timeout_ms: u32) -> Result<(usize, [u8; 4], u16), i64> {
        let want = dst.len().min(SOCK_SLOT_BYTES as usize) as u32;
        let off = SOCK_SLOT_BYTES;
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        let sqe = Sqe { id, op: RING_RECV, a: u64::from(self.sock_id), b: 0, buf_off: off, buf_len: want };
        if !self.ring.push_sq(sqe) {
            return Err(sys::ERR_SHOULD_WAIT);
        }
        let mut m = [0u8; HEADER];
        Header { txid: 0, op: OP_SOCK_KICK, status: 0, a: u64::from(self.sock_id), b: 0 }.put(&mut m);
        let _ = sys::channel_write(self.ch, &m);
        let dl = sys::clock_ns().saturating_add(u64::from(timeout_ms) * MS);
        loop {
            let mut tmp = [0u8; HEADER];
            while sys::channel_read(self.ch, &mut tmp, 0).is_ok() {}
            if let Some(cqe) = self.ring.pop_cq() {
                if cqe.status != 0 {
                    return Err(i64::from(cqe.status));
                }
                let got = ((cqe.a & 0xFFFF) as usize).min(dst.len());
                let ip = unpack_ipv4(cqe.a >> 16);
                let port = ((cqe.a >> 48) & 0xFFFF) as u16;
                if got > 0
                    && let Some(src) = self.ring.data(off, got as u32)
                {
                    dst[..got].copy_from_slice(src);
                }
                return Ok((got, ip, port));
            }
            let now = sys::clock_ns();
            if now >= dl {
                return Err(sys::ERR_TIMED_OUT);
            }
            let _ = sys::object_wait(self.ch, sys::READABLE | sys::PEER_CLOSED, (dl - now).min(20 * MS));
        }
    }
}

impl Drop for UdpSocket {
    fn drop(&mut self) {
        if self.sock_id != 0 {
            let mut req = [0u8; HEADER];
            Header { txid: 0, op: OP_SOCK_CLOSE, status: 0, a: u64::from(self.sock_id), b: 0 }.put(&mut req);
            let mut rep = [0u8; HEADER];
            let _ = sys::channel_call(self.ch, &req, &mut rep, 1_000 * MS);
            self.sock_id = 0;
        }
    }
}

// ---- Cryptographic randomness (backed by kernel ChaCha20 CSPRNG, ABI v14) -----------------------

/// Fill `out` with cryptographically strong random bytes from the kernel CSPRNG (`SYS_GET_RANDOM`).
/// Fails closed with an error if the kernel refuses (e.g. `RANDOM_STRICT` without hardware entropy).
pub fn random_bytes(out: &mut [u8]) -> Result<(), i64> {
    sys::get_random(out, 0)
}

/// Like [`random_bytes`], requiring true hardware entropy (`RDSEED`, `RDRAND`, or TPM) in the kernel pool.
pub fn random_bytes_strict(out: &mut [u8]) -> Result<(), i64> {
    sys::get_random(out, sys::RANDOM_STRICT)
}
