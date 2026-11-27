//! D-OS in-tree network service (`net.dsvc`).
//!
//! - Connects to `devmgr.net` to attach IOMMU-confined NIC drivers (`virtio-net.ddrv`,
//!   `e1000e.ddrv`, `r8169.ddrv`) via zero-copy shared-memory `IoRing`s (TX + RX).
//! - Runs the `dosnet::stack::NetStack` state machine (Ethernet II, ARP, IPv4, ICMPv4, UDP,
//!   DHCPv4, DNS, TCP), automatically obtaining an IPv4 lease via DHCP when a NIC attaches.
//! - Provides three capability-separated endpoints:
//!   - `net.client`:  DNS resolution, TCP streams, UDP sockets, interface status.
//!   - `net.icmp`:    ICMP echo (`ping`), DNS resolution, interface status.
//!   - `net.control`: interface status and DNS server configuration.
//!
//!   Processes without `grants.net` receive no endpoints and cannot reach the network.

#![no_std]

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use dosid::NetworkSettings;
use dosnet::stack::{DhcpState, NetStack};
use dosnet::tcp::TcpState;
use dosnet::{fmt_ipv4, fmt_mac};
use libd::fs as fp;
use libd::net::{self, NET_STATUS_BYTES, NetStatus};
use libd::proto::{self, HEADER, Header};
use libd::ring::{Cqe, IoRing, Sqe};
use libd::sys::{self, Handle, MsgHandle};
use libd::{Port, Startup, println, svc};

libd::entry!(dsvc_net, main);

const MS: u64 = 1_000_000;
const KEY_CTL: u64 = 1;
const KEY_DEVMGR: u64 = 2;
const KEY_NIC: u64 = 3;
const KEY_CLIENT_BASE: u64 = 100;

const NIC_SLOTS: u32 = 32;
const NIC_SLOT_BYTES: u32 = 2048;
const HOME_CFG_DIR: &[u8] = b".dos";
const HOME_NET_FILE: &[u8] = b".dos/network.toml";
const HOME_NET_TMP: &[u8] = b".dos/network.tmp";

fn load_net_settings() -> Option<NetworkSettings> {
    let ns = fp::Namespace::get();
    let (dir, _) = ns.resolve(b"/home")?;
    let d = fp::Node::from(dir);
    let parsed = (|| {
        let (f, _, size) = d.open(HOME_NET_FILE, 0, fp::R_READ).ok()?;
        let size = usize::try_from(size).ok()?;
        if size == 0 || size > 16 * 1024 {
            return None;
        }
        let mut buf = alloc::vec![0u8; size];
        let n = f.read(0, &mut buf).ok()?;
        NetworkSettings::from_toml(&buf[..n]).ok()
    })();
    let _ = d.into_handle();
    parsed
}

fn save_net_settings(cfg: &NetworkSettings) {
    let ns = fp::Namespace::get();
    let Some((dir, _)) = ns.resolve(b"/home") else {
        return;
    };
    let d = fp::Node::from(dir);
    if d.stat().is_ok_and(|st| st.rights & fp::R_WRITE != 0) {
        let text = cfg.to_toml();
        let _ = d.open(HOME_CFG_DIR, fp::O_DIRECTORY | fp::O_CREATE, fp::R_READ | fp::R_WRITE);
        if let Ok((f, _, _)) = d.open(HOME_NET_TMP, fp::O_CREATE | fp::O_TRUNCATE, fp::R_READ | fp::R_WRITE)
            && f.write(0, text.as_bytes()).is_ok()
        {
            drop(f);
            if d.rename(HOME_NET_TMP, HOME_NET_FILE, true).is_err()
                && let Ok((f2, _, _)) = d.open(HOME_NET_FILE, fp::O_CREATE | fp::O_TRUNCATE, fp::R_READ | fp::R_WRITE)
            {
                let _ = f2.write(0, text.as_bytes());
            }
            let _ = d.sync();
        }
    }
    let _ = d.into_handle();
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Role {
    Client,
    Icmp,
    Control,
    /// Read-only interface status (`OP_STATUS` only): the desktop's network indicator.
    Status,
}

struct NicPipe {
    drv_key: u8,
    name: String,
    ch: Handle,
    tx_ring: IoRing,
    rx_ring: IoRing,
    tx_next_slot: u32,
    tx_in_flight: u32,
    tx_next_id: u32,
    link_up: bool,
    dhcp_offer_logged: bool,
    dhcp_logged: bool,
    stack: NetStack,
}

impl NicPipe {
    fn open(drv_key: u8, name: String, ch: Handle, mac: [u8; 6], link_up: bool, now_ms: u64) -> Result<Self, i64> {
        let tx_ring = IoRing::create(NIC_SLOTS, NIC_SLOTS * NIC_SLOT_BYTES)?;
        let rx_ring = IoRing::create(NIC_SLOTS, NIC_SLOTS * NIC_SLOT_BYTES)?;
        let rights = sys::RIGHT_READ | sys::RIGHT_WRITE | sys::RIGHT_MAP | sys::RIGHT_INSPECT | sys::RIGHT_TRANSFER;
        let tx_dup = sys::handle_duplicate(tx_ring.vmo(), rights)?;
        let rx_dup = match sys::handle_duplicate(rx_ring.vmo(), rights) {
            Ok(h) => h,
            Err(e) => {
                sys::handle_close(tx_dup);
                return Err(e);
            }
        };
        let mut req = [0u8; HEADER];
        Header { txid: 0, op: net::DRV_SETUP_RINGS, status: 0, a: 0, b: 0 }.put(&mut req);
        let mut rep = [0u8; HEADER];
        let mut rh = [0 as Handle; 1];
        let (n, nh) = sys::channel_call_h(
            ch,
            &req,
            &[
                MsgHandle { handle: tx_dup, rights: sys::RIGHTS_SAME },
                MsgHandle { handle: rx_dup, rights: sys::RIGHTS_SAME },
            ],
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

        // Pre-post all RX buffer slots into `rx_ring`.
        for slot in 0..NIC_SLOTS {
            let _ = rx_ring.push_sq(Sqe {
                id: slot,
                op: net::DRV_RING_FRAME,
                a: 0,
                b: 0,
                buf_off: slot * NIC_SLOT_BYTES,
                buf_len: NIC_SLOT_BYTES,
            });
        }

        let mut seed_bytes = [0u8; 8];
        let _ = net::random_bytes(&mut seed_bytes);
        let seed = u64::from_le_bytes(seed_bytes);
        let mut stack = NetStack::new(mac, seed);
        stack.start_dhcp(now_ms);

        Ok(Self {
            drv_key,
            name,
            ch,
            tx_ring,
            rx_ring,
            tx_next_slot: 0,
            tx_in_flight: 0,
            tx_next_id: 1,
            link_up,
            dhcp_offer_logged: false,
            dhcp_logged: false,
            stack,
        })
    }

    fn drain_tx_cq(&mut self) {
        while self.tx_ring.pop_cq().is_some() {
            self.tx_in_flight = self.tx_in_flight.saturating_sub(1);
        }
    }

    fn flush_tx(&mut self) {
        self.drain_tx_cq();
        let mut kicked = false;
        while self.tx_in_flight < NIC_SLOTS {
            let Some(frame) = self.stack.poll_tx() else {
                break;
            };
            if frame.len() > NIC_SLOT_BYTES as usize {
                continue;
            }
            let slot = self.tx_next_slot % NIC_SLOTS;
            let off = slot * NIC_SLOT_BYTES;
            if let Some(dst) = self.tx_ring.data_mut(off, frame.len() as u32) {
                dst.copy_from_slice(&frame);
                let sqe = Sqe {
                    id: self.tx_next_id,
                    op: net::DRV_RING_FRAME,
                    a: 0,
                    b: 0,
                    buf_off: off,
                    buf_len: frame.len() as u32,
                };
                if self.tx_ring.push_sq(sqe) {
                    self.tx_next_id = self.tx_next_id.wrapping_add(1);
                    self.tx_next_slot = self.tx_next_slot.wrapping_add(1);
                    self.tx_in_flight += 1;
                    kicked = true;
                }
            }
        }
        if kicked {
            proto::send(self.ch, net::DRV_TX_KICK, 0, 0);
        }
    }

    fn drain_rx(&mut self, now_ms: u64) {
        while let Some(cqe) = self.rx_ring.pop_cq() {
            let slot = cqe.id % NIC_SLOTS;
            let off = slot * NIC_SLOT_BYTES;
            if cqe.status == 0 {
                let len = (cqe.a as usize).min(NIC_SLOT_BYTES as usize);
                if len >= 14
                    && let Some(raw) = self.rx_ring.data(off, len as u32)
                {
                    let frame = raw.to_vec();
                    self.stack.on_rx_frame(&frame, now_ms);
                }
            }
            // Repost RX slot.
            let _ = self.rx_ring.push_sq(Sqe {
                id: slot,
                op: net::DRV_RING_FRAME,
                a: 0,
                b: 0,
                buf_off: off,
                buf_len: NIC_SLOT_BYTES,
            });
        }
    }
}

struct ClientConn {
    id: u64,
    role: Role,
    ch: Handle,
}

struct PendingPingCall {
    client_id: u64,
    ch: Handle,
    txid: u32,
    ping_id: u16,
    seq: u16,
    dst: dosnet::Ipv4Addr,
    deadline_ms: u64,
}

struct PendingDnsCall {
    client_id: u64,
    ch: Handle,
    txid: u32,
    query_id: u16,
    deadline_ms: u64,
}

struct PendingConnect {
    client_id: u64,
    ch: Handle,
    txid: u32,
    sock_id: u32,
    ring: IoRing,
    deadline_ms: u64,
}

struct ClientSock {
    client_id: u64,
    sock_id: u32,
    is_udp: bool,
    ring: IoRing,
    pending_recv: Option<Sqe>,
}

struct NetSvc {
    port: Port,
    ctl: Handle,
    devmgr: Handle,
    stop: bool,
    nic: Option<NicPipe>,
    clients: Vec<ClientConn>,
    next_client_id: u64,
    next_ping_id: u16,
    pending_pings: Vec<PendingPingCall>,
    pending_dns: Vec<PendingDnsCall>,
    pending_connects: Vec<PendingConnect>,
    sockets: Vec<ClientSock>,
    saved_cfg: Option<NetworkSettings>,
}

fn now_ms() -> u64 {
    sys::clock_ns() / MS
}

impl NetSvc {
    fn reply(ch: Handle, txid: u32, op: u32, status: i32, a: u64, b: u64) {
        let mut rep = [0u8; HEADER];
        Header { txid, op, status, a, b }.put(&mut rep);
        let _ = sys::channel_write(ch, &rep);
    }

    fn client_ch(&self, client_id: u64) -> Handle {
        self.clients.iter().find(|c| c.id == client_id).map_or(0, |c| c.ch)
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
                            b"devmgr.net" => {
                                if self.devmgr != 0 {
                                    sys::handle_close(self.devmgr);
                                }
                                self.devmgr = hnd;
                                self.port.arm(hnd, sys::READABLE | sys::PEER_CLOSED, KEY_DEVMGR);
                            }
                            b"client" | b"icmp" | b"control" | b"status" => {
                                let role = match ep {
                                    b"client" => Role::Client,
                                    b"icmp" => Role::Icmp,
                                    b"status" => Role::Status,
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
                        net::BACKEND_ADD if hnd != 0 => {
                            let mac = net::unpack_mac(h.a);
                            let link_up = ((h.a >> 48) & 1) != 0;
                            let drv_key = ((h.a >> 56) & 0xFF) as u8;
                            let name = String::from_utf8_lossy(&buf[HEADER..n]).into_owned();
                            if let Some(old) = self.nic.take() {
                                sys::handle_close(old.ch);
                            }
                            match NicPipe::open(drv_key, name.clone(), hnd, mac, link_up, now_ms()) {
                                Ok(mut nic) => {
                                    self.port.arm(nic.ch, sys::READABLE | sys::PEER_CLOSED, KEY_NIC);
                                    println!("net: interface '{}' attached (MAC {})", name, fmt_mac(mac));
                                    if let Some(cfg) = self.saved_cfg {
                                        if cfg.dhcp {
                                            nic.stack.enable_dhcp(cfg.dns1, cfg.dns2, cfg.dns_port, cfg.dns_fallback, now_ms());
                                        } else {
                                            nic.stack.set_static_full(
                                                cfg.ip,
                                                cfg.netmask,
                                                cfg.gateway,
                                                cfg.dns1,
                                                cfg.dns2,
                                                cfg.dns_port,
                                                cfg.dns_fallback,
                                            );
                                        }
                                        println!("net: restored saved network configuration on '{}'", name);
                                    }
                                    nic.flush_tx();
                                    self.nic = Some(nic);
                                }
                                Err(e) => {
                                    println!("net: failed to attach '{}': {}", name, sys::status(e));
                                    sys::handle_close(hnd);
                                }
                            }
                        }
                        net::BACKEND_LINK => {
                            if hnd != 0 {
                                sys::handle_close(hnd);
                            }
                            let drv_key = (h.a & 0xFF) as u8;
                            let up = h.b != 0;
                            if let Some(nic) = self.nic.as_mut()
                                && nic.drv_key == drv_key
                            {
                                let was_up = nic.link_up;
                                nic.link_up = up;
                                if up && !was_up {
                                    println!("net: '{}' link up", nic.name);
                                    if !nic.stack.static_mode && nic.stack.dhcp_state != DhcpState::Bound {
                                        nic.stack.start_dhcp(now_ms());
                                        nic.flush_tx();
                                    }
                                } else if !up && was_up {
                                    println!("net: '{}' link down", nic.name);
                                }
                            }
                        }
                        net::BACKEND_GONE => {
                            if hnd != 0 {
                                sys::handle_close(hnd);
                            }
                            let drv_key = (h.a & 0xFF) as u8;
                            if self.nic.as_ref().is_some_and(|n| n.drv_key == drv_key)
                                && let Some(old) = self.nic.take()
                            {
                                sys::handle_close(old.ch);
                                println!("net: interface '{}' detached", old.name);
                            }
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

    fn handle_nic(&mut self) {
        let mut buf = [0u8; HEADER];
        loop {
            let Some(nic) = self.nic.as_mut() else { return };
            let ch = nic.ch;
            match sys::channel_read(ch, &mut buf, 0) {
                Ok(_) => {}
                Err(sys::ERR_SHOULD_WAIT) => {
                    self.port.arm(ch, sys::READABLE | sys::PEER_CLOSED, KEY_NIC);
                    return;
                }
                Err(_) => {
                    if let Some(old) = self.nic.take() {
                        println!("net: driver '{}' disconnected (restart pending)", old.name);
                        sys::handle_close(old.ch);
                    }
                    return;
                }
            }
        }
    }

    fn handle_client(&mut self, client_id: u64) {
        let mut buf = [0u8; HEADER + 260];
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
                    self.dispatch_client(client_id, ch, role, h, &buf[HEADER..n], hnd);
                }
                Err(sys::ERR_SHOULD_WAIT) => {
                    self.port.arm(ch, sys::READABLE | sys::PEER_CLOSED, KEY_CLIENT_BASE + client_id);
                    return;
                }
                Err(_) => {
                    self.clients.remove(pos);
                    sys::handle_close(ch);
                    self.pending_pings.retain(|p| p.client_id != client_id);
                    self.pending_dns.retain(|d| d.client_id != client_id);
                    self.pending_connects.retain(|c| c.client_id != client_id);
                    let now = now_ms();
                    if let Some(nic) = self.nic.as_mut() {
                        for s in self.sockets.iter().filter(|s| s.client_id == client_id) {
                            if s.is_udp {
                                nic.stack.udp_close(s.sock_id);
                            } else {
                                nic.stack.tcp_close(s.sock_id, now);
                            }
                        }
                    }
                    self.sockets.retain(|s| s.client_id != client_id);
                    return;
                }
            }
        }
    }

    fn dispatch_client(&mut self, client_id: u64, ch: Handle, role: Role, h: Header, payload: &[u8], hnd: Handle) {
        let close_hnd = || {
            if hnd != 0 {
                sys::handle_close(hnd);
            }
        };
        let now = now_ms();
        match h.op {
            net::OP_STATUS => {
                close_hnd();
                let mut st = NetStatus::empty();
                if let Some(nic) = self.nic.as_ref() {
                    st.mac = nic.stack.mac;
                    st.link_up = nic.link_up;
                    st.dhcp_bound = nic.stack.dhcp_state == DhcpState::Bound;
                    st.static_mode = nic.stack.static_mode;
                    st.dns_fallback = nic.stack.dns_fallback;
                    st.ip = nic.stack.ip;
                    st.netmask = nic.stack.netmask;
                    st.gateway = nic.stack.gateway;
                    st.dns = nic.stack.dns_server;
                    st.dns2 = nic.stack.dns_server2;
                    st.dns_port = nic.stack.dns_port;
                    st.rx_packets = nic.stack.rx_packets;
                    st.tx_packets = nic.stack.tx_packets;
                    let nb = nic.name.as_bytes();
                    let nl = nb.len().min(32);
                    st.name[..nl].copy_from_slice(&nb[..nl]);
                    st.name_len = nl as u8;
                    let bb = nic.stack.bootfile.as_bytes();
                    let bl = bb.len().min(48);
                    st.bootfile[..bl].copy_from_slice(&bb[..bl]);
                    st.bootfile_len = bl as u8;
                }
                let mut rep = [0u8; HEADER + NET_STATUS_BYTES];
                Header { txid: h.txid, op: h.op, status: 0, a: 0, b: 0 }.put(&mut rep);
                let mut enc = [0u8; NET_STATUS_BYTES];
                st.encode(&mut enc);
                rep[HEADER..HEADER + NET_STATUS_BYTES].copy_from_slice(&enc);
                let _ = sys::channel_write(ch, &rep);
            }
            net::OP_SET_DNS => {
                close_hnd();
                if role != Role::Control {
                    Self::reply(ch, h.txid, h.op, sys::ERR_ACCESS_DENIED as i32, 0, 0);
                    return;
                }
                let ip = net::unpack_ipv4(h.a);
                let port = ((h.a >> 32) & 0xFFFF) as u16;
                if let Some(nic) = self.nic.as_mut() {
                    let eff_port = if port == 0 { 53 } else { port };
                    nic.stack.set_dns(ip, eff_port);
                    let mut cfg = self.saved_cfg.unwrap_or_default();
                    cfg.dns1 = ip;
                    cfg.dns_port = eff_port;
                    self.saved_cfg = Some(cfg);
                    save_net_settings(&cfg);
                    Self::reply(ch, h.txid, h.op, 0, 0, 0);
                } else {
                    Self::reply(ch, h.txid, h.op, sys::ERR_BAD_STATE as i32, 0, 0);
                }
            }
            net::OP_SET_CONFIG => {
                close_hnd();
                if role != Role::Control {
                    Self::reply(ch, h.txid, h.op, sys::ERR_ACCESS_DENIED as i32, 0, 0);
                    return;
                }
                let Some(cfg) = net::NetConfig::decode(payload) else {
                    Self::reply(ch, h.txid, h.op, sys::ERR_INVALID_ARGS as i32, 0, 0);
                    return;
                };
                let Some(nic) = self.nic.as_mut() else {
                    Self::reply(ch, h.txid, h.op, sys::ERR_BAD_STATE as i32, 0, 0);
                    return;
                };
                if cfg.dhcp {
                    nic.dhcp_offer_logged = false;
                    nic.dhcp_logged = false;
                    nic.stack.enable_dhcp(cfg.dns1, cfg.dns2, cfg.dns_port, cfg.dns_fallback, now);
                    nic.flush_tx();
                    println!(
                        "net: configured DHCP on '{}' (dns_override={} / {}, fallback={})",
                        nic.name,
                        fmt_ipv4(cfg.dns1),
                        fmt_ipv4(cfg.dns2),
                        cfg.dns_fallback
                    );
                } else {
                    if cfg.ip == [0, 0, 0, 0] {
                        Self::reply(ch, h.txid, h.op, sys::ERR_INVALID_ARGS as i32, 0, 0);
                        return;
                    }
                    nic.stack.set_static_full(
                        cfg.ip,
                        cfg.netmask,
                        cfg.gateway,
                        cfg.dns1,
                        cfg.dns2,
                        cfg.dns_port,
                        cfg.dns_fallback,
                    );
                    nic.flush_tx();
                    println!(
                        "net: configured static IPv4 {} mask {} gw {} dns {} / {} (fallback={})",
                        fmt_ipv4(nic.stack.ip),
                        fmt_ipv4(nic.stack.netmask),
                        fmt_ipv4(nic.stack.gateway),
                        fmt_ipv4(nic.stack.dns_server),
                        fmt_ipv4(nic.stack.dns_server2),
                        nic.stack.dns_fallback
                    );
                }
                let persisted = NetworkSettings {
                    dhcp: cfg.dhcp,
                    ip: cfg.ip,
                    netmask: cfg.netmask,
                    gateway: cfg.gateway,
                    dns1: cfg.dns1,
                    dns2: cfg.dns2,
                    dns_port: cfg.dns_port,
                    dns_fallback: cfg.dns_fallback,
                };
                self.saved_cfg = Some(persisted);
                save_net_settings(&persisted);
                Self::reply(ch, h.txid, h.op, 0, 0, 0);
            }
            net::OP_DNS_RESOLVE => {
                close_hnd();
                if role != Role::Client && role != Role::Icmp {
                    Self::reply(ch, h.txid, h.op, sys::ERR_ACCESS_DENIED as i32, 0, 0);
                    return;
                }
                let Ok(host) = core::str::from_utf8(payload) else {
                    Self::reply(ch, h.txid, h.op, sys::ERR_INVALID_ARGS as i32, 0, 0);
                    return;
                };
                if let Some(ip) = dosnet::parse_ipv4(host) {
                    Self::reply(ch, h.txid, h.op, 0, net::pack_ipv4(ip), 0);
                    return;
                }
                let Some(nic) = self.nic.as_mut() else {
                    Self::reply(ch, h.txid, h.op, sys::ERR_BAD_STATE as i32, 0, 0);
                    return;
                };
                let Some(qid) = nic.stack.start_dns_resolve(host, now) else {
                    Self::reply(ch, h.txid, h.op, sys::ERR_BAD_STATE as i32, 0, 0);
                    return;
                };
                self.pending_dns.push(PendingDnsCall {
                    client_id,
                    ch,
                    txid: h.txid,
                    query_id: qid,
                    deadline_ms: now.saturating_add(6_500),
                });
            }
            net::OP_PING => {
                close_hnd();
                if role != Role::Icmp {
                    println!("net: refused ICMP ping on non-icmp endpoint");
                    Self::reply(ch, h.txid, h.op, sys::ERR_ACCESS_DENIED as i32, 0, 0);
                    return;
                }
                let Some(nic) = self.nic.as_mut() else {
                    Self::reply(ch, h.txid, h.op, sys::ERR_BAD_STATE as i32, 0, 0);
                    return;
                };
                let ip = net::unpack_ipv4(h.a);
                let seq = ((h.a >> 32) & 0xFFFF) as u16;
                let timeout = (h.b as u32).clamp(200, 10_000);
                let pid = self.next_ping_id;
                self.next_ping_id = self.next_ping_id.wrapping_add(1).max(1);
                if !nic.stack.send_ping(ip, pid, seq, now) {
                    Self::reply(ch, h.txid, h.op, sys::ERR_BAD_STATE as i32, 0, 0);
                    return;
                }
                self.pending_pings.push(PendingPingCall {
                    client_id,
                    ch,
                    txid: h.txid,
                    ping_id: pid,
                    seq,
                    dst: ip,
                    deadline_ms: now.saturating_add(u64::from(timeout)),
                });
            }
            net::OP_TCP_CONNECT => {
                if role != Role::Client {
                    close_hnd();
                    println!("net: refused TCP connect on non-client endpoint");
                    Self::reply(ch, h.txid, h.op, sys::ERR_ACCESS_DENIED as i32, 0, 0);
                    return;
                }
                if hnd == 0 {
                    Self::reply(ch, h.txid, h.op, sys::ERR_INVALID_ARGS as i32, 0, 0);
                    return;
                }
                let ring = match IoRing::attach(hnd) {
                    Ok(r) => r,
                    Err(e) => {
                        Self::reply(ch, h.txid, h.op, e as i32, 0, 0);
                        return;
                    }
                };
                let Some(nic) = self.nic.as_mut() else {
                    Self::reply(ch, h.txid, h.op, sys::ERR_BAD_STATE as i32, 0, 0);
                    return;
                };
                let ip = net::unpack_ipv4(h.a);
                let port = ((h.a >> 32) & 0xFFFF) as u16;
                let timeout = (h.b as u32).clamp(500, 15_000);
                let Some(sock_id) = nic.stack.tcp_connect(ip, port, now) else {
                    Self::reply(ch, h.txid, h.op, sys::ERR_NO_RESOURCES as i32, 0, 0);
                    return;
                };
                self.pending_connects.push(PendingConnect {
                    client_id,
                    ch,
                    txid: h.txid,
                    sock_id,
                    ring,
                    deadline_ms: now.saturating_add(u64::from(timeout)),
                });
            }
            net::OP_UDP_OPEN => {
                if role != Role::Client {
                    close_hnd();
                    Self::reply(ch, h.txid, h.op, sys::ERR_ACCESS_DENIED as i32, 0, 0);
                    return;
                }
                if hnd == 0 {
                    Self::reply(ch, h.txid, h.op, sys::ERR_INVALID_ARGS as i32, 0, 0);
                    return;
                }
                let ring = match IoRing::attach(hnd) {
                    Ok(r) => r,
                    Err(e) => {
                        Self::reply(ch, h.txid, h.op, e as i32, 0, 0);
                        return;
                    }
                };
                let Some(nic) = self.nic.as_mut() else {
                    Self::reply(ch, h.txid, h.op, sys::ERR_BAD_STATE as i32, 0, 0);
                    return;
                };
                let Some(sock_id) = nic.stack.udp_open(h.a as u16) else {
                    Self::reply(ch, h.txid, h.op, sys::ERR_NO_RESOURCES as i32, 0, 0);
                    return;
                };
                self.sockets.push(ClientSock {
                    client_id,
                    sock_id,
                    is_udp: true,
                    ring,
                    pending_recv: None,
                });
                Self::reply(ch, h.txid, h.op, 0, u64::from(sock_id), 0);
            }
            net::OP_SOCK_KICK => {
                close_hnd();
                self.pump_sockets(now);
            }
            net::OP_SOCK_CLOSE => {
                close_hnd();
                let sid = h.a as u32;
                if let Some(pos) = self.sockets.iter().position(|s| s.client_id == client_id && s.sock_id == sid) {
                    let s = self.sockets.remove(pos);
                    if let Some(nic) = self.nic.as_mut() {
                        if s.is_udp {
                            nic.stack.udp_close(sid);
                        } else {
                            nic.stack.tcp_close(sid, now);
                        }
                    }
                }
                Self::reply(ch, h.txid, h.op, 0, 0, 0);
            }
            _ => {
                close_hnd();
                Self::reply(ch, h.txid, h.op, sys::ERR_NOT_SUPPORTED as i32, 0, 0);
            }
        }
    }

    fn pump_sockets(&mut self, now: u64) {
        let Some(nic) = self.nic.as_mut() else { return };
        let mut wake: Vec<(u64, u32)> = Vec::new();
        for s in &mut self.sockets {
            // Pull new SQEs (always allow RING_SEND even while a RING_RECV is pending so
            // full-duplex interactive protocols like SSH never stall on an idle recv).
            while let Some(sqe) = s.ring.pop_sq() {
                match sqe.op {
                    net::RING_SEND => {
                        if let Some(src) = s.ring.data(sqe.buf_off, sqe.buf_len) {
                            let bytes = src.to_vec();
                            let sent = if s.is_udp {
                                let ip = net::unpack_ipv4(sqe.b);
                                let port = ((sqe.b >> 32) & 0xFFFF) as u16;
                                if nic.stack.udp_send(s.sock_id, ip, port, &bytes, now) {
                                    bytes.len()
                                } else {
                                    0
                                }
                            } else {
                                nic.stack.tcp_send(s.sock_id, &bytes, now)
                            };
                            let status = if sent > 0 || bytes.is_empty() {
                                0
                            } else {
                                sys::ERR_PEER_CLOSED as i32
                            };
                            s.ring.push_cq(Cqe { id: sqe.id, status, a: sent as u64 });
                            wake.push((s.client_id, s.sock_id));
                        } else {
                            s.ring.push_cq(Cqe { id: sqe.id, status: sys::ERR_INVALID_ARGS as i32, a: 0 });
                            wake.push((s.client_id, s.sock_id));
                        }
                    }
                    net::RING_RECV => {
                        s.pending_recv = Some(sqe);
                    }
                    _ => {
                        s.ring.push_cq(Cqe { id: sqe.id, status: sys::ERR_INVALID_ARGS as i32, a: 0 });
                        wake.push((s.client_id, s.sock_id));
                    }
                }
            }

            // Try to satisfy a pending RECV SQE.
            if let Some(sqe) = s.pending_recv {
                if s.is_udp {
                    if let Some((ip, port, data)) = nic.stack.udp_recv(s.sock_id) {
                        s.pending_recv = None;
                        let n = data.len().min(sqe.buf_len as usize);
                        if let Some(dst) = s.ring.data_mut(sqe.buf_off, n as u32) {
                            dst.copy_from_slice(&data[..n]);
                            let a = (n as u64) | (net::pack_ipv4(ip) << 16) | (u64::from(port) << 48);
                            s.ring.push_cq(Cqe { id: sqe.id, status: 0, a });
                        } else {
                            s.ring.push_cq(Cqe { id: sqe.id, status: sys::ERR_INVALID_ARGS as i32, a: 0 });
                        }
                        wake.push((s.client_id, s.sock_id));
                    }
                } else {
                    let avail = nic.stack.tcp_rx_available(s.sock_id);
                    if avail > 0 {
                        s.pending_recv = None;
                        let want = avail.min(sqe.buf_len as usize);
                        if let Some(dst) = s.ring.data_mut(sqe.buf_off, want as u32) {
                            let got = nic.stack.tcp_recv(s.sock_id, dst);
                            s.ring.push_cq(Cqe { id: sqe.id, status: 0, a: got as u64 });
                        } else {
                            s.ring.push_cq(Cqe { id: sqe.id, status: sys::ERR_INVALID_ARGS as i32, a: 0 });
                        }
                        wake.push((s.client_id, s.sock_id));
                    } else if nic.stack.tcp_peer_closed(s.sock_id)
                        || nic.stack.tcp_state(s.sock_id).is_none_or(|st| st == TcpState::Closed)
                    {
                        s.pending_recv = None;
                        let status = if nic.stack.tcp_is_reset(s.sock_id) {
                            sys::ERR_PEER_CLOSED as i32
                        } else {
                            0 // clean EOF: 0 bytes
                        };
                        s.ring.push_cq(Cqe { id: sqe.id, status, a: 0 });
                        wake.push((s.client_id, s.sock_id));
                    }
                }
            }
        }
        for (cid, sid) in wake {
            let ch = self.client_ch(cid);
            if ch != 0 {
                proto::send(ch, net::OP_SOCK_EVENT, u64::from(sid), 0);
            }
        }
    }

    fn pump_stack(&mut self) {
        let now = now_ms();
        if let Some(nic) = self.nic.as_mut() {
            nic.drain_rx(now);
            nic.stack.tick(now);

            if !nic.dhcp_offer_logged && nic.stack.dhcp_state == DhcpState::Requesting {
                nic.dhcp_offer_logged = true;
                println!("net: dhcp offer received on '{}'", nic.name);
            }
            if !nic.dhcp_logged && nic.stack.dhcp_state == DhcpState::Bound {
                nic.dhcp_logged = true;
                println!(
                    "net: dhcp bound {} gw {} dns {}",
                    fmt_ipv4(nic.stack.ip),
                    fmt_ipv4(nic.stack.gateway),
                    fmt_ipv4(nic.stack.dns_server)
                );
            }

            // Complete ping replies.
            while let Some(rep) = nic.stack.poll_ping_reply() {
                if let Some(pos) = self
                    .pending_pings
                    .iter()
                    .position(|p| p.ping_id == rep.id && p.seq == rep.seq)
                {
                    let call = self.pending_pings.remove(pos);
                    let a = u64::from(rep.rtt_ms) | (u64::from(rep.ttl) << 32);
                    Self::reply(call.ch, call.txid, net::OP_PING, 0, a, 0);
                }
            }

            // Complete DNS responses.
            while let Some(res) = nic.stack.poll_dns_result() {
                if let Some(pos) = self.pending_dns.iter().position(|d| d.query_id == res.query_id) {
                    let call = self.pending_dns.remove(pos);
                    Self::reply(call.ch, call.txid, net::OP_DNS_RESOLVE, 0, net::pack_ipv4(res.ip), u64::from(res.ttl));
                }
            }

            // Complete pending TCP connects.
            let mut i = 0;
            while i < self.pending_connects.len() {
                let sid = self.pending_connects[i].sock_id;
                let st = nic.stack.tcp_state(sid);
                if st == Some(TcpState::Established) {
                    let pc = self.pending_connects.remove(i);
                    Self::reply(pc.ch, pc.txid, net::OP_TCP_CONNECT, 0, u64::from(pc.sock_id), 0);
                    self.sockets.push(ClientSock {
                        client_id: pc.client_id,
                        sock_id: pc.sock_id,
                        is_udp: false,
                        ring: pc.ring,
                        pending_recv: None,
                    });
                } else if st.is_none() || st == Some(TcpState::Closed) {
                    let pc = self.pending_connects.remove(i);
                    nic.stack.tcp_remove(sid);
                    Self::reply(pc.ch, pc.txid, net::OP_TCP_CONNECT, sys::ERR_PEER_CLOSED as i32, 0, 0);
                } else if now >= self.pending_connects[i].deadline_ms {
                    let pc = self.pending_connects.remove(i);
                    nic.stack.tcp_remove(sid);
                    Self::reply(pc.ch, pc.txid, net::OP_TCP_CONNECT, sys::ERR_TIMED_OUT as i32, 0, 0);
                } else {
                    i += 1;
                }
            }
        }

        // Expire timed-out pings & DNS calls.
        let mut i = 0;
        while i < self.pending_pings.len() {
            if now >= self.pending_pings[i].deadline_ms {
                let p = self.pending_pings.remove(i);
                // Say where it failed: the first hop never answered ARP (no unicast frames
                // reach us, or a wrong gateway), or the echo went out and nothing came back.
                if let Some(nic) = self.nic.as_ref() {
                    let (hop, mac) = nic.stack.next_hop_mac(p.dst, now);
                    let why = match mac {
                        Some(m) => format!("echo sent to {} via {} ({}), no reply", fmt_ipv4(p.dst), fmt_ipv4(hop), fmt_mac(m)),
                        None => format!("no ARP reply from {} (the first hop to {})", fmt_ipv4(hop), fmt_ipv4(p.dst)),
                    };
                    println!("net: ping seq {} timed out: {}; frames rx {} tx {}", p.seq, why, nic.stack.rx_packets, nic.stack.tx_packets);
                }
                Self::reply(p.ch, p.txid, net::OP_PING, sys::ERR_TIMED_OUT as i32, 0, 0);
            } else {
                i += 1;
            }
        }
        let mut i = 0;
        while i < self.pending_dns.len() {
            if now >= self.pending_dns[i].deadline_ms {
                let d = self.pending_dns.remove(i);
                if let Some(nic) = self.nic.as_ref() {
                    let probe = if nic.stack.dns_server != [0; 4] { nic.stack.dns_server } else { [1, 1, 1, 1] };
                    let (hop, mac) = nic.stack.next_hop_mac(probe, now);
                    let arp = match mac {
                        Some(m) => format!("via {} ({})", fmt_ipv4(hop), fmt_mac(m)),
                        None => format!("no ARP reply from {}", fmt_ipv4(hop)),
                    };
                    println!(
                        "net: dns query {:#x} timed out (dns {} / {}, fallback={}, {}; frames rx {} tx {})",
                        d.query_id,
                        fmt_ipv4(nic.stack.dns_server),
                        fmt_ipv4(nic.stack.dns_server2),
                        nic.stack.dns_fallback,
                        arp,
                        nic.stack.rx_packets,
                        nic.stack.tx_packets
                    );
                }
                Self::reply(d.ch, d.txid, net::OP_DNS_RESOLVE, sys::ERR_TIMED_OUT as i32, 0, 0);
            } else {
                i += 1;
            }
        }

        self.pump_sockets(now);
        if let Some(nic) = self.nic.as_mut() {
            nic.flush_tx();
        }
    }
}

fn main(s: *const Startup) -> i32 {
    // SAFETY: `s` is the startup block pointer passed by the kernel.
    if !unsafe { libd::init(s, "net") } {
        return -1;
    }
    let Ok(port) = Port::new(128) else {
        println!("net: cannot create port");
        return 1;
    };
    let ctl = libd::startup_handle(proto::TAG_CONTROL);
    let devmgr = svc::endpoint(b"devmgr.net");
    if ctl != 0 {
        port.arm(ctl, sys::READABLE | sys::PEER_CLOSED, KEY_CTL);
    }
    if devmgr != 0 {
        port.arm(devmgr, sys::READABLE | sys::PEER_CLOSED, KEY_DEVMGR);
    }

    let saved_cfg = load_net_settings();
    let mut svc_state = NetSvc {
        port,
        ctl,
        devmgr,
        stop: false,
        nic: None,
        clients: Vec::new(),
        next_client_id: 1,
        next_ping_id: 1,
        pending_pings: Vec::new(),
        pending_dns: Vec::new(),
        pending_connects: Vec::new(),
        sockets: Vec::new(),
        saved_cfg,
    };

    println!("net: ready (in-tree TCP/IP, DHCP, DNS, capability-gated endpoints)");

    while !svc_state.stop {
        let busy = !svc_state.sockets.is_empty()
            || !svc_state.pending_connects.is_empty()
            || !svc_state.pending_pings.is_empty()
            || !svc_state.pending_dns.is_empty()
            || svc_state
                .nic
                .as_ref()
                .is_some_and(|n| n.stack.dhcp_state != DhcpState::Bound);
        let wait = if busy { 5 * MS } else { 50 * MS };
        if let Some((key, _)) = svc_state.port.wait(wait) {
            match key {
                KEY_CTL => svc_state.handle_ctl(),
                KEY_DEVMGR => svc_state.handle_devmgr(),
                KEY_NIC => svc_state.handle_nic(),
                k if k >= KEY_CLIENT_BASE => svc_state.handle_client(k - KEY_CLIENT_BASE),
                _ => {}
            }
        }
        svc_state.pump_stack();
    }

    if let Some(nic) = svc_state.nic.take() {
        let mut req = [0u8; HEADER];
        Header { txid: 0, op: net::DRV_STOP, status: 0, a: 0, b: 0 }.put(&mut req);
        let mut rep = [0u8; HEADER];
        let _ = sys::channel_call(nic.ch, &req, &mut rep, 500 * MS);
        sys::handle_close(nic.ch);
    }
    println!("net: shutdown");
    0
}
