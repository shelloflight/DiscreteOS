//! Sans-IO network stack (`NetStack`): Ethernet II, ARP, IPv4, ICMPv4, UDP, DHCPv4, DNS, TCP.
//!
//! Pure `no_std` + `alloc`, `#![forbid(unsafe_code)]`. Drives all protocol logic cleanly without
//! platform I/O so both `net.dsvc` and host unit/fuzz tests run the exact same state machine.

use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::vec::Vec;

use crate::arp::ArpTable;
use crate::tcp::{OutSegment, TcpConn, TcpState};
use crate::wire::{
    ARP_OP_REPLY, ARP_OP_REQUEST, ArpPacket, DHCP_ACK, DHCP_DISCOVER, DHCP_NAK, DHCP_OFFER,
    DHCP_REQUEST, ETH_TYPE_ARP, ETH_TYPE_IPV4, EthFrame, ICMP_ECHO_REPLY, ICMP_ECHO_REQUEST,
    IcmpPacket, Ipv4Packet, PROTO_ICMP, PROTO_TCP, PROTO_UDP, TcpSegment, UdpPacket,
    build_dhcp_packet, build_dns_query, build_eth, build_icmp_echo, build_ipv4, build_tcp,
    build_udp, parse_dhcp, parse_dns_response,
};
use crate::{IP_BROADCAST, IP_UNSPECIFIED, Ipv4Addr, MAC_BROADCAST, MacAddr};

const MAX_TX_QUEUE: usize = 128;
const MAX_TCP: usize = 32;
const MAX_UDP: usize = 16;
const MAX_UDP_RX: usize = 16;
const MAX_PINGS: usize = 16;
const MAX_DNS_PENDING: usize = 8;
const MAX_DNS_CACHE: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DhcpState {
    Idle,
    Discovering,
    Requesting,
    Bound,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PingReply {
    pub id: u16,
    pub seq: u16,
    pub from: Ipv4Addr,
    pub rtt_ms: u32,
    pub ttl: u8,
}

struct PendingPing {
    id: u16,
    seq: u16,
    dst: Ipv4Addr,
    sent_ms: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DnsResult {
    pub query_id: u16,
    pub ip: Ipv4Addr,
    pub ttl: u32,
}

struct PendingDns {
    id: u16,
    local_port: u16,
    server_ip: Ipv4Addr,
    server_port: u16,
    hostname: String,
    last_tx_ms: u64,
    retries: u8,
}

struct DnsCacheEntry {
    hostname: String,
    ip: Ipv4Addr,
    expires_ms: u64,
}

pub struct UdpSocket {
    pub id: u32,
    pub local_port: u16,
    pub rx: VecDeque<(Ipv4Addr, u16, Vec<u8>)>,
}

pub struct NetStack {
    pub mac: MacAddr,
    pub ip: Ipv4Addr,
    pub netmask: Ipv4Addr,
    pub gateway: Ipv4Addr,
    pub dns_server: Ipv4Addr,
    pub dns_port: u16,
    pub bootfile: String,
    pub dhcp_state: DhcpState,
    dhcp_xid: u32,
    dhcp_server: Ipv4Addr,
    dhcp_offered: Ipv4Addr,
    dhcp_offer_router: Option<Ipv4Addr>,
    dhcp_offer_dns: Option<Ipv4Addr>,
    dhcp_retries: u8,
    dhcp_last_tx_ms: u64,
    arp: ArpTable,
    tx_queue: VecDeque<Vec<u8>>,
    tcp: Vec<TcpConn>,
    udp: Vec<UdpSocket>,
    pings: Vec<PendingPing>,
    ping_replies: VecDeque<PingReply>,
    dns_pending: Vec<PendingDns>,
    dns_results: VecDeque<DnsResult>,
    dns_cache: Vec<DnsCacheEntry>,
    next_sock_id: u32,
    next_ephemeral: u16,
    next_ip_id: u16,
    rng_state: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
}

impl NetStack {
    pub fn new(mac: MacAddr, seed: u64) -> Self {
        Self {
            mac,
            ip: IP_UNSPECIFIED,
            netmask: [255, 255, 255, 0],
            gateway: IP_UNSPECIFIED,
            dns_server: IP_UNSPECIFIED,
            dns_port: 53,
            bootfile: String::new(),
            dhcp_state: DhcpState::Idle,
            dhcp_xid: 0,
            dhcp_server: IP_UNSPECIFIED,
            dhcp_offered: IP_UNSPECIFIED,
            dhcp_offer_router: None,
            dhcp_offer_dns: None,
            dhcp_retries: 0,
            dhcp_last_tx_ms: 0,
            arp: ArpTable::new(),
            tx_queue: VecDeque::new(),
            tcp: Vec::new(),
            udp: Vec::new(),
            pings: Vec::new(),
            ping_replies: VecDeque::new(),
            dns_pending: Vec::new(),
            dns_results: VecDeque::new(),
            dns_cache: Vec::new(),
            next_sock_id: 1,
            next_ephemeral: 49152,
            next_ip_id: 1,
            rng_state: seed ^ 0x9E37_79B9_7F4A_7C15,
            rx_packets: 0,
            tx_packets: 0,
        }
    }

    pub fn set_static(&mut self, ip: Ipv4Addr, netmask: Ipv4Addr, gateway: Ipv4Addr, dns: Ipv4Addr) {
        self.ip = ip;
        self.netmask = netmask;
        self.gateway = gateway;
        self.dns_server = dns;
        self.dhcp_state = DhcpState::Bound;
    }

    pub fn set_dns(&mut self, ip: Ipv4Addr, port: u16) {
        self.dns_server = ip;
        self.dns_port = port;
    }

    fn next_rand(&mut self) -> u32 {
        let mut x = self.rng_state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.rng_state = x;
        (x >> 16) as u32
    }

    fn alloc_port(&mut self) -> u16 {
        for _ in 0..16384 {
            let p = self.next_ephemeral;
            self.next_ephemeral = if p >= 65500 { 49152 } else { p + 1 };
            let used = self.tcp.iter().any(|c| c.local_port == p)
                || self.udp.iter().any(|u| u.local_port == p)
                || self.dns_pending.iter().any(|d| d.local_port == p);
            if !used {
                return p;
            }
        }
        50000
    }

    fn push_tx(&mut self, frame: Vec<u8>) {
        if self.tx_queue.len() >= MAX_TX_QUEUE {
            self.tx_queue.pop_front();
        }
        self.tx_queue.push_back(frame);
        self.tx_packets += 1;
    }

    pub fn poll_tx(&mut self) -> Option<Vec<u8>> {
        self.tx_queue.pop_front()
    }

    fn same_subnet(&self, dst: Ipv4Addr) -> bool {
        if self.ip == IP_UNSPECIFIED {
            return true;
        }
        for i in 0..4 {
            if (self.ip[i] & self.netmask[i]) != (dst[i] & self.netmask[i]) {
                return false;
            }
        }
        true
    }

    fn next_hop(&self, dst: Ipv4Addr) -> Ipv4Addr {
        if dst == IP_BROADCAST || self.same_subnet(dst) || self.gateway == IP_UNSPECIFIED {
            dst
        } else {
            self.gateway
        }
    }

    fn send_arp_request(&mut self, target_ip: Ipv4Addr) {
        let arp = ArpPacket {
            op: ARP_OP_REQUEST,
            sha: self.mac,
            spa: self.ip,
            tha: [0; 6],
            tpa: target_ip,
        };
        let frame = build_eth(MAC_BROADCAST, self.mac, ETH_TYPE_ARP, &arp.encode());
        self.push_tx(frame);
    }

    fn send_ipv4(&mut self, src: Ipv4Addr, dst: Ipv4Addr, proto: u8, payload: &[u8], now_ms: u64) {
        let id = self.next_ip_id;
        self.next_ip_id = self.next_ip_id.wrapping_add(1);
        let Some(pkt) = build_ipv4(src, dst, proto, id, 64, payload) else {
            return;
        };
        if dst == IP_BROADCAST {
            let frame = build_eth(MAC_BROADCAST, self.mac, ETH_TYPE_IPV4, &pkt);
            self.push_tx(frame);
            return;
        }
        let hop = self.next_hop(dst);
        if let Some(mac) = self.arp.lookup(hop, now_ms) {
            let frame = build_eth(mac, self.mac, ETH_TYPE_IPV4, &pkt);
            self.push_tx(frame);
        } else {
            self.arp.queue_pending(hop, pkt, now_ms);
            self.send_arp_request(hop);
        }
    }

    // ---- DHCP -----------------------------------------------------------------------------------

    pub fn start_dhcp(&mut self, now_ms: u64) {
        self.dhcp_xid = self.next_rand().max(1);
        self.dhcp_state = DhcpState::Discovering;
        self.dhcp_offer_router = None;
        self.dhcp_offer_dns = None;
        self.dhcp_retries = 0;
        self.dhcp_last_tx_ms = now_ms;
        self.send_dhcp_discover(now_ms);
    }

    fn send_dhcp_discover(&mut self, now_ms: u64) {
        let dhcp = build_dhcp_packet(DHCP_DISCOVER, self.dhcp_xid, self.mac, None, None);
        if let Some(udp) = build_udp(IP_UNSPECIFIED, IP_BROADCAST, 68, 67, &dhcp) {
            self.send_ipv4(IP_UNSPECIFIED, IP_BROADCAST, PROTO_UDP, &udp, now_ms);
        }
    }

    fn send_dhcp_request(&mut self, now_ms: u64) {
        let server = if self.dhcp_server != IP_UNSPECIFIED {
            Some(self.dhcp_server)
        } else {
            None
        };
        let dhcp = build_dhcp_packet(
            DHCP_REQUEST,
            self.dhcp_xid,
            self.mac,
            Some(self.dhcp_offered),
            server,
        );
        if let Some(udp) = build_udp(IP_UNSPECIFIED, IP_BROADCAST, 68, 67, &dhcp) {
            self.send_ipv4(IP_UNSPECIFIED, IP_BROADCAST, PROTO_UDP, &udp, now_ms);
        }
    }

    fn handle_dhcp(&mut self, src_ip: Ipv4Addr, payload: &[u8], now_ms: u64) {
        let Some(msg) = parse_dhcp(payload, self.mac) else {
            return;
        };
        if msg.xid != self.dhcp_xid {
            return;
        }
        match (self.dhcp_state, msg.msg_type) {
            (DhcpState::Discovering, DHCP_OFFER) if msg.your_ip != IP_UNSPECIFIED => {
                self.dhcp_offered = msg.your_ip;
                self.dhcp_server = if msg.server_ip != IP_UNSPECIFIED {
                    msg.server_ip
                } else {
                    src_ip
                };
                self.dhcp_offer_router = msg.router;
                self.dhcp_offer_dns = msg.dns;
                self.dhcp_retries = 0;
                self.dhcp_state = DhcpState::Requesting;
                self.dhcp_last_tx_ms = now_ms;
                self.send_dhcp_request(now_ms);
            }
            (DhcpState::Requesting, DHCP_ACK) if msg.your_ip != IP_UNSPECIFIED => {
                self.ip = msg.your_ip;
                self.netmask = msg.subnet_mask;
                if let Some(gw) = msg.router.or(self.dhcp_offer_router) {
                    self.gateway = gw;
                }
                if let Some(dns) = msg.dns.or(self.dhcp_offer_dns) {
                    self.dns_server = dns;
                } else if self.gateway != IP_UNSPECIFIED {
                    self.dns_server = self.gateway;
                }
                if !msg.bootfile.is_empty() {
                    self.bootfile = msg.bootfile;
                }
                self.dhcp_state = DhcpState::Bound;
            }
            (DhcpState::Requesting, DHCP_NAK) => {
                self.start_dhcp(now_ms);
            }
            _ => {}
        }
    }

    // ---- ICMP ping ------------------------------------------------------------------------------

    pub fn send_ping(&mut self, dst: Ipv4Addr, id: u16, seq: u16, now_ms: u64) -> bool {
        if self.ip == IP_UNSPECIFIED {
            return false;
        }
        if self.pings.len() >= MAX_PINGS {
            self.pings.remove(0);
        }
        self.pings.push(PendingPing { id, seq, dst, sent_ms: now_ms });
        let icmp = build_icmp_echo(false, id, seq, b"D-OS ping payload 0123456789abcd");
        self.send_ipv4(self.ip, dst, PROTO_ICMP, &icmp, now_ms);
        true
    }

    pub fn poll_ping_reply(&mut self) -> Option<PingReply> {
        self.ping_replies.pop_front()
    }

    // ---- DNS ------------------------------------------------------------------------------------

    pub fn start_dns_resolve(&mut self, hostname: &str, now_ms: u64) -> Option<u16> {
        if let Some(ip) = crate::parse_ipv4(hostname) {
            let id = (self.next_rand() as u16).max(1);
            self.dns_results.push_back(DnsResult { query_id: id, ip, ttl: 0 });
            return Some(id);
        }
        // Check cache first.
        if let Some((ip, expires_ms)) = self
            .dns_cache
            .iter()
            .find(|c| c.hostname.eq_ignore_ascii_case(hostname) && c.expires_ms > now_ms)
            .map(|c| (c.ip, c.expires_ms))
        {
            let id = (self.next_rand() as u16).max(1);
            self.dns_results.push_back(DnsResult {
                query_id: id,
                ip,
                ttl: ((expires_ms - now_ms) / 1000) as u32,
            });
            return Some(id);
        }
        if self.ip == IP_UNSPECIFIED || self.dns_server == IP_UNSPECIFIED {
            return None;
        }
        let id = (self.next_rand() as u16).max(1);
        let q = build_dns_query(id, hostname)?;
        let port = self.alloc_port();
        if self.dns_pending.len() >= MAX_DNS_PENDING {
            self.dns_pending.remove(0);
        }
        let server_ip = self.dns_server;
        let server_port = self.dns_port;
        self.dns_pending.push(PendingDns {
            id,
            local_port: port,
            server_ip,
            server_port,
            hostname: String::from(hostname),
            last_tx_ms: now_ms,
            retries: 0,
        });
        if let Some(udp) = build_udp(self.ip, server_ip, port, server_port, &q) {
            self.send_ipv4(self.ip, server_ip, PROTO_UDP, &udp, now_ms);
        }
        Some(id)
    }

    pub fn poll_dns_result(&mut self) -> Option<DnsResult> {
        self.dns_results.pop_front()
    }

    // ---- UDP sockets ----------------------------------------------------------------------------

    pub fn udp_open(&mut self, bind_port: u16) -> Option<u32> {
        if self.udp.len() >= MAX_UDP {
            return None;
        }
        let port = if bind_port == 0 { self.alloc_port() } else { bind_port };
        let id = self.next_sock_id;
        self.next_sock_id += 1;
        self.udp.push(UdpSocket { id, local_port: port, rx: VecDeque::new() });
        Some(id)
    }

    pub fn udp_send(&mut self, id: u32, dst_ip: Ipv4Addr, dst_port: u16, data: &[u8], now_ms: u64) -> bool {
        let Some(local_port) = self.udp.iter().find(|u| u.id == id).map(|u| u.local_port) else {
            return false;
        };
        if self.ip == IP_UNSPECIFIED {
            return false;
        }
        let Some(udp) = build_udp(self.ip, dst_ip, local_port, dst_port, data) else {
            return false;
        };
        self.send_ipv4(self.ip, dst_ip, PROTO_UDP, &udp, now_ms);
        true
    }

    pub fn udp_recv(&mut self, id: u32) -> Option<(Ipv4Addr, u16, Vec<u8>)> {
        self.udp.iter_mut().find(|u| u.id == id)?.rx.pop_front()
    }

    pub fn udp_close(&mut self, id: u32) {
        self.udp.retain(|u| u.id != id);
    }

    // ---- TCP sockets ----------------------------------------------------------------------------

    fn emit_tcp_segments(&mut self, segs: &[OutSegment], now_ms: u64) {
        let src = self.ip;
        for s in segs {
            if let Some(raw) = build_tcp(
                src,
                s.dst_ip,
                s.src_port,
                s.dst_port,
                s.seq,
                s.ack,
                s.flags,
                s.window,
                s.mss,
                &s.payload,
            ) {
                self.send_ipv4(src, s.dst_ip, PROTO_TCP, &raw, now_ms);
            }
        }
    }

    pub fn tcp_connect(&mut self, dst_ip: Ipv4Addr, dst_port: u16, now_ms: u64) -> Option<u32> {
        if self.ip == IP_UNSPECIFIED || self.tcp.len() >= MAX_TCP {
            return None;
        }
        let id = self.next_sock_id;
        self.next_sock_id += 1;
        let local_port = self.alloc_port();
        let iss = self.next_rand();
        let mut conn = TcpConn::new_client(id, local_port, dst_ip, dst_port, iss);
        let syn = conn.start_connect(now_ms);
        self.tcp.push(conn);
        self.emit_tcp_segments(&[syn], now_ms);
        Some(id)
    }

    pub fn tcp_listen(&mut self, local_port: u16) -> Option<u32> {
        if self.tcp.len() >= MAX_TCP {
            return None;
        }
        let id = self.next_sock_id;
        self.next_sock_id += 1;
        self.tcp.push(TcpConn::new_listen(id, local_port));
        Some(id)
    }

    pub fn tcp_state(&self, id: u32) -> Option<TcpState> {
        self.tcp.iter().find(|c| c.id == id).map(|c| c.state)
    }

    pub fn tcp_is_reset(&self, id: u32) -> bool {
        self.tcp.iter().find(|c| c.id == id).is_some_and(|c| c.reset)
    }

    pub fn tcp_peer_closed(&self, id: u32) -> bool {
        self.tcp.iter().find(|c| c.id == id).is_some_and(|c| c.peer_closed)
    }

    pub fn tcp_rx_available(&self, id: u32) -> usize {
        self.tcp.iter().find(|c| c.id == id).map_or(0, |c| c.rx_buf.len())
    }

    pub fn tcp_send(&mut self, id: u32, data: &[u8], now_ms: u64) -> usize {
        let mut segs = Vec::new();
        let n = if let Some(c) = self.tcp.iter_mut().find(|c| c.id == id) {
            let n = c.enqueue_tx(data);
            c.flush_tx(now_ms, &mut segs);
            n
        } else {
            0
        };
        self.emit_tcp_segments(&segs, now_ms);
        n
    }

    pub fn tcp_recv(&mut self, id: u32, out: &mut [u8]) -> usize {
        self.tcp.iter_mut().find(|c| c.id == id).map_or(0, |c| c.read_rx(out))
    }

    pub fn tcp_close(&mut self, id: u32, now_ms: u64) {
        let mut segs = Vec::new();
        if let Some(c) = self.tcp.iter_mut().find(|c| c.id == id) {
            c.close(now_ms, &mut segs);
        }
        self.emit_tcp_segments(&segs, now_ms);
        self.tcp.retain(|c| !(c.id == id && c.state == TcpState::Closed));
    }

    pub fn tcp_remove(&mut self, id: u32) {
        self.tcp.retain(|c| c.id != id);
    }

    // ---- RX packet processing & timer tick ------------------------------------------------------

    pub fn on_rx_frame(&mut self, raw: &[u8], now_ms: u64) {
        self.rx_packets += 1;
        let Some(eth) = EthFrame::parse(raw) else {
            return;
        };
        if eth.dst != self.mac && eth.dst != MAC_BROADCAST {
            return;
        }
        match eth.ethertype {
            ETH_TYPE_ARP => self.on_arp(eth.payload, now_ms),
            ETH_TYPE_IPV4 => self.on_ipv4(eth.src, eth.payload, now_ms),
            _ => {}
        }
    }

    fn on_arp(&mut self, payload: &[u8], now_ms: u64) {
        let Some(arp) = ArpPacket::parse(payload) else {
            return;
        };
        if arp.spa != IP_UNSPECIFIED {
            let ready = self.arp.insert(arp.spa, arp.sha, now_ms);
            for pkt in ready {
                let frame = build_eth(arp.sha, self.mac, ETH_TYPE_IPV4, &pkt);
                self.push_tx(frame);
            }
        }
        if arp.op == ARP_OP_REQUEST && self.ip != IP_UNSPECIFIED && arp.tpa == self.ip {
            let reply = ArpPacket {
                op: ARP_OP_REPLY,
                sha: self.mac,
                spa: self.ip,
                tha: arp.sha,
                tpa: arp.spa,
            };
            let frame = build_eth(arp.sha, self.mac, ETH_TYPE_ARP, &reply.encode());
            self.push_tx(frame);
        }
    }

    fn on_ipv4(&mut self, src_mac: MacAddr, payload: &[u8], now_ms: u64) {
        let Some(ip) = Ipv4Packet::parse(payload) else {
            return;
        };
        // Learn sender MAC when on our subnet.
        if ip.src != IP_UNSPECIFIED && self.same_subnet(ip.src) {
            let ready = self.arp.insert(ip.src, src_mac, now_ms);
            for pkt in ready {
                let frame = build_eth(src_mac, self.mac, ETH_TYPE_IPV4, &pkt);
                self.push_tx(frame);
            }
        }
        let for_us = ip.dst == IP_BROADCAST
            || self.ip == IP_UNSPECIFIED
            || ip.dst == self.ip;
        if !for_us {
            return;
        }
        match ip.proto {
            PROTO_ICMP => self.on_icmp(&ip, now_ms),
            PROTO_UDP => self.on_udp(&ip, now_ms),
            PROTO_TCP => self.on_tcp(&ip, now_ms),
            _ => {}
        }
    }

    fn on_icmp(&mut self, ip: &Ipv4Packet<'_>, now_ms: u64) {
        let Some(icmp) = IcmpPacket::parse(ip.payload) else {
            return;
        };
        match icmp.ty {
            ICMP_ECHO_REQUEST if self.ip != IP_UNSPECIFIED && ip.dst == self.ip => {
                let rep = build_icmp_echo(true, icmp.id, icmp.seq, icmp.payload);
                self.send_ipv4(self.ip, ip.src, PROTO_ICMP, &rep, now_ms);
            }
            ICMP_ECHO_REPLY => {
                if let Some(pos) = self
                    .pings
                    .iter()
                    .position(|p| p.id == icmp.id && p.seq == icmp.seq && p.dst == ip.src)
                {
                    let p = self.pings.remove(pos);
                    let rtt_ms = now_ms.saturating_sub(p.sent_ms).min(u64::from(u32::MAX)) as u32;
                    self.ping_replies.push_back(PingReply {
                        id: icmp.id,
                        seq: icmp.seq,
                        from: ip.src,
                        rtt_ms,
                        ttl: ip.ttl,
                    });
                }
            }
            _ => {}
        }
    }

    fn on_udp(&mut self, ip: &Ipv4Packet<'_>, now_ms: u64) {
        let Some(udp) = UdpPacket::parse(ip.src, ip.dst, ip.payload) else {
            return;
        };
        if udp.dst_port == 68 {
            self.handle_dhcp(ip.src, udp.payload, now_ms);
            return;
        }
        if let Some(pos) = self.dns_pending.iter().position(|d| d.local_port == udp.dst_port) {
            let expected_id = self.dns_pending[pos].id;
            if let Some(ans) = parse_dns_response(udp.payload, expected_id) {
                let req = self.dns_pending.remove(pos);
                let ttl_ms = u64::from(ans.ttl.clamp(5, 3600)) * 1000;
                if self.dns_cache.len() >= MAX_DNS_CACHE {
                    self.dns_cache.remove(0);
                }
                self.dns_cache.push(DnsCacheEntry {
                    hostname: req.hostname,
                    ip: ans.ip,
                    expires_ms: now_ms.saturating_add(ttl_ms),
                });
                self.dns_results.push_back(DnsResult {
                    query_id: ans.id,
                    ip: ans.ip,
                    ttl: ans.ttl,
                });
                return;
            }
        }
        if let Some(sock) = self.udp.iter_mut().find(|u| u.local_port == udp.dst_port) {
            if sock.rx.len() >= MAX_UDP_RX {
                sock.rx.pop_front();
            }
            sock.rx.push_back((ip.src, udp.src_port, udp.payload.to_vec()));
        }
    }

    fn on_tcp(&mut self, ip: &Ipv4Packet<'_>, now_ms: u64) {
        if self.ip == IP_UNSPECIFIED || ip.dst != self.ip {
            return;
        }
        let Some(seg) = TcpSegment::parse(ip.src, ip.dst, ip.payload) else {
            return;
        };
        let iss = self.next_rand();
        let mut out = Vec::new();
        // Prefer exact 4-tuple match; fall back to matching LISTEN socket.
        let idx = self
            .tcp
            .iter()
            .position(|c| {
                c.state != TcpState::Listen
                    && c.local_port == seg.dst_port
                    && c.remote_port == seg.src_port
                    && c.remote_ip == ip.src
            })
            .or_else(|| {
                self.tcp
                    .iter()
                    .position(|c| c.state == TcpState::Listen && c.local_port == seg.dst_port)
            });
        if let Some(i) = idx {
            self.tcp[i].on_segment(ip.src, &seg, iss, now_ms, &mut out);
        }
        self.emit_tcp_segments(&out, now_ms);
    }

    /// Periodic maintenance: DHCP retries, DNS retries, TCP retransmits, ARP aging.
    pub fn tick(&mut self, now_ms: u64) {
        self.arp.prune(now_ms);
        self.pings.retain(|p| now_ms.saturating_sub(p.sent_ms) < 5_000);
        self.dns_cache.retain(|c| c.expires_ms > now_ms);

        match self.dhcp_state {
            DhcpState::Discovering if now_ms.saturating_sub(self.dhcp_last_tx_ms) >= 1_500 => {
                self.dhcp_last_tx_ms = now_ms;
                self.send_dhcp_discover(now_ms);
            }
            DhcpState::Requesting if now_ms.saturating_sub(self.dhcp_last_tx_ms) >= 1_500 => {
                if self.dhcp_retries >= 4 {
                    self.start_dhcp(now_ms);
                } else {
                    self.dhcp_retries += 1;
                    self.dhcp_last_tx_ms = now_ms;
                    self.send_dhcp_request(now_ms);
                }
            }
            _ => {}
        }

        // Retry pending DNS queries.
        let mut resend_dns: Vec<(Ipv4Addr, u16, u16, Vec<u8>)> = Vec::new();
        self.dns_pending.retain_mut(|d| {
            if now_ms.saturating_sub(d.last_tx_ms) >= 1_000 {
                if d.retries >= 3 {
                    return false;
                }
                d.retries += 1;
                d.last_tx_ms = now_ms;
                if let Some(q) = build_dns_query(d.id, &d.hostname) {
                    resend_dns.push((d.server_ip, d.local_port, d.server_port, q));
                }
            }
            true
        });
        for (sip, lport, sport, q) in resend_dns {
            if let Some(udp) = build_udp(self.ip, sip, lport, sport, &q) {
                self.send_ipv4(self.ip, sip, PROTO_UDP, &udp, now_ms);
            }
        }

        // TCP retransmission timers.
        let mut segs = Vec::new();
        for c in &mut self.tcp {
            c.tick(now_ms, &mut segs);
        }
        self.emit_tcp_segments(&segs, now_ms);
    }
}
