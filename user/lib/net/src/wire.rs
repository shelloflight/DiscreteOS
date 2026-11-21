//! Strict bounds-checked wire parsers and serializers for Ethernet II, ARP, IPv4, ICMPv4,
//! UDP, TCP, DHCPv4, and DNS. Never panics on untrusted or truncated packets.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use crate::{Ipv4Addr, MacAddr};

pub const ETH_HDR_LEN: usize = 14;
pub const ETH_TYPE_IPV4: u16 = 0x0800;
pub const ETH_TYPE_ARP: u16 = 0x0806;
pub const MAX_FRAME_LEN: usize = 1522;
pub const MTU: usize = 1500;

pub const PROTO_ICMP: u8 = 1;
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;

pub const ARP_OP_REQUEST: u16 = 1;
pub const ARP_OP_REPLY: u16 = 2;

pub const ICMP_ECHO_REPLY: u8 = 0;
pub const ICMP_DEST_UNREACH: u8 = 3;
pub const ICMP_ECHO_REQUEST: u8 = 8;
pub const ICMP_TIME_EXCEEDED: u8 = 11;

pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;
pub const TCP_PSH: u8 = 0x08;
pub const TCP_ACK: u8 = 0x10;
pub const TCP_URG: u8 = 0x20;

pub const DHCP_DISCOVER: u8 = 1;
pub const DHCP_OFFER: u8 = 2;
pub const DHCP_REQUEST: u8 = 3;
pub const DHCP_ACK: u8 = 5;
pub const DHCP_NAK: u8 = 6;
pub const DHCP_MAGIC: [u8; 4] = [99, 130, 83, 99];

#[inline]
fn be16(b: &[u8], off: usize) -> u16 {
    u16::from_be_bytes([b[off], b[off + 1]])
}

#[inline]
fn be32(b: &[u8], off: usize) -> u32 {
    u32::from_be_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

/// RFC 1071 one's-complement checksum over `chunks`.
pub fn internet_checksum(chunks: &[&[u8]]) -> u16 {
    let mut sum = 0u32;
    let mut carry_byte: Option<u8> = None;
    for &c in chunks {
        let mut s = c;
        if let Some(prev) = carry_byte.take() {
            if let Some((&first, rest)) = s.split_first() {
                sum += u32::from(u16::from_be_bytes([prev, first]));
                s = rest;
            } else {
                carry_byte = Some(prev);
                continue;
            }
        }
        let mut i = 0;
        while i + 1 < s.len() {
            sum += u32::from(u16::from_be_bytes([s[i], s[i + 1]]));
            i += 2;
        }
        if i < s.len() {
            carry_byte = Some(s[i]);
        }
    }
    if let Some(last) = carry_byte {
        sum += u32::from(u16::from_be_bytes([last, 0]));
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// IPv4 pseudo-header checksum for UDP or TCP.
pub fn pseudo_checksum(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, payload: &[u8]) -> u16 {
    let len = (payload.len() as u16).to_be_bytes();
    let ph = [src[0], src[1], src[2], src[3], dst[0], dst[1], dst[2], dst[3], 0, proto, len[0], len[1]];
    internet_checksum(&[&ph, payload])
}

// ---- Ethernet II --------------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EthFrame<'a> {
    pub dst: MacAddr,
    pub src: MacAddr,
    pub ethertype: u16,
    pub payload: &'a [u8],
}

impl<'a> EthFrame<'a> {
    pub fn parse(raw: &'a [u8]) -> Option<Self> {
        if raw.len() < ETH_HDR_LEN || raw.len() > MAX_FRAME_LEN {
            return None;
        }
        let mut dst = [0u8; 6];
        let mut src = [0u8; 6];
        dst.copy_from_slice(&raw[0..6]);
        src.copy_from_slice(&raw[6..12]);
        let ethertype = be16(raw, 12);
        Some(Self { dst, src, ethertype, payload: &raw[ETH_HDR_LEN..] })
    }
}

pub fn build_eth(dst: MacAddr, src: MacAddr, ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity((ETH_HDR_LEN + payload.len()).max(60));
    out.extend_from_slice(&dst);
    out.extend_from_slice(&src);
    out.extend_from_slice(&ethertype.to_be_bytes());
    out.extend_from_slice(payload);
    if out.len() < 60 {
        out.resize(60, 0);
    }
    out
}

// ---- ARP ----------------------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArpPacket {
    pub op: u16,
    pub sha: MacAddr,
    pub spa: Ipv4Addr,
    pub tha: MacAddr,
    pub tpa: Ipv4Addr,
}

impl ArpPacket {
    pub fn parse(raw: &[u8]) -> Option<Self> {
        if raw.len() < 28 {
            return None;
        }
        let htype = be16(raw, 0);
        let ptype = be16(raw, 2);
        let hlen = raw[4];
        let plen = raw[5];
        if htype != 1 || ptype != ETH_TYPE_IPV4 || hlen != 6 || plen != 4 {
            return None;
        }
        let op = be16(raw, 6);
        let mut sha = [0u8; 6];
        let mut spa = [0u8; 4];
        let mut tha = [0u8; 6];
        let mut tpa = [0u8; 4];
        sha.copy_from_slice(&raw[8..14]);
        spa.copy_from_slice(&raw[14..18]);
        tha.copy_from_slice(&raw[18..24]);
        tpa.copy_from_slice(&raw[24..28]);
        Some(Self { op, sha, spa, tha, tpa })
    }

    pub fn encode(&self) -> [u8; 28] {
        let mut out = [0u8; 28];
        out[0..2].copy_from_slice(&1u16.to_be_bytes());
        out[2..4].copy_from_slice(&ETH_TYPE_IPV4.to_be_bytes());
        out[4] = 6;
        out[5] = 4;
        out[6..8].copy_from_slice(&self.op.to_be_bytes());
        out[8..14].copy_from_slice(&self.sha);
        out[14..18].copy_from_slice(&self.spa);
        out[18..24].copy_from_slice(&self.tha);
        out[24..28].copy_from_slice(&self.tpa);
        out
    }
}

// ---- IPv4 ---------------------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ipv4Packet<'a> {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub proto: u8,
    pub ttl: u8,
    pub id: u16,
    pub payload: &'a [u8],
}

impl<'a> Ipv4Packet<'a> {
    pub fn parse(raw: &'a [u8]) -> Option<Self> {
        if raw.len() < 20 {
            return None;
        }
        let ver = raw[0] >> 4;
        let ihl = usize::from(raw[0] & 0x0F) * 4;
        if ver != 4 || ihl < 20 || ihl > raw.len() {
            return None;
        }
        let total_len = usize::from(be16(raw, 2));
        if total_len < ihl || total_len > raw.len() {
            return None;
        }
        // Drop fragmented IPv4 packets safely (MF bit or non-zero fragment offset).
        let flags_frag = be16(raw, 6);
        if (flags_frag & 0x3FFF) != 0 {
            return None;
        }
        if internet_checksum(&[&raw[..ihl]]) != 0 {
            return None;
        }
        let id = be16(raw, 4);
        let ttl = raw[8];
        let proto = raw[9];
        let src = [raw[12], raw[13], raw[14], raw[15]];
        let dst = [raw[16], raw[17], raw[18], raw[19]];
        Some(Self { src, dst, proto, ttl, id, payload: &raw[ihl..total_len] })
    }
}

pub fn build_ipv4(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, id: u16, ttl: u8, payload: &[u8]) -> Option<Vec<u8>> {
    let total = 20usize.checked_add(payload.len())?;
    if total > MTU {
        return None;
    }
    let mut out = Vec::with_capacity(total);
    out.push(0x45); // v4, IHL=5
    out.push(0x00); // DSCP/ECN
    out.extend_from_slice(&(total as u16).to_be_bytes());
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&0x4000u16.to_be_bytes()); // DF
    out.push(ttl);
    out.push(proto);
    out.extend_from_slice(&[0, 0]); // checksum placeholder
    out.extend_from_slice(&src);
    out.extend_from_slice(&dst);
    let csum = internet_checksum(&[&out[..20]]);
    out[10..12].copy_from_slice(&csum.to_be_bytes());
    out.extend_from_slice(payload);
    Some(out)
}

// ---- ICMPv4 -------------------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IcmpPacket<'a> {
    pub ty: u8,
    pub code: u8,
    pub id: u16,
    pub seq: u16,
    pub payload: &'a [u8],
}

impl<'a> IcmpPacket<'a> {
    pub fn parse(raw: &'a [u8]) -> Option<Self> {
        if raw.len() < 8 {
            return None;
        }
        if internet_checksum(&[raw]) != 0 {
            return None;
        }
        Some(Self {
            ty: raw[0],
            code: raw[1],
            id: be16(raw, 4),
            seq: be16(raw, 6),
            payload: &raw[8..],
        })
    }
}

pub fn build_icmp_echo(reply: bool, id: u16, seq: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + payload.len());
    out.push(if reply { ICMP_ECHO_REPLY } else { ICMP_ECHO_REQUEST });
    out.push(0);
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&seq.to_be_bytes());
    out.extend_from_slice(payload);
    let csum = internet_checksum(&[&out]);
    out[2..4].copy_from_slice(&csum.to_be_bytes());
    out
}

// ---- UDP ----------------------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UdpPacket<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub payload: &'a [u8],
}

impl<'a> UdpPacket<'a> {
    pub fn parse(src: Ipv4Addr, dst: Ipv4Addr, raw: &'a [u8]) -> Option<Self> {
        if raw.len() < 8 {
            return None;
        }
        let len = usize::from(be16(raw, 4));
        if len < 8 || len > raw.len() {
            return None;
        }
        let csum = be16(raw, 6);
        if csum != 0 && pseudo_checksum(src, dst, PROTO_UDP, &raw[..len]) != 0 {
            return None;
        }
        Some(Self {
            src_port: be16(raw, 0),
            dst_port: be16(raw, 2),
            payload: &raw[8..len],
        })
    }
}

pub fn build_udp(src: Ipv4Addr, dst: Ipv4Addr, src_port: u16, dst_port: u16, payload: &[u8]) -> Option<Vec<u8>> {
    let len = 8usize.checked_add(payload.len())?;
    if len > MTU - 20 {
        return None;
    }
    let mut out = Vec::with_capacity(len);
    out.extend_from_slice(&src_port.to_be_bytes());
    out.extend_from_slice(&dst_port.to_be_bytes());
    out.extend_from_slice(&(len as u16).to_be_bytes());
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(payload);
    let mut csum = pseudo_checksum(src, dst, PROTO_UDP, &out);
    if csum == 0 {
        csum = 0xFFFF;
    }
    out[6..8].copy_from_slice(&csum.to_be_bytes());
    Some(out)
}

// ---- TCP ----------------------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TcpSegment<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub window: u16,
    pub mss: Option<u16>,
    pub payload: &'a [u8],
}

impl<'a> TcpSegment<'a> {
    pub fn parse(src: Ipv4Addr, dst: Ipv4Addr, raw: &'a [u8]) -> Option<Self> {
        if raw.len() < 20 {
            return None;
        }
        let data_off = usize::from(raw[12] >> 4) * 4;
        if data_off < 20 || data_off > raw.len() {
            return None;
        }
        if pseudo_checksum(src, dst, PROTO_TCP, raw) != 0 {
            return None;
        }
        let mut mss = None;
        let opts = &raw[20..data_off];
        let mut i = 0;
        while i < opts.len() {
            match opts[i] {
                0 => break, // EOL
                1 => i += 1, // NOP
                kind => {
                    if i + 1 >= opts.len() {
                        break;
                    }
                    let olen = usize::from(opts[i + 1]);
                    if olen < 2 || i + olen > opts.len() {
                        break;
                    }
                    if kind == 2 && olen == 4 {
                        mss = Some(be16(opts, i + 2));
                    }
                    i += olen;
                }
            }
        }
        Some(Self {
            src_port: be16(raw, 0),
            dst_port: be16(raw, 2),
            seq: be32(raw, 4),
            ack: be32(raw, 8),
            flags: raw[13] & 0x3F,
            window: be16(raw, 14),
            mss,
            payload: &raw[data_off..],
        })
    }
}

#[allow(clippy::too_many_arguments)]
pub fn build_tcp(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    mss: Option<u16>,
    payload: &[u8],
) -> Option<Vec<u8>> {
    let hdr_len: usize = if mss.is_some() { 24 } else { 20 };
    let total = hdr_len.checked_add(payload.len())?;
    if total > MTU - 20 {
        return None;
    }
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&src_port.to_be_bytes());
    out.extend_from_slice(&dst_port.to_be_bytes());
    out.extend_from_slice(&seq.to_be_bytes());
    out.extend_from_slice(&ack.to_be_bytes());
    out.push(((hdr_len / 4) as u8) << 4);
    out.push(flags);
    out.extend_from_slice(&window.to_be_bytes());
    out.extend_from_slice(&[0, 0]); // checksum
    out.extend_from_slice(&[0, 0]); // urgent
    if let Some(m) = mss {
        out.extend_from_slice(&[2, 4, (m >> 8) as u8, m as u8]);
    }
    out.extend_from_slice(payload);
    let csum = pseudo_checksum(src, dst, PROTO_TCP, &out);
    out[16..18].copy_from_slice(&csum.to_be_bytes());
    Some(out)
}

// ---- DHCPv4 -------------------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DhcpOffer {
    pub xid: u32,
    pub msg_type: u8,
    pub your_ip: Ipv4Addr,
    pub server_ip: Ipv4Addr,
    pub subnet_mask: Ipv4Addr,
    pub router: Option<Ipv4Addr>,
    pub dns: Option<Ipv4Addr>,
    /// A second DNS server from option 6, if the server sent more than one.
    pub dns2: Option<Ipv4Addr>,
    pub lease_secs: u32,
    pub bootfile: String,
}

pub fn build_dhcp_packet(
    msg_type: u8,
    xid: u32,
    mac: MacAddr,
    requested_ip: Option<Ipv4Addr>,
    server_id: Option<Ipv4Addr>,
) -> Vec<u8> {
    let mut b = vec![0u8; 240];
    b[0] = 1; // BOOTREQUEST
    b[1] = 1; // Ethernet
    b[2] = 6; // MAC len
    b[4..8].copy_from_slice(&xid.to_be_bytes());
    b[10..12].copy_from_slice(&0x8000u16.to_be_bytes()); // broadcast flag
    b[28..34].copy_from_slice(&mac);
    b[236..240].copy_from_slice(&DHCP_MAGIC);

    // Option 53: DHCP Message Type
    b.extend_from_slice(&[53, 1, msg_type]);
    // Option 61: Client Identifier (type 1 = Ethernet + 6-byte MAC)
    b.extend_from_slice(&[61, 7, 1, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]]);
    // Option 57: Maximum DHCP Message Size (1500 bytes)
    b.extend_from_slice(&[57, 2, 0x05, 0xDC]);
    if let Some(ip) = requested_ip {
        b.extend_from_slice(&[50, 4, ip[0], ip[1], ip[2], ip[3]]);
    }
    if let Some(sid) = server_id {
        b.extend_from_slice(&[54, 4, sid[0], sid[1], sid[2], sid[3]]);
    }
    // Option 12: Host Name ("discrete-os")
    b.extend_from_slice(b"\x0c\x0bdiscrete-os");
    // Option 55: Parameter Request List (subnet, router, DNS, lease time)
    b.extend_from_slice(&[55, 4, 1, 3, 6, 51]);
    // Option 255: End
    b.push(255);
    if b.len() < 300 {
        b.resize(300, 0);
    }
    b
}

pub fn parse_dhcp(raw: &[u8], expect_mac: MacAddr) -> Option<DhcpOffer> {
    if raw.len() < 240 {
        return None;
    }
    if raw[0] != 2 || raw[1] != 1 || raw[2] != 6 {
        return None;
    }
    if raw[28..34] != expect_mac || raw[236..240] != DHCP_MAGIC {
        return None;
    }
    let xid = be32(raw, 4);
    let your_ip = [raw[16], raw[17], raw[18], raw[19]];
    let mut server_ip = [raw[20], raw[21], raw[22], raw[23]];
    let bf_raw = &raw[108..236];
    let bf_len = bf_raw.iter().position(|&c| c == 0).unwrap_or(bf_raw.len());
    let bootfile = String::from_utf8_lossy(&bf_raw[..bf_len]).into_owned();

    let mut msg_type = 0u8;
    let mut subnet_mask = [255, 255, 255, 0];
    let mut router = None;
    let mut dns = None;
    let mut dns2 = None;
    let mut lease_secs = 3600u32;

    let opts = &raw[240..];
    let mut i = 0;
    while i < opts.len() {
        match opts[i] {
            0 => i += 1,
            255 => break,
            code => {
                if i + 1 >= opts.len() {
                    break;
                }
                let len = usize::from(opts[i + 1]);
                if i + 2 + len > opts.len() {
                    return None;
                }
                let val = &opts[i + 2..i + 2 + len];
                match code {
                    53 if len == 1 => msg_type = val[0],
                    1 if len == 4 => subnet_mask.copy_from_slice(val),
                    3 if len >= 4 => router = Some([val[0], val[1], val[2], val[3]]),
                    6 if len >= 4 => {
                        dns = Some([val[0], val[1], val[2], val[3]]);
                        if len >= 8 {
                            dns2 = Some([val[4], val[5], val[6], val[7]]);
                        }
                    }
                    51 if len == 4 => lease_secs = be32(val, 0),
                    54 if len == 4 => server_ip.copy_from_slice(val),
                    _ => {}
                }
                i += 2 + len;
            }
        }
    }
    if msg_type == 0 {
        return None;
    }
    Some(DhcpOffer { xid, msg_type, your_ip, server_ip, subnet_mask, router, dns, dns2, lease_secs, bootfile })
}

// ---- DNS (RFC 1035) -----------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DnsAnswer {
    pub id: u16,
    pub ip: Ipv4Addr,
    pub ttl: u32,
}

/// Build a DNS standard query (A record, class IN, recursion desired).
pub fn build_dns_query(id: u16, hostname: &str) -> Option<Vec<u8>> {
    let name = hostname.trim_end_matches('.');
    if name.is_empty() || name.len() > 253 {
        return None;
    }
    let mut out = Vec::with_capacity(12 + name.len() + 6);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&0x0100u16.to_be_bytes()); // RD=1
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT=1
    out.extend_from_slice(&[0; 6]); // ANCOUNT/NSCOUNT/ARCOUNT = 0
    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 || !label.is_ascii() {
            return None;
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out.extend_from_slice(&1u16.to_be_bytes()); // QTYPE = A
    out.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN
    Some(out)
}

/// Skip a DNS name at `off`, strictly validating compression pointers (max 16 hops, no loops,
/// strictly in-bounds). Returns the byte offset immediately after the name in the stream.
fn skip_dns_name(pkt: &[u8], mut off: usize) -> Option<usize> {
    let mut jumped = false;
    let mut next_after = 0usize;
    let mut hops = 0usize;
    let mut labels = 0usize;
    loop {
        if off >= pkt.len() || labels > 128 {
            return None;
        }
        let len = pkt[off];
        if len == 0 {
            return Some(if jumped { next_after } else { off + 1 });
        }
        match len & 0xC0 {
            0xC0 => {
                if off + 1 >= pkt.len() || hops >= 16 {
                    return None;
                }
                let ptr = usize::from(u16::from_be_bytes([len & 0x3F, pkt[off + 1]]));
                // Compression pointers must reference an earlier offset (RFC 1035 §4.1.4) to prevent loops.
                if ptr >= off || ptr >= pkt.len() {
                    return None;
                }
                if !jumped {
                    next_after = off + 2;
                    jumped = true;
                }
                off = ptr;
                hops += 1;
            }
            0x00 => {
                let n = usize::from(len);
                off = off.checked_add(1 + n)?;
                if off > pkt.len() {
                    return None;
                }
                labels += 1;
            }
            _ => return None, // reserved label type
        }
    }
}

/// Parse a DNS response packet and return the first valid IPv4 A record matching `expect_id`.
pub fn parse_dns_response(pkt: &[u8], expect_id: u16) -> Option<DnsAnswer> {
    if pkt.len() < 12 {
        return None;
    }
    let id = be16(pkt, 0);
    if id != expect_id {
        return None;
    }
    let flags = be16(pkt, 2);
    // QR must be 1 (response), RCODE must be 0 (NOERROR).
    if (flags & 0x8000) == 0 || (flags & 0x000F) != 0 {
        return None;
    }
    let qdcount = be16(pkt, 4);
    let ancount = be16(pkt, 6);
    if qdcount > 16 || ancount == 0 || ancount > 64 {
        return None;
    }
    let mut off = 12usize;
    for _ in 0..qdcount {
        off = skip_dns_name(pkt, off)?;
        off = off.checked_add(4)?;
        if off > pkt.len() {
            return None;
        }
    }
    for _ in 0..ancount {
        off = skip_dns_name(pkt, off)?;
        if off + 10 > pkt.len() {
            return None;
        }
        let rtype = be16(pkt, off);
        let rclass = be16(pkt, off + 2);
        let ttl = be32(pkt, off + 4);
        let rdlen = usize::from(be16(pkt, off + 8));
        off += 10;
        if off + rdlen > pkt.len() {
            return None;
        }
        if rtype == 1 && rclass == 1 && rdlen == 4 {
            let ip = [pkt[off], pkt[off + 1], pkt[off + 2], pkt[off + 3]];
            return Some(DnsAnswer { id, ip, ttl });
        }
        off += rdlen;
    }
    None
}
