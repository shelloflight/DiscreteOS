//! In-tree, `no_std`, zero-unsafe networking stack and strict TLS 1.3 client (`dosnet`).
//!
//! - [`wire`]: strict bounds-checked parsers/serializers for Ethernet II, ARP, IPv4, ICMPv4,
//!   UDP, TCP, DHCPv4, and DNS (with compression-pointer loop & bounds protection).
//! - [`arp`]: bounded ARP neighbor cache with TTL aging and pending transmit queue.
//! - [`tcp`]: RFC 9293 TCP state machine with sequence windowing, retransmission backoff,
//!   and bounded per-connection buffers.
//! - [`stack`]: sans-IO [`stack::NetStack`] engine combining L2..L4, DHCP, DNS, and ICMP ping.
//! - [`tls`]: strict TLS 1.3 (RFC 8446) client over `doscrypt` (X25519 + ChaCha20-Poly1305 +
//!   HKDF-SHA256 + RSA-PSS/ECDSA-P256/Ed25519 + full X.509 chain/SAN/expiry verification).

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod arp;
pub mod roots;
pub mod ssh;
pub mod stack;
pub mod tcp;
pub mod tls;
pub mod wire;

#[cfg(test)]
extern crate std;
#[cfg(test)]
mod tests;

pub type Ipv4Addr = [u8; 4];
pub type MacAddr = [u8; 6];

pub const MAC_BROADCAST: MacAddr = [0xFF; 6];
pub const IP_UNSPECIFIED: Ipv4Addr = [0, 0, 0, 0];
pub const IP_BROADCAST: Ipv4Addr = [255, 255, 255, 255];

/// Parse a strict dotted-decimal IPv4 literal (no leading zeros, 4 octets).
pub fn parse_ipv4(s: &str) -> Option<Ipv4Addr> {
    let mut out = [0u8; 4];
    let mut n = 0usize;
    for part in s.split('.') {
        if n >= 4 || part.is_empty() || (part.len() > 1 && part.starts_with('0')) {
            return None;
        }
        out[n] = part.parse::<u8>().ok()?;
        n += 1;
    }
    (n == 4).then_some(out)
}

/// Format an IPv4 address as `a.b.c.d`.
pub fn fmt_ipv4(ip: Ipv4Addr) -> alloc::string::String {
    alloc::format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
}

/// Format a MAC address as `aa:bb:cc:dd:ee:ff`.
pub fn fmt_mac(mac: MacAddr) -> alloc::string::String {
    alloc::format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}
