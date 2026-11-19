//! Test helpers: an AML builder (byte code without an ASL compiler) and simulated hardware.
#![allow(dead_code)]

use std::collections::BTreeMap;

use aml::Handler;

// ---- AML builder ------------------------------------------------------------------------------

/// A PkgLength that counts itself and `body` bytes.
pub fn pkglen(body: usize) -> Vec<u8> {
    for n in 1..=4usize {
        let total = body + n;
        let ok = match n {
            1 => total < 0x40,
            2 => total < 1 << 12,
            3 => total < 1 << 20,
            _ => total < 1 << 28,
        };
        if ok {
            return raw_len_n(total, n);
        }
    }
    panic!("package too large");
}

/// A PkgLength-encoded plain number (field element bit counts).
pub fn rawlen(v: usize) -> Vec<u8> {
    let n = if v < 0x40 {
        1
    } else if v < 1 << 12 {
        2
    } else if v < 1 << 20 {
        3
    } else {
        4
    };
    raw_len_n(v, n)
}

fn raw_len_n(v: usize, n: usize) -> Vec<u8> {
    if n == 1 {
        return vec![v as u8];
    }
    let mut out = vec![(((n - 1) as u8) << 6) | (v & 0xF) as u8];
    for i in 0..n - 1 {
        out.push((v >> (4 + 8 * i)) as u8);
    }
    out
}

pub fn cat(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

pub fn pkg(op: &[u8], body: Vec<u8>) -> Vec<u8> {
    let mut v = op.to_vec();
    v.extend(pkglen(body.len()));
    v.extend(body);
    v
}

fn seg(s: &str) -> [u8; 4] {
    let mut out = [b'_'; 4];
    out[..s.len()].copy_from_slice(s.as_bytes());
    out
}

/// A NameString from text: `\_SB.PCI0`, `^FOO`, `BAR`.
pub fn ns(path: &str) -> Vec<u8> {
    let mut v = Vec::new();
    let mut rest = path;
    if let Some(r) = rest.strip_prefix('\\') {
        v.push(b'\\');
        rest = r;
    }
    while let Some(r) = rest.strip_prefix('^') {
        v.push(b'^');
        rest = r;
    }
    if rest.is_empty() {
        v.push(0);
        return v;
    }
    let segs: Vec<[u8; 4]> = rest.split('.').map(seg).collect();
    match segs.len() {
        1 => {}
        2 => v.push(0x2E),
        n => {
            v.push(0x2F);
            v.push(n as u8);
        }
    }
    for s in segs {
        v.extend_from_slice(&s);
    }
    v
}

pub fn int(x: u64) -> Vec<u8> {
    match x {
        0 => vec![0x00],
        1 => vec![0x01],
        x if x <= 0xFF => vec![0x0A, x as u8],
        x if x <= 0xFFFF => cat(&[&[0x0B], &(x as u16).to_le_bytes()]),
        x if x <= 0xFFFF_FFFF => cat(&[&[0x0C], &(x as u32).to_le_bytes()]),
        x => cat(&[&[0x0E], &x.to_le_bytes()]),
    }
}

pub const ONES: &[u8] = &[0xFF];
pub const ZERO: &[u8] = &[0x00];

pub fn string(s: &str) -> Vec<u8> {
    cat(&[&[0x0D], s.as_bytes(), &[0]])
}

pub fn buffer(b: &[u8]) -> Vec<u8> {
    pkg(&[0x11], cat(&[&int(b.len() as u64), b]))
}

pub fn package(el: &[Vec<u8>]) -> Vec<u8> {
    let mut body = vec![el.len() as u8];
    for e in el {
        body.extend(e);
    }
    pkg(&[0x12], body)
}

pub fn name(n: &str, v: Vec<u8>) -> Vec<u8> {
    cat(&[&[0x08], &ns(n), &v])
}

pub fn method(n: &str, args: u8, body: Vec<u8>) -> Vec<u8> {
    pkg(&[0x14], cat(&[&ns(n), &[args], &body]))
}

pub fn scope(n: &str, body: Vec<u8>) -> Vec<u8> {
    pkg(&[0x10], cat(&[&ns(n), &body]))
}

pub fn device(n: &str, body: Vec<u8>) -> Vec<u8> {
    pkg(&[0x5B, 0x82], cat(&[&ns(n), &body]))
}

pub fn store(src: Vec<u8>, dst: Vec<u8>) -> Vec<u8> {
    cat(&[&[0x70], &src, &dst])
}

pub fn ret(v: Vec<u8>) -> Vec<u8> {
    cat(&[&[0xA4], &v])
}

pub fn if_(pred: Vec<u8>, body: Vec<u8>) -> Vec<u8> {
    pkg(&[0xA0], cat(&[&pred, &body]))
}

pub fn else_(body: Vec<u8>) -> Vec<u8> {
    pkg(&[0xA1], body)
}

pub fn while_(pred: Vec<u8>, body: Vec<u8>) -> Vec<u8> {
    pkg(&[0xA2], cat(&[&pred, &body]))
}

pub fn op2(op: u8, a: Vec<u8>, b: Vec<u8>, t: Vec<u8>) -> Vec<u8> {
    cat(&[&[op], &a, &b, &t])
}

pub fn add(a: Vec<u8>, b: Vec<u8>, t: Vec<u8>) -> Vec<u8> {
    op2(0x72, a, b, t)
}

pub fn lequal(a: Vec<u8>, b: Vec<u8>) -> Vec<u8> {
    cat(&[&[0x93], &a, &b])
}

pub fn lless(a: Vec<u8>, b: Vec<u8>) -> Vec<u8> {
    cat(&[&[0x95], &a, &b])
}

pub fn incr(t: Vec<u8>) -> Vec<u8> {
    cat(&[&[0x75], &t])
}

pub fn local(i: u8) -> Vec<u8> {
    vec![0x60 + i]
}

pub fn arg(i: u8) -> Vec<u8> {
    vec![0x68 + i]
}

pub fn index(src: Vec<u8>, i: Vec<u8>, t: Vec<u8>) -> Vec<u8> {
    cat(&[&[0x88], &src, &i, &t])
}

pub fn derefof(v: Vec<u8>) -> Vec<u8> {
    cat(&[&[0x83], &v])
}

pub fn sizeof(v: Vec<u8>) -> Vec<u8> {
    cat(&[&[0x87], &v])
}

pub fn call(n: &str, args: &[Vec<u8>]) -> Vec<u8> {
    let mut v = ns(n);
    for a in args {
        v.extend(a);
    }
    v
}

pub fn opregion(n: &str, space: u8, off: u64, len: u64) -> Vec<u8> {
    cat(&[&[0x5B, 0x80], &ns(n), &[space], &int(off), &int(len)])
}

/// Field(region, flags) { name: bits, ... }; an empty name is a reserved gap.
pub fn field(region: &str, flags: u8, elems: &[(&str, usize)]) -> Vec<u8> {
    let mut body = cat(&[&ns(region), &[flags]]);
    for (n, bits) in elems {
        if n.is_empty() {
            body.push(0);
        } else {
            body.extend_from_slice(&seg(n));
        }
        body.extend(rawlen(*bits));
    }
    pkg(&[0x5B, 0x81], body)
}

pub fn index_field(idx: &str, data: &str, flags: u8, elems: &[(&str, usize)]) -> Vec<u8> {
    let mut body = cat(&[&ns(idx), &ns(data), &[flags]]);
    for (n, bits) in elems {
        if n.is_empty() {
            body.push(0);
        } else {
            body.extend_from_slice(&seg(n));
        }
        body.extend(rawlen(*bits));
    }
    pkg(&[0x5B, 0x86], body)
}

/// A DSDT (or SSDT) with a valid header and checksum.
pub fn table(sig: &[u8; 4], rev: u8, body: &[u8]) -> Vec<u8> {
    let len = 36 + body.len();
    let mut t = Vec::with_capacity(len);
    t.extend_from_slice(sig);
    t.extend_from_slice(&(len as u32).to_le_bytes());
    t.push(rev);
    t.push(0);
    t.extend_from_slice(b"D-OS  ");
    t.extend_from_slice(b"TESTTABL");
    t.extend_from_slice(&1u32.to_le_bytes());
    t.extend_from_slice(b"DOS ");
    t.extend_from_slice(&1u32.to_le_bytes());
    t.extend_from_slice(body);
    let sum = t.iter().fold(0u8, |a, &b| a.wrapping_add(b));
    t[9] = 0u8.wrapping_sub(sum);
    t
}

pub fn dsdt(body: &[u8]) -> Vec<u8> {
    table(b"DSDT", 2, body)
}

// ---- simulated hardware -----------------------------------------------------------------------

/// (segment, bus, device, function).
pub type Pci = (u16, u8, u8, u8);

#[derive(Default)]
pub struct Sim {
    pub io: BTreeMap<u16, u8>,
    pub mem: BTreeMap<u64, u8>,
    pub pci: BTreeMap<(Pci, u16), u8>,
    pub io_writes: Vec<(u16, u8, u64)>,
    pub notifies: Vec<(String, u64)>,
    pub debug: Vec<String>,
    pub slept_ms: u64,
    pub clock: u64,
    /// Stack depth measurement: the highest address seen (outermost frame) and the deepest use.
    pub stack_top: usize,
    pub stack_deepest: usize,
}

impl Handler for Sim {
    fn read_io(&mut self, port: u16, width: u8) -> Result<u64, aml::Refused> {
        Ok((0..width as u16).fold(0, |v, i| {
            v | (*self.io.get(&port.wrapping_add(i)).unwrap_or(&0) as u64) << (8 * i)
        }))
    }
    fn write_io(&mut self, port: u16, width: u8, value: u64) -> Result<(), aml::Refused> {
        self.io_writes.push((port, width, value));
        for i in 0..width as u16 {
            self.io
                .insert(port.wrapping_add(i), (value >> (8 * i)) as u8);
        }
        Ok(())
    }
    fn read_mem(&mut self, addr: u64, width: u8) -> Result<u64, aml::Refused> {
        Ok((0..width as u64).fold(0, |v, i| {
            v | (*self.mem.get(&addr.wrapping_add(i)).unwrap_or(&0) as u64) << (8 * i)
        }))
    }
    fn write_mem(&mut self, addr: u64, width: u8, value: u64) -> Result<(), aml::Refused> {
        for i in 0..width as u64 {
            self.mem
                .insert(addr.wrapping_add(i), (value >> (8 * i)) as u8);
        }
        Ok(())
    }
    fn read_pci(
        &mut self,
        pci: (u16, u8, u8, u8),
        offset: u16,
        width: u8,
    ) -> Result<u64, aml::Refused> {
        Ok((0..width as u16).fold(0, |v, i| {
            v | (*self.pci.get(&(pci, offset + i)).unwrap_or(&0) as u64) << (8 * i)
        }))
    }
    fn write_pci(
        &mut self,
        pci: (u16, u8, u8, u8),
        offset: u16,
        width: u8,
        value: u64,
    ) -> Result<(), aml::Refused> {
        for i in 0..width as u16 {
            self.pci.insert((pci, offset + i), (value >> (8 * i)) as u8);
        }
        Ok(())
    }
    fn stall_us(&mut self, us: u64) {
        self.clock += us * 10;
    }
    fn sleep_ms(&mut self, ms: u64) {
        self.slept_ms += ms;
        self.clock += ms * 10_000;
    }
    fn timer(&mut self) -> u64 {
        self.clock += 1;
        self.clock
    }
    fn notify(&mut self, path: &str, value: u64) {
        self.notifies.push((path.to_string(), value));
    }
    fn debug(&mut self, text: &str) {
        self.debug.push(text.to_string());
    }
    fn stack_ok(&mut self) -> bool {
        let here = 0u8;
        let sp = std::hint::black_box(&here) as *const u8 as usize;
        if sp > self.stack_top {
            self.stack_top = sp;
        }
        self.stack_deepest = self.stack_deepest.max(self.stack_top - sp);
        true
    }
}

/// A small deterministic random generator for the fuzzers.
pub struct Rng(pub u64);

impl Rng {
    pub fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    pub fn below(&mut self, n: u64) -> u64 {
        if n == 0 { 0 } else { self.next() % n }
    }
}
