//! ACPI table fuzzing (ktest `fuzz`).
//!
//! Firmware tables are untrusted input. Every parser the kernel runs on one is fed mutated copies
//! of real tables (from the machine, here QEMU's) and of hand-built ones covering the entry kinds
//! the machine may not have:
//!   - MADT (C, `acpi_madt_check`): CPUs, I/O APICs, overrides, x2APIC entries;
//!   - MCFG (`pci::parse_mcfg_bytes`), DMAR (`vtd::fuzz_dmar`), IVRS (`amdvi::fuzz_ivrs`),
//!     TPM2 (`tpm::parse_tpm2`);
//!   - DSDT `\_S5` (C, `power_parse_s5`): the AML scanner behind ACPI power-off.
//! Each copy is its own exact-size heap allocation, so with KASAN (`kasan-fuzz`) a read one byte
//! past the table is reported. A parser must not panic or fault, and what it returns must hold
//! the invariants its callers rely on (bounded counts, aligned addresses, no CPU twice).

use alloc::vec::Vec;

use crate::dev::iommu::{amdvi, vtd};
use crate::dev::pci;
use crate::ffi;
use crate::security::tpm;

unsafe extern "C" {
    fn acpi_madt_check(table: *const u8, len: u32) -> i32;
    fn power_parse_s5(aml: *const u8, len: u32, a: *mut u8, b: *mut u8) -> i32;
    fn acpi_table_at(phys: u64, len: *mut u32) -> *const u8;
}

const ROUNDS: u32 = 20_000;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        if n == 0 { 0 } else { (self.next() % n as u64) as usize }
    }
}

fn header(sig: &[u8; 4], len: usize) -> Vec<u8> {
    let mut t = alloc::vec![0u8; len];
    t[0..4].copy_from_slice(sig);
    t[4..8].copy_from_slice(&(len as u32).to_le_bytes());
    t[8] = 1;
    t
}

/// Hand-built seeds: every entry kind each parser understands.
fn synthetic() -> Vec<(&'static [u8; 4], Vec<u8>)> {
    let mut v = Vec::new();
    // MADT: LAPIC, x2APIC (duplicate id), I/O APIC, override, LAPIC address override, unknown.
    let mut m = header(b"APIC", 44);
    m[36..40].copy_from_slice(&0xFEE0_0000u32.to_le_bytes());
    for e in [
        &[0u8, 8, 0, 0, 1, 0, 0, 0][..],
        &[0, 8, 1, 1, 1, 0, 0, 0],
        &[9, 16, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0],
        &[1, 12, 0, 0, 0, 0, 0xC0, 0xFE, 0, 0, 0, 0],
        &[2, 10, 0, 0, 2, 0, 0, 0, 0, 0],
        &[5, 12, 0, 0, 0, 0, 0xE0, 0xFE, 0, 0, 0, 0],
        &[0x7F, 4, 0, 0],
    ] {
        m.extend_from_slice(e);
    }
    let n = m.len() as u32;
    m[4..8].copy_from_slice(&n.to_le_bytes());
    v.push((b"APIC", m));
    // MCFG: one allocation (segment 0, buses 0-255).
    let mut c = header(b"MCFG", 60);
    c[44..52].copy_from_slice(&0xB000_0000u64.to_le_bytes());
    c[55] = 255;
    v.push((b"MCFG", c));
    // DMAR: one DRHD with an endpoint and a bridge scope, an RMRR.
    let mut d = header(b"DMAR", 48);
    d[36] = 38;
    let mut drhd = alloc::vec![0u8, 0, 32, 0, 1, 0, 0, 0];
    drhd.extend_from_slice(&0xFED9_0000u64.to_le_bytes());
    drhd.extend_from_slice(&[1, 8, 0, 0, 0, 0, 2, 0]);
    drhd.extend_from_slice(&[2, 8, 0, 0, 0, 0, 3, 1]);
    d.extend_from_slice(&drhd[..32]);
    d.extend_from_slice(&[1, 0, 24, 0, 0, 0, 0, 0]);
    d.extend_from_slice(&[0; 16]);
    let n = d.len() as u32;
    d[4..8].copy_from_slice(&n.to_le_bytes());
    v.push((b"DMAR", d));
    // IVRS: IVHD 10h (select, range, alias range, extended select, special, ACPI HID, unknown)
    // and IVHD 11h for the same unit, an IVMD.
    let mut r = header(b"IVRS", 48);
    let mut ents: Vec<u8> = Vec::new();
    for e in [
        &[2u8, 0x10, 0, 0][..],
        &[3, 0, 1, 0],
        &[4, 0xFF, 1, 0],
        &[0x43, 0, 2, 0, 0, 0x08, 0, 0],
        &[4, 0xFF, 2, 0],
        &[0x46, 0x18, 0, 0, 0, 0, 0, 0],
        &[0x48, 0, 0, 0, 0xA0, 0, 0, 1],
        &[0xF0, 0x20, 0, 0, b'A', b'M', b'D', b'I', b'0', b'0', b'4', b'0', 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, b'0', b'1'],
        &[1, 0, 0, 0],
        &[0x7E, 0, 0, 0, 0, 0, 0, 0],
    ] {
        ents.extend_from_slice(e);
    }
    for (ty, hdr) in [(0x10u8, 24usize), (0x11, 40)] {
        let mut h = alloc::vec![0u8; hdr];
        h[0] = ty;
        h[2..4].copy_from_slice(&((hdr + ents.len()) as u16).to_le_bytes());
        h[4] = 0x10;
        h[6] = 0x40;
        h[8..16].copy_from_slice(&0xFED8_0000u64.to_le_bytes());
        r.extend_from_slice(&h);
        r.extend_from_slice(&ents);
    }
    r.extend_from_slice(&[0x21, 8, 32, 0, 0x10, 0, 0, 0]);
    r.extend_from_slice(&[0; 24]);
    let n = r.len() as u32;
    r[4..8].copy_from_slice(&n.to_le_bytes());
    v.push((b"IVRS", r));
    // DSDT: Name(\_S5, Package(4) {0x05, One, Zero, Zero}) after some other AML.
    let mut s = header(b"DSDT", 36);
    s.extend_from_slice(&[0x10, 0x05, 0x5C, 0x5F, 0x53, 0x42, 0x5F]); // Scope(\_SB_) {}
    s.extend_from_slice(&[0x08, 0x5C, b'_', b'S', b'5', b'_', 0x12, 0x08, 0x04, 0x0A, 0x05, 0x01, 0x00, 0x00]);
    s.extend_from_slice(&[0x08, b'_', b'S', b'4', b'_', 0x12, 0x06, 0x04, 0x0B, 0x07, 0x00, 0xFF]);
    let n = s.len() as u32;
    s[4..8].copy_from_slice(&n.to_le_bytes());
    v.push((b"DSDT", s));
    // TPM2: CRB start method with a control area.
    let mut t = header(b"TPM2", 52);
    t[40..48].copy_from_slice(&0xFED4_0040u64.to_le_bytes());
    t[48..52].copy_from_slice(&7u32.to_le_bytes());
    v.push((b"TPM2", t));
    v
}

fn real(sig: &'static [u8; 4]) -> Option<Vec<u8>> {
    let mut len = 0u32;
    // SAFETY: a validated, mapped table of `len` bytes, or NULL.
    let t = unsafe { ffi::acpi_find_table(sig.as_ptr(), &mut len) };
    if t.is_null() {
        return None;
    }
    // SAFETY: as above; copied out.
    Some(unsafe { core::slice::from_raw_parts(t, len as usize) }.to_vec())
}

fn mutate(rng: &mut Rng, buf: &mut Vec<u8>) {
    let n = 1 + rng.below(8);
    for _ in 0..n {
        if buf.is_empty() {
            return;
        }
        // Mostly the header and the first entries, where the lengths and counts are.
        let span = if rng.next() % 4 == 0 { buf.len() } else { buf.len().min(96) };
        let at = rng.below(span);
        match rng.next() % 6 {
            0 => buf[at] ^= 1 << (rng.next() % 8),
            1 => buf[at] = rng.next() as u8,
            2 => buf[at] = [0x00, 0xFF, 0x7F, 0x80, 0x01, 0x02][rng.below(6)],
            3 => {
                let w = at & !1;
                if w + 2 <= buf.len() {
                    let v = [0u16, 0xFFFF, 1, 2, 3, 4][rng.below(6)];
                    buf[w..w + 2].copy_from_slice(&v.to_le_bytes());
                }
            }
            4 => {
                let new = rng.below(buf.len() + 1);
                buf.truncate(new);
            }
            _ => {
                let w = at & !7;
                if w + 8 <= buf.len() {
                    let v = [0u64, u64::MAX, 1 << 63, 4096, 1 << 46, rng.next()][rng.below(6)];
                    buf[w..w + 8].copy_from_slice(&v.to_le_bytes());
                }
            }
        }
    }
}

fn check(sig: &[u8; 4], b: &[u8]) -> u32 {
    // Each parser sees every table (a wrong signature must be harmless too).
    // SAFETY: `b` is a live allocation of exactly b.len() bytes.
    let madt = unsafe { acpi_madt_check(b.as_ptr(), b.len() as u32) };
    if madt != 0 {
        crate::kprintln!("  FAIL acpi fuzz: MADT parser broke invariant {} on a {} table", madt, sig_str(sig));
        return 1;
    }
    if let Some((base, start, end)) = pci::parse_mcfg_bytes(b)
        && (base == 0 || base % (1 << 20) != 0 || start > end || base >= 1 << 46)
    {
        crate::kprintln!("  FAIL acpi fuzz: MCFG gave base {:#x} buses {}-{}", base, start, end);
        return 1;
    }
    let d = vtd::fuzz_dmar(b);
    if d != 0 {
        crate::kprintln!("  FAIL acpi fuzz: DMAR parser broke invariant {}", d);
        return 1;
    }
    let r = amdvi::fuzz_ivrs(b);
    if r != 0 {
        crate::kprintln!("  FAIL acpi fuzz: IVRS parser broke invariant {}", r);
        return 1;
    }
    let _ = tpm::parse_tpm2(b);
    if b.len() > 36 {
        let (mut ta, mut tb) = (0xEEu8, 0xEEu8);
        // SAFETY: `b[36..]` is live for its length; the outputs are locals.
        let r = unsafe { power_parse_s5(b.as_ptr().add(36), (b.len() - 36) as u32, &mut ta, &mut tb) };
        if r == 0 && (ta > 7 || tb > 7) {
            crate::kprintln!("  FAIL acpi fuzz: \\_S5 parser gave SLP_TYP {}/{}", ta, tb);
            return 1;
        }
    }
    0
}

/// The machine's DSDT (through the FADT's pointer), if it has one.
fn real_dsdt() -> Option<Vec<u8>> {
    let f = real(b"FACP")?;
    let mut phys = 0u64;
    if f.len() >= 148 {
        phys = u64::from_le_bytes(f[140..148].try_into().ok()?);
    }
    if phys == 0 && f.len() >= 44 {
        phys = u64::from(u32::from_le_bytes(f[40..44].try_into().ok()?));
    }
    let mut len = 0u32;
    // SAFETY: a validated, mapped table of `len` bytes, or NULL.
    let t = unsafe { acpi_table_at(phys, &mut len) };
    if t.is_null() {
        return None;
    }
    // SAFETY: as above; copied out.
    Some(unsafe { core::slice::from_raw_parts(t, len as usize) }.to_vec())
}

fn sig_str(sig: &[u8; 4]) -> &str {
    core::str::from_utf8(sig).unwrap_or("????")
}

#[unsafe(no_mangle)]
pub extern "C" fn rust_acpi_fuzz() -> u32 {
    let mut rng = Rng(0xA5A5_0000_1234_5678 ^ ffi::now_ns() | 1);
    let mut seeds = synthetic();
    let mut found = 0;
    for sig in [b"APIC", b"MCFG", b"DMAR", b"IVRS", b"TPM2", b"FACP", b"HPET"] {
        if let Some(t) = real(sig) {
            seeds.push((sig, t));
            found += 1;
        }
    }
    if let Some(t) = real_dsdt() {
        seeds.push((b"DSDT", t));
        found += 1;
    }
    let mut failures = 0;
    let mut runs = 0u64;
    for (sig, seed) in &seeds {
        failures += check(sig, seed);
        for _ in 0..ROUNDS {
            let mut b = seed.clone();
            mutate(&mut rng, &mut b);
            // An exact-size copy: KASAN catches a read past the end.
            let mut exact = Vec::new();
            if exact.try_reserve_exact(b.len()).is_err() {
                return failures + 1;
            }
            exact.extend_from_slice(&b);
            failures += check(sig, &exact);
            runs += 1;
            if failures > 10 {
                return failures;
            }
        }
    }
    crate::kprintln!(
        "acpi fuzz: {} mutated tables ({} seeds: {} from this machine, {} built) through the MADT, MCFG, DMAR, IVRS, TPM2 and \\_S5 parsers, {} failures",
        runs,
        seeds.len(),
        found,
        seeds.len() - found,
        failures
    );
    failures
}
