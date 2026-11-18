//! Remote attestation reports (docs/attestation.md): one format for the kernel,
//! which builds and signs them, and for verifiers (`dosimg attest-verify`), which check them.
//!
//! A report answers "what is this machine running?" for a remote party, fresh for its question:
//! - the party's 32-byte **nonce** (so an old report cannot be replayed);
//! - the kernel's identity: version, the key its loader verified it with, its **measurement log**
//!   (every event: PCR, digest, description) and the resulting **PCRs 8 and 10**;
//! - the per-boot **attestation key** (Ed25519) that signs the report. Its public half is itself an
//!   event in PCR 8, right after the kernel, so it is part of the measured chain (and of the TPM's
//!   PCR 8 when there is a TPM).
//!
//! Layout (little-endian), `HEADER` bytes, then `count` events of `EVENT` bytes, then the signature:
//!
//! | off | size | field |
//! |---|---|---|
//! | 0 | 8 | magic `DOSATT01` |
//! | 8 | 4 | version (1) |
//! | 12 | 4 | flags (`F_*`) |
//! | 16 | 4 | firmware (1 BIOS, 2 UEFI) |
//! | 20 | 4 | events lost (log overflow; must be 0 to verify) |
//! | 24 | 32 | nonce |
//! | 56 | 16 | kernel version (ASCII, NUL-padded) |
//! | 72 | 16 | key id of the key the kernel trusts (`dsig::key_id`) |
//! | 88 | 32 | attestation public key |
//! | 120 | 32 | PCR 8 |
//! | 152 | 32 | PCR 10 |
//! | 184 | 4 | event count |
//! | 188 | 92 × n | events: pcr, in_tpm, text length, 0, digest (32), text (56) |
//! | end | 64 | Ed25519 signature of everything before it, by the attestation key |

use crate::dsig;
use crate::ed25519::{self, SigningKey};
use crate::sha2::{Sha256, sha256};

pub const MAGIC: &[u8; 8] = b"DOSATT01";
pub const VERSION: u32 = 1;
pub const HEADER: usize = 188;
pub const EVENT: usize = 92;
pub const TEXT: usize = 56;
pub const SIG: usize = 64;
pub const MAX_EVENTS: usize = 256;
/// The largest report (a full log).
pub const MAX_SIZE: usize = HEADER + MAX_EVENTS * EVENT + SIG;

/// A TPM was found and used for the measurements.
pub const F_TPM: u32 = 1;
/// The TPM's PCRs equal the log's (read back when the report was made).
pub const F_TPM_MATCH: u32 = 2;
/// The loader verified the kernel's signature (BootInfo).
pub const F_KERNEL_VERIFIED: u32 = 4;

pub const PCR_KERNEL: u8 = 8;
pub const PCR_CODE: u8 = 10;
/// Description of the attestation key's event in PCR 8.
pub const AK_EVENT: &str = "attestation key (this boot)";

pub fn size(events: usize) -> usize {
    HEADER + events * EVENT + SIG
}

/// The digest measured for an attestation public key.
pub fn ak_digest(public: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"D-OS attestation key v1");
    h.update(public);
    h.finish()
}

#[derive(Clone, Copy)]
pub struct Event<'a> {
    pub pcr: u8,
    pub in_tpm: bool,
    pub digest: [u8; 32],
    pub text: &'a str,
}

pub struct Claims<'a> {
    pub flags: u32,
    pub firmware: u32,
    pub lost: u32,
    pub nonce: [u8; 32],
    pub kernel_version: &'a str,
    pub trusted_key_id: [u8; 16],
    pub pcr8: [u8; 32],
    pub pcr10: [u8; 32],
}

/// Write a signed report into `out` (at least `size(events.len())` bytes); returns its length.
pub fn build(c: &Claims<'_>, events: &[Event<'_>], ak: &SigningKey, out: &mut [u8]) -> Option<usize> {
    let n = size(events.len());
    if events.len() > MAX_EVENTS || out.len() < n {
        return None;
    }
    let o = &mut out[..n];
    o.fill(0);
    o[0..8].copy_from_slice(MAGIC);
    o[8..12].copy_from_slice(&VERSION.to_le_bytes());
    o[12..16].copy_from_slice(&c.flags.to_le_bytes());
    o[16..20].copy_from_slice(&c.firmware.to_le_bytes());
    o[20..24].copy_from_slice(&c.lost.to_le_bytes());
    o[24..56].copy_from_slice(&c.nonce);
    let v = c.kernel_version.as_bytes();
    let k = v.len().min(16);
    o[56..56 + k].copy_from_slice(&v[..k]);
    o[72..88].copy_from_slice(&c.trusted_key_id);
    o[88..120].copy_from_slice(&ak.public());
    o[120..152].copy_from_slice(&c.pcr8);
    o[152..184].copy_from_slice(&c.pcr10);
    o[184..188].copy_from_slice(&(events.len() as u32).to_le_bytes());
    for (i, e) in events.iter().enumerate() {
        let r = &mut o[HEADER + i * EVENT..HEADER + (i + 1) * EVENT];
        let t = e.text.as_bytes();
        let tl = t.len().min(TEXT);
        r[0] = e.pcr;
        r[1] = u8::from(e.in_tpm);
        r[2] = tl as u8;
        r[4..36].copy_from_slice(&e.digest);
        r[36..36 + tl].copy_from_slice(&t[..tl]);
    }
    let body = n - SIG;
    let sig = ak.sign(&o[..body]);
    o[body..].copy_from_slice(&sig);
    Some(n)
}

/// Why a report was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Not a report, or a size that does not match its event count.
    Format,
    /// The signature does not verify with the report's attestation key.
    Signature,
    /// Not the nonce the verifier asked with (replayed or for someone else).
    Nonce,
    /// The log overflowed: it cannot explain the PCRs.
    LogIncomplete,
    /// Replaying the log does not give the reported PCRs.
    PcrMismatch,
    /// The attestation key is not the event right after the kernel in PCR 8.
    KeyNotMeasured,
    /// The kernel is not the reference kernel (another build, or modified).
    UnknownKernel,
    /// The kernel trusts another signing key than the reference one.
    UnknownKey,
    /// The loader did not verify the kernel.
    KernelUnverified,
    /// Code ran that was allowed unsigned (and the policy forbids it).
    UnsignedCode,
}

/// What the verifier trusts (its reference values) and accepts.
pub struct Policy<'a> {
    /// The reference kernel's `.dsig` (KERNEL.DSIG of the release being checked against).
    pub kernel_dsig: &'a [u8],
    /// The D-OS signing public key.
    pub key: &'a [u8; 32],
    /// Accept programs the VMEX authority allowed to run unsigned (PCR 10 "unsigned ..." events).
    pub allow_unsigned: bool,
}

/// A verified report's facts.
#[derive(Debug)]
pub struct Verified {
    pub flags: u32,
    pub firmware: u32,
    pub kernel_version: [u8; 16],
    pub events: usize,
    pub signed_code: usize,
    pub unsigned_code: usize,
    /// Service manager decisions (PCR 10 "svc ..." events: manifests accepted or refused).
    pub decisions: usize,
    pub ak: [u8; 32],
}

fn u32_at(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

fn arr32(b: &[u8]) -> [u8; 32] {
    let mut a = [0; 32];
    a.copy_from_slice(&b[..32]);
    a
}

/// Check `r` against the nonce the verifier sent and its policy. Every check must pass.
pub fn verify(r: &[u8], nonce: &[u8; 32], p: &Policy<'_>) -> Result<Verified, Error> {
    if r.len() < size(0) || &r[0..8] != MAGIC || u32_at(r, 8) != VERSION {
        return Err(Error::Format);
    }
    let count = u32_at(r, 184) as usize;
    if count > MAX_EVENTS || r.len() != size(count) {
        return Err(Error::Format);
    }
    let body = r.len() - SIG;
    let ak = arr32(&r[88..120]);
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&r[body..]);
    if !ed25519::verify(&ak, &r[..body], &sig) {
        return Err(Error::Signature);
    }
    if &r[24..56] != nonce {
        return Err(Error::Nonce);
    }
    if u32_at(r, 20) != 0 {
        return Err(Error::LogIncomplete);
    }
    // Replay the log.
    let (mut pcr8, mut pcr10) = ([0u8; 32], [0u8; 32]);
    let mut v = Verified { flags: u32_at(r, 12), firmware: u32_at(r, 16), kernel_version: [0; 16], events: count, signed_code: 0, unsigned_code: 0, decisions: 0, ak };
    v.kernel_version.copy_from_slice(&r[56..72]);
    let mut kernel_events = 0;
    let want_kernel = sha256(p.kernel_dsig.get(..dsig::SIGNED).ok_or(Error::UnknownKernel)?);
    for i in 0..count {
        let e = &r[HEADER + i * EVENT..HEADER + (i + 1) * EVENT];
        let (pcr, tl) = (e[0], usize::from(e[2]));
        if tl > TEXT || e[3] != 0 {
            return Err(Error::Format);
        }
        let digest = arr32(&e[4..36]);
        let text = &e[36..36 + tl];
        let target = match pcr {
            PCR_KERNEL => &mut pcr8,
            PCR_CODE => &mut pcr10,
            _ => return Err(Error::Format),
        };
        let mut h = Sha256::new();
        h.update(target);
        h.update(&digest);
        *target = h.finish();
        if pcr == PCR_KERNEL {
            // PCR 8 holds exactly: the kernel, then this boot's attestation key.
            match kernel_events {
                0 if digest == want_kernel => {}
                0 => return Err(Error::UnknownKernel),
                1 if digest == ak_digest(&ak) && text == AK_EVENT.as_bytes() => {}
                _ => return Err(Error::KeyNotMeasured),
            }
            kernel_events += 1;
        } else if text.starts_with(b"unsigned ") {
            v.unsigned_code += 1;
        } else if text.starts_with(b"svc ") {
            v.decisions += 1;
        } else {
            v.signed_code += 1;
        }
    }
    if pcr8 != arr32(&r[120..152]) || pcr10 != arr32(&r[152..184]) {
        return Err(Error::PcrMismatch);
    }
    if kernel_events != 2 {
        return Err(if kernel_events == 0 { Error::UnknownKernel } else { Error::KeyNotMeasured });
    }
    if r[72..88] != dsig::key_id(p.key) {
        return Err(Error::UnknownKey);
    }
    if v.flags & F_KERNEL_VERIFIED == 0 {
        return Err(Error::KernelUnverified);
    }
    if v.unsigned_code > 0 && !p.allow_unsigned {
        return Err(Error::UnsignedCode);
    }
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use std::vec;
    use std::vec::Vec;

    struct Fixture {
        dsig: Vec<u8>,
        key: [u8; 32],
        ak: SigningKey,
    }

    fn fixture() -> Fixture {
        let signer = SigningKey::from_seed(&[7; 32]);
        let dsig = dsig::sign(&signer, dsig::KIND_KERNEL, "KERNEL.BIN", b"kernel image bytes").to_vec();
        Fixture { dsig, key: signer.public(), ak: SigningKey::from_seed(&[9; 32]) }
    }

    /// A report as the kernel makes it; `edit` changes the events before the PCRs are computed.
    fn report(f: &Fixture, nonce: [u8; 32], unsigned: bool, edit: impl FnOnce(&mut Vec<(u8, [u8; 32], &'static str)>)) -> Vec<u8> {
        let mut ev: Vec<(u8, [u8; 32], &'static str)> = vec![
            (PCR_KERNEL, sha256(&f.dsig[..dsig::SIGNED]), "kernel KERNEL.BIN (.dsig header)"),
            (PCR_KERNEL, ak_digest(&f.ak.public()), AK_EVENT),
            (PCR_CODE, [3; 32], "signed hello.dx"),
        ];
        if unsigned {
            ev.push((PCR_CODE, [4; 32], "unsigned w1.exe"));
        }
        edit(&mut ev);
        let (mut p8, mut p10) = ([0u8; 32], [0u8; 32]);
        for (pcr, d, _) in &ev {
            let t = if *pcr == PCR_KERNEL { &mut p8 } else { &mut p10 };
            let mut h = Sha256::new();
            h.update(t);
            h.update(d);
            *t = h.finish();
        }
        let events: Vec<Event<'_>> = ev.iter().map(|(pcr, d, t)| Event { pcr: *pcr, in_tpm: false, digest: *d, text: t }).collect();
        let c = Claims {
            flags: F_KERNEL_VERIFIED,
            firmware: 2,
            lost: 0,
            nonce,
            kernel_version: "0.13.5",
            trusted_key_id: dsig::key_id(&f.key),
            pcr8: p8,
            pcr10: p10,
        };
        let mut out = vec![0u8; MAX_SIZE];
        let n = build(&c, &events, &f.ak, &mut out).unwrap();
        out.truncate(n);
        out
    }

    fn resign(f: &Fixture, r: &mut [u8]) {
        let body = r.len() - SIG;
        let s = f.ak.sign(&r[..body]);
        r[body..].copy_from_slice(&s);
    }

    #[test]
    fn good_report_verifies() {
        let f = fixture();
        let r = report(&f, [1; 32], false, |_| {});
        let p = Policy { kernel_dsig: &f.dsig, key: &f.key, allow_unsigned: false };
        let v = verify(&r, &[1; 32], &p).unwrap();
        assert_eq!((v.events, v.signed_code, v.unsigned_code), (3, 1, 0));
        assert_eq!(&v.kernel_version[..6], b"0.13.5");
        // Service manager decisions are counted on their own, never as code.
        let r = report(&f, [1; 32], false, |ev| ev.push((PCR_CODE, [5; 32], "svc accept storaged")));
        let v = verify(&r, &[1; 32], &p).unwrap();
        assert_eq!((v.events, v.signed_code, v.unsigned_code, v.decisions), (4, 1, 0, 1));
    }

    #[test]
    fn every_kind_of_bad_report_is_refused() {
        let f = fixture();
        let p = Policy { kernel_dsig: &f.dsig, key: &f.key, allow_unsigned: false };
        let good = report(&f, [1; 32], false, |_| {});
        // Any changed byte breaks the signature.
        for at in [0, 30, 100, 130, HEADER + 5, good.len() - 1] {
            let mut r = good.clone();
            r[at] ^= 1;
            assert!(verify(&r, &[1; 32], &p).is_err(), "byte {}", at);
        }
        let mut r = good.clone();
        r[HEADER + 40] ^= 1; // an event's text
        assert_eq!(verify(&r, &[1; 32], &p).unwrap_err(), Error::Signature);
        assert_eq!(verify(&good[..good.len() - 1], &[1; 32], &p).unwrap_err(), Error::Format);
        assert_eq!(verify(&good, &[2; 32], &p).unwrap_err(), Error::Nonce);
        // Re-signed by whoever holds the key, but inconsistent: caught by the replay and the policy.
        let mut r = good.clone();
        r[125] ^= 1; // PCR 8
        resign(&f, &mut r);
        assert_eq!(verify(&r, &[1; 32], &p).unwrap_err(), Error::PcrMismatch);
        let mut r = good.clone();
        r[20] = 1; // events lost
        resign(&f, &mut r);
        assert_eq!(verify(&r, &[1; 32], &p).unwrap_err(), Error::LogIncomplete);
        let other = report(&f, [1; 32], false, |ev| ev[0].1 = [5; 32]); // another kernel
        assert_eq!(verify(&other, &[1; 32], &p).unwrap_err(), Error::UnknownKernel);
        let nokey = report(&f, [1; 32], false, |ev| {
            ev.remove(1);
        });
        assert_eq!(verify(&nokey, &[1; 32], &p).unwrap_err(), Error::KeyNotMeasured);
        let wrongkey = report(&f, [1; 32], false, |ev| ev[1].1 = [6; 32]);
        assert_eq!(verify(&wrongkey, &[1; 32], &p).unwrap_err(), Error::KeyNotMeasured);
        let mut r = good.clone();
        r[72] ^= 1; // trusted key id
        resign(&f, &mut r);
        assert_eq!(verify(&r, &[1; 32], &p).unwrap_err(), Error::UnknownKey);
        let mut r = good.clone();
        r[12] = 0; // loader did not verify the kernel
        resign(&f, &mut r);
        assert_eq!(verify(&r, &[1; 32], &p).unwrap_err(), Error::KernelUnverified);
        let uns = report(&f, [1; 32], true, |_| {});
        assert_eq!(verify(&uns, &[1; 32], &p).unwrap_err(), Error::UnsignedCode);
        let lenient = Policy { allow_unsigned: true, ..p };
        assert_eq!(verify(&uns, &[1; 32], &lenient).unwrap().unsigned_code, 1);
    }
}
