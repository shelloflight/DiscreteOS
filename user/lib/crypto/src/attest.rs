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
//! With a TPM, the report also carries the TPM's own evidence: a **quote** of PCRs 8 and 10 for the
//! same nonce, signed by the TPM's attestation key (AK), and the TPM's endorsement key (EK) with its
//! manufacturer certificate. The quote ties the report to the TPM's PCRs; the certificate ties the
//! EK to a real TPM; `challenge` (answered by the kernel's `attest_activate`) proves the AK lives in
//! the TPM that holds that EK.
//!
//! Layout (little-endian), `HEADER` bytes, then `count` events of `EVENT` bytes, then the TPM
//! evidence (`u32` length, then five fields of `u16` length + bytes: AK `TPMT_PUBLIC`, quote
//! `TPMS_ATTEST`, quote `TPMT_SIGNATURE`, EK `TPMT_PUBLIC`, EK certificate (DER, may be empty);
//! length 0 without a TPM), then the signature:
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
//! | e | 4 + t | TPM evidence (t bytes, at most `TPM_MAX`) |
//! | end | 64 | Ed25519 signature of everything before it, by the attestation key |

use crate::dsig;
use crate::ed25519::{self, SigningKey};
use crate::sha2::{Sha256, sha256};
use crate::{tpm, x509};

pub const MAGIC: &[u8; 8] = b"DOSATT01";
pub const VERSION: u32 = 2;
pub const HEADER: usize = 188;
pub const EVENT: usize = 92;
pub const TEXT: usize = 56;
pub const SIG: usize = 64;
pub const MAX_EVENTS: usize = 256;
/// Largest TPM evidence section (its five fields).
pub const TPM_MAX: usize = 2816;
/// The largest report (a full log and TPM evidence).
pub const MAX_SIZE: usize = HEADER + MAX_EVENTS * EVENT + 4 + TPM_MAX + SIG;
/// The PCRs the TPM quotes: 8 and 10.
pub const QUOTED_PCRS: u32 = (1 << PCR_KERNEL) | (1 << PCR_CODE);

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

pub fn size(events: usize, tpm: usize) -> usize {
    HEADER + events * EVENT + 4 + tpm + SIG
}

/// What the TPM says, as the kernel got it (TPM wire formats, unchanged).
#[derive(Clone, Copy)]
pub struct TpmEvidence<'a> {
    pub ak_public: &'a [u8],
    pub quote: &'a [u8],
    pub quote_sig: &'a [u8],
    pub ek_public: &'a [u8],
    pub ek_cert: &'a [u8],
}

impl<'a> TpmEvidence<'a> {
    fn fields(&self) -> [&'a [u8]; 5] {
        [self.ak_public, self.quote, self.quote_sig, self.ek_public, self.ek_cert]
    }
    /// Its size in a report (without the u32 length).
    pub fn size(&self) -> usize {
        self.fields().iter().map(|f| 2 + f.len()).sum()
    }
    fn parse(b: &'a [u8]) -> Option<TpmEvidence<'a>> {
        let mut f: [&[u8]; 5] = [&[]; 5];
        let mut o = 0;
        for x in f.iter_mut() {
            let n = usize::from(u16::from_le_bytes([*b.get(o)?, *b.get(o + 1)?]));
            *x = b.get(o + 2..o + 2 + n)?;
            o += 2 + n;
        }
        (o == b.len()).then_some(TpmEvidence { ak_public: f[0], quote: f[1], quote_sig: f[2], ek_public: f[3], ek_cert: f[4] })
    }
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

/// Write a signed report into `out` (at least `size(events, tpm)` bytes); returns its length.
pub fn build(c: &Claims<'_>, events: &[Event<'_>], tpm: Option<&TpmEvidence<'_>>, ak: &SigningKey, out: &mut [u8]) -> Option<usize> {
    let tlen = tpm.map_or(0, |t| t.size());
    let n = size(events.len(), tlen);
    if events.len() > MAX_EVENTS || tlen > TPM_MAX || out.len() < n {
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
    let mut at = HEADER + events.len() * EVENT;
    o[at..at + 4].copy_from_slice(&(tlen as u32).to_le_bytes());
    at += 4;
    if let Some(t) = tpm {
        for f in t.fields() {
            o[at..at + 2].copy_from_slice(&(f.len() as u16).to_le_bytes());
            o[at + 2..at + 2 + f.len()].copy_from_slice(f);
            at += 2 + f.len();
        }
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
    /// The policy requires TPM evidence and the report has none.
    TpmRequired,
    /// The TPM evidence is malformed, or its EK is not an EK (the TCG RSA 2048 template).
    TpmFormat,
    /// The TPM's quote does not verify for this report (signature, nonce, PCRs 8 and 10).
    Quote(tpm::QuoteError),
    /// The EK certificate names another key than the TPM's EK.
    EkMismatch,
    /// The EK certificate is missing, malformed or not signed by an issuer the verifier trusts.
    EkUntrusted,
}

/// What the TPM evidence of a verified report established.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TpmStatus {
    /// No TPM evidence (no TPM, or its PCRs did not match the log).
    None,
    /// The TPM quoted PCRs 8 and 10 for this nonce; its EK was not checked (no issuers given).
    Quoted,
    /// Quoted, and the EK's certificate is signed by an issuer the verifier trusts.
    Certified,
}

/// What the verifier trusts (its reference values) and accepts.
pub struct Policy<'a> {
    /// The reference kernel's `.dsig` (KERNEL.DSIG of the release being checked against).
    pub kernel_dsig: &'a [u8],
    /// The D-OS signing public key.
    pub key: &'a [u8; 32],
    /// Accept programs the VMEX authority allowed to run unsigned (PCR 10 "unsigned ..." events).
    pub allow_unsigned: bool,
    /// Refuse reports without TPM evidence.
    pub require_tpm: bool,
    /// Certificates (DER) of the EK certificate issuers trusted (TPM vendors' CAs). Empty: the EK
    /// certificate is not checked.
    pub ek_issuers: &'a [&'a [u8]],
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
    pub tpm: TpmStatus,
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
    if r.len() < size(0, 0) || &r[0..8] != MAGIC || u32_at(r, 8) != VERSION {
        return Err(Error::Format);
    }
    let count = u32_at(r, 184) as usize;
    if count > MAX_EVENTS || r.len() < size(count, 0) {
        return Err(Error::Format);
    }
    let tlen = u32_at(r, HEADER + count * EVENT) as usize;
    if tlen > TPM_MAX || r.len() != size(count, tlen) {
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
    let mut v = Verified {
        flags: u32_at(r, 12),
        firmware: u32_at(r, 16),
        kernel_version: [0; 16],
        events: count,
        signed_code: 0,
        unsigned_code: 0,
        decisions: 0,
        ak,
        tpm: TpmStatus::None,
    };
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
    v.tpm = verify_tpm(r, count, tlen, nonce, p)?;
    Ok(v)
}

fn evidence(r: &[u8], count: usize, tlen: usize) -> Result<Option<TpmEvidence<'_>>, Error> {
    if tlen == 0 {
        return Ok(None);
    }
    let at = HEADER + count * EVENT + 4;
    TpmEvidence::parse(&r[at..at + tlen]).map(Some).ok_or(Error::TpmFormat)
}

/// The TPM evidence: the quote of PCRs 8 and 10 (the values the log replay just confirmed) for
/// this nonce, by a TPM attestation key; the EK; its certificate against the trusted issuers.
fn verify_tpm(r: &[u8], count: usize, tlen: usize, nonce: &[u8; 32], p: &Policy<'_>) -> Result<TpmStatus, Error> {
    let Some(t) = evidence(r, count, tlen)? else {
        return if p.require_tpm { Err(Error::TpmRequired) } else { Ok(TpmStatus::None) };
    };
    let pcrs = [(PCR_KERNEL, arr32(&r[120..152])), (PCR_CODE, arr32(&r[152..184]))];
    tpm::verify_quote(t.ak_public, t.quote, t.quote_sig, nonce, &pcrs).map_err(Error::Quote)?;
    let ek = tpm::parse_rsa_ek(t.ek_public).ok_or(Error::TpmFormat)?;
    if p.ek_issuers.is_empty() {
        return Ok(TpmStatus::Quoted);
    }
    let cert = x509::parse(t.ek_cert).ok_or(Error::EkUntrusted)?;
    if cert.rsa_n != ek.modulus || cert.rsa_e != ek.exponent {
        return Err(Error::EkMismatch);
    }
    let trusted = p.ek_issuers.iter().filter_map(|i| x509::parse(i)).any(|i| cert.signed_by(&i));
    if trusted { Ok(TpmStatus::Certified) } else { Err(Error::EkUntrusted) }
}

/// A report's TPM evidence, if it has well-formed evidence (nothing is verified: use `verify`).
pub fn tpm_evidence(r: &[u8]) -> Option<TpmEvidence<'_>> {
    if r.len() < size(0, 0) || &r[0..8] != MAGIC {
        return None;
    }
    let count = u32_at(r, 184) as usize;
    if count > MAX_EVENTS || r.len() < size(count, 0) {
        return None;
    }
    let tlen = u32_at(r, HEADER + count * EVENT) as usize;
    if tlen > TPM_MAX || r.len() != size(count, tlen) {
        return None;
    }
    evidence(r, count, tlen).ok()?
}

/// A credential challenge for a report `verify` accepted with TPM evidence: `credential` (the
/// verifier's fresh secret) encrypted to the report's EK, bound to its AK. Only the TPM holding
/// that EK, with that AK loaded, can give `credential` back (the kernel's `attest_activate`).
/// `seed` and `oaep_seed`: fresh random bytes. None without TPM evidence.
pub fn challenge(
    r: &[u8],
    credential: &[u8; 32],
    seed: &[u8; 32],
    oaep_seed: &[u8; 32],
) -> Option<([u8; tpm::ID_OBJECT], [u8; tpm::SECRET])> {
    let t = tpm_evidence(r)?;
    let ak = tpm::parse_ecc_public(t.ak_public)?;
    let ek = tpm::parse_rsa_ek(t.ek_public)?;
    tpm::make_credential(&ek, &ak.name, credential, seed, oaep_seed)
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
        let n = build(&c, &events, None, &f.ak, &mut out).unwrap();
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
        let p = Policy { kernel_dsig: &f.dsig, key: &f.key, allow_unsigned: false, require_tpm: false, ek_issuers: &[] };
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
        let p = Policy { kernel_dsig: &f.dsig, key: &f.key, allow_unsigned: false, require_tpm: false, ek_issuers: &[] };
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
