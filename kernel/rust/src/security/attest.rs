//! Remote attestation (docs/attestation.md): the `attest` and `attest_activate` syscalls.
//!
//! At boot the kernel makes an Ed25519 **attestation key** for this boot from the CPU's random
//! number generator and measures its public half into PCR 8, right after the kernel itself. A
//! program asks for a report with a remote party's nonce; the kernel fills in its measurement log
//! and PCRs and signs it (`doscrypt::attest`). The private key never leaves the kernel and dies with
//! the boot.
//!
//! With a TPM whose PCRs match the log, the report also carries the TPM's evidence: a TPM2_Quote of
//! PCRs 8 and 10 for the same nonce by a TPM-resident attestation key (ECC P-256, restricted
//! signing, a primary key of the endorsement hierarchy: the same key every boot), the endorsement
//! key (RSA 2048, the TCG template; the persistent one at 0x81010001 when present) and its
//! manufacturer certificate (NV 0x01C00002). A verifier checks the quote and the certificate, then
//! sends a credential challenge (`doscrypt::attest::challenge`) that only this TPM can open
//! (`activate`): the hardware vouches for the key that signed the report, as far as the TPM vendor's
//! CA is trusted.
//!
//! The TPM identity is made on the first request, not at boot: creating an RSA EK can take seconds
//! on a firmware TPM, and most boots never attest.

use alloc::vec::Vec;

use crate::security::measure;
use crate::security::tpm::{self, Key, Tpm};
use crate::sync::Mutex;
use doscrypt::attest::{self, Claims, Event, TpmEvidence};
use doscrypt::dsig;
use doscrypt::ed25519::SigningKey;
use doscrypt::sha2::Sha256;

/// The TPM's keys for attestation, loaded for the rest of the boot.
struct TpmIdentity {
    ak: Key,
    ek: Key,
    /// Created here (flushed with the identity), not the persistent EK.
    ek_transient: bool,
    ek_cert: Vec<u8>,
}

struct State {
    ak: Option<SigningKey>,
    flags: u32,
    firmware: u32,
    /// None: not tried yet; Some(None): the TPM could not make one (not tried again).
    tpm: Option<Option<TpmIdentity>>,
}

static STATE: Mutex<State> = Mutex::new(c"attest", State { ak: None, flags: 0, firmware: 0, tpm: None });

/// Boot (dkrnl_security_init, after the kernel's own measurement): make this boot's key and
/// measure it. `kernel_verified`: the loader checked the kernel's signature.
pub fn init(firmware: u32, kernel_verified: bool) -> [u8; 32] {
    let mut seed = [0u8; 32];
    let _ = crate::security::csprng::fill_bytes(&mut seed, 0);
    let key = SigningKey::from_seed(&seed);
    doscrypt::ct::wipe_bytes(&mut seed);
    let public = key.public();
    measure::measure(attest::PCR_KERNEL, &attest::ak_digest(&public), attest::AK_EVENT, false);
    let mut s = STATE.lock();
    s.ak = Some(key);
    s.firmware = firmware;
    s.flags = if kernel_verified { attest::F_KERNEL_VERIFIED } else { 0 };
    public
}

/// Make (or find) the EK and the AK, and read the EK certificate.
fn make_identity(t: &mut Tpm) -> Result<TpmIdentity, tpm::Error> {
    let (ek, ek_transient) = match t.read_public(tpm::EK_PERSISTENT) {
        Ok(k) if doscrypt::tpm::parse_rsa_ek(&k.public).is_some() => (k, false),
        _ => {
            let (tmpl, n) = doscrypt::tpm::ek_template();
            (t.create_primary(tpm::RH_ENDORSEMENT, &tmpl[..n])?, true)
        }
    };
    if doscrypt::tpm::parse_rsa_ek(&ek.public).is_none() {
        if ek_transient {
            t.flush(ek.handle);
        }
        return Err(tpm::Error::Protocol("the EK is not the TCG RSA 2048 EK"));
    }
    let (tmpl, n) = doscrypt::tpm::ak_template();
    let ak = match t.create_primary(tpm::RH_ENDORSEMENT, &tmpl[..n]) {
        Ok(k) => k,
        Err(e) => {
            if ek_transient {
                t.flush(ek.handle);
            }
            return Err(e);
        }
    };
    // The certificate is optional (some TPMs have none; the verifier then refuses or knows the EK).
    let ek_cert = t.nv_read_all(tpm::EK_CERT_NV_RSA, tpm::EK_CERT_MAX).unwrap_or_default();
    Ok(TpmIdentity { ak, ek, ek_transient, ek_cert })
}

/// The identity, made on first use (with the TPM, under the log lock).
fn identity(s: &mut State) -> Option<&TpmIdentity> {
    if s.tpm.is_none() {
        let made = measure::with_tpm(|t| match make_identity(t) {
            Ok(id) => Some(id),
            Err(e) => {
                crate::kprintln!("Attestation: the TPM could not make its attestation key ({:?}); reports carry no TPM evidence", e);
                None
            }
        })?;
        if let Some(id) = &made {
            crate::kprintln!(
                "Attestation: TPM attestation key ready (ECC P-256, endorsement hierarchy); EK {}, certificate {}",
                if id.ek_transient { "created" } else { "persistent" },
                if id.ek_cert.is_empty() { "none" } else { "read" }
            );
        }
        s.tpm = Some(made);
    }
    s.tpm.as_ref()?.as_ref()
}

/// One log event copied out of the log: text, text length, PCR, in TPM, digest.
type Copied = ([u8; attest::TEXT], usize, u8, bool, [u8; 32]);

/// A signed report for `nonce`.
pub fn report(nonce: &[u8; 32]) -> Option<Vec<u8>> {
    let mut s = STATE.lock();
    let id = identity(&mut s).map(|i| i.ak.handle);
    // Room for the whole log first: nothing allocates while the log is locked.
    let mut texts: Vec<Copied> = Vec::new();
    texts.try_reserve_exact(measure::LOG_MAX).ok()?;
    let mut oom = false;
    let (n, lost, pcrs, quote) = measure::snapshot_with_tpm(
        |e| {
            if texts.len() == texts.capacity() {
                oom = true;
                return;
            }
            let mut t = [0u8; attest::TEXT];
            let b = e.text().as_bytes();
            let k = b.len().min(attest::TEXT);
            t[..k].copy_from_slice(&b[..k]);
            texts.push((t, k, e.pcr, e.in_tpm, e.digest));
        },
        |t, pcrs| {
            // Quote only if the TPM's PCRs are the log's (the quote says which values it saw).
            let q = t.quote(id?, nonce, attest::QUOTED_PCRS).ok()?;
            let mut h = Sha256::new();
            h.update(&pcrs[usize::from(attest::PCR_KERNEL)]);
            h.update(&pcrs[usize::from(attest::PCR_CODE)]);
            let ok = doscrypt::tpm::parse_quote(&q.0).is_some_and(|p| p.pcr_digest == h.finish());
            ok.then_some(q)
        },
    );
    if oom || texts.len() != n {
        return None;
    }
    let events: Vec<Event<'_>> = texts
        .iter()
        .map(|(t, k, pcr, in_tpm, d)| Event { pcr: *pcr, in_tpm: *in_tpm, digest: *d, text: core::str::from_utf8(&t[..*k]).unwrap_or("?") })
        .collect();
    let quote = quote.flatten();
    let mut flags = 0;
    if measure::tpm_present() {
        flags |= attest::F_TPM;
        if quote.is_some() {
            flags |= attest::F_TPM_MATCH;
        }
    }
    let id = s.tpm.as_ref().and_then(|i| i.as_ref());
    let evidence = match (id, &quote) {
        (Some(id), Some((q, qs))) => Some(TpmEvidence { ak_public: &id.ak.public, quote: q, quote_sig: qs, ek_public: &id.ek.public, ek_cert: &id.ek_cert }),
        _ => None,
    };
    let ak = s.ak.as_ref()?;
    let c = Claims {
        flags: flags | s.flags,
        firmware: s.firmware,
        lost: lost.min(u64::from(u32::MAX)) as u32,
        nonce: *nonce,
        kernel_version: env!("CARGO_PKG_VERSION"),
        trusted_key_id: dsig::key_id(super::trusted_key()),
        pcr8: pcrs[usize::from(attest::PCR_KERNEL)],
        pcr10: pcrs[usize::from(attest::PCR_CODE)],
    };
    let size = attest::size(events.len(), evidence.as_ref().map_or(0, |e| e.size()));
    let mut out = Vec::new();
    out.try_reserve_exact(size).ok()?;
    out.resize(size, 0);
    let len = attest::build(&c, &events, evidence.as_ref(), ak, &mut out)?;
    out.truncate(len);
    Some(out)
}

/// Why `activate` gave nothing back.
#[derive(Debug, PartialEq, Eq)]
pub enum ActivateError {
    /// No TPM, or it could not make the attestation key.
    NoTpm,
    /// The TPM refused: the challenge is not for this TPM's EK and AK (or is damaged).
    Refused,
}

/// Answer a verifier's credential challenge (`doscrypt::attest::challenge`): the TPM opens it
/// only if it was made for its EK and its attestation key.
pub fn activate(blob: &[u8; doscrypt::tpm::ID_OBJECT], secret: &[u8; doscrypt::tpm::SECRET]) -> Result<[u8; 32], ActivateError> {
    let mut s = STATE.lock();
    let (ak, ek) = identity(&mut s).map(|i| (i.ak.handle, i.ek.handle)).ok_or(ActivateError::NoTpm)?;
    match measure::with_tpm(|t| t.activate_credential(ak, ek, blob, secret)) {
        Some(Ok(c)) => Ok(c),
        Some(Err(_)) => Err(ActivateError::Refused),
        None => Err(ActivateError::NoTpm),
    }
}

/// Test builds: forget the TPM identity (the selftest's simulated TPM goes away).
#[cfg(ktest)]
pub fn forget_tpm() {
    let mut s = STATE.lock();
    if let Some(Some(id)) = s.tpm.take() {
        measure::with_tpm(|t| {
            t.flush(id.ak.handle);
            if id.ek_transient {
                t.flush(id.ek.handle);
            }
        });
    }
}
