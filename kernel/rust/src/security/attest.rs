//! Remote attestation (docs/attestation.md): the `attest` syscall.
//!
//! At boot the kernel makes an Ed25519 **attestation key** for this boot from the CPU's random
//! number generator and measures its public half into PCR 8, right after the kernel itself. A
//! program asks for a report with a remote party's nonce; the kernel fills in its measurement log
//! and PCRs and signs it (`doscrypt::attest`). The private key never leaves the kernel and dies with
//! the boot.
//!
//! What a report proves depends on the root of the chain. The loader verified the kernel's
//! signature, the kernel measured itself and every program it ran: a verifier that trusts the
//! signed D-OS kernel learns exactly which kernel and which code ran, for this nonce. Without a TPM
//! quote nothing below the kernel vouches for the key (a kernel modified *and* re-signed with the
//! D-OS key could lie): the hardware-rooted step (TPM2_Quote over PCR 8 with a TPM-resident key) is
//! future work, see the doc.

use alloc::vec::Vec;

use crate::ffi;
use crate::security::measure;
use crate::sync::Mutex;
use doscrypt::attest::{self, Claims, Event};
use doscrypt::dsig;
use doscrypt::ed25519::SigningKey;
use doscrypt::sha2::Sha256;

struct State {
    ak: Option<SigningKey>,
    flags: u32,
    firmware: u32,
}

static STATE: Mutex<State> = Mutex::new(c"attest", State { ak: None, flags: 0, firmware: 0 });

/// Boot (dkrnl_security_init, after the kernel's own measurement): make this boot's key and
/// measure it. `kernel_verified`: the loader checked the kernel's signature.
pub fn init(firmware: u32, kernel_verified: bool) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"D-OS attestation key seed");
    for _ in 0..8 {
        // SAFETY: reads the CPU's random number generator (RDSEED/RDRAND, TSC fallback).
        h.update(&unsafe { ffi::cpu_random64() }.to_le_bytes());
    }
    let mut seed = h.finish();
    let key = SigningKey::from_seed(&seed);
    seed.fill(0);
    let public = key.public();
    measure::measure(attest::PCR_KERNEL, &attest::ak_digest(&public), attest::AK_EVENT, false);
    let mut s = STATE.lock();
    s.ak = Some(key);
    s.firmware = firmware;
    s.flags = if kernel_verified { attest::F_KERNEL_VERIFIED } else { 0 };
    public
}

/// One log event copied out of the log: text, text length, PCR, in TPM, digest.
type Copied = ([u8; attest::TEXT], usize, u8, bool, [u8; 32]);

/// A signed report for `nonce`.
pub fn report(nonce: &[u8; 32]) -> Option<Vec<u8>> {
    // Room for the whole log first: nothing allocates while the log is locked.
    let mut texts: Vec<Copied> = Vec::new();
    texts.try_reserve_exact(measure::LOG_MAX).ok()?;
    let mut oom = false;
    let (n, lost, pcrs) = measure::snapshot(|e| {
        if texts.len() == texts.capacity() {
            oom = true;
            return;
        }
        let mut t = [0u8; attest::TEXT];
        let s = e.text().as_bytes();
        let k = s.len().min(attest::TEXT);
        t[..k].copy_from_slice(&s[..k]);
        texts.push((t, k, e.pcr, e.in_tpm, e.digest));
    });
    if oom || texts.len() != n {
        return None;
    }
    let events: Vec<Event<'_>> = texts
        .iter()
        .map(|(t, k, pcr, in_tpm, d)| Event { pcr: *pcr, in_tpm: *in_tpm, digest: *d, text: core::str::from_utf8(&t[..*k]).unwrap_or("?") })
        .collect();
    let mut flags = 0;
    if measure::tpm_present() {
        flags |= attest::F_TPM;
        if measure::tpm_matches() == Some(true) {
            flags |= attest::F_TPM_MATCH;
        }
    }
    let s = STATE.lock();
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
    let mut out = Vec::new();
    out.try_reserve_exact(attest::size(events.len())).ok()?;
    out.resize(attest::size(events.len()), 0);
    let len = attest::build(&c, &events, ak, &mut out)?;
    out.truncate(len);
    Some(out)
}
