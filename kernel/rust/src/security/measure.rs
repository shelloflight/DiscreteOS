//! Measured boot: the kernel's measurement log and its software PCRs (SHA-256 bank, the TPM's
//! extend rule: PCR' = SHA-256(PCR || digest)). Every event also goes to the TPM when there is one;
//! events recorded before the TPM was found are replayed into it, except those the loader already
//! put there (UEFI TCG2). The log is what a verifier replays to check a TPM quote (section 6,
//! attestation): with a TPM, the hardware PCRs must equal the software ones.
//!
//! PCR map (docs/signing.md): 8 kernel (its signed .dsig header), 10 code the kernel verified or
//! was allowed to run unsigned (programs, drivers).

use crate::kprintln;
use crate::security::tpm::Tpm;
use crate::sync::Mutex;
use doscrypt::sha2::Sha256;

pub const PCRS: usize = 24;
pub const PCR_KERNEL: u8 = 8;
pub const PCR_CODE: u8 = 10;
pub const LOG_MAX: usize = 256;
pub const TEXT_MAX: usize = 56;

#[derive(Clone, Copy)]
pub struct Event {
    pub pcr: u8,
    /// Extended into the TPM (by the loader or by the kernel).
    pub in_tpm: bool,
    pub digest: [u8; 32],
    text: [u8; TEXT_MAX],
    len: u8,
}

impl Event {
    const EMPTY: Event = Event { pcr: 0, in_tpm: false, digest: [0; 32], text: [0; TEXT_MAX], len: 0 };
    pub fn text(&self) -> &str {
        core::str::from_utf8(&self.text[..self.len as usize]).unwrap_or("?")
    }
}

struct Log {
    pcrs: [[u8; 32]; PCRS],
    events: [Event; LOG_MAX],
    n: usize,
    /// Events beyond LOG_MAX: still extended, but the log can no longer explain the PCRs.
    lost: u64,
    tpm: Option<Tpm>,
    tpm_errors: u64,
}

static LOG: Mutex<Log> = Mutex::new(
    c"measure",
    Log { pcrs: [[0; 32]; PCRS], events: [Event::EMPTY; LOG_MAX], n: 0, lost: 0, tpm: None, tpm_errors: 0 },
);

pub fn extend(pcr: &[u8; 32], digest: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(pcr);
    h.update(digest);
    h.finish()
}

fn to_tpm(l: &mut Log, pcr: u8, digest: &[u8; 32]) -> bool {
    let Some(t) = l.tpm.as_mut() else { return false };
    match t.pcr_extend(u32::from(pcr), digest) {
        Ok(()) => true,
        Err(e) => {
            l.tpm_errors += 1;
            kprintln!("TPM: PCR {} extend failed ({:?}); the kernel log keeps the measurement", pcr, e);
            false
        }
    }
}

/// Record `digest` in `pcr` with a description. `in_tpm`: the loader already extended the TPM.
pub fn measure(pcr: u8, digest: &[u8; 32], text: &str, in_tpm: bool) {
    let mut l = LOG.lock();
    let p = usize::from(pcr).min(PCRS - 1);
    l.pcrs[p] = extend(&l.pcrs[p], digest);
    let in_tpm = in_tpm || to_tpm(&mut l, pcr, digest);
    if l.n == LOG_MAX {
        l.lost += 1;
        return;
    }
    let mut e = Event { pcr, in_tpm, digest: *digest, text: [0; TEXT_MAX], len: 0 };
    let t = text.as_bytes();
    let k = t.len().min(TEXT_MAX);
    e.text[..k].copy_from_slice(&t[..k]);
    e.len = k as u8;
    let n = l.n;
    l.events[n] = e;
    l.n += 1;
}

/// A TPM was found: replay what it does not have yet, then use it for every new event.
/// Returns the number of events replayed.
pub fn attach_tpm(t: Tpm) -> usize {
    let mut l = LOG.lock();
    l.tpm = Some(t);
    let mut replayed = 0;
    for i in 0..l.n {
        if l.events[i].in_tpm {
            continue;
        }
        let (pcr, d) = (l.events[i].pcr, l.events[i].digest);
        if to_tpm(&mut l, pcr, &d) {
            l.events[i].in_tpm = true;
            replayed += 1;
        }
    }
    replayed
}

pub fn pcr(i: usize) -> [u8; 32] {
    LOG.lock().pcrs[i.min(PCRS - 1)]
}

/// Visit the log (holding the lock): `f(index, event)`. Returns (events, lost).
pub fn for_each(mut f: impl FnMut(usize, &Event)) -> (usize, u64) {
    let l = LOG.lock();
    for (i, e) in l.events.iter().enumerate().take(l.n) {
        f(i, e);
    }
    (l.n, l.lost)
}

/// The log and the PCRs at one instant (attestation: a measurement in between would make them
/// disagree): `f(event)` for each event; returns (events, lost, PCRs).
pub fn snapshot(mut f: impl FnMut(&Event)) -> (usize, u64, [[u8; 32]; PCRS]) {
    let l = LOG.lock();
    for e in l.events.iter().take(l.n) {
        f(e);
    }
    (l.n, l.lost, l.pcrs)
}

/// Like `snapshot`, and `g(tpm, PCRs)` under the same lock when there is a TPM (attestation:
/// the TPM quotes exactly the PCRs reported).
pub fn snapshot_with_tpm<R>(
    mut f: impl FnMut(&Event),
    g: impl FnOnce(&mut Tpm, &[[u8; 32]; PCRS]) -> R,
) -> (usize, u64, [[u8; 32]; PCRS], Option<R>) {
    let mut l = LOG.lock();
    for e in l.events.iter().take(l.n) {
        f(e);
    }
    let pcrs = l.pcrs;
    let r = l.tpm.as_mut().map(|t| g(t, &pcrs));
    (l.n, l.lost, pcrs, r)
}

/// `f(tpm)` under the log lock; None without a TPM.
pub fn with_tpm<R>(f: impl FnOnce(&mut Tpm) -> R) -> Option<R> {
    LOG.lock().tpm.as_mut().map(f)
}

/// With a TPM: does every PCR the log touched match the hardware? (selftest, attestation)
pub fn tpm_matches() -> Option<bool> {
    let mut l = LOG.lock();
    let pcrs = l.pcrs;
    let used: u32 = (0..l.n).fold(0, |m, i| m | 1 << l.events[i].pcr);
    let t = l.tpm.as_mut()?;
    Some((0..PCRS).filter(|i| used & (1 << i) != 0).all(|i| t.pcr_read(i as u32) == Ok(pcrs[i])))
}

pub fn tpm_present() -> bool {
    LOG.lock().tpm.is_some()
}

/// Test builds: drop the TPM (the selftest attaches a simulator and must leave no trace).
#[cfg(ktest)]
pub fn detach_tpm() {
    let mut l = LOG.lock();
    l.tpm = None;
    let n = l.n;
    for e in l.events.iter_mut().take(n) {
        e.in_tpm = false; // the next TPM attached gets the whole log replayed
    }
}
