//! Kernel cryptographic random number generator (CSPRNG).
//!
//! Fast-Key-Erasure ChaCha20 design (256-bit key, backtracking-resistant):
//! - Seeded at boot from hardware entropy (`RDSEED` / `RDRAND`), mixed with monotonic/boot timing
//!   via SHA-256, and augmented with 32 bytes from `TPM2_GetRandom` when a TPM 2.0 is present.
//! - Every read generates `(new_key || output)` from a single ChaCha20 stream, immediately replaces
//!   the internal 256-bit key with `new_key`, and wipes the temporary keystream block with
//!   `write_volatile` — past outputs cannot be recovered even if kernel memory is later compromised.
//! - Automatically reseeds from hardware entropy every 64 KiB generated or every 60 seconds.
//! - Exposed to ring 3 through `SYS_GET_RANDOM` (ABI v14).

use crate::ffi;
use crate::kprintln;
use crate::object::Status;
use crate::sync::Mutex;
use doscrypt::chacha20::chacha20_block;
use doscrypt::ct::wipe_bytes;
use doscrypt::sha2::Sha256;

/// Maximum bytes returned by a single `get_random` syscall.
pub const MAX_CALL_BYTES: usize = 4096;
/// Force a fresh hardware reseed after this many output bytes.
const RESEED_BYTES: u64 = 64 * 1024;
/// Force a fresh hardware reseed after this many nanoseconds (60 seconds).
const RESEED_NS: u64 = 60_000_000_000;

/// Flags for `SYS_GET_RANDOM`.
/// `STRICT` refuses to serve bytes unless true hardware entropy (RDSEED, RDRAND, or TPM) was mixed.
pub const FLAG_STRICT: u64 = 1 << 0;

struct Pool {
    key: [u8; 32],
    reseed_seq: u64,
    bytes_since_reseed: u64,
    last_reseed_ns: u64,
    seeded: bool,
    hw_cpu: bool,
    hw_tpm: bool,
}

static POOL: Mutex<Pool> = Mutex::new(
    c"csprng",
    Pool {
        key: [0; 32],
        reseed_seq: 0,
        bytes_since_reseed: 0,
        last_reseed_ns: 0,
        seeded: false,
        hw_cpu: false,
        hw_tpm: false,
    },
);

fn sample_hw_cpu(out: &mut [u8; 64]) -> bool {
    let mut got_hw = false;
    for chunk in out.as_chunks_mut::<8>().0 {
        let mut v = 0u64;
        // SAFETY: cpu_hw_random64 writes to a valid local u64 and returns whether RDSEED/RDRAND succeeded.
        if unsafe { ffi::cpu_hw_random64(&raw mut v) } {
            got_hw = true;
        } else {
            // SAFETY: cpu_random64 is always safe and returns mixed timing fallback when no HW RNG exists.
            v = unsafe { ffi::cpu_random64() };
        }
        chunk.copy_from_slice(&v.to_le_bytes());
    }
    got_hw
}

fn remix(p: &mut Pool, label: &[u8], extra: &[u8]) {
    let mut h = Sha256::new();
    h.update(b"D-OS CSPRNG v1 ");
    h.update(label);
    h.update(&p.key);
    h.update(&p.reseed_seq.to_le_bytes());
    h.update(&ffi::now_ns().to_le_bytes());
    let mut cpu_ent = [0u8; 64];
    if sample_hw_cpu(&mut cpu_ent) {
        p.hw_cpu = true;
    }
    h.update(&cpu_ent);
    wipe_bytes(&mut cpu_ent);
    h.update(extra);
    p.key = h.finish();
    p.reseed_seq = p.reseed_seq.wrapping_add(1);
    p.bytes_since_reseed = 0;
    p.last_reseed_ns = ffi::now_ns();
    p.seeded = true;
}

/// Initialize the kernel CSPRNG at boot (before attestation key generation).
pub fn init() {
    let mut p = POOL.lock();
    remix(&mut p, b"boot", &[]);
    let hw = p.hw_cpu;
    drop(p);
    kprintln!(
        "CSPRNG: ChaCha20 fast-key-erasure ready (sources: {})",
        if hw { "RDSEED/RDRAND + monotonic" } else { "monotonic fallback (no HW RNG)" }
    );
}

/// Mix additional hardware entropy (e.g. from `TPM2_GetRandom`) into the CSPRNG pool.
pub fn mix_tpm_entropy(bytes: &[u8]) {
    if bytes.is_empty() {
        return;
    }
    let mut p = POOL.lock();
    remix(&mut p, b"tpm", bytes);
    p.hw_tpm = true;
}

/// Returns whether true hardware entropy (CPU RDSEED/RDRAND or TPM) has seeded the pool.
pub fn has_hw_entropy() -> bool {
    let p = POOL.lock();
    p.hw_cpu || p.hw_tpm
}

/// Fill `out` with cryptographically strong random bytes using Fast-Key-Erasure ChaCha20.
pub fn fill_bytes(out: &mut [u8], flags: u64) -> Result<(), Status> {
    if (flags & !FLAG_STRICT) != 0 {
        return Err(Status::InvalidArgs);
    }
    let mut p = POOL.lock();
    if !p.seeded {
        remix(&mut p, b"lazy", &[]);
    }
    if (flags & FLAG_STRICT) != 0 && !(p.hw_cpu || p.hw_tpm) {
        return Err(Status::BadState);
    }
    let now = ffi::now_ns();
    if p.bytes_since_reseed >= RESEED_BYTES || now.saturating_sub(p.last_reseed_ns) >= RESEED_NS {
        remix(&mut p, b"periodic", &[]);
    }

    // Fast-Key-Erasure: block 0 yields the next 32-byte key (plus 32 bytes of output);
    // subsequent blocks yield the rest of the requested bytes, then the key is immediately replaced.
    let mut nonce = [0u8; 12];
    nonce[..8].copy_from_slice(&p.reseed_seq.to_le_bytes());
    let mut key = p.key;

    let mut blk0 = chacha20_block(&key, 0, &nonce);
    p.key.copy_from_slice(&blk0[..32]);
    p.reseed_seq = p.reseed_seq.wrapping_add(1);
    p.bytes_since_reseed = p.bytes_since_reseed.saturating_add(out.len() as u64);

    let mut pos = 0usize;
    let first = out.len().min(32);
    out[..first].copy_from_slice(&blk0[32..32 + first]);
    wipe_bytes(&mut blk0);
    pos += first;

    let mut ctr = 1u32;
    while pos < out.len() {
        let mut blk = chacha20_block(&key, ctr, &nonce);
        let take = (out.len() - pos).min(64);
        out[pos..pos + take].copy_from_slice(&blk[..take]);
        wipe_bytes(&mut blk);
        pos += take;
        ctr = ctr.wrapping_add(1);
    }
    wipe_bytes(&mut key);
    Ok(())
}
