//! TPM 2.0 quotes (TPM 2.0 Library Part 2): the hardware root for remote attestation.
//!
//! A verifier gets three blobs from the machine: the attestation key's public area (`TPMT_PUBLIC`),
//! the quote (`TPMS_ATTEST`, what the TPM signed) and its signature (`TPMT_SIGNATURE`). It checks:
//! - the key is an ECC NIST P-256 key that only the TPM can use (`fixedTPM`, `fixedParent`,
//!   `sensitiveDataOrigin`) and that is a *restricted* signing key: the TPM signs only data it
//!   produced itself with such a key, so a quote cannot be forged by asking the TPM to sign
//!   arbitrary bytes;
//! - the ECDSA-SHA256 signature over the quote bytes;
//! - the quote: `TPM_GENERATED` magic, type `TPM_ST_ATTEST_QUOTE`, signed by this key (its Name),
//!   the verifier's nonce, exactly the expected PCR selection (SHA-256 bank) and a PCR digest equal
//!   to SHA-256 of the expected PCR values in index order.
//!
//! Every structure is untrusted input: sizes are bounds-checked and the whole blob must be consumed.
//! Not here: proving that the attestation key belongs to a real TPM (certification through the
//! endorsement key and the vendor's EK certificate chain, X.509), which the verifier must do too.

use crate::p256::{self, PublicKey};
use crate::sha2::{Sha256, sha256};

pub const TPM_GENERATED: u32 = 0xFF54_4347;
pub const ST_ATTEST_QUOTE: u16 = 0x8018;
pub const ALG_SHA256: u16 = 0x000B;
pub const ALG_NULL: u16 = 0x0010;
pub const ALG_ECDSA: u16 = 0x0018;
pub const ALG_ECC: u16 = 0x0023;
pub const ECC_NIST_P256: u16 = 0x0003;

// TPMA_OBJECT
pub const OBJ_FIXED_TPM: u32 = 1 << 1;
pub const OBJ_FIXED_PARENT: u32 = 1 << 4;
pub const OBJ_SENSITIVE_DATA_ORIGIN: u32 = 1 << 5;
pub const OBJ_RESTRICTED: u32 = 1 << 16;
pub const OBJ_DECRYPT: u32 = 1 << 17;
pub const OBJ_SIGN: u32 = 1 << 18;
/// What an attestation key must have.
pub const AK_ATTRIBUTES: u32 = OBJ_FIXED_TPM | OBJ_FIXED_PARENT | OBJ_SENSITIVE_DATA_ORIGIN | OBJ_RESTRICTED | OBJ_SIGN;

/// Big-endian reader over an untrusted TPM structure.
struct Reader<'a> {
    b: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn new(b: &'a [u8]) -> Self {
        Reader { b, at: 0 }
    }
    fn bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.at.checked_add(n)?;
        let s = self.b.get(self.at..end)?;
        self.at = end;
        Some(s)
    }
    fn u8(&mut self) -> Option<u8> {
        Some(self.bytes(1)?[0])
    }
    fn u16(&mut self) -> Option<u16> {
        Some(u16::from_be_bytes(self.bytes(2)?.try_into().ok()?))
    }
    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_be_bytes(self.bytes(4)?.try_into().ok()?))
    }
    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_be_bytes(self.bytes(8)?.try_into().ok()?))
    }
    /// TPM2B: a u16 size, then that many bytes.
    fn tpm2b(&mut self) -> Option<&'a [u8]> {
        let n = self.u16()?;
        self.bytes(usize::from(n))
    }
    fn done(&self) -> bool {
        self.at == self.b.len()
    }
}

/// A big-endian integer of at most 32 bytes, left-padded (TPM ECC parameters drop leading zeros).
fn pad32(b: &[u8]) -> Option<[u8; 32]> {
    if b.len() > 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out[32 - b.len()..].copy_from_slice(b);
    Some(out)
}

/// An ECC P-256 key's public area, parsed.
pub struct EccPublic {
    pub key: PublicKey,
    pub attributes: u32,
    /// The key's Name: nameAlg (SHA-256) || SHA-256(public area), how the TPM names the signer.
    pub name: [u8; 34],
}

/// Parse a `TPMT_PUBLIC` (no TPM2B size prefix) of an ECC NIST P-256 key with SHA-256 names.
pub fn parse_ecc_public(area: &[u8]) -> Option<EccPublic> {
    let mut r = Reader::new(area);
    if r.u16()? != ALG_ECC || r.u16()? != ALG_SHA256 {
        return None;
    }
    let attributes = r.u32()?;
    let _policy = r.tpm2b()?;
    // TPMS_ECC_PARMS: symmetric (NULL for a signing key), scheme, curve, KDF, then the point.
    let sym = r.u16()?;
    if sym != ALG_NULL {
        r.u16()?; // key bits
        r.u16()?; // mode
    }
    let scheme = r.u16()?;
    if scheme != ALG_NULL && (scheme != ALG_ECDSA || r.u16()? != ALG_SHA256) {
        return None;
    }
    if r.u16()? != ECC_NIST_P256 {
        return None;
    }
    let kdf = r.u16()?;
    if kdf != ALG_NULL {
        r.u16()?;
    }
    let x = pad32(r.tpm2b()?)?;
    let y = pad32(r.tpm2b()?)?;
    if !r.done() {
        return None;
    }
    let key = PublicKey::from_xy(&x, &y)?;
    let mut name = [0u8; 34];
    name[..2].copy_from_slice(&ALG_SHA256.to_be_bytes());
    name[2..].copy_from_slice(&sha256(area));
    Some(EccPublic { key, attributes, name })
}

/// Parse a `TPMT_SIGNATURE` holding an ECDSA-SHA256 signature: (r, s) big-endian.
pub fn parse_ecdsa_signature(sig: &[u8]) -> Option<([u8; 32], [u8; 32])> {
    let mut rd = Reader::new(sig);
    if rd.u16()? != ALG_ECDSA || rd.u16()? != ALG_SHA256 {
        return None;
    }
    let r = pad32(rd.tpm2b()?)?;
    let s = pad32(rd.tpm2b()?)?;
    if !rd.done() {
        return None;
    }
    Some((r, s))
}

/// A parsed quote (`TPMS_ATTEST` with `TPMS_QUOTE_INFO`).
#[derive(Debug)]
pub struct Quote<'a> {
    pub signer: &'a [u8],
    pub extra: &'a [u8],
    pub clock: u64,
    pub reset_count: u32,
    pub restart_count: u32,
    pub safe: bool,
    pub firmware: u64,
    /// PCRs selected in the SHA-256 bank (bit i = PCR i, 0-31).
    pub pcrs: u32,
    pub pcr_digest: &'a [u8],
}

/// Parse a quote. Only one bank, SHA-256, may be selected.
pub fn parse_quote(attest: &[u8]) -> Option<Quote<'_>> {
    let mut r = Reader::new(attest);
    if r.u32()? != TPM_GENERATED || r.u16()? != ST_ATTEST_QUOTE {
        return None;
    }
    let signer = r.tpm2b()?;
    let extra = r.tpm2b()?;
    let clock = r.u64()?;
    let reset_count = r.u32()?;
    let restart_count = r.u32()?;
    let safe = match r.u8()? {
        0 => false,
        1 => true,
        _ => return None,
    };
    let firmware = r.u64()?;
    if r.u32()? != 1 {
        return None; // one TPMS_PCR_SELECTION
    }
    if r.u16()? != ALG_SHA256 {
        return None;
    }
    let n = usize::from(r.u8()?);
    if !(3..=4).contains(&n) {
        return None;
    }
    let mut pcrs = 0u32;
    for (i, &b) in r.bytes(n)?.iter().enumerate() {
        pcrs |= u32::from(b) << (8 * i);
    }
    let pcr_digest = r.tpm2b()?;
    if !r.done() {
        return None;
    }
    Some(Quote { signer, extra, clock, reset_count, restart_count, safe, firmware, pcrs, pcr_digest })
}

/// The PCR digest a quote over `values` (in ascending PCR order) must carry.
pub fn pcr_digest(values: &[[u8; 32]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for v in values {
        h.update(v);
    }
    h.finish()
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum QuoteError {
    /// The attestation key's public area is malformed or not ECC P-256 / SHA-256.
    BadKey,
    /// The key is not a restricted, TPM-bound signing key.
    NotAttestationKey,
    /// The signature is malformed or not ECDSA-SHA256.
    BadSignatureFormat,
    /// The signature does not verify.
    BadSignature,
    /// The quote is malformed or not a quote.
    BadQuote,
    /// Signed by another key.
    WrongSigner,
    /// The nonce differs (a replay or another request).
    WrongNonce,
    /// The PCR selection differs from the expected PCRs.
    WrongSelection,
    /// The PCR values differ from the expected ones.
    WrongPcrs,
}

/// Verify a quote of `pcrs` (PCR index and expected SHA-256 value, any order, each index once)
/// signed by the attestation key `ak_public` for `nonce`.
pub fn verify_quote<'a>(
    ak_public: &[u8],
    attest: &'a [u8],
    signature: &[u8],
    nonce: &[u8],
    pcrs: &[(u8, [u8; 32])],
) -> Result<Quote<'a>, QuoteError> {
    let ak = parse_ecc_public(ak_public).ok_or(QuoteError::BadKey)?;
    if ak.attributes & AK_ATTRIBUTES != AK_ATTRIBUTES || ak.attributes & OBJ_DECRYPT != 0 {
        return Err(QuoteError::NotAttestationKey);
    }
    let (r, s) = parse_ecdsa_signature(signature).ok_or(QuoteError::BadSignatureFormat)?;
    if !p256::verify_prehash(&ak.key, &sha256(attest), &r, &s) {
        return Err(QuoteError::BadSignature);
    }
    let q = parse_quote(attest).ok_or(QuoteError::BadQuote)?;
    if q.signer != ak.name {
        return Err(QuoteError::WrongSigner);
    }
    if q.extra != nonce {
        return Err(QuoteError::WrongNonce);
    }
    let mut want = 0u32;
    for &(i, _) in pcrs {
        if i >= 24 || want & (1 << i) != 0 {
            return Err(QuoteError::WrongSelection);
        }
        want |= 1 << i;
    }
    if q.pcrs != want {
        return Err(QuoteError::WrongSelection);
    }
    let mut h = Sha256::new();
    for i in 0..24u8 {
        if let Some((_, v)) = pcrs.iter().find(|(j, _)| *j == i) {
            h.update(v);
        }
    }
    if q.pcr_digest != h.finish() {
        return Err(QuoteError::WrongPcrs);
    }
    Ok(q)
}
