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
//!
//! Proving the attestation key lives in a genuine TPM: the vendor's certificate names the TPM's
//! endorsement key (EK, `parse_rsa_ek`, `x509`); `make_credential` encrypts a fresh secret to that
//! EK, bound to the AK's Name, and only that TPM, with that AK loaded, can return it
//! (TPM2_ActivateCredential). `sim` is the TPM's side, for tests.

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

// ---- keys the kernel creates, and binding the attestation key to the endorsement key ---------

pub const ALG_RSA: u16 = 0x0001;
pub const ALG_AES: u16 = 0x0006;
pub const ALG_CFB: u16 = 0x0043;
pub const OBJ_USER_WITH_AUTH: u32 = 1 << 6;
pub const OBJ_ADMIN_WITH_POLICY: u32 = 1 << 7;

/// The TCG EK Credential Profile's RSA 2048 endorsement-key template ("L-1"): a restricted
/// decryption key whose use needs PolicySecret(TPM_RH_ENDORSEMENT). Created from the TPM's
/// endorsement seed, it is the key the manufacturer's EK certificate names.
pub const EK_ATTRIBUTES: u32 =
    OBJ_FIXED_TPM | OBJ_FIXED_PARENT | OBJ_SENSITIVE_DATA_ORIGIN | OBJ_ADMIN_WITH_POLICY | OBJ_RESTRICTED | OBJ_DECRYPT;
pub const EK_POLICY: [u8; 32] = [
    0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xb3, 0xf8, 0x1a, 0x90, 0xcc, 0x8d, 0x46, 0xa5, 0xd7, 0x24, 0xfd, 0x52, 0xd7, 0x6e, 0x06, 0x52,
    0x0b, 0x64, 0xf2, 0xa1, 0xda, 0x1b, 0x33, 0x14, 0x69, 0xaa,
];
/// The attestation key the kernel creates: ECC P-256, restricted signing (ECDSA-SHA256), usable
/// with its (empty) password.
pub const AK_CREATE_ATTRIBUTES: u32 = AK_ATTRIBUTES | OBJ_USER_WITH_AUTH;

/// Fixed-capacity big-endian writer.
struct Writer<const N: usize> {
    b: [u8; N],
    n: usize,
}

impl<const N: usize> Writer<N> {
    fn new() -> Self {
        Writer { b: [0; N], n: 0 }
    }
    fn put(&mut self, v: &[u8]) -> &mut Self {
        self.b[self.n..self.n + v.len()].copy_from_slice(v);
        self.n += v.len();
        self
    }
    fn u16(&mut self, v: u16) -> &mut Self {
        self.put(&v.to_be_bytes())
    }
    fn u32(&mut self, v: u32) -> &mut Self {
        self.put(&v.to_be_bytes())
    }
    fn tpm2b(&mut self, v: &[u8]) -> &mut Self {
        self.u16(v.len() as u16).put(v)
    }
}

/// `TPMT_PUBLIC` of the RSA 2048 EK template (unique: 256 zero bytes, as the profile says).
pub fn ek_template() -> ([u8; 320], usize) {
    let mut w = Writer::<320>::new();
    w.u16(ALG_RSA).u16(ALG_SHA256).u32(EK_ATTRIBUTES).tpm2b(&EK_POLICY);
    w.u16(ALG_AES).u16(128).u16(ALG_CFB).u16(ALG_NULL).u16(2048).u32(0);
    w.tpm2b(&[0u8; 256]);
    (w.b, w.n)
}

/// `TPMT_PUBLIC` of the attestation-key template (empty unique: the TPM fills in the point).
pub fn ak_template() -> ([u8; 64], usize) {
    let mut w = Writer::<64>::new();
    w.u16(ALG_ECC).u16(ALG_SHA256).u32(AK_CREATE_ATTRIBUTES).tpm2b(&[]);
    w.u16(ALG_NULL).u16(ALG_ECDSA).u16(ALG_SHA256).u16(ECC_NIST_P256).u16(ALG_NULL);
    w.tpm2b(&[]).tpm2b(&[]);
    (w.b, w.n)
}

/// An RSA endorsement key's public area, parsed and checked against the EK template.
pub struct RsaEk<'a> {
    pub modulus: &'a [u8],
    pub exponent: u32,
    pub name: [u8; 34],
}

/// Parse an RSA EK `TPMT_PUBLIC`. Everything but the modulus must be the EK template's: a
/// restricted decryption key with the endorsement policy, AES-128-CFB, 2048 bits.
pub fn parse_rsa_ek(area: &[u8]) -> Option<RsaEk<'_>> {
    let mut r = Reader::new(area);
    if r.u16()? != ALG_RSA || r.u16()? != ALG_SHA256 || r.u32()? != EK_ATTRIBUTES || r.tpm2b()? != EK_POLICY {
        return None;
    }
    if r.u16()? != ALG_AES || r.u16()? != 128 || r.u16()? != ALG_CFB || r.u16()? != ALG_NULL || r.u16()? != 2048 {
        return None;
    }
    let exponent = match r.u32()? {
        0 | 65537 => 65537,
        _ => return None,
    };
    let modulus = r.tpm2b()?;
    if modulus.len() != 256 || !r.done() {
        return None;
    }
    let mut name = [0u8; 34];
    name[..2].copy_from_slice(&ALG_SHA256.to_be_bytes());
    name[2..].copy_from_slice(&sha256(area));
    Some(RsaEk { modulus, exponent, name })
}

/// Size of the `TPM2B_ID_OBJECT` `make_credential` produces (wire form, with its size field).
pub const ID_OBJECT: usize = 2 + 2 + 32 + 2 + 32;
/// Size of the `TPM2B_ENCRYPTED_SECRET` for a 2048-bit EK.
pub const SECRET: usize = 2 + 256;
/// A credential challenge as the kernel's `attest_activate` takes it: blob, then secret.
pub const CHALLENGE: usize = ID_OBJECT + SECRET;

/// TPM2_MakeCredential done by the verifier (TPM 2.0 Library Part 1, 24): `credential` can only
/// be recovered by the TPM that holds the EK's private key, and only for the object named
/// `ak_name` loaded in it. `seed` and `oaep_seed` must be fresh random bytes. Returns the
/// credential blob and the encrypted secret, as `TPM2_ActivateCredential` takes them.
pub fn make_credential(
    ek: &RsaEk<'_>,
    ak_name: &[u8; 34],
    credential: &[u8; 32],
    seed: &[u8; 32],
    oaep_seed: &[u8; 32],
) -> Option<([u8; ID_OBJECT], [u8; SECRET])> {
    use crate::sym::{Aes128, hmac_sha256, kdfa};
    let key = crate::rsa::PublicKey::new(ek.modulus, ek.exponent)?;
    if key.size() != 256 {
        return None;
    }
    let mut secret = [0u8; SECRET];
    secret[..2].copy_from_slice(&256u16.to_be_bytes());
    crate::rsa::oaep_encrypt(&key, seed, b"IDENTITY\0", oaep_seed, &mut secret[2..])?;
    let mut sym = [0u8; 16];
    kdfa(seed, "STORAGE", ak_name, &[], &mut sym);
    let mut enc = [0u8; 34];
    enc[..2].copy_from_slice(&32u16.to_be_bytes());
    enc[2..].copy_from_slice(credential);
    Aes128::new(&sym).cfb_encrypt(&mut enc);
    let mut hkey = [0u8; 32];
    kdfa(seed, "INTEGRITY", &[], &[], &mut hkey);
    let mac = hmac_sha256(&hkey, &[&enc, ak_name]);
    let mut blob = [0u8; ID_OBJECT];
    blob[..2].copy_from_slice(&((ID_OBJECT - 2) as u16).to_be_bytes());
    blob[2..4].copy_from_slice(&32u16.to_be_bytes());
    blob[4..36].copy_from_slice(&mac);
    blob[36..].copy_from_slice(&enc);
    sym.fill(0);
    hkey.fill(0);
    Some((blob, secret))
}

/// The TPM's side, for the test TPM simulator (the kernel's selftest and the host tests).
pub mod sim {
    use super::*;
    use crate::sym::{Aes128, hmac_sha256, kdfa};

    /// TPM2_ActivateCredential: recover the credential with the EK's private exponent `d`;
    /// None if the blob was not made for this EK and `ak_name`.
    pub fn open_credential(ek_n: &[u8], ek_d: &[u8], ak_name: &[u8; 34], blob: &[u8], secret: &[u8]) -> Option<[u8; 32]> {
        let key = crate::rsa::PublicKey::new(ek_n, 65537)?;
        let mut r = Reader::new(secret);
        let ct = r.tpm2b()?;
        let mut seed = [0u8; 64];
        let n = crate::rsa::sim::oaep_decrypt(&key, ek_d, ct, b"IDENTITY\0", &mut seed)?;
        let seed = &seed[..n];
        let mut r = Reader::new(blob);
        let inner = r.tpm2b()?;
        let mut r = Reader::new(inner);
        let mac = r.tpm2b()?;
        let enc = r.bytes(inner.len().checked_sub(2 + mac.len())?)?;
        let mut hkey = [0u8; 32];
        kdfa(seed, "INTEGRITY", &[], &[], &mut hkey);
        if hmac_sha256(&hkey, &[enc, ak_name]) != mac {
            return None;
        }
        if enc.len() != 34 {
            return None;
        }
        let mut sym = [0u8; 16];
        kdfa(seed, "STORAGE", ak_name, &[], &mut sym);
        let mut plain = [0u8; 34];
        plain.copy_from_slice(enc);
        Aes128::new(&sym).cfb_decrypt(&mut plain);
        if plain[..2] != 32u16.to_be_bytes() {
            return None;
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&plain[2..]);
        Some(out)
    }

    /// A `TPMS_ATTEST` quote of one SHA-256 PCR bank selection (`pcrs`: bit i = PCR i).
    pub fn quote_info(signer: &[u8; 34], extra: &[u8], pcrs: u32, digest: &[u8; 32]) -> ([u8; 192], usize) {
        let mut w = Writer::<192>::new();
        w.u32(TPM_GENERATED).u16(ST_ATTEST_QUOTE).tpm2b(signer).tpm2b(extra);
        w.put(&[0; 8]).u32(0).u32(0).put(&[1]); // clock, resets, restarts, safe
        w.put(&0x0D05_0001u64.to_be_bytes()); // firmware version
        w.u32(1).u16(ALG_SHA256).put(&[3, pcrs as u8, (pcrs >> 8) as u8, (pcrs >> 16) as u8]);
        w.tpm2b(digest);
        (w.b, w.n)
    }

    /// The `TPMT_PUBLIC` of an ECC P-256 attestation key with point (x, y).
    pub fn ak_public(x: &[u8; 32], y: &[u8; 32]) -> ([u8; 128], usize) {
        let mut w = Writer::<128>::new();
        w.u16(ALG_ECC).u16(ALG_SHA256).u32(AK_CREATE_ATTRIBUTES).tpm2b(&[]);
        w.u16(ALG_NULL).u16(ALG_ECDSA).u16(ALG_SHA256).u16(ECC_NIST_P256).u16(ALG_NULL);
        w.tpm2b(x).tpm2b(y);
        (w.b, w.n)
    }

    /// The `TPMT_PUBLIC` of the RSA EK with modulus `n` (the template, unique filled in).
    pub fn ek_public(n: &[u8; 256]) -> ([u8; 320], usize) {
        let (mut t, len) = ek_template();
        t[len - 256..len].copy_from_slice(n);
        (t, len)
    }

    /// A `TPMT_SIGNATURE` (ECDSA-SHA256).
    pub fn ecdsa_signature(r: &[u8; 32], s: &[u8; 32]) -> ([u8; 72], usize) {
        let mut w = Writer::<72>::new();
        w.u16(ALG_ECDSA).u16(ALG_SHA256).tpm2b(r).tpm2b(s);
        (w.b, w.n)
    }
}
