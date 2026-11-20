//! X.509 certificates, as far as TPM endorsement-key certificates need (RFC 5280): parse the DER,
//! find the subject's RSA public key, and check the signature with the issuer's certificate.
//!
//! Strict DER subset: definite lengths only (at most 4 length bytes), every element inside its
//! parent, nothing left over at any level parsed. Signatures: sha256WithRSAEncryption and
//! sha384WithRSAEncryption (what TPM vendors' CAs use). Not checked here: validity dates (a TPM
//! has no trusted clock and EK certificates last decades), revocation, name constraints, policies;
//! a verifier that needs them applies its own PKI tooling to the chain above the issuer.

use crate::ed25519;
use crate::p256;
use crate::p384;
use crate::rsa::{self, Hash, PublicKey};
use crate::sha2::sha256;

const SEQUENCE: u8 = 0x30;
const INTEGER: u8 = 0x02;
const BIT_STRING: u8 = 0x03;
const OCTET_STRING: u8 = 0x04;
const OID: u8 = 0x06;
const BOOLEAN: u8 = 0x01;
const UTC_TIME: u8 = 0x17;
const GENERALIZED_TIME: u8 = 0x18;
const CONTEXT_0: u8 = 0xA0;
const CONTEXT_3: u8 = 0xA3;

const OID_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
const OID_SHA256_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];
const OID_SHA384_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c];
const OID_SHA512_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d];
const OID_RSA_PSS: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a];
const OID_EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const OID_PRIME256V1: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
const OID_SECP384R1: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x22];
const OID_ECDSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
const OID_ECDSA_SHA384: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03];
const OID_ED25519: &[u8] = &[0x2b, 0x65, 0x70];
const OID_SHA256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
const OID_SHA384: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02];
const OID_SHA512: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03];
const OID_MGF1: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08];
// X.509 v3 extensions (2.5.29.*)
const OID_EXT_KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x0f];
const OID_EXT_SAN: &[u8] = &[0x55, 0x1d, 0x11];
const OID_EXT_BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x13];
const OID_EXT_NAME_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x1e];
const OID_EXT_EKU: &[u8] = &[0x55, 0x1d, 0x25];
const OID_EXT_SKI: &[u8] = &[0x55, 0x1d, 0x0e];
const OID_EXT_AKI: &[u8] = &[0x55, 0x1d, 0x23];
const OID_EKU_SERVER_AUTH: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];
const OID_EKU_ANY: &[u8] = &[0x55, 0x1d, 0x25, 0x00];

/// One DER element: tag, contents, the whole encoding, and the rest of the input.
type Element<'a> = (u8, &'a [u8], &'a [u8], &'a [u8]);

fn element(b: &[u8]) -> Option<Element<'_>> {
    let tag = *b.first()?;
    if tag & 0x1F == 0x1F {
        return None; // high tag numbers: not in certificates we read
    }
    let l0 = *b.get(1)?;
    let (len, hdr) = if l0 < 0x80 {
        (usize::from(l0), 2)
    } else {
        let n = usize::from(l0 & 0x7F);
        if n == 0 || n > 4 {
            return None;
        }
        let mut len = 0usize;
        for i in 0..n {
            len = (len << 8) | usize::from(*b.get(2 + i)?);
        }
        if len < 0x80 {
            return None; // not the shortest form
        }
        (len, 2 + n)
    };
    let end = hdr.checked_add(len)?;
    let whole = b.get(..end)?;
    Some((tag, &whole[hdr..], whole, &b[end..]))
}

fn expect(b: &[u8], tag: u8) -> Option<(&[u8], &[u8], &[u8])> {
    let (t, c, w, rest) = element(b)?;
    (t == tag).then_some((c, w, rest))
}

/// A positive INTEGER's magnitude (leading zero byte removed).
fn uint(c: &[u8]) -> Option<&[u8]> {
    match c {
        [] => None,
        [0, rest @ ..] if rest.first().is_some_and(|&b| b & 0x80 != 0) => Some(rest),
        [b, ..] if b & 0x80 != 0 => None,
        _ => Some(c),
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SigAlg {
    Sha256Rsa,
    Sha384Rsa,
}

/// A parsed certificate; every slice points into the DER.
#[derive(Debug)]
pub struct Cert<'a> {
    /// The signed part (`tbsCertificate`, whole encoding).
    pub tbs: &'a [u8],
    pub serial: &'a [u8],
    /// Issuer and subject names (whole encodings, compared byte for byte).
    pub issuer: &'a [u8],
    pub subject: &'a [u8],
    pub sig_alg: SigAlg,
    pub signature: &'a [u8],
    /// The subject's RSA key: modulus (big-endian, no leading zero) and exponent.
    pub rsa_n: &'a [u8],
    pub rsa_e: u32,
}

fn parse_sig_alg(alg_id: &[u8]) -> Option<SigAlg> {
    let (oid, _, rest) = expect(alg_id, OID)?;
    // Parameters: NULL or absent.
    if !(rest.is_empty() || rest == [0x05, 0x00]) {
        return None;
    }
    match oid {
        OID_SHA256_RSA => Some(SigAlg::Sha256Rsa),
        OID_SHA384_RSA => Some(SigAlg::Sha384Rsa),
        _ => None,
    }
}

/// Parse a DER certificate whose subject key is RSA. None for anything else or anything malformed.
pub fn parse(der: &[u8]) -> Option<Cert<'_>> {
    let (cert, _, rest) = expect(der, SEQUENCE)?;
    if !rest.is_empty() {
        return None;
    }
    let (tbs_c, tbs, rest) = expect(cert, SEQUENCE)?;
    let (alg, _, rest) = expect(rest, SEQUENCE)?;
    let sig_alg = parse_sig_alg(alg)?;
    let (bits, _, rest) = expect(rest, BIT_STRING)?;
    if !rest.is_empty() || bits.first() != Some(&0) {
        return None;
    }
    let signature = &bits[1..];

    let mut r = tbs_c;
    if r.first() == Some(&CONTEXT_0) {
        let (_, _, _, rest) = element(r)?; // version
        r = rest;
    }
    let (serial, _, rest) = expect(r, INTEGER)?;
    let (inner_alg, _, rest) = expect(rest, SEQUENCE)?;
    if parse_sig_alg(inner_alg)? != sig_alg {
        return None; // the two algorithm fields must agree
    }
    let (_, issuer, rest) = expect(rest, SEQUENCE)?;
    let (_, _, rest) = expect(rest, SEQUENCE)?; // validity
    let (_, subject, rest) = expect(rest, SEQUENCE)?;
    let (spki, _, _) = expect(rest, SEQUENCE)?;
    let (spki_alg, _, spki_rest) = expect(spki, SEQUENCE)?;
    let (oid, _, params) = expect(spki_alg, OID)?;
    if oid != OID_RSA || !(params.is_empty() || params == [0x05, 0x00]) {
        return None;
    }
    let (key_bits, _, spki_end) = expect(spki_rest, BIT_STRING)?;
    if !spki_end.is_empty() || key_bits.first() != Some(&0) {
        return None;
    }
    let (rsa_key, _, end) = expect(&key_bits[1..], SEQUENCE)?;
    if !end.is_empty() {
        return None;
    }
    let (n, _, rest) = expect(rsa_key, INTEGER)?;
    let (e, _, rest) = expect(rest, INTEGER)?;
    if !rest.is_empty() {
        return None;
    }
    let rsa_n = uint(n)?;
    let e = uint(e)?;
    if e.len() > 4 {
        return None;
    }
    let rsa_e = e.iter().fold(0u32, |a, &b| (a << 8) | u32::from(b));
    Some(Cert { tbs, serial, issuer, subject, sig_alg, signature, rsa_n, rsa_e })
}

impl Cert<'_> {
    pub fn public_key(&self) -> Option<PublicKey> {
        PublicKey::new(self.rsa_n, self.rsa_e)
    }

    /// Is this certificate signed by `issuer` (names match, signature verifies with its key)?
    pub fn signed_by(&self, issuer: &Cert<'_>) -> bool {
        if self.issuer != issuer.subject {
            return false;
        }
        let Some(key) = issuer.public_key() else { return false };
        let hash = match self.sig_alg {
            SigAlg::Sha256Rsa => Hash::Sha256,
            SigAlg::Sha384Rsa => Hash::Sha384,
        };
        rsa::verify_pkcs1(&key, hash, self.tbs, self.signature)
    }
}

// ---- Full X.509 v3 certificate parsing & chain verification for TLS 1.3 -------------------------

pub const MAX_SAN_DNS: usize = 64;
pub const MAX_SAN_IPS: usize = 8;
pub const MAX_NAME_CONSTRAINTS: usize = 16;
pub const MAX_CHAIN_LEN: usize = 10;

/// X.509 certificate verification error.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum VerifyError {
    Malformed,
    UnsupportedAlgorithm,
    UnknownCriticalExtension,
    WeakKey,
    Expired,
    NotYetValid,
    HostnameMismatch,
    NameConstraintViolation,
    NotCa,
    PathLenExceeded,
    KeyUsageViolation,
    BadSignature,
    UntrustedRoot,
    Revoked,
    EmptyChain,
    ChainTooLong,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TlsSigAlg {
    Sha256RsaPkcs1,
    Sha384RsaPkcs1,
    Sha512RsaPkcs1,
    RsaPssSha256,
    RsaPssSha384,
    RsaPssSha512,
    EcdsaP256Sha256,
    EcdsaP384Sha384,
    Ed25519,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PubKey<'a> {
    Rsa { n: &'a [u8], e: u32 },
    P256(&'a [u8]),
    P384(&'a [u8]),
    Ed25519([u8; 32]),
}

/// Full X.509 v3 certificate parsed without heap allocation (`no_std`).
#[derive(Debug)]
pub struct TlsCert<'a> {
    pub tbs: &'a [u8],
    pub issuer: &'a [u8],
    pub subject: &'a [u8],
    pub not_before: i64,
    pub not_after: i64,
    pub sig_alg: TlsSigAlg,
    pub signature: &'a [u8],
    pub pub_key: PubKey<'a>,
    pub is_ca: bool,
    pub path_len: Option<u32>,
    pub has_key_usage: bool,
    pub key_usage: u16,
    pub has_eku: bool,
    pub eku_server_auth: bool,
    pub san_dns: [&'a [u8]; MAX_SAN_DNS],
    pub san_dns_count: usize,
    pub san_ips: [[u8; 4]; MAX_SAN_IPS],
    pub san_ips_count: usize,
    pub permitted_dns: [&'a [u8]; MAX_NAME_CONSTRAINTS],
    pub permitted_dns_count: usize,
    pub excluded_dns: [&'a [u8]; MAX_NAME_CONSTRAINTS],
    pub excluded_dns_count: usize,
}

/// KeyUsage bit flags (RFC 5280 §4.2.1.3, MSB-first bit numbers mapped to u16).
pub const KU_DIGITAL_SIGNATURE: u16 = 1 << 0;
pub const KU_KEY_CERT_SIGN: u16 = 1 << 5;

fn parse_2digits(b: &[u8]) -> Option<u32> {
    if b.len() < 2 || !b[0].is_ascii_digit() || !b[1].is_ascii_digit() {
        return None;
    }
    Some(u32::from(b[0] - b'0') * 10 + u32::from(b[1] - b'0'))
}

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = y - if m <= 2 { 1 } else { 0 };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn days_in_month(y: i64, m: u32) -> u32 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            let leap = (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0);
            if leap { 29 } else { 28 }
        }
        _ => 0,
    }
}

/// Parse DER UTCTime (`YYMMDDHHMMSSZ`) or GeneralizedTime (`YYYYMMDDHHMMSSZ`) to Unix seconds.
fn parse_time(b: &[u8]) -> Option<(i64, &[u8])> {
    let (tag, content, _, rest) = element(b)?;
    let (year, off): (i64, usize) = match tag {
        UTC_TIME => {
            if content.len() != 13 || content[12] != b'Z' {
                return None;
            }
            let yy = parse_2digits(&content[0..2])? as i64;
            // RFC 5280 §4.1.2.5.1: 00..=49 -> 2000..=2049, 50..=99 -> 1950..=1999.
            (if yy >= 50 { 1900 + yy } else { 2000 + yy }, 2)
        }
        GENERALIZED_TIME => {
            if content.len() != 15 || content[14] != b'Z' {
                return None;
            }
            let hi = parse_2digits(&content[0..2])? as i64;
            let lo = parse_2digits(&content[2..4])? as i64;
            (hi * 100 + lo, 4)
        }
        _ => return None,
    };
    let month = parse_2digits(&content[off..off + 2])?;
    let day = parse_2digits(&content[off + 2..off + 4])?;
    let hour = parse_2digits(&content[off + 4..off + 6])?;
    let min = parse_2digits(&content[off + 6..off + 8])?;
    let sec = parse_2digits(&content[off + 8..off + 10])?;
    if !(1..=12).contains(&month) || day < 1 || day > days_in_month(year, month) {
        return None;
    }
    if hour > 23 || min > 59 || sec > 59 {
        return None;
    }
    let days = days_from_civil(year, i64::from(month), i64::from(day));
    let secs = days
        .checked_mul(86_400)?
        .checked_add(i64::from(hour) * 3600 + i64::from(min) * 60 + i64::from(sec))?;
    Some((secs, rest))
}

fn parse_pss_params(params: &[u8]) -> Option<TlsSigAlg> {
    let (seq, _, rest) = expect(params, SEQUENCE)?;
    if !rest.is_empty() {
        return None;
    }
    let mut r = seq;
    let mut hash = Hash::Sha256;
    let mut mgf_hash = Hash::Sha256;
    let mut salt_len: Option<u32> = None;
    while !r.is_empty() {
        let (tag, inner, _, next) = element(r)?;
        r = next;
        match tag {
            0xA0 => {
                let (alg, _, end) = expect(inner, SEQUENCE)?;
                if !end.is_empty() {
                    return None;
                }
                let (oid, _, p) = expect(alg, OID)?;
                if !(p.is_empty() || p == [0x05, 0x00]) {
                    return None;
                }
                hash = match oid {
                    OID_SHA256 => Hash::Sha256,
                    OID_SHA384 => Hash::Sha384,
                    OID_SHA512 => Hash::Sha512,
                    _ => return None,
                };
            }
            0xA1 => {
                let (alg, _, end) = expect(inner, SEQUENCE)?;
                if !end.is_empty() {
                    return None;
                }
                let (oid, _, p) = expect(alg, OID)?;
                if oid != OID_MGF1 {
                    return None;
                }
                let (hseq, _, pend) = expect(p, SEQUENCE)?;
                if !pend.is_empty() {
                    return None;
                }
                let (hoid, _, hp) = expect(hseq, OID)?;
                if !(hp.is_empty() || hp == [0x05, 0x00]) {
                    return None;
                }
                mgf_hash = match hoid {
                    OID_SHA256 => Hash::Sha256,
                    OID_SHA384 => Hash::Sha384,
                    OID_SHA512 => Hash::Sha512,
                    _ => return None,
                };
            }
            0xA2 => {
                let (iv, _, end) = expect(inner, INTEGER)?;
                if !end.is_empty() {
                    return None;
                }
                let u = uint(iv)?;
                if u.len() > 4 {
                    return None;
                }
                salt_len = Some(u.iter().fold(0u32, |a, &b| (a << 8) | u32::from(b)));
            }
            0xA3 => {
                // trailerField must be 1 if present.
                let (iv, _, end) = expect(inner, INTEGER)?;
                if !end.is_empty() || uint(iv)? != [1] {
                    return None;
                }
            }
            _ => return None,
        }
    }
    if hash != mgf_hash {
        return None;
    }
    let want_salt = match hash {
        Hash::Sha256 => 32,
        Hash::Sha384 => 48,
        Hash::Sha512 => 64,
    };
    if let Some(s) = salt_len
        && s != want_salt
    {
        return None;
    }
    Some(match hash {
        Hash::Sha256 => TlsSigAlg::RsaPssSha256,
        Hash::Sha384 => TlsSigAlg::RsaPssSha384,
        Hash::Sha512 => TlsSigAlg::RsaPssSha512,
    })
}

fn parse_tls_sig_alg(alg_id: &[u8]) -> Result<TlsSigAlg, VerifyError> {
    let (oid, _, rest) = expect(alg_id, OID).ok_or(VerifyError::Malformed)?;
    match oid {
        OID_SHA256_RSA => {
            if !(rest.is_empty() || rest == [0x05, 0x00]) {
                return Err(VerifyError::Malformed);
            }
            Ok(TlsSigAlg::Sha256RsaPkcs1)
        }
        OID_SHA384_RSA => {
            if !(rest.is_empty() || rest == [0x05, 0x00]) {
                return Err(VerifyError::Malformed);
            }
            Ok(TlsSigAlg::Sha384RsaPkcs1)
        }
        OID_SHA512_RSA => {
            if !(rest.is_empty() || rest == [0x05, 0x00]) {
                return Err(VerifyError::Malformed);
            }
            Ok(TlsSigAlg::Sha512RsaPkcs1)
        }
        OID_RSA_PSS => parse_pss_params(rest).ok_or(VerifyError::UnsupportedAlgorithm),
        OID_ECDSA_SHA256 => {
            if !rest.is_empty() {
                return Err(VerifyError::Malformed);
            }
            Ok(TlsSigAlg::EcdsaP256Sha256)
        }
        OID_ECDSA_SHA384 => {
            if !rest.is_empty() {
                return Err(VerifyError::Malformed);
            }
            Ok(TlsSigAlg::EcdsaP384Sha384)
        }
        OID_ED25519 => {
            if !rest.is_empty() {
                return Err(VerifyError::Malformed);
            }
            Ok(TlsSigAlg::Ed25519)
        }
        _ => Err(VerifyError::UnsupportedAlgorithm),
    }
}

fn parse_spki(spki: &[u8]) -> Result<PubKey<'_>, VerifyError> {
    let (spki_alg, _, spki_rest) = expect(spki, SEQUENCE).ok_or(VerifyError::Malformed)?;
    let (oid, _, params) = expect(spki_alg, OID).ok_or(VerifyError::Malformed)?;
    let (key_bits, _, spki_end) = expect(spki_rest, BIT_STRING).ok_or(VerifyError::Malformed)?;
    if !spki_end.is_empty() || key_bits.first() != Some(&0) {
        return Err(VerifyError::Malformed);
    }
    let key_bytes = &key_bits[1..];
    match oid {
        OID_RSA => {
            if !(params.is_empty() || params == [0x05, 0x00]) {
                return Err(VerifyError::Malformed);
            }
            let (rsa_key, _, end) = expect(key_bytes, SEQUENCE).ok_or(VerifyError::Malformed)?;
            if !end.is_empty() {
                return Err(VerifyError::Malformed);
            }
            let (n, _, rest) = expect(rsa_key, INTEGER).ok_or(VerifyError::Malformed)?;
            let (e, _, rest) = expect(rest, INTEGER).ok_or(VerifyError::Malformed)?;
            if !rest.is_empty() {
                return Err(VerifyError::Malformed);
            }
            let rsa_n = uint(n).ok_or(VerifyError::Malformed)?;
            let e_bytes = uint(e).ok_or(VerifyError::Malformed)?;
            if e_bytes.len() > 4 {
                return Err(VerifyError::Malformed);
            }
            let rsa_e = e_bytes.iter().fold(0u32, |a, &b| (a << 8) | u32::from(b));
            let pk = PublicKey::new(rsa_n, rsa_e).ok_or(VerifyError::Malformed)?;
            if pk.bits() < 2048 {
                return Err(VerifyError::WeakKey);
            }
            Ok(PubKey::Rsa { n: rsa_n, e: rsa_e })
        }
        OID_EC_PUBLIC_KEY => {
            let (curve_oid, _, pend) = expect(params, OID).ok_or(VerifyError::Malformed)?;
            if !pend.is_empty() {
                return Err(VerifyError::Malformed);
            }
            match curve_oid {
                OID_PRIME256V1 => {
                    if p256::PublicKey::from_sec1(key_bytes).is_none() {
                        return Err(VerifyError::Malformed);
                    }
                    Ok(PubKey::P256(key_bytes))
                }
                OID_SECP384R1 => {
                    if p384::PublicKey::from_sec1(key_bytes).is_none() {
                        return Err(VerifyError::Malformed);
                    }
                    Ok(PubKey::P384(key_bytes))
                }
                _ => Err(VerifyError::UnsupportedAlgorithm),
            }
        }
        OID_ED25519 => {
            if !params.is_empty() || key_bytes.len() != 32 {
                return Err(VerifyError::Malformed);
            }
            let mut k = [0u8; 32];
            k.copy_from_slice(key_bytes);
            Ok(PubKey::Ed25519(k))
        }
        _ => Err(VerifyError::UnsupportedAlgorithm),
    }
}

/// Parse DER ECDSA-Sig-Value (`SEQUENCE { r INTEGER, s INTEGER }`) into 64-byte big-endian `r || s` (P-256).
pub fn parse_ecdsa_der_sig(der: &[u8]) -> Option<[u8; 64]> {
    let (seq, _, rest) = expect(der, SEQUENCE)?;
    if !rest.is_empty() {
        return None;
    }
    let (r_raw, _, rest) = expect(seq, INTEGER)?;
    let (s_raw, _, rest) = expect(rest, INTEGER)?;
    if !rest.is_empty() {
        return None;
    }
    let r = uint(r_raw)?;
    let s = uint(s_raw)?;
    if r.is_empty() || r.len() > 32 || s.is_empty() || s.len() > 32 {
        return None;
    }
    let mut out = [0u8; 64];
    out[32 - r.len()..32].copy_from_slice(r);
    out[64 - s.len()..64].copy_from_slice(s);
    Some(out)
}

/// Parse DER ECDSA-Sig-Value (`SEQUENCE { r INTEGER, s INTEGER }`) into 96-byte big-endian `r || s` (P-384).
pub fn parse_ecdsa_p384_der_sig(der: &[u8]) -> Option<[u8; 96]> {
    let (seq, _, rest) = expect(der, SEQUENCE)?;
    if !rest.is_empty() {
        return None;
    }
    let (r_raw, _, rest) = expect(seq, INTEGER)?;
    let (s_raw, _, rest) = expect(rest, INTEGER)?;
    if !rest.is_empty() {
        return None;
    }
    let r = uint(r_raw)?;
    let s = uint(s_raw)?;
    if r.is_empty() || r.len() > 48 || s.is_empty() || s.len() > 48 {
        return None;
    }
    let mut out = [0u8; 96];
    out[48 - r.len()..48].copy_from_slice(r);
    out[96 - s.len()..96].copy_from_slice(s);
    Some(out)
}

/// Parse an X.509 v3 certificate for TLS verification.
pub fn parse_tls(der: &[u8]) -> Result<TlsCert<'_>, VerifyError> {
    let (cert, _, rest) = expect(der, SEQUENCE).ok_or(VerifyError::Malformed)?;
    if !rest.is_empty() {
        return Err(VerifyError::Malformed);
    }
    let (tbs_c, tbs, rest) = expect(cert, SEQUENCE).ok_or(VerifyError::Malformed)?;
    let (alg, _, rest) = expect(rest, SEQUENCE).ok_or(VerifyError::Malformed)?;
    let sig_alg = parse_tls_sig_alg(alg)?;
    let (bits, _, rest) = expect(rest, BIT_STRING).ok_or(VerifyError::Malformed)?;
    if !rest.is_empty() || bits.first() != Some(&0) {
        return Err(VerifyError::Malformed);
    }
    let signature = &bits[1..];

    let mut r = tbs_c;
    let mut version = 0u8;
    if r.first() == Some(&CONTEXT_0) {
        let (_, vc, _, rest) = element(r).ok_or(VerifyError::Malformed)?;
        let (vi, _, vend) = expect(vc, INTEGER).ok_or(VerifyError::Malformed)?;
        if !vend.is_empty() || vi.len() != 1 || vi[0] > 2 {
            return Err(VerifyError::Malformed);
        }
        version = vi[0];
        r = rest;
    }
    let (_serial, _, rest) = expect(r, INTEGER).ok_or(VerifyError::Malformed)?;
    let (inner_alg, _, rest) = expect(rest, SEQUENCE).ok_or(VerifyError::Malformed)?;
    if parse_tls_sig_alg(inner_alg)? != sig_alg {
        return Err(VerifyError::Malformed);
    }
    let (_, issuer, rest) = expect(rest, SEQUENCE).ok_or(VerifyError::Malformed)?;
    let (validity, _, rest) = expect(rest, SEQUENCE).ok_or(VerifyError::Malformed)?;
    let (not_before, vrest) = parse_time(validity).ok_or(VerifyError::Malformed)?;
    let (not_after, vend) = parse_time(vrest).ok_or(VerifyError::Malformed)?;
    if !vend.is_empty() || not_after < not_before {
        return Err(VerifyError::Malformed);
    }
    let (_, subject, rest) = expect(rest, SEQUENCE).ok_or(VerifyError::Malformed)?;
    let (spki, _, mut ext_tail) = expect(rest, SEQUENCE).ok_or(VerifyError::Malformed)?;
    let pub_key = parse_spki(spki)?;

    // Skip optional issuerUniqueID ([1]) and subjectUniqueID ([2]).
    while let Some(&t) = ext_tail.first() {
        if t == 0x81 || t == 0x82 {
            if version == 0 {
                return Err(VerifyError::Malformed);
            }
            let (_, _, _, next) = element(ext_tail).ok_or(VerifyError::Malformed)?;
            ext_tail = next;
        } else {
            break;
        }
    }

    let mut parsed = TlsCert {
        tbs,
        issuer,
        subject,
        not_before,
        not_after,
        sig_alg,
        signature,
        pub_key,
        is_ca: false,
        path_len: None,
        has_key_usage: false,
        key_usage: 0,
        has_eku: false,
        eku_server_auth: false,
        san_dns: [b""; MAX_SAN_DNS],
        san_dns_count: 0,
        san_ips: [[0; 4]; MAX_SAN_IPS],
        san_ips_count: 0,
        permitted_dns: [b""; MAX_NAME_CONSTRAINTS],
        permitted_dns_count: 0,
        excluded_dns: [b""; MAX_NAME_CONSTRAINTS],
        excluded_dns_count: 0,
    };

    if !ext_tail.is_empty() {
        if version != 2 {
            return Err(VerifyError::Malformed);
        }
        let (exts_wrap, _, end) = expect(ext_tail, CONTEXT_3).ok_or(VerifyError::Malformed)?;
        if !end.is_empty() {
            return Err(VerifyError::Malformed);
        }
        let (mut exts, _, end) = expect(exts_wrap, SEQUENCE).ok_or(VerifyError::Malformed)?;
        if !end.is_empty() {
            return Err(VerifyError::Malformed);
        }
        while !exts.is_empty() {
            let (ext, _, next) = expect(exts, SEQUENCE).ok_or(VerifyError::Malformed)?;
            exts = next;
            let (oid, _, mut er) = expect(ext, OID).ok_or(VerifyError::Malformed)?;
            let mut critical = false;
            if er.first() == Some(&BOOLEAN) {
                let (bc, _, next_er) = expect(er, BOOLEAN).ok_or(VerifyError::Malformed)?;
                if bc.len() != 1 || (bc[0] != 0x00 && bc[0] != 0xFF) {
                    return Err(VerifyError::Malformed);
                }
                critical = bc[0] == 0xFF;
                er = next_er;
            }
            let (val, _, eend) = expect(er, OCTET_STRING).ok_or(VerifyError::Malformed)?;
            if !eend.is_empty() {
                return Err(VerifyError::Malformed);
            }
            match oid {
                OID_EXT_BASIC_CONSTRAINTS => {
                    let (mut bc, _, bend) = expect(val, SEQUENCE).ok_or(VerifyError::Malformed)?;
                    if !bend.is_empty() {
                        return Err(VerifyError::Malformed);
                    }
                    if bc.first() == Some(&BOOLEAN) {
                        let (v, _, next_bc) = expect(bc, BOOLEAN).ok_or(VerifyError::Malformed)?;
                        if v.len() != 1 || (v[0] != 0x00 && v[0] != 0xFF) {
                            return Err(VerifyError::Malformed);
                        }
                        parsed.is_ca = v[0] == 0xFF;
                        bc = next_bc;
                    }
                    if !bc.is_empty() {
                        let (pl, _, pl_end) = expect(bc, INTEGER).ok_or(VerifyError::Malformed)?;
                        if !pl_end.is_empty() {
                            return Err(VerifyError::Malformed);
                        }
                        let u = uint(pl).ok_or(VerifyError::Malformed)?;
                        if u.len() > 4 {
                            return Err(VerifyError::Malformed);
                        }
                        parsed.path_len = Some(u.iter().fold(0u32, |a, &b| (a << 8) | u32::from(b)));
                    }
                }
                OID_EXT_KEY_USAGE => {
                    let (bits, _, kend) = expect(val, BIT_STRING).ok_or(VerifyError::Malformed)?;
                    if !kend.is_empty() || bits.len() < 2 || bits[0] > 7 {
                        return Err(VerifyError::Malformed);
                    }
                    let mut mask = 0u16;
                    for (byte_idx, &byte) in bits[1..].iter().take(2).enumerate() {
                        for bit in 0..8usize {
                            if (byte & (0x80 >> bit)) != 0 {
                                mask |= 1u16 << (byte_idx * 8 + bit);
                            }
                        }
                    }
                    parsed.has_key_usage = true;
                    parsed.key_usage = mask;
                }
                OID_EXT_SAN => {
                    let (mut names, _, send) = expect(val, SEQUENCE).ok_or(VerifyError::Malformed)?;
                    if !send.is_empty() {
                        return Err(VerifyError::Malformed);
                    }
                    while !names.is_empty() {
                        let (tag, content, _, nnext) = element(names).ok_or(VerifyError::Malformed)?;
                        names = nnext;
                        match tag {
                            0x82 => {
                                // dNSName (IA5String)
                                if !content.is_empty()
                                    && content.iter().all(|&c| c.is_ascii_graphic())
                                    && parsed.san_dns_count < MAX_SAN_DNS
                                {
                                    parsed.san_dns[parsed.san_dns_count] = content;
                                    parsed.san_dns_count += 1;
                                }
                            }
                            0x87 => {
                                // iPAddress (IPv4 = 4 bytes)
                                if content.len() == 4 && parsed.san_ips_count < MAX_SAN_IPS {
                                    parsed.san_ips[parsed.san_ips_count]
                                        .copy_from_slice(content);
                                    parsed.san_ips_count += 1;
                                }
                            }
                            _ => {}
                        }
                    }
                }
                OID_EXT_EKU => {
                    let (mut oids, _, eend) = expect(val, SEQUENCE).ok_or(VerifyError::Malformed)?;
                    if !eend.is_empty() {
                        return Err(VerifyError::Malformed);
                    }
                    parsed.has_eku = true;
                    while !oids.is_empty() {
                        let (eoid, _, onext) = expect(oids, OID).ok_or(VerifyError::Malformed)?;
                        oids = onext;
                        if eoid == OID_EKU_SERVER_AUTH || eoid == OID_EKU_ANY {
                            parsed.eku_server_auth = true;
                        }
                    }
                }
                OID_EXT_NAME_CONSTRAINTS => {
                    let (mut nc, _, nend) = expect(val, SEQUENCE).ok_or(VerifyError::Malformed)?;
                    if !nend.is_empty() {
                        return Err(VerifyError::Malformed);
                    }
                    while !nc.is_empty() {
                        let (tag, mut subtrees, _, next_nc) = element(nc).ok_or(VerifyError::Malformed)?;
                        nc = next_nc;
                        let is_permitted = match tag {
                            0xA0 => true,
                            0xA1 => false,
                            _ => return Err(VerifyError::Malformed),
                        };
                        while !subtrees.is_empty() {
                            let (sub, _, next_sub) = expect(subtrees, SEQUENCE).ok_or(VerifyError::Malformed)?;
                            subtrees = next_sub;
                            let (gtag, gcontent, _, _) = element(sub).ok_or(VerifyError::Malformed)?;
                            if gtag == 0x82 && !gcontent.is_empty() {
                                if is_permitted {
                                    if parsed.permitted_dns_count < MAX_NAME_CONSTRAINTS {
                                        parsed.permitted_dns[parsed.permitted_dns_count] = gcontent;
                                        parsed.permitted_dns_count += 1;
                                    }
                                } else if parsed.excluded_dns_count < MAX_NAME_CONSTRAINTS {
                                    parsed.excluded_dns[parsed.excluded_dns_count] = gcontent;
                                    parsed.excluded_dns_count += 1;
                                }
                            }
                        }
                    }
                }
                OID_EXT_SKI | OID_EXT_AKI => {}
                _ if critical => return Err(VerifyError::UnknownCriticalExtension),
                _ => {}
            }
        }
    }

    Ok(parsed)
}

impl TlsCert<'_> {
    /// Verify `msg`'s signature using this certificate's subject public key and `alg`.
    pub fn verify_signature(&self, alg: TlsSigAlg, msg: &[u8], sig: &[u8]) -> bool {
        match (self.pub_key, alg) {
            (PubKey::Rsa { n, e }, TlsSigAlg::Sha256RsaPkcs1) => {
                PublicKey::new(n, e).is_some_and(|k| k.bits() >= 2048 && rsa::verify_pkcs1(&k, Hash::Sha256, msg, sig))
            }
            (PubKey::Rsa { n, e }, TlsSigAlg::Sha384RsaPkcs1) => {
                PublicKey::new(n, e).is_some_and(|k| k.bits() >= 2048 && rsa::verify_pkcs1(&k, Hash::Sha384, msg, sig))
            }
            (PubKey::Rsa { n, e }, TlsSigAlg::Sha512RsaPkcs1) => {
                PublicKey::new(n, e).is_some_and(|k| k.bits() >= 2048 && rsa::verify_pkcs1(&k, Hash::Sha512, msg, sig))
            }
            (PubKey::Rsa { n, e }, TlsSigAlg::RsaPssSha256) => {
                PublicKey::new(n, e).is_some_and(|k| k.bits() >= 2048 && rsa::verify_pss(&k, Hash::Sha256, msg, sig))
            }
            (PubKey::Rsa { n, e }, TlsSigAlg::RsaPssSha384) => {
                PublicKey::new(n, e).is_some_and(|k| k.bits() >= 2048 && rsa::verify_pss(&k, Hash::Sha384, msg, sig))
            }
            (PubKey::Rsa { n, e }, TlsSigAlg::RsaPssSha512) => {
                PublicKey::new(n, e).is_some_and(|k| k.bits() >= 2048 && rsa::verify_pss(&k, Hash::Sha512, msg, sig))
            }
            (PubKey::P256(sec1), TlsSigAlg::EcdsaP256Sha256) => {
                let Some(pk) = p256::PublicKey::from_sec1(sec1) else {
                    return false;
                };
                let Some(rs) = parse_ecdsa_der_sig(sig) else {
                    return false;
                };
                p256::verify(&pk, msg, &rs)
            }
            (PubKey::P384(sec1), TlsSigAlg::EcdsaP384Sha384) => {
                let Some(pk) = p384::PublicKey::from_sec1(sec1) else {
                    return false;
                };
                let Some(rs) = parse_ecdsa_p384_der_sig(sig) else {
                    return false;
                };
                p384::verify(&pk, msg, &rs)
            }
            (PubKey::Ed25519(pk), TlsSigAlg::Ed25519) => {
                let Ok(s): Result<&[u8; 64], _> = sig.try_into() else {
                    return false;
                };
                ed25519::verify(&pk, msg, s)
            }
            _ => false,
        }
    }

    pub fn signed_by(&self, issuer: &TlsCert<'_>) -> bool {
        self.issuer == issuer.subject && issuer.verify_signature(self.sig_alg, self.tbs, self.signature)
    }

    pub fn check_validity(&self, now_unix: i64) -> Result<(), VerifyError> {
        if now_unix < self.not_before {
            return Err(VerifyError::NotYetValid);
        }
        if now_unix > self.not_after {
            return Err(VerifyError::Expired);
        }
        Ok(())
    }

    /// Does this leaf certificate match `host` (IPv4 literal or DNS name) via SAN?
    pub fn matches_host(&self, host: &str) -> bool {
        if let Some(ip) = parse_ipv4_literal(host) {
            return self.san_ips[..self.san_ips_count].contains(&ip);
        }
        for &pat in &self.san_dns[..self.san_dns_count] {
            if let Ok(pat_s) = core::str::from_utf8(pat)
                && dns_pattern_matches(pat_s, host)
            {
                return true;
            }
        }
        false
    }
}

fn parse_ipv4_literal(s: &str) -> Option<[u8; 4]> {
    let mut out = [0u8; 4];
    let mut count = 0usize;
    for part in s.split('.') {
        if count >= 4 || part.is_empty() || (part.len() > 1 && part.starts_with('0')) {
            return None;
        }
        out[count] = part.parse::<u8>().ok()?;
        count += 1;
    }
    (count == 4).then_some(out)
}

/// Strict RFC 6125 DNS matching: case-insensitive exact match or single-leftmost-label wildcard
/// (`*.example.com` matches `a.example.com`, never `example.com` or `a.b.example.com`, never `*` or `*.com`).
pub fn dns_pattern_matches(pattern: &str, host: &str) -> bool {
    let pat = pattern.trim_end_matches('.');
    let h = host.trim_end_matches('.');
    if pat.is_empty() || h.is_empty() {
        return false;
    }
    if !pat.contains('*') {
        return pat.eq_ignore_ascii_case(h);
    }
    // Wildcard must be the entire leftmost label: `*.<rest>` with at least two labels in `<rest>`.
    let Some(suffix) = pat.strip_prefix("*.") else {
        return false;
    };
    if suffix.contains('*') || !suffix.contains('.') {
        return false;
    }
    let Some((first_label, host_suffix)) = h.split_once('.') else {
        return false;
    };
    !first_label.is_empty() && host_suffix.eq_ignore_ascii_case(suffix)
}

/// RFC 5280 §4.2.1.10 DNS subtree matching for Name Constraints.
fn dns_subtree_matches(constraint: &str, host: &str) -> bool {
    let c = constraint.trim_end_matches('.');
    let h = host.trim_end_matches('.');
    if c.is_empty() || h.is_empty() {
        return false;
    }
    if let Some(dot_rest) = c.strip_prefix('.') {
        // Leading dot matches any strict subdomain.
        h.len() > dot_rest.len()
            && h.as_bytes()[h.len() - dot_rest.len() - 1] == b'.'
            && h[h.len() - dot_rest.len()..].eq_ignore_ascii_case(dot_rest)
    } else if h.eq_ignore_ascii_case(c) {
        true
    } else {
        h.len() > c.len()
            && h.as_bytes()[h.len() - c.len() - 1] == b'.'
            && h[h.len() - c.len()..].eq_ignore_ascii_case(c)
    }
}

fn check_name_constraints(ca: &TlsCert<'_>, hostname: &str) -> Result<(), VerifyError> {
    if parse_ipv4_literal(hostname).is_some() {
        return Ok(());
    }
    if ca.permitted_dns_count > 0 {
        let mut ok = false;
        for &c in &ca.permitted_dns[..ca.permitted_dns_count] {
            if let Ok(cs) = core::str::from_utf8(c)
                && dns_subtree_matches(cs, hostname)
            {
                ok = true;
                break;
            }
        }
        if !ok {
            return Err(VerifyError::NameConstraintViolation);
        }
    }
    for &c in &ca.excluded_dns[..ca.excluded_dns_count] {
        if let Ok(cs) = core::str::from_utf8(c)
            && dns_subtree_matches(cs, hostname)
        {
            return Err(VerifyError::NameConstraintViolation);
        }
    }
    Ok(())
}

fn check_ca_anchor(
    a: &TlsCert<'_>,
    hostname: &str,
    now_unix: i64,
    intermediates_passed: u32,
) -> Result<(), VerifyError> {
    a.check_validity(now_unix)?;
    if !a.is_ca {
        return Err(VerifyError::NotCa);
    }
    if a.has_key_usage && (a.key_usage & KU_KEY_CERT_SIGN) == 0 {
        return Err(VerifyError::KeyUsageViolation);
    }
    if let Some(pl) = a.path_len
        && intermediates_passed > pl
    {
        return Err(VerifyError::PathLenExceeded);
    }
    check_name_constraints(a, hostname)?;
    Ok(())
}

fn is_revoked_der(der: &[u8], revoked_sha256: &[[u8; 32]]) -> bool {
    if revoked_sha256.is_empty() {
        return false;
    }
    let h = sha256(der);
    revoked_sha256.contains(&h)
}

/// Verify a TLS server certificate chain (`chain_ders[0]` = leaf, followed by intermediates)
/// against `trust_anchors`, checking validity at `now_unix`, CA/pathLen/keyUsage/nameConstraints,
/// cryptographic signatures at every hop, and leaf SAN matching `hostname`.
pub fn verify_chain(
    chain_ders: &[&[u8]],
    trust_anchors: &[&[u8]],
    hostname: &str,
    now_unix: i64,
) -> Result<(), VerifyError> {
    verify_chain_with_revoked(chain_ders, trust_anchors, &[], hostname, now_unix)
}

/// Like [`verify_chain`], also rejecting any certificate in the verified path whose DER SHA-256
/// appears in `revoked_sha256` (supporting offline/shipped revocation lists and pinning).
pub fn verify_chain_with_revoked(
    chain_ders: &[&[u8]],
    trust_anchors: &[&[u8]],
    revoked_sha256: &[[u8; 32]],
    hostname: &str,
    now_unix: i64,
) -> Result<(), VerifyError> {
    if chain_ders.is_empty() {
        return Err(VerifyError::EmptyChain);
    }
    if chain_ders.len() > MAX_CHAIN_LEN {
        return Err(VerifyError::ChainTooLong);
    }
    if is_revoked_der(chain_ders[0], revoked_sha256) {
        return Err(VerifyError::Revoked);
    }
    let leaf = parse_tls(chain_ders[0])?;
    leaf.check_validity(now_unix)?;
    if !leaf.matches_host(hostname) {
        return Err(VerifyError::HostnameMismatch);
    }
    if leaf.has_key_usage && (leaf.key_usage & KU_DIGITAL_SIGNATURE) == 0 {
        return Err(VerifyError::KeyUsageViolation);
    }
    if leaf.has_eku && !leaf.eku_server_auth {
        return Err(VerifyError::KeyUsageViolation);
    }

    // Helper: check if any trust anchor signs `cert` (no artificial cap on anchor count).
    let find_anchor = |cert: &TlsCert<'_>, intermediates_passed: u32| -> Option<Result<(), VerifyError>> {
        for &der in trust_anchors {
            let Ok(a) = parse_tls(der) else { continue };
            if cert.issuer == a.subject && cert.signed_by(&a) {
                if is_revoked_der(der, revoked_sha256) {
                    return Some(Err(VerifyError::Revoked));
                }
                return Some(check_ca_anchor(&a, hostname, now_unix, intermediates_passed));
            }
        }
        None
    };

    let mut current = leaf;
    let mut intermediates_passed = 0u32;
    if let Some(res) = find_anchor(&current, intermediates_passed) {
        return res;
    }

    // Walk intermediates by issuer/subject matching (handles out-of-order and extra certs safely).
    let mut used = [false; MAX_CHAIN_LEN];
    let mut last_err: Option<VerifyError> = None;
    for _step in 1..chain_ders.len() {
        let mut advanced = false;
        for (idx, &cand_der) in chain_ders.iter().enumerate().skip(1) {
            if used[idx] {
                continue;
            }
            let cand = match parse_tls(cand_der) {
                Ok(c) => c,
                Err(e) => {
                    last_err = Some(e);
                    continue;
                }
            };
            if current.issuer != cand.subject {
                continue;
            }
            if !current.signed_by(&cand) {
                last_err = Some(VerifyError::BadSignature);
                continue;
            }
            if is_revoked_der(cand_der, revoked_sha256) {
                return Err(VerifyError::Revoked);
            }
            check_ca_anchor(&cand, hostname, now_unix, intermediates_passed)?;
            used[idx] = true;
            intermediates_passed += 1;
            current = cand;
            advanced = true;
            if let Some(res) = find_anchor(&current, intermediates_passed) {
                return res;
            }
            break;
        }
        if !advanced {
            break;
        }
    }

    Err(last_err.unwrap_or(VerifyError::UntrustedRoot))
}
