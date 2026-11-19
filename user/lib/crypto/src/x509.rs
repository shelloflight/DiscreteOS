//! X.509 certificates, as far as TPM endorsement-key certificates need (RFC 5280): parse the DER,
//! find the subject's RSA public key, and check the signature with the issuer's certificate.
//!
//! Strict DER subset: definite lengths only (at most 4 length bytes), every element inside its
//! parent, nothing left over at any level parsed. Signatures: sha256WithRSAEncryption and
//! sha384WithRSAEncryption (what TPM vendors' CAs use). Not checked here: validity dates (a TPM
//! has no trusted clock and EK certificates last decades), revocation, name constraints, policies;
//! a verifier that needs them applies its own PKI tooling to the chain above the issuer.

use crate::rsa::{self, Hash, PublicKey};

const SEQUENCE: u8 = 0x30;
const INTEGER: u8 = 0x02;
const BIT_STRING: u8 = 0x03;
const OID: u8 = 0x06;
const CONTEXT_0: u8 = 0xA0;

const OID_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
const OID_SHA256_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];
const OID_SHA384_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c];

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
