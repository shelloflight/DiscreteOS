//! Host tests for endorsement-key checking: SHA-384, RSA (PKCS #1 v1.5, OAEP) and X.509 against
//! .NET-made fixtures (`testkeys`), AES/HMAC/KDFa against published vectors, and the credential
//! binding (`make_credential` / `sim::open_credential`), including hostile input.

extern crate std;
use std::vec::Vec;

use crate::rsa::{self, Hash, PublicKey};
use crate::sha2::sha384;
use crate::sym::{Aes128, hmac_sha256, kdfa};
use crate::testkeys::*;
use crate::tpm;
use crate::x509;

fn hex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

struct XorShift(u64);
impl XorShift {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

#[test]
fn sha384_vectors() {
    assert_eq!(
        sha384(b"abc").to_vec(),
        hex("cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7")
    );
    assert_eq!(
        sha384(b"").to_vec(),
        hex("38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b")
    );
}

#[test]
fn aes_hmac_kdf_vectors() {
    // FIPS 197 C.1.
    let key: [u8; 16] = hex("000102030405060708090a0b0c0d0e0f").try_into().unwrap();
    let mut b: [u8; 16] = hex("00112233445566778899aabbccddeeff").try_into().unwrap();
    Aes128::new(&key).encrypt_block(&mut b);
    assert_eq!(b.to_vec(), hex("69c4e0d86a7b0430d8cdb78070b4c55a"));
    // SP 800-38A F.3.13 (CFB128-AES128, first two blocks; that test uses a non-zero IV, so check
    // CFB through its definition: block 1 = P1 ^ E(IV) with IV = 0 here).
    let k2: [u8; 16] = hex("2b7e151628aed2a6abf7158809cf4f3c").try_into().unwrap();
    let aes = Aes128::new(&k2);
    let mut data = hex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411");
    let orig = data.clone();
    aes.cfb_encrypt(&mut data);
    let mut iv = [0u8; 16];
    aes.encrypt_block(&mut iv);
    for i in 0..16 {
        assert_eq!(data[i], orig[i] ^ iv[i]);
    }
    let mut iv2: [u8; 16] = data[..16].try_into().unwrap();
    aes.encrypt_block(&mut iv2);
    for i in 0..16 {
        assert_eq!(data[16 + i], orig[16 + i] ^ iv2[i]);
    }
    aes.cfb_decrypt(&mut data);
    assert_eq!(data, orig);
    // RFC 4231 test cases 1 and 2.
    assert_eq!(
        hmac_sha256(&[0x0b; 20], &[b"Hi There"]).to_vec(),
        hex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
    );
    assert_eq!(
        hmac_sha256(b"Jefe", &[b"what do ya want ", b"for nothing?"]).to_vec(),
        hex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
    );
    // A long key is hashed first (RFC 4231 case 6).
    assert_eq!(
        hmac_sha256(&[0xaa; 131], &[b"Test Using Larger Than Block-Size Key - Hash Key First"]).to_vec(),
        hex("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54")
    );
    // KDFa: the counter, label, zero, contexts and bit count go into HMAC in that order.
    let mut out = [0u8; 40];
    kdfa(b"seed", "STORAGE", b"u", b"v", &mut out);
    let first = hmac_sha256(b"seed", &[&1u32.to_be_bytes(), b"STORAGE\0", b"u", b"v", &320u32.to_be_bytes()]);
    let second = hmac_sha256(b"seed", &[&2u32.to_be_bytes(), b"STORAGE\0", b"u", b"v", &320u32.to_be_bytes()]);
    assert_eq!(&out[..32], &first);
    assert_eq!(&out[32..], &second[..8]);
}

#[test]
fn rsa_against_dotnet() {
    let ca = x509::parse(&CA_CERT).expect("CA certificate parses");
    let key = ca.public_key().unwrap();
    assert_eq!(key.size(), 256);
    assert!(rsa::verify_pkcs1(&key, Hash::Sha384, &MSG, &MSG_SIG_SHA384));
    assert!(!rsa::verify_pkcs1(&key, Hash::Sha256, &MSG, &MSG_SIG_SHA384));
    assert!(!rsa::verify_pkcs1(&key, Hash::Sha384, b"D-OS RSA test vectoR", &MSG_SIG_SHA384));
    let mut bad = MSG_SIG_SHA384;
    bad[100] ^= 1;
    assert!(!rsa::verify_pkcs1(&key, Hash::Sha384, &MSG, &bad));
    assert!(!rsa::verify_pkcs1(&key, Hash::Sha384, &MSG, &MSG_SIG_SHA384[1..]));
    // A signature >= n is refused, not reduced.
    let mut n = [0u8; 256];
    key.modulus(&mut n);
    assert!(!rsa::verify_pkcs1(&key, Hash::Sha384, &MSG, &n));
    // OAEP: .NET's ciphertext decrypts with our private operation; ours round-trips.
    let ek = PublicKey::new(&EK_N, 65537).unwrap();
    let mut m = [0u8; 64];
    let len = rsa::sim::oaep_decrypt(&ek, &EK_D, &OAEP_CT, b"", &mut m).expect(".NET OAEP decrypts");
    assert_eq!(&m[..len], &(1..=32).collect::<Vec<u8>>()[..]);
    assert!(rsa::sim::oaep_decrypt(&ek, &EK_D, &OAEP_CT, b"IDENTITY\0", &mut m).is_none());
    let mut ct = [0u8; 256];
    rsa::oaep_encrypt(&ek, b"secret", b"L\0", &[7; 32], &mut ct).unwrap();
    let len = rsa::sim::oaep_decrypt(&ek, &EK_D, &ct, b"L\0", &mut m).unwrap();
    assert_eq!(&m[..len], b"secret");
    // Keys that are not RSA keys.
    assert!(PublicKey::new(&EK_N[..100], 65537).is_none());
    assert!(PublicKey::new(&EK_N, 65536).is_none());
    let mut even = EK_N;
    even[255] &= !1;
    assert!(PublicKey::new(&even, 65537).is_none());
}

#[test]
fn x509_chain() {
    let ca = x509::parse(&CA_CERT).unwrap();
    let ek = x509::parse(&EK_CERT).expect("EK certificate parses");
    assert_eq!(ek.rsa_n, &EK_N[..]);
    assert_eq!(ek.rsa_e, 65537);
    assert_eq!(ek.sig_alg, x509::SigAlg::Sha256Rsa);
    assert!(ek.signed_by(&ca));
    assert!(ca.signed_by(&ca));
    assert!(!ca.signed_by(&ek)); // names differ
    // Any change to the signed part breaks the signature (when it still parses).
    let mut rng = XorShift(0x5EED);
    let mut parsed_bad = 0;
    for _ in 0..3_000 {
        let mut b = EK_CERT.to_vec();
        let at = (rng.next() as usize) % b.len();
        let v = rng.next() as u8;
        if b[at] == v {
            continue;
        }
        b[at] = v;
        if let Some(c) = x509::parse(&b) {
            parsed_bad += 1;
            assert!(!c.signed_by(&ca), "damaged byte {} accepted", at);
        }
    }
    assert!(parsed_bad > 100);
    // Truncations and trailing data are refused.
    for n in 0..EK_CERT.len() {
        assert!(x509::parse(&EK_CERT[..n]).is_none());
    }
    let mut longer = EK_CERT.to_vec();
    longer.push(0);
    assert!(x509::parse(&longer).is_none());
    // Random bytes and random DER-looking headers never panic.
    for _ in 0..20_000 {
        let len = (rng.next() % 64) as usize;
        let mut b: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
        if !b.is_empty() {
            b[0] = 0x30;
        }
        let _ = x509::parse(&b);
    }
}

/// The TPM's EK public area for the test key.
fn ek_area() -> Vec<u8> {
    let (a, n) = tpm::sim::ek_public(&EK_N);
    a[..n].to_vec()
}

#[test]
fn credential_binding() {
    let area = ek_area();
    let ek = tpm::parse_rsa_ek(&area).expect("EK area parses");
    assert_eq!(ek.modulus, &EK_N[..]);
    assert_eq!(ek.exponent, 65537);
    let (template, tn) = tpm::ek_template();
    assert_eq!(tn, area.len());
    assert_eq!(&template[..tn - 256], &area[..tn - 256]);
    let (ak, an) = tpm::sim::ak_public(&[1; 32], &[2; 32]);
    let mut ak_name = [0u8; 34];
    ak_name[..2].copy_from_slice(&tpm::ALG_SHA256.to_be_bytes());
    ak_name[2..].copy_from_slice(&crate::sha2::sha256(&ak[..an]));
    let cred = [0x42u8; 32];
    let (blob, secret) = tpm::make_credential(&ek, &ak_name, &cred, &[9; 32], &[3; 32]).unwrap();
    assert_eq!(tpm::sim::open_credential(&EK_N, &EK_D, &ak_name, &blob, &secret), Some(cred));
    // Bound to the AK: another object's name gets nothing.
    let mut other = ak_name;
    other[5] ^= 1;
    assert_eq!(tpm::sim::open_credential(&EK_N, &EK_D, &other, &blob, &secret), None);
    // Any damage to the blob or the secret is detected.
    for i in 0..blob.len() {
        let mut b = blob;
        b[i] ^= 0x10;
        assert_eq!(tpm::sim::open_credential(&EK_N, &EK_D, &ak_name, &b, &secret), None, "blob byte {}", i);
    }
    let mut rng = XorShift(99);
    for _ in 0..40 {
        let mut s = secret;
        let at = 2 + (rng.next() as usize) % 256;
        s[at] ^= 1 << (rng.next() % 8);
        assert_eq!(tpm::sim::open_credential(&EK_N, &EK_D, &ak_name, &blob, &s), None);
    }
    // EK areas that are not the EK template are refused.
    for at in 0..area.len() - 256 {
        let mut a = area.clone();
        a[at] ^= 0x01;
        assert!(tpm::parse_rsa_ek(&a).is_none(), "area byte {}", at);
    }
    for n in 0..area.len() {
        assert!(tpm::parse_rsa_ek(&area[..n]).is_none());
    }
}

/// The build machine's own EK certificate, when build.ps1 has saved one (never committed).
#[test]
fn host_ek_certificate() {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../build/host/ekcert.der");
    let Ok(der) = std::fs::read(&p) else { return };
    let c = x509::parse(&der).expect("this machine's EK certificate parses");
    assert!(c.public_key().is_some_and(|k| k.size() == 256));
    std::println!("host EK certificate: {} bytes, RSA {} bits, {:?}", der.len(), c.rsa_n.len() * 8, c.sig_alg);
}

/// A report with TPM evidence, made the way the kernel makes it (the TPM side simulated), checked
/// the way a verifier checks it, then the credential challenge answered by the "TPM".
#[test]
fn report_with_tpm_evidence() {
    use crate::attest::{self, Claims, Error, Event, Policy, TpmEvidence, TpmStatus};
    use crate::dsig;
    use crate::ed25519::SigningKey;
    use crate::p256;
    use crate::sha2::{Sha256, sha256};
    let signer = SigningKey::from_seed(&[7; 32]);
    let kdsig = dsig::sign(&signer, dsig::KIND_KERNEL, "KERNEL.BIN", b"kernel").to_vec();
    let key = signer.public();
    let ak = SigningKey::from_seed(&[9; 32]);
    let nonce = [0x33u8; 32];
    let ev = [(attest::PCR_KERNEL, sha256(&kdsig[..dsig::SIGNED]), "kernel"), (attest::PCR_KERNEL, attest::ak_digest(&ak.public()), attest::AK_EVENT)];
    let mut p8 = [0u8; 32];
    for (_, d, _) in &ev {
        let mut h = Sha256::new();
        h.update(&p8);
        h.update(d);
        p8 = h.finish();
    }
    let p10 = [0u8; 32];
    // The TPM: AK, quote over PCRs 8 and 10 with the nonce, EK, certificate.
    let d = sha256(b"test AK");
    let pk = p256::sim::public(&d);
    let (akp, an) = tpm::sim::ak_public(&pk.x(), &pk.y());
    let ak_public = akp[..an].to_vec();
    let ak_name = tpm::parse_ecc_public(&ak_public).unwrap().name;
    let quote_for = |n: &[u8], pcr8: [u8; 32]| {
        let mut h = Sha256::new();
        h.update(&pcr8);
        h.update(&p10);
        let (info, len) = tpm::sim::quote_info(&ak_name, n, attest::QUOTED_PCRS, &h.finish());
        let (r, s) = p256::sim::sign_prehash(&d, &[5; 32], &sha256(&info[..len])).unwrap();
        let (sig, sl) = tpm::sim::ecdsa_signature(&r, &s);
        (info[..len].to_vec(), sig[..sl].to_vec())
    };
    let (quote, qsig) = quote_for(&nonce, p8);
    let ek_public = ek_area();
    let build = |q: &[u8], qs: &[u8], ekp: &[u8], cert: &[u8]| {
        let t = TpmEvidence { ak_public: &ak_public, quote: q, quote_sig: qs, ek_public: ekp, ek_cert: cert };
        let events: Vec<Event<'_>> = ev.iter().map(|(p, d, t)| Event { pcr: *p, in_tpm: true, digest: *d, text: t }).collect();
        let c = Claims { flags: attest::F_KERNEL_VERIFIED | attest::F_TPM | attest::F_TPM_MATCH, firmware: 2, lost: 0, nonce, kernel_version: "0.15", trusted_key_id: dsig::key_id(&key), pcr8: p8, pcr10: p10 };
        let mut out = std::vec![0u8; attest::MAX_SIZE];
        let n = attest::build(&c, &events, Some(&t), &ak, &mut out).unwrap();
        out.truncate(n);
        out
    };
    let good = build(&quote, &qsig, &ek_public, &EK_CERT);
    let issuers: [&[u8]; 1] = [&CA_CERT];
    let p = Policy { kernel_dsig: &kdsig, key: &key, allow_unsigned: false, require_tpm: true, ek_issuers: &issuers };
    assert_eq!(attest::verify(&good, &nonce, &p).unwrap().tpm, TpmStatus::Certified);
    let p_quoted = Policy { kernel_dsig: &kdsig, key: &key, allow_unsigned: false, require_tpm: true, ek_issuers: &[] };
    assert_eq!(attest::verify(&good, &nonce, &p_quoted).unwrap().tpm, TpmStatus::Quoted);
    // A quote for another nonce, or of other PCR values, is refused.
    let (q2, s2) = quote_for(&[0x44; 32], p8);
    assert_eq!(attest::verify(&build(&q2, &s2, &ek_public, &EK_CERT), &nonce, &p).unwrap_err(), Error::Quote(tpm::QuoteError::WrongNonce));
    let (q3, s3) = quote_for(&nonce, [1; 32]);
    assert_eq!(attest::verify(&build(&q3, &s3, &ek_public, &EK_CERT), &nonce, &p).unwrap_err(), Error::Quote(tpm::QuoteError::WrongPcrs));
    // A certificate for another key; one from an untrusted issuer; none at all.
    assert_eq!(attest::verify(&build(&quote, &qsig, &ek_public, &CA_CERT), &nonce, &p).unwrap_err(), Error::EkMismatch);
    let wrong_issuer: [&[u8]; 1] = [&EK_CERT];
    let p_wrong = Policy { kernel_dsig: &kdsig, key: &key, allow_unsigned: false, require_tpm: true, ek_issuers: &wrong_issuer };
    assert_eq!(attest::verify(&good, &nonce, &p_wrong).unwrap_err(), Error::EkUntrusted);
    assert_eq!(attest::verify(&build(&quote, &qsig, &ek_public, &[]), &nonce, &p).unwrap_err(), Error::EkUntrusted);
    // An EK area that is not the EK template.
    let mut bad_ek = ek_public.clone();
    bad_ek[5] ^= 1;
    assert_eq!(attest::verify(&build(&quote, &qsig, &bad_ek, &EK_CERT), &nonce, &p).unwrap_err(), Error::TpmFormat);
    // Malformed evidence: every truncation of the section (re-signed) is refused, never a panic.
    let count = 2;
    let at = attest::HEADER + count * attest::EVENT;
    let tlen = u32::from_le_bytes(good[at..at + 4].try_into().unwrap()) as usize;
    for cut in [1usize, 2, 50, tlen / 2, tlen - 1] {
        let mut r = good[..at + 4 + tlen - cut].to_vec();
        r[at..at + 4].copy_from_slice(&((tlen - cut) as u32).to_le_bytes());
        r.extend_from_slice(&[0; 64]);
        let body = r.len() - 64;
        let s = ak.sign(&r[..body]);
        r[body..].copy_from_slice(&s);
        assert_eq!(attest::verify(&r, &nonce, &p).unwrap_err(), Error::TpmFormat, "cut {}", cut);
        assert!(attest::challenge(&r, &[0; 32], &[1; 32], &[2; 32]).is_none());
    }
    // Without TPM evidence: refused when the policy requires it.
    let events: Vec<Event<'_>> = ev.iter().map(|(p, d, t)| Event { pcr: *p, in_tpm: false, digest: *d, text: t }).collect();
    let c = Claims { flags: attest::F_KERNEL_VERIFIED, firmware: 2, lost: 0, nonce, kernel_version: "0.15", trusted_key_id: dsig::key_id(&key), pcr8: p8, pcr10: p10 };
    let mut plain = std::vec![0u8; attest::MAX_SIZE];
    let n = attest::build(&c, &events, None, &ak, &mut plain).unwrap();
    plain.truncate(n);
    assert_eq!(attest::verify(&plain, &nonce, &p).unwrap_err(), Error::TpmRequired);
    assert!(attest::challenge(&plain, &[0; 32], &[1; 32], &[2; 32]).is_none());
    // The challenge: only the EK's private key with this AK's name opens it.
    let cred = [0x77u8; 32];
    let (blob, secret) = attest::challenge(&good, &cred, &[1; 32], &[2; 32]).unwrap();
    assert_eq!(tpm::sim::open_credential(&EK_N, &EK_D, &ak_name, &blob, &secret), Some(cred));
}
