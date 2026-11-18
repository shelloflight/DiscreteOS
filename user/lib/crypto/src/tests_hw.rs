//! Host tests for the hardware-attestation crypto: constant-time Ed25519 scalar multiplication,
//! ECDSA P-256 (RFC 6979 vectors, edge cases, signatures from .NET when build.ps1 provides them),
//! TPM 2.0 quote parsing and verification (good quotes, every kind of bad one, hostile blobs).

extern crate std;
use std::vec::Vec;

use crate::ed25519::{SigningKey, verify};
use crate::p256::{self, PublicKey, testsign};
use crate::sha2::sha256;
use crate::tpm::{self, QuoteError};

fn hex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn h32(s: &str) -> [u8; 32] {
    hex(s).try_into().unwrap()
}

struct XorShift(u64);
impl XorShift {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn bytes<const N: usize>(&mut self) -> [u8; N] {
        let mut b = [0u8; N];
        for x in b.iter_mut() {
            *x = self.next() as u8;
        }
        b
    }
}

// ---- Ed25519: constant-time scalar multiplication ------------------------------------------------

#[test]
fn ed25519_mul_ct_equals_mul() {
    let mut rng = XorShift(0x1234_5678_9ABC_DEF1);
    let mut edge = [[0u8; 32], [0xFF; 32], [0u8; 32]];
    edge[2][0] = 1;
    for s in edge {
        assert!(crate::ed25519::mul_ct_matches(&s));
    }
    for _ in 0..24 {
        assert!(crate::ed25519::mul_ct_matches(&rng.bytes::<32>()));
    }
    // Signatures from the constant-time signer verify, for many keys and messages.
    for i in 0..16usize {
        let k = SigningKey::from_seed(&rng.bytes::<32>());
        let m: Vec<u8> = (0..i * 13).map(|_| rng.next() as u8).collect();
        let sig = k.sign(&m);
        assert!(verify(&k.public(), &m, &sig));
    }
}

// ---- ECDSA P-256 --------------------------------------------------------------------------------

/// RFC 6979 A.2.5 (P-256, SHA-256): the key and the "sample" / "test" signatures.
const D: &str = "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721";
const UX: &str = "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6";
const UY: &str = "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299";
const RFC6979: [(&str, &str, &str, &str); 2] = [
    (
        "sample",
        "A6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60",
        "EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716",
        "F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8",
    ),
    (
        "test",
        "D16B6AE827F17175E040871A1C7EC3500192C4C92677336EC2537ACAEE0008E0",
        "F1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367",
        "019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083",
    ),
];

#[test]
fn p256_constants() {
    assert!(testsign::check_constants(), "G on the curve, n*G = O, (n-1)*G = -G");
}

#[test]
fn p256_rfc6979_vectors() {
    let key = PublicKey::from_xy(&h32(UX), &h32(UY)).expect("RFC 6979 key on the curve");
    assert_eq!(testsign::public(&h32(D)), key, "public key of d");
    for (msg, k, r, s) in RFC6979 {
        let hm = sha256(msg.as_bytes());
        let (gr, gs) = testsign::sign_prehash(&h32(D), &h32(k), &hm).unwrap();
        assert_eq!((gr, gs), (h32(r), h32(s)), "signature of {msg:?} with the RFC's k");
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&h32(r));
        sig[32..].copy_from_slice(&h32(s));
        assert!(p256::verify(&key, msg.as_bytes(), &sig), "{msg}");
        assert!(!p256::verify(&key, b"other", &sig));
        // n - s is the other valid signature; r or s out of range never verifies.
        assert!(p256::verify_prehash(&key, &hm, &h32(r), &testsign::negate_s(&h32(s))));
        let n = testsign::order();
        assert!(!p256::verify_prehash(&key, &hm, &[0; 32], &h32(s)));
        assert!(!p256::verify_prehash(&key, &hm, &h32(r), &[0; 32]));
        assert!(!p256::verify_prehash(&key, &hm, &n, &h32(s)));
        assert!(!p256::verify_prehash(&key, &hm, &h32(r), &n));
        assert!(!p256::verify_prehash(&key, &hm, &[0xFF; 32], &h32(s)));
        // Single-bit changes are refused.
        for bit in (0..512).step_by(37) {
            let mut bad = sig;
            bad[bit / 8] ^= 1 << (bit % 8);
            assert!(!p256::verify(&key, msg.as_bytes(), &bad));
        }
    }
}

#[test]
fn p256_bad_keys() {
    let (x, y) = (h32(UX), h32(UY));
    let mut y1 = y;
    y1[31] ^= 1;
    assert!(PublicKey::from_xy(&x, &y1).is_none(), "off the curve");
    assert!(PublicKey::from_xy(&[0; 32], &[0; 32]).is_none(), "identity encoding");
    let p = h32("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF");
    assert!(PublicKey::from_xy(&p, &y).is_none(), "x = p");
    assert!(PublicKey::from_xy(&x, &[0xFF; 32]).is_none(), "y >= p");
    let mut sec1 = [0u8; 65];
    sec1[0] = 4;
    sec1[1..33].copy_from_slice(&x);
    sec1[33..].copy_from_slice(&y);
    assert!(PublicKey::from_sec1(&sec1).is_some());
    sec1[0] = 2;
    assert!(PublicKey::from_sec1(&sec1).is_none(), "compressed form refused");
    assert!(PublicKey::from_sec1(&sec1[..64]).is_none());
}

#[test]
fn p256_random_sign_verify() {
    let mut rng = XorShift(0xDEAD_BEEF_CAFE_F00D);
    for i in 0..40 {
        let mut d = rng.bytes::<32>();
        let mut k = rng.bytes::<32>();
        d[0] &= 0x7F; // < n
        k[0] &= 0x7F;
        if i == 0 {
            d = [0; 32];
            d[31] = 1; // Q = G
        }
        if i == 1 {
            d = testsign::order();
            d[31] -= 1; // Q = -G
        }
        let key = testsign::public(&d);
        let m = rng.bytes::<48>();
        let hm = sha256(&m);
        let (r, s) = testsign::sign_prehash(&d, &k, &hm).unwrap();
        assert!(p256::verify_prehash(&key, &hm, &r, &s));
        assert!(!p256::verify_prehash(&key, &sha256(&m[1..]), &r, &s));
        let other = testsign::public(&rng.bytes::<32>().map(|b| b & 0x3F));
        assert!(!p256::verify_prehash(&other, &hm, &r, &s));
    }
}

/// Signatures made by another implementation (.NET's ECDsa, written by build.ps1 crypto-host to the
/// file named in DOSCRYPT_P256_VECTORS): `qx qy message signature expected` per line, hex.
#[test]
fn p256_external_vectors() {
    let Ok(path) = std::env::var("DOSCRYPT_P256_VECTORS") else { return };
    let text = std::fs::read_to_string(path).unwrap();
    let mut n = 0;
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let f: Vec<&str> = line.split_whitespace().collect();
        let key = PublicKey::from_xy(&h32(f[0]), &h32(f[1])).expect("key from .NET on the curve");
        let msg = if f[2] == "-" { Vec::new() } else { hex(f[2]) };
        let sig: [u8; 64] = hex(f[3]).try_into().unwrap();
        assert_eq!(p256::verify(&key, &msg, &sig), f[4] == "1", "vector {n}: {line}");
        n += 1;
    }
    assert!(n >= 32, "only {n} external vectors");
}

// ---- TPM 2.0 quotes -----------------------------------------------------------------------------

fn be16(v: &mut Vec<u8>, x: u16) {
    v.extend_from_slice(&x.to_be_bytes());
}

fn tpm2b(v: &mut Vec<u8>, b: &[u8]) {
    be16(v, b.len() as u16);
    v.extend_from_slice(b);
}

/// TPMT_PUBLIC of an ECC P-256 key with the given attributes and point.
fn ak_public(attrs: u32, key: &PublicKey) -> Vec<u8> {
    let mut v = Vec::new();
    be16(&mut v, tpm::ALG_ECC);
    be16(&mut v, tpm::ALG_SHA256);
    v.extend_from_slice(&attrs.to_be_bytes());
    tpm2b(&mut v, &[]); // no policy
    be16(&mut v, tpm::ALG_NULL); // symmetric
    be16(&mut v, tpm::ALG_ECDSA);
    be16(&mut v, tpm::ALG_SHA256);
    be16(&mut v, tpm::ECC_NIST_P256);
    be16(&mut v, tpm::ALG_NULL); // KDF
    let x = key.x();
    let first = x.iter().position(|&b| b != 0).unwrap_or(31);
    tpm2b(&mut v, &x[first..]); // leading zeros dropped, as a TPM may
    tpm2b(&mut v, &key.y());
    v
}

fn quote_bytes(signer: &[u8], nonce: &[u8], select: [u8; 3], digest: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&tpm::TPM_GENERATED.to_be_bytes());
    be16(&mut v, tpm::ST_ATTEST_QUOTE);
    tpm2b(&mut v, signer);
    tpm2b(&mut v, nonce);
    v.extend_from_slice(&0x1234_5678u64.to_be_bytes()); // clock
    v.extend_from_slice(&3u32.to_be_bytes()); // resets
    v.extend_from_slice(&7u32.to_be_bytes()); // restarts
    v.push(1); // safe
    v.extend_from_slice(&0x0001_0002_0003_0004u64.to_be_bytes()); // firmware
    v.extend_from_slice(&1u32.to_be_bytes());
    be16(&mut v, tpm::ALG_SHA256);
    v.push(3);
    v.extend_from_slice(&select);
    tpm2b(&mut v, digest);
    v
}

fn signature_bytes(d: &[u8; 32], k: &[u8; 32], attest: &[u8]) -> Vec<u8> {
    let (r, s) = testsign::sign_prehash(d, k, &sha256(attest)).unwrap();
    let mut v = Vec::new();
    be16(&mut v, tpm::ALG_ECDSA);
    be16(&mut v, tpm::ALG_SHA256);
    tpm2b(&mut v, &r);
    tpm2b(&mut v, &s);
    v
}

#[test]
fn tpm_quote_verification() {
    let d = h32(D);
    let k = h32("0F1E2D3C4B5A69788796A5B4C3D2E1F00112233445566778899AABBCCDDEEFF0");
    let key = testsign::public(&d);
    let public = ak_public(tpm::AK_ATTRIBUTES | (1 << 6) | (1 << 7), &key);
    let ak = tpm::parse_ecc_public(&public).expect("AK public area");
    assert_eq!(ak.key, key);
    let nonce = [0x5Au8; 32];
    let pcr8 = sha256(b"kernel");
    let pcr10 = sha256(b"programs");
    let digest = tpm::pcr_digest(&[pcr8, pcr10]);
    let attest = quote_bytes(&ak.name, &nonce, [0x00, 0x05, 0x00], &digest); // PCR 8 and 10
    let sig = signature_bytes(&d, &k, &attest);
    let want = [(10u8, pcr10), (8u8, pcr8)];
    let q = tpm::verify_quote(&public, &attest, &sig, &nonce, &want).expect("good quote");
    assert_eq!((q.clock, q.reset_count, q.restart_count, q.safe, q.pcrs), (0x1234_5678, 3, 7, true, 0x500));

    let check = |p: &[u8], a: &[u8], s: &[u8], n: &[u8], w: &[(u8, [u8; 32])]| tpm::verify_quote(p, a, s, n, w).err();
    // Wrong nonce (replay), PCR values, PCR selection.
    assert_eq!(check(&public, &attest, &sig, &[0x5B; 32], &want), Some(QuoteError::WrongNonce));
    assert_eq!(check(&public, &attest, &sig, &nonce, &[(8, pcr8), (10, pcr8)]), Some(QuoteError::WrongPcrs));
    assert_eq!(check(&public, &attest, &sig, &nonce, &[(8, pcr8)]), Some(QuoteError::WrongSelection));
    assert_eq!(check(&public, &attest, &sig, &nonce, &[(8, pcr8), (8, pcr8)]), Some(QuoteError::WrongSelection));
    // Any changed byte of the quote breaks the signature.
    for i in 0..attest.len() {
        let mut bad = attest.clone();
        bad[i] ^= 0x10;
        assert_eq!(check(&public, &bad, &sig, &nonce, &want), Some(QuoteError::BadSignature), "byte {i}");
    }
    // Signed by another key, or the key is not a restricted TPM signing key.
    let other_d = h32("1111111111111111111111111111111111111111111111111111111111111111");
    let other = ak_public(tpm::AK_ATTRIBUTES, &testsign::public(&other_d));
    assert_eq!(check(&other, &attest, &sig, &nonce, &want), Some(QuoteError::BadSignature));
    let resigned = signature_bytes(&other_d, &k, &attest);
    assert_eq!(check(&other, &attest, &resigned, &nonce, &want), Some(QuoteError::WrongSigner));
    for attrs in [
        tpm::AK_ATTRIBUTES & !tpm::OBJ_RESTRICTED,
        tpm::AK_ATTRIBUTES & !tpm::OBJ_FIXED_TPM,
        tpm::AK_ATTRIBUTES | tpm::OBJ_DECRYPT,
    ] {
        let p = ak_public(attrs, &key);
        assert_eq!(check(&p, &attest, &sig, &nonce, &want), Some(QuoteError::NotAttestationKey));
    }
    // Well signed but not a quote, or with trailing bytes.
    let mut not_quote = attest.clone();
    not_quote[5] = 0x17; // TPM_ST_ATTEST_CERTIFY
    let s2 = signature_bytes(&d, &k, &not_quote);
    assert_eq!(check(&public, &not_quote, &s2, &nonce, &want), Some(QuoteError::BadQuote));
    let mut trailing = attest.clone();
    trailing.push(0);
    let s3 = signature_bytes(&d, &k, &trailing);
    assert_eq!(check(&public, &trailing, &s3, &nonce, &want), Some(QuoteError::BadQuote));
    // Malformed blobs: every truncation is refused; random damage never panics.
    for n in 0..public.len() {
        assert!(tpm::parse_ecc_public(&public[..n]).is_none());
    }
    for n in 0..attest.len() {
        assert!(tpm::parse_quote(&attest[..n]).is_none());
    }
    for n in 0..sig.len() {
        assert!(tpm::parse_ecdsa_signature(&sig[..n]).is_none());
    }
    let mut rng = XorShift(77);
    for _ in 0..5_000 {
        let mut b = attest.clone();
        for _ in 0..1 + rng.next() % 4 {
            let at = (rng.next() as usize) % b.len();
            b[at] = rng.next() as u8;
        }
        let _ = tpm::parse_quote(&b);
        let _ = tpm::verify_quote(&public, &b, &sig, &nonce, &want);
        let mut p = public.clone();
        let at = (rng.next() as usize) % p.len();
        p[at] = rng.next() as u8;
        let _ = tpm::parse_ecc_public(&p);
    }
}
