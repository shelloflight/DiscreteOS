//! Host tests (`cargo test`, build.ps1 case `crypto-host`): FIPS 180 and RFC 8032 vectors, the SHA-2
//! constant tables recomputed from the primes, Ed25519 and `.dsig` negative cases.

extern crate std;
use std::vec::Vec;

use crate::dsig;
use crate::ed25519::{SigningKey, verify};
use crate::sha2::{Sha256, Sha512, TABLES, sha256, sha512};

fn hex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

#[test]
fn sha2_vectors() {
    assert_eq!(sha256(b"abc").to_vec(), hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    assert_eq!(sha256(b"").to_vec(), hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
    assert_eq!(
        sha256(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq").to_vec(),
        hex("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1")
    );
    assert_eq!(
        sha512(b"abc").to_vec(),
        hex("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f")
    );
    assert_eq!(
        sha512(b"").to_vec(),
        hex("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e")
    );
    // Streaming in odd pieces gives the same digest.
    let data: Vec<u8> = (0..1000u32).map(|i| (i * 7 + 3) as u8).collect();
    let (mut a, mut b) = (Sha256::new(), Sha512::new());
    for c in data.chunks(37) {
        a.update(c);
        b.update(c);
    }
    assert_eq!(a.finish(), sha256(&data));
    assert_eq!(b.finish(), sha512(&data));
}

// 256-bit unsigned helpers for recomputing the constants.
fn mul_wide(a: &[u64; 4], b: u128) -> [u64; 4] {
    let (bl, bh) = (b as u64, (b >> 64) as u64);
    let mut out = [0u64; 6];
    for (k, bw) in [bl, bh].into_iter().enumerate() {
        let mut carry = 0u128;
        for i in 0..4 {
            let t = a[i] as u128 * bw as u128 + out[i + k] as u128 + carry;
            out[i + k] = t as u64;
            carry = t >> 64;
        }
        out[4 + k] = out[4 + k].wrapping_add(carry as u64);
    }
    assert!(out[4] == 0 && out[5] == 0, "overflow");
    [out[0], out[1], out[2], out[3]]
}
fn le(a: &[u64; 4], b: &[u64; 4]) -> bool {
    for i in (0..4).rev() {
        if a[i] != b[i] {
            return a[i] < b[i];
        }
    }
    true
}
/// floor(root-th root of n), searched in [0, 2^70).
fn iroot(n: &[u64; 4], root: u32) -> u128 {
    let (mut lo, mut hi) = (0u128, 1u128 << 70);
    while hi - lo > 1 {
        let mid = (lo + hi) / 2;
        let mut p = [1u64, 0, 0, 0];
        for _ in 0..root {
            p = mul_wide(&p, mid);
        }
        if le(&p, n) { lo = mid } else { hi = mid }
    }
    lo
}

#[test]
fn sha2_constants_from_primes() {
    let primes: Vec<u64> = (2u64..).filter(|n| (2..*n).take_while(|d| d * d <= *n).all(|d| n % d != 0)).take(80).collect();
    let (k, h) = TABLES;
    for (i, p) in primes.iter().enumerate() {
        // frac(cbrt(p)) * 2^64 = low 64 bits of floor(cbrt(p * 2^192))
        let n = [0, 0, 0, *p];
        assert_eq!(iroot(&n, 3) as u64, k[i], "K[{}]", i);
        if i < 8 {
            let n = [0, 0, *p, 0]; // p * 2^128
            assert_eq!(iroot(&n, 2) as u64, h[i], "H[{}]", i);
        }
    }
}

const RFC8032: [(&str, &str, &str, &str); 3] = [
    (
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "",
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    ),
    (
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "72",
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    ),
    (
        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        "af82",
        "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
    ),
];

#[test]
fn ed25519_rfc8032() {
    for (seed, public, msg, sig) in RFC8032 {
        let seed: [u8; 32] = hex(seed).try_into().unwrap();
        let k = SigningKey::from_seed(&seed);
        assert_eq!(k.public().to_vec(), hex(public), "public key");
        let m = hex(msg);
        let s = k.sign(&m);
        assert_eq!(s.to_vec(), hex(sig), "signature");
        assert!(verify(&k.public(), &m, &s));
    }
}

#[test]
fn ed25519_rejects() {
    let k = SigningKey::from_seed(&[7; 32]);
    let m = b"D-OS kernel";
    let s = k.sign(m);
    assert!(verify(&k.public(), m, &s));
    assert!(!verify(&k.public(), b"D-OS kernel!", &s), "other message");
    for i in [0, 31, 32, 63] {
        let mut t = s;
        t[i] ^= 1;
        assert!(!verify(&k.public(), m, &t), "flipped signature byte {}", i);
    }
    let other = SigningKey::from_seed(&[8; 32]);
    assert!(!verify(&other.public(), m, &s), "other key");
    // S + L is the same scalar but not canonical: refused (malleability).
    let mut t = s;
    let l = hex("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010");
    let mut carry = 0u16;
    for i in 0..32 {
        let v = t[32 + i] as u16 + l[i] as u16 + carry;
        t[32 + i] = v as u8;
        carry = v >> 8;
    }
    assert!(!verify(&k.public(), m, &t), "non-canonical S");
    // A public key whose y is not canonical (y = p): refused.
    let mut bad = [0xFFu8; 32];
    bad[0] = 0xED;
    bad[31] = 0x7F;
    assert!(!verify(&bad, m, &s));
}

#[test]
fn dsig_round_trip_and_tamper() {
    let k = SigningKey::from_seed(&[1; 32]);
    let content: Vec<u8> = (0..5000u32).map(|i| (i * 13) as u8).collect();
    let d = dsig::sign(&k, dsig::KIND_PROGRAM, "hello.dx", &content);
    let h = dsig::verify(&d, &k.public(), &content).unwrap();
    assert_eq!((h.kind, h.size, h.name_str()), (dsig::KIND_PROGRAM, 5000, "hello.dx"));
    let mut c2 = content.clone();
    c2[1234] ^= 0x40;
    assert_eq!(dsig::verify(&d, &k.public(), &c2).unwrap_err(), dsig::Error::Content);
    assert_eq!(dsig::verify(&d, &k.public(), &content[..4999]).unwrap_err(), dsig::Error::Content);
    let other = SigningKey::from_seed(&[2; 32]);
    assert_eq!(dsig::verify(&d, &other.public(), &content).unwrap_err(), dsig::Error::UnknownKey);
    // Any change to the signed header (here: the name or kind) breaks the signature.
    for at in [8, 104, 150, 191] {
        let mut d2 = d;
        d2[at] ^= 1;
        let e = dsig::verify(&d2, &k.public(), &content).unwrap_err();
        assert!(e == dsig::Error::Signature || e == dsig::Error::Format, "byte {}: {:?}", at, e);
    }
    let mut d3 = d;
    d3[0] = b'X';
    assert_eq!(dsig::verify(&d3, &k.public(), &content).unwrap_err(), dsig::Error::Format);
    assert_eq!(dsig::verify(&d[..255], &k.public(), &content).unwrap_err(), dsig::Error::Format);
}
