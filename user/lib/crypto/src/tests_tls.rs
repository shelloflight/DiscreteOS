//! Host unit tests and fuzzers for TLS 1.3 cryptographic primitives in `doscrypt`:
//! - X25519 (RFC 7748 §6.1 test vectors + low-order point rejection)
//! - ChaCha20-Poly1305 (RFC 8439 §2.3.2, §2.4.2, §2.5.2, §2.8.2 test vectors + tamper wipe)
//! - HKDF-SHA256 (RFC 5869 Appendix A test cases 1..3 + TLS 1.3 HKDF-Expand-Label)
//! - RSA-PSS (SHA-256 & SHA-384 sign/verify + tamper detection)
//! - X.509 v3 chain/SAN/wildcard/expiry/critical-extension verification + 5,000-round fuzzer.

extern crate std;
use std::vec;
use std::vec::Vec;

use crate::chacha20::{chacha20_block, open_in_place, poly1305_mac, seal_in_place};
use crate::ed25519::SigningKey;
use crate::hkdf::{expand_label_sha256, expand_sha256, extract_sha256};
use crate::rsa::{self, Hash, PublicKey};
use crate::testkeys;
use crate::x25519::{diffie_hellman, public_key, x25519_raw};
use crate::x509::{self, VerifyError, dns_pattern_matches};

fn hex(s: &str) -> Vec<u8> {
    let clean: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    (0..clean.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(core::str::from_utf8(&clean[i..i + 2]).unwrap(), 16).unwrap())
        .collect()
}

fn hex32(s: &str) -> [u8; 32] {
    hex(s).try_into().unwrap()
}

#[test]
fn x25519_rfc7748_vectors() {
    // RFC 7748 §5.2 test vector 1
    let scalar1 = hex32("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
    let u1 = hex32("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
    let out1 = hex32("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");
    assert_eq!(diffie_hellman(&scalar1, &u1), Some(out1));

    // RFC 7748 §5.2 test vector 2
    let scalar2 = hex32("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d");
    let u2 = hex32("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493");
    let out2 = hex32("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957");
    assert_eq!(diffie_hellman(&scalar2, &u2), Some(out2));

    // RFC 7748 §6.1 Alice/Bob key exchange
    let alice_priv = hex32("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    let alice_pub = hex32("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    let bob_priv = hex32("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
    let bob_pub = hex32("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    let shared = hex32("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
    assert_eq!(public_key(&alice_priv), alice_pub);
    assert_eq!(public_key(&bob_priv), bob_pub);
    assert_eq!(diffie_hellman(&alice_priv, &bob_pub), Some(shared));
    assert_eq!(diffie_hellman(&bob_priv, &alice_pub), Some(shared));

    // RFC 7748 §5.2 iterative test (1 iteration and 1,000 iterations)
    let mut k = [0u8; 32];
    k[0] = 9;
    let mut u = k;
    let r1 = x25519_raw(&k, &u);
    assert_eq!(r1, hex32("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079"));
    u = k;
    k = r1;
    for _ in 1..1000 {
        let next = x25519_raw(&k, &u);
        u = k;
        k = next;
    }
    assert_eq!(k, hex32("684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51"));

    // Low-order point (all zeros) must be rejected.
    assert_eq!(diffie_hellman(&alice_priv, &[0u8; 32]), None);
}

#[test]
fn chacha20_poly1305_rfc8439_vectors() {
    // RFC 8439 §2.3.2 ChaCha20 block
    let key = hex32("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    let nonce: [u8; 12] = hex("000000090000004a00000000").try_into().unwrap();
    let blk = chacha20_block(&key, 1, &nonce);
    assert_eq!(
        blk.to_vec(),
        hex(
            "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e\
             d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e"
        )
    );

    // RFC 8439 §2.5.2 Poly1305
    let pkey = hex32("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b");
    let pmsg = b"Cryptographic Forum Research Group";
    assert_eq!(
        poly1305_mac(&pkey, pmsg).to_vec(),
        hex("a8061dc1305136c6c22b8baf0c0127a9")
    );

    // RFC 8439 §2.8.2 AEAD_CHACHA20_POLY1305
    let akey = hex32("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
    let anonce: [u8; 12] = hex("070000004041424344454647").try_into().unwrap();
    let aad = hex("50515253c0c1c2c3c4c5c6c7");
    let pt = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    let expected_ct = hex(
        "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6\
         3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36\
         92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc\
         3ff4def08e4b7a9de576d26586cec64b6116",
    );
    let expected_tag: [u8; 16] = hex("1ae10b594f09e26a7e902ecbd0600691").try_into().unwrap();

    let mut buf = pt.to_vec();
    let tag = seal_in_place(&akey, &anonce, &aad, &mut buf);
    assert_eq!(buf, expected_ct);
    assert_eq!(tag, expected_tag);

    assert!(open_in_place(&akey, &anonce, &aad, &mut buf, &tag));
    assert_eq!(&buf[..], &pt[..]);

    // Tampered tag must fail and wipe buffer.
    let mut ct2 = expected_ct.clone();
    let mut bad_tag = expected_tag;
    bad_tag[15] ^= 1;
    assert!(!open_in_place(&akey, &anonce, &aad, &mut ct2, &bad_tag));
    assert!(ct2.iter().all(|&b| b == 0));
}

#[test]
fn hkdf_rfc5869_vectors() {
    // Test Case 1
    let ikm = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    let salt = hex("000102030405060708090a0b0c");
    let info = hex("f0f1f2f3f4f5f6f7f8f9");
    let prk = extract_sha256(&salt, &ikm);
    assert_eq!(prk.to_vec(), hex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"));
    let mut okm = [0u8; 42];
    assert!(expand_sha256(&prk, &info, &mut okm));
    assert_eq!(
        okm.to_vec(),
        hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
    );

    // Test Case 3 (empty salt & info)
    let prk3 = extract_sha256(&[], &ikm);
    assert_eq!(prk3.to_vec(), hex("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04"));
    let mut okm3 = [0u8; 42];
    assert!(expand_sha256(&prk3, &[], &mut okm3));
    assert_eq!(
        okm3.to_vec(),
        hex("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8")
    );

    // RFC 8448 §3 TLS 1.3 Early Secret -> Derive-Secret("derived", "")
    let early = extract_sha256(&[], &[0u8; 32]);
    assert_eq!(early, hex32("33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a"));
    let empty_hash = crate::sha2::sha256(b"");
    let mut derived = [0u8; 32];
    assert!(expand_label_sha256(&early, b"derived", &empty_hash, &mut derived));
    assert_eq!(derived, hex32("6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba"));
}

#[test]
fn rsa_pss_round_trip_and_tamper() {
    let key = PublicKey::new(&testkeys::EK_N, 65537).unwrap();
    let msg = b"TLS 1.3, server CertificateVerify test payload";
    for (hash, slen) in [(Hash::Sha256, 32usize), (Hash::Sha384, 48usize)] {
        let mut salt = [0u8; 48];
        for (i, b) in salt[..slen].iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(17).wrapping_add(3);
        }
        let mut sig = vec![0u8; key.size()];
        assert!(rsa::sim::sign_pss(&key, &testkeys::EK_D, hash, msg, &salt[..slen], &mut sig).is_some());
        assert!(rsa::verify_pss(&key, hash, msg, &sig));
        assert!(!rsa::verify_pss(&key, hash, b"tampered", &sig));
        let mut bad = sig.clone();
        bad[sig.len() - 1] ^= 1;
        assert!(!rsa::verify_pss(&key, hash, msg, &bad));
    }
}

// ---- Minimal DER builder for X.509 v3 tests -----------------------------------------------------

fn der_tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 6);
    out.push(tag);
    if body.len() < 128 {
        out.push(body.len() as u8);
    } else if body.len() < 256 {
        out.push(0x81);
        out.push(body.len() as u8);
    } else {
        out.push(0x82);
        out.push((body.len() >> 8) as u8);
        out.push(body.len() as u8);
    }
    out.extend_from_slice(body);
    out
}

fn der_seq(parts: &[&[u8]]) -> Vec<u8> {
    let mut body = Vec::new();
    for p in parts {
        body.extend_from_slice(p);
    }
    der_tlv(0x30, &body)
}

fn der_name(cn: &str) -> Vec<u8> {
    let oid_cn = der_tlv(0x06, &[0x55, 0x04, 0x03]);
    let val = der_tlv(0x0C, cn.as_bytes());
    let atv = der_seq(&[&oid_cn, &val]);
    let rdn = der_tlv(0x31, &atv);
    der_seq(&[&rdn])
}

#[allow(clippy::too_many_arguments)]
fn build_ed25519_cert(
    subject_cn: &str,
    issuer_cn: &str,
    subject_pub: &[u8; 32],
    issuer_key: &SigningKey,
    not_before: &[u8],
    not_after: &[u8],
    is_ca: bool,
    san_dns: &[&str],
    san_ips: &[[u8; 4]],
    extra_crit_ext: bool,
) -> Vec<u8> {
    let ver = der_tlv(0xA0, &der_tlv(0x02, &[2])); // v3
    let serial = der_tlv(0x02, &[1]);
    let ed_alg = der_seq(&[&der_tlv(0x06, &[0x2b, 0x65, 0x70])]);
    let issuer = der_name(issuer_cn);
    let subject = der_name(subject_cn);
    let validity = der_seq(&[&der_tlv(0x17, not_before), &der_tlv(0x17, not_after)]);

    let mut spki_bits = vec![0u8];
    spki_bits.extend_from_slice(subject_pub);
    let spki = der_seq(&[&ed_alg, &der_tlv(0x03, &spki_bits)]);

    let mut exts = Vec::new();
    // basicConstraints (critical)
    let bc_val = if is_ca {
        der_seq(&[&der_tlv(0x01, &[0xFF])])
    } else {
        der_seq(&[])
    };
    exts.extend_from_slice(&der_seq(&[
        &der_tlv(0x06, &[0x55, 0x1d, 0x13]),
        &der_tlv(0x01, &[0xFF]),
        &der_tlv(0x04, &bc_val),
    ]));

    if !san_dns.is_empty() || !san_ips.is_empty() {
        let mut san_body = Vec::new();
        for d in san_dns {
            san_body.extend_from_slice(&der_tlv(0x82, d.as_bytes()));
        }
        for ip in san_ips {
            san_body.extend_from_slice(&der_tlv(0x87, ip));
        }
        let san_seq = der_tlv(0x30, &san_body);
        exts.extend_from_slice(&der_seq(&[
            &der_tlv(0x06, &[0x55, 0x1d, 0x11]),
            &der_tlv(0x04, &san_seq),
        ]));
    }
    if extra_crit_ext {
        exts.extend_from_slice(&der_seq(&[
            &der_tlv(0x06, &[0x55, 0x1d, 0x63]), // unknown OID
            &der_tlv(0x01, &[0xFF]),             // critical = true
            &der_tlv(0x04, &[0x05, 0x00]),
        ]));
    }
    let exts_field = der_tlv(0xA3, &der_tlv(0x30, &exts));
    let tbs = der_seq(&[&ver, &serial, &ed_alg, &issuer, &validity, &subject, &spki, &exts_field]);
    let sig = issuer_key.sign(&tbs);
    let mut sig_bits = vec![0u8];
    sig_bits.extend_from_slice(&sig);
    der_seq(&[&tbs, &ed_alg, &der_tlv(0x03, &sig_bits)])
}

#[test]
fn x509_chain_san_expiry_and_fuzz() {
    assert!(dns_pattern_matches("example.com", "EXAMPLE.COM"));
    assert!(dns_pattern_matches("*.example.com", "api.example.com"));
    assert!(!dns_pattern_matches("*.example.com", "example.com"));
    assert!(!dns_pattern_matches("*.example.com", "a.b.example.com"));
    assert!(!dns_pattern_matches("*.com", "example.com"));

    let ca_key = SigningKey::from_seed(&[0x11; 32]);
    let leaf_key = SigningKey::from_seed(&[0x22; 32]);
    let rogue_key = SigningKey::from_seed(&[0x33; 32]);

    let ca_der = build_ed25519_cert(
        "D-OS Test Root",
        "D-OS Test Root",
        &ca_key.public(),
        &ca_key,
        b"250101000000Z",
        b"350101000000Z",
        true,
        &[],
        &[],
        false,
    );
    let leaf_der = build_ed25519_cert(
        "test.dos.local",
        "D-OS Test Root",
        &leaf_key.public(),
        &ca_key,
        b"260101000000Z",
        b"271231235959Z",
        false,
        &["test.dos.local", "*.svc.dos.local"],
        &[[10, 0, 2, 100]],
        false,
    );

    let now_2026: i64 = 1_795_000_000; // late 2026
    assert_eq!(x509::verify_chain(&[&leaf_der], &[&ca_der], "test.dos.local", now_2026), Ok(()));
    assert_eq!(x509::verify_chain(&[&leaf_der], &[&ca_der], "api.svc.dos.local", now_2026), Ok(()));
    assert_eq!(x509::verify_chain(&[&leaf_der], &[&ca_der], "10.0.2.100", now_2026), Ok(()));

    // Negative cases: hostname mismatch, expiry, not-yet-valid, untrusted CA, unknown critical ext.
    assert_eq!(
        x509::verify_chain(&[&leaf_der], &[&ca_der], "evil.dos.local", now_2026),
        Err(VerifyError::HostnameMismatch)
    );
    assert_eq!(
        x509::verify_chain(&[&leaf_der], &[&ca_der], "a.b.svc.dos.local", now_2026),
        Err(VerifyError::HostnameMismatch)
    );
    assert_eq!(
        x509::verify_chain(&[&leaf_der], &[&ca_der], "test.dos.local", 1_900_000_000),
        Err(VerifyError::Expired)
    );
    assert_eq!(
        x509::verify_chain(&[&leaf_der], &[&ca_der], "test.dos.local", 1_700_000_000),
        Err(VerifyError::NotYetValid)
    );
    let rogue_ca = build_ed25519_cert(
        "Rogue Root",
        "Rogue Root",
        &rogue_key.public(),
        &rogue_key,
        b"250101000000Z",
        b"350101000000Z",
        true,
        &[],
        &[],
        false,
    );
    assert_eq!(
        x509::verify_chain(&[&leaf_der], &[&rogue_ca], "test.dos.local", now_2026),
        Err(VerifyError::UntrustedRoot)
    );
    let crit_leaf = build_ed25519_cert(
        "test.dos.local",
        "D-OS Test Root",
        &leaf_key.public(),
        &ca_key,
        b"260101000000Z",
        b"271231235959Z",
        false,
        &["test.dos.local"],
        &[],
        true,
    );
    assert_eq!(
        x509::verify_chain(&[&crit_leaf], &[&ca_der], "test.dos.local", now_2026),
        Err(VerifyError::UnknownCriticalExtension)
    );

    // 5,000-round deterministic fuzzer over X.509 DER parser (random + mutated valid cert).
    let mut seed = 0x5A17_9C21_D05E_F00Du64;
    let mut next = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    for round in 0..5000u32 {
        let mut buf = if round % 2 == 0 {
            let mut v = leaf_der.clone();
            let flips = (next() % 6 + 1) as usize;
            for _ in 0..flips {
                let idx = (next() as usize) % v.len();
                v[idx] ^= (next() as u8).max(1);
            }
            if round % 6 == 0 {
                let cut = (next() as usize) % v.len();
                v.truncate(cut);
            }
            v
        } else {
            let len = (next() % 512) as usize;
            (0..len).map(|_| next() as u8).collect()
        };
        let _ = x509::parse(&buf);
        let _ = x509::parse_tls(&buf);
        let _ = x509::verify_chain(&[&buf], &[&ca_der], "test.dos.local", now_2026);
        buf.clear();
    }

    // Revocation denylist check.
    let revoked_hash = crate::sha2::sha256(&leaf_der);
    assert_eq!(
        x509::verify_chain_with_revoked(&[&leaf_der], &[&ca_der], &[revoked_hash], "test.dos.local", now_2026),
        Err(VerifyError::Revoked)
    );
}

#[test]
fn aes_gcm_nist_vectors_and_sbox() {
    use crate::aes_gcm::{
        aes128_gcm_open_in_place, aes128_gcm_seal_in_place, aes256_gcm_open_in_place,
        aes256_gcm_seal_in_place, sbox_ct,
    };
    // Verify constant-time algebraic S-box matches FIPS 197 on key points + bijection.
    assert_eq!(sbox_ct(0x00), 0x63);
    assert_eq!(sbox_ct(0x01), 0x7c);
    assert_eq!(sbox_ct(0x53), 0xed);
    assert_eq!(sbox_ct(0xff), 0x16);
    let mut seen = [false; 256];
    for x in 0..=255u8 {
        let y = sbox_ct(x);
        assert!(!seen[usize::from(y)], "S-box collision at {x:#x}");
        seen[usize::from(y)] = true;
    }

    // NIST SP 800-38D Test Case 1: AES-128-GCM, empty PT, empty AAD, all-zero key & IV.
    let mut empty = [];
    let tag1 = aes128_gcm_seal_in_place(&[0u8; 16], &[0u8; 12], b"", &mut empty);
    assert_eq!(tag1, hex("58e2fccefa7e3061367f1d57a4e7455a").as_slice());
    assert!(aes128_gcm_open_in_place(&[0u8; 16], &[0u8; 12], b"", &mut empty, &tag1));

    // NIST SP 800-38D Test Case 2: AES-128-GCM, 16-byte zero PT, empty AAD.
    let mut buf2 = [0u8; 16];
    let tag2 = aes128_gcm_seal_in_place(&[0u8; 16], &[0u8; 12], b"", &mut buf2);
    assert_eq!(buf2, hex("0388dace60b6a392f328c2b971b2fe78").as_slice());
    assert_eq!(tag2, hex("ab6e47d42cec13bdf53a67b21257bddf").as_slice());
    assert!(aes128_gcm_open_in_place(&[0u8; 16], &[0u8; 12], b"", &mut buf2, &tag2));
    assert_eq!(buf2, [0u8; 16]);

    // NIST SP 800-38D Test Case 4: AES-128-GCM with non-empty AAD and PT.
    let k4: [u8; 16] = hex("feffe9928665731c6d6a8f9467308308").try_into().unwrap();
    let iv4: [u8; 12] = hex("cafebabefacedbaddecaf888").try_into().unwrap();
    let aad4 = hex("feedfacedeadbeeffeedfacedeadbeefabaddad2");
    let pt4 = hex(
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
         1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
    );
    let mut ct4 = pt4.clone();
    let tag4 = aes128_gcm_seal_in_place(&k4, &iv4, &aad4, &mut ct4);
    assert_eq!(
        ct4,
        hex(
            "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e\
             21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091"
        )
    );
    assert_eq!(tag4, hex("5bc94fbc3221a5db94fae95ae7121a47").as_slice());
    // Tampered tag must fail and wipe buffer.
    let mut bad_tag = tag4;
    bad_tag[0] ^= 1;
    let mut ct4_bad = ct4.clone();
    assert!(!aes128_gcm_open_in_place(&k4, &iv4, &aad4, &mut ct4_bad, &bad_tag));
    assert!(ct4_bad.iter().all(|&b| b == 0));
    assert!(aes128_gcm_open_in_place(&k4, &iv4, &aad4, &mut ct4, &tag4));
    assert_eq!(ct4, pt4);

    // NIST SP 800-38D Test Case 16: AES-256-GCM with AAD and PT.
    let k16: [u8; 32] = hex("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308")
        .try_into()
        .unwrap();
    let mut ct16 = pt4.clone();
    let tag16 = aes256_gcm_seal_in_place(&k16, &iv4, &aad4, &mut ct16);
    assert_eq!(
        ct16,
        hex(
            "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa\
             8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662"
        )
    );
    assert_eq!(tag16, hex("76fc6ece0f4e1768cddf8853bb2d551b").as_slice());
    assert!(aes256_gcm_open_in_place(&k16, &iv4, &aad4, &mut ct16, &tag16));
    assert_eq!(ct16, pt4);
}

#[test]
fn sha3_and_shake_fips202_vectors() {
    use crate::sha3::{Shake128, Shake256, sha3_256, sha3_512};
    // FIPS 202 official empty-string and "abc" vectors.
    assert_eq!(
        sha3_256(b""),
        hex("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a").as_slice()
    );
    assert_eq!(
        sha3_256(b"abc"),
        hex("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532").as_slice()
    );
    assert_eq!(
        sha3_512(b""),
        hex(
            "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6\
             15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
        )
        .as_slice()
    );
    let mut s128 = Shake128::new();
    let mut out128 = [0u8; 16];
    s128.squeeze(&mut out128);
    assert_eq!(out128, hex("7f9c2ba4e88f827d616045507605853e").as_slice());

    let mut s256 = Shake256::new();
    s256.update(b"abc");
    let mut out256 = [0u8; 32];
    s256.squeeze(&mut out256);
    assert_eq!(
        out256,
        hex("483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739").as_slice()
    );
}

#[test]
fn mlkem768_fips203_compress_roundtrip_and_implicit_rejection() {
    use crate::mlkem::{CT_LEN, EK_LEN, compress, decaps, encaps, keygen, validate_ek};
    // Exhaustively verify constant-time Compress_d matches exact rounded division for all x in [0, 3328].
    for d in [1u32, 4, 10] {
        let mask = (1u64 << d) - 1;
        for x in 0..3329i16 {
            let exact = ((((x as u64) << d) + 1664) / 3329) & mask;
            assert_eq!(u64::from(compress(x, d)), exact, "compress mismatch x={x} d={d}");
        }
    }

    let seed = [0x42u8; 64];
    let (ek, dk) = keygen(&seed);
    assert_eq!(ek.len(), EK_LEN);
    assert!(validate_ek(&ek));

    let m = [0xA5u8; 32];
    let (ct, ss_enc) = encaps(&ek, &m).expect("encaps");
    assert_eq!(ct.len(), CT_LEN);
    let ss_dec = decaps(&dk, &ct);
    assert_eq!(ss_enc, ss_dec);

    // Tampered ciphertext must trigger implicit rejection (deterministic, != ss_enc).
    let mut bad_ct = ct;
    bad_ct[17] ^= 0x01;
    let ss_rej1 = decaps(&dk, &bad_ct);
    let ss_rej2 = decaps(&dk, &bad_ct);
    assert_eq!(ss_rej1, ss_rej2);
    assert_ne!(ss_rej1, ss_enc);

    // Invalid encapsulation key (coefficient >= 3329) must be rejected.
    let mut bad_ek = ek;
    bad_ek[0] = 0xFF;
    bad_ek[1] |= 0x0F; // 12-bit coeff = 4095 >= 3329
    assert!(!validate_ek(&bad_ek));
    assert!(encaps(&bad_ek, &m).is_none());
}

#[test]
fn p384_nist_ecdsa_vector() {
    use crate::p384;
    assert!(p384::generator_on_curve());
    // NIST P-384 (secp384r1) SHA-384 ECDSA vector for RFC 6979 A.2.6 key (d = 0x6b9d...),
    // message = "sample".
    let qx: [u8; 48] = hex(
        "ec3a4e415b4e19a4568618029f427fa5da9a8bc4ae92e02e06aae5286b300c64\
         def8f0ea9055866064a254515480bc13",
    )
    .try_into()
    .unwrap();
    let qy: [u8; 48] = hex(
        "8015d9b72d7d57244ea8ef9ac0c621896708a59367f9dfb9f54ca84b3f1c9db1\
         288b231c3ae0d4fe7344fd2533264720",
    )
    .try_into()
    .unwrap();
    let pk = p384::PublicKey::from_xy(&qx, &qy).expect("valid P-384 public key");
    let mut sig = [0u8; 96];
    sig[..48].copy_from_slice(&hex(
        "451bd008677acd4f4e7d06104e7a159b04e909462702311c4faf651dd296fd2c\
         1c5e9ca50409fe096a000f9e70edca1b",
    ));
    sig[48..].copy_from_slice(&hex(
        "de8e1e630335be24fdd33f463bd9998449f8bd8906d4c5adb676fdc7f8648594\
         24b68f5be2b39091e596ef2f60abb75e",
    ));
    assert!(p384::verify(&pk, b"sample", &sig));
    assert!(!p384::verify(&pk, b"tampered", &sig));
    let mut bad_sig = sig;
    bad_sig[95] ^= 1;
    assert!(!p384::verify(&pk, b"sample", &bad_sig));
}

#[test]
fn hkdf_sha384_rfc8448_check() {
    use crate::hkdf::{derive_secret_sha384, expand_label_sha384, extract_sha384};
    use crate::sha2::sha384;
    let empty_hash = sha384(b"");
    let early = extract_sha384(&[], &[0u8; 48]);
    let derived = derive_secret_sha384(&early, b"derived", &empty_hash);
    assert_ne!(derived, [0u8; 48]);
    let mut key = [0u8; 32];
    assert!(expand_label_sha384(&derived, b"key", b"", &mut key));
    assert_ne!(key, [0u8; 32]);
}
