//! Host unit tests and 10,000-round fuzzer for `dosid`.

use alloc::vec::Vec;

use crate::kdf::pbkdf2_hmac_sha256;
use crate::model::*;
use crate::wire::*;

#[test]
fn pbkdf2_hmac_sha256_rfc6070_vectors() {
    // Standard PBKDF2-HMAC-SHA256 test vectors (c=1 and c=2).
    let mut out = [0u8; 32];
    pbkdf2_hmac_sha256(b"password", b"salt", 1, &mut out);
    assert_eq!(
        encode_hex(&out),
        "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
    );
    pbkdf2_hmac_sha256(b"password", b"salt", 2, &mut out);
    assert_eq!(
        encode_hex(&out),
        "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"
    );
    pbkdf2_hmac_sha256(b"password", b"salt", 4096, &mut out);
    assert_eq!(
        encode_hex(&out),
        "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"
    );
}

#[test]
fn no_root_user_and_per_identity_namespaces() {
    assert_eq!(validate_name("root"), Err(IdentityError::RootForbidden));
    assert_eq!(validate_name("ROOT"), Err(IdentityError::RootForbidden));
    assert_eq!(IdentityError::RootForbidden.message(), "D-OS has no root user");
    for bad in ["superuser", "sudo", "system", "kernel", "init", "nobody", "", "Alice", "1alice", "a_b"] {
        assert!(validate_name(bad).is_err(), "accepted forbidden name {bad:?}");
    }
    assert!(validate_name("alice").is_ok());
    assert!(validate_name("work-01").is_ok());

    let mut store = IdentityStore::default_store();
    assert_eq!(store.create_identity("root", "Root", IdentityRole::Operator), Err(IdentityError::RootForbidden));
    let alice_id = store.create_identity("alice", "Alice", IdentityRole::Standard).unwrap();
    let alice = store.find_by_id(alice_id).unwrap();
    assert_eq!(alice.home_subdir(), "home/alice");
    // Standard identity gets isolated /home + read-only /system, NOT raw /data or admin caps.
    assert!(!alice.namespace.iter().any(|n| n.mount == "/data"));
    assert_eq!(alice.caps & caps::IDENTITY_ADMIN, 0);
    assert_eq!(alice.caps & caps::APP_ADMIN, 0);
    // Operator identity has explicit caps and its own separate /home/user.
    let user = store.find_by_name("user").unwrap();
    assert_eq!(user.home_subdir(), "home/user");
    assert_ne!(user.home_subdir(), alice.home_subdir());
    assert_ne!(user.caps & caps::IDENTITY_ADMIN, 0);
}

#[test]
fn software_and_tpm_credential_binding_and_throttle() {
    let secret = [0x42u8; 32];
    let salt = [0x11u8; 16];
    let nonce = [0x22u8; 12];
    let cred = Credential::seal_software(1, "user", b"correct-horse", salt, nonce, &secret, 100).unwrap();
    assert_eq!(cred.open_software(1, "user", b"correct-horse"), Ok(secret));
    // Wrong passphrase fails.
    assert_eq!(cred.open_software(1, "user", b"wrong-horse"), Err(IdentityError::InvalidCredentials));
    // Cross-identity replay fails because AAD + verifier bind identity id & name.
    assert_eq!(cred.open_software(2, "alice", b"correct-horse"), Err(IdentityError::InvalidCredentials));
    // Tampered ciphertext fails.
    let mut bad = cred.clone();
    bad.blob[30] ^= 1;
    assert_eq!(bad.open_software(1, "user", b"correct-horse"), Err(IdentityError::InvalidCredentials));

    // TPM credential preparation and verification.
    let (auth, ver, iter) = Credential::prepare_tpm(1, "user", b"tpm-pass", salt, &secret, 100).unwrap();
    let mut fake_blob = b"DTPM".to_vec();
    fake_blob.extend_from_slice(&[1, 0, 2, 0, 0xAA, 0xBB, 2, 0, 0xCC, 0xDD]);
    let tpm_cred = Credential::from_tpm_blob(salt, iter, ver, fake_blob).unwrap();
    assert_eq!(tpm_cred.tpm_auth_for(b"tpm-pass").unwrap(), auth);
    assert!(tpm_cred.verify_tpm_unsealed(1, "user", &secret));
    assert!(!tpm_cred.verify_tpm_unsealed(2, "alice", &secret));
    assert!(!tpm_cred.verify_tpm_unsealed(1, "user", &[0x99u8; 32]));

    // Exponential backoff throttle: 0, 0, 0, 2s, 5s, 15s, 30s.
    let mut th = AuthThrottle::default();
    let t0 = 1_000_000_000u64;
    assert_eq!(th.record_failure(t0), 0);
    assert_eq!(th.record_failure(t0), 0);
    assert_eq!(th.record_failure(t0), 0);
    assert_eq!(th.record_failure(t0), 2_000_000_000);
    assert_eq!(th.retry_after_ns(t0 + 500_000_000), 1_500_000_000);
    assert_eq!(th.record_failure(t0), 5_000_000_000);
    assert_eq!(th.record_failure(t0), 15_000_000_000);
    assert_eq!(th.record_failure(t0), 30_000_000_000);
    assert_eq!(th.record_failure(t0), 30_000_000_000);
    th.reset();
    assert_eq!(th.failures, 0);
    assert_eq!(th.retry_after_ns(t0), 0);
}

#[test]
fn toml_and_wire_roundtrip_and_fail_closed() {
    let mut store = IdentityStore::default_store();
    store.lock_policy.idle_timeout_secs = 120;
    store.lock_policy.lock_at_boot = true;
    let id = store.create_identity("alice", "Alice", IdentityRole::Standard).unwrap();
    let cred = Credential::seal_software(id, "alice", b"pass123", [3; 16], [4; 12], &[5; 32], 100).unwrap();
    store.find_by_id_mut(id).unwrap().cred = cred;
    let toml_text = store.to_toml();
    let parsed = IdentityStore::from_toml(toml_text.as_bytes()).unwrap();
    assert_eq!(parsed, store);

    // Wire round-trip.
    let w = IdentityWire::from_identity(store.find_by_id(id).unwrap(), false);
    let mut buf = [0u8; IDENTITY_WIRE_BYTES];
    w.encode(&mut buf);
    let dec = IdentityWire::decode(&buf).unwrap();
    assert_eq!(dec, w);
    assert_eq!(dec.name_str(), "alice");
    assert_eq!(dec.home_str(), "home/alice");

    let pw = LockPolicyWire { policy: store.lock_policy, tpm_available: true };
    let mut pbuf = [0u8; LOCK_POLICY_WIRE_BYTES];
    pw.encode(&mut pbuf);
    assert_eq!(LockPolicyWire::decode(&pbuf), Some(pw));

    // Root in stored TOML is refused.
    let evil = toml_text.replace("name = \"alice\"", "name = \"root\"");
    assert_eq!(IdentityStore::from_toml(evil.as_bytes()), Err(IdentityError::RootForbidden));
    // Unknown capability bit is refused.
    let bad_cap = toml_text.replace("caps = 8191", "caps = 9999999");
    assert!(IdentityStore::from_toml(bad_cap.as_bytes()).is_err());
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

#[test]
fn fuzz_identity_store_and_wire_10000_rounds() {
    let seed = IdentityStore::default_store().to_toml().into_bytes();
    let mut rng = Rng(0x1D05_5EED_CAFE_1234);
    for _ in 0..5000 {
        let mut b = seed.clone();
        for _ in 0..1 + rng.below(6) {
            if !b.is_empty() && rng.below(2) == 0 {
                let i = rng.below(b.len());
                b[i] ^= 1 << rng.below(8);
            } else {
                let at = rng.below(b.len() + 1);
                b.insert(at, rng.next() as u8);
            }
        }
        if let Ok(st) = IdentityStore::from_toml(&b) {
            assert!(!st.identities.is_empty() && st.identities.len() <= MAX_IDENTITIES);
            assert!(st.identities.iter().all(|i| validate_name(&i.name).is_ok()));
        }
    }
    for _ in 0..5000 {
        let len = rng.below(160);
        let buf: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
        let _ = IdentityWire::decode(&buf);
        let _ = LockPolicyWire::decode(&buf);
    }
}
