//! Host unit tests and 10,000-round fuzzers for `dosapp`.

use alloc::vec::Vec;

use doscrypt::dsig::{self, KIND_PROGRAM};
use doscrypt::ed25519::SigningKey;
use dosid::caps;

use crate::bundle::*;
use crate::manifest::*;
use crate::perm::*;

const SAMPLE_MANIFEST: &[u8] = br#"
kind = "app"
name = "files"
title = "Files"
version = "1.0.0"
binary = "files.dx"
description = "Browse and manage files in your namespace"
pinned = true

[permissions]
required = ["window", "files:read"]
optional = ["files:write"]
prompt = ["files:read"]

[quota]
memory = "32M"
handles = 128
threads = 4
"#;

#[test]
fn app_manifest_and_permission_ledger_and_revocation() {
    let m = parse_manifest(SAMPLE_MANIFEST).unwrap();
    assert_eq!(m.name, "files");
    assert_eq!(m.title, "Files");
    assert!(m.pinned && !m.autostart);
    assert_eq!(m.required_perms, Permission::Window.bit() | Permission::FilesRead.bit());
    assert_eq!(m.optional_perms, Permission::FilesWrite.bit());
    assert_eq!(m.prompt_perms, Permission::FilesRead.bit());
    assert_eq!(m.quota.memory, 32 << 20);

    // First launch: Window granted (required, not in prompt); FilesRead pending prompt.
    let mut ledger = PermissionLedger::new();
    let (eff, pending) = ledger.evaluate("user", caps::OPERATOR_DEFAULT, "files", m.required_perms, m.optional_perms, m.prompt_perms);
    assert_eq!(eff, Permission::Window.bit());
    assert_eq!(pending, Permission::FilesRead.bit());

    // User approves FilesRead on the compositor prompt.
    ledger.apply_prompt("user", "files", Permission::FilesRead.bit(), 0);
    let (eff, pending) = ledger.evaluate("user", caps::OPERATOR_DEFAULT, "files", m.required_perms, m.optional_perms, m.prompt_perms);
    assert_eq!(eff, Permission::Window.bit() | Permission::FilesRead.bit());
    assert_eq!(pending, 0);

    // User enables FilesWrite, then revokes FilesRead -> FilesRead is stripped even though required!
    ledger.set_decision("user", "files", Permission::FilesWrite, PermDecision::Granted);
    ledger.set_decision("user", "files", Permission::FilesRead, PermDecision::Denied);
    let (eff, pending) = ledger.evaluate("user", caps::OPERATOR_DEFAULT, "files", m.required_perms, m.optional_perms, m.prompt_perms);
    assert_eq!(eff, Permission::Window.bit() | Permission::FilesWrite.bit());
    assert_eq!(pending, 0);

    // Separate identity ("alice") has an independent permission state and capability ceiling.
    let (eff_a, pending_a) = ledger.evaluate("alice", 0, "files", m.required_perms, m.optional_perms, m.prompt_perms);
    assert_eq!(eff_a, Permission::Window.bit());
    assert_eq!(pending_a, 0, "identity without FILES_READ cap cannot be prompted for files:read");

    // TOML round-trip.
    let toml_text = ledger.to_toml();
    let parsed = PermissionLedger::from_toml(toml_text.as_bytes()).unwrap();
    assert_eq!(parsed, ledger);

    // Fail-closed on unknown keys or overlapping required/optional.
    assert!(parse_manifest(b"kind = \"app\"\nname = \"x\"\ntitle = \"X\"\nversion = \"1\"\nbinary = \"x.dx\"\nextra = 1\n").is_err());
    assert!(parse_manifest(b"kind = \"app\"\nname = \"x\"\ntitle = \"X\"\nversion = \"1\"\nbinary = \"x.dx\"\n[permissions]\nrequired = [\"window\"]\noptional = [\"window\"]\n").is_err());
}

#[test]
fn dapp_bundle_build_verify_and_tamper_refusal() {
    let key = SigningKey::from_seed(&[0x5Au8; 32]);
    let other_key = SigningKey::from_seed(&[0x33u8; 32]);
    let fake_elf = b"\x7fELFfake-files-binary-payload-0123456789";
    let bin_sig = dsig::sign(&key, KIND_PROGRAM, "files.dx", fake_elf);
    let about = b"D-OS Files v1.0.0";

    // Intentionally pass unsorted inputs to verify build_bundle sorts deterministically.
    let inputs_a = [
        BundleInput { kind: ENTRY_RESOURCE, name: "res/about.txt", data: about },
        BundleInput { kind: ENTRY_BINARY_SIG, name: "files.dx.dsig", data: &bin_sig },
        BundleInput { kind: ENTRY_BINARY, name: "files.dx", data: fake_elf },
        BundleInput { kind: ENTRY_MANIFEST, name: "manifest.dman", data: SAMPLE_MANIFEST },
    ];
    let inputs_b = [inputs_a[3], inputs_a[2], inputs_a[1], inputs_a[0]];
    let bundle_a = build_bundle(&key, "files.dapp", &inputs_a).unwrap();
    let bundle_b = build_bundle(&key, "files.dapp", &inputs_b).unwrap();
    assert_eq!(bundle_a, bundle_b, "bundle generation must be deterministic");

    let parsed = verify_bundle_with_key(&bundle_a, &key.public()).unwrap();
    assert_eq!(parsed.binary.data, fake_elf);
    assert_eq!(parsed.resources.len(), 1);
    assert_eq!(parsed.resources[0].name, "res/about.txt");
    assert_eq!(parsed.resources[0].data, about);

    // Wrong signing key is refused.
    assert_eq!(verify_bundle_with_key(&bundle_a, &other_key.public()).err(), Some(BundleError::BadSignature));

    // Flipping 1 bit in payload is caught by SHA-256 and bundle signature.
    let mut tampered = bundle_a.clone();
    let mid = tampered.len() - dsig::SIZE - 20;
    tampered[mid] ^= 1;
    assert!(parse_bundle(&tampered).is_err());
    assert!(verify_bundle_with_key(&tampered, &key.public()).is_err());

    // Flipping 1 bit in trailing signature is caught.
    let mut bad_sig = bundle_a.clone();
    let last = bad_sig.len() - 1;
    bad_sig[last] ^= 1;
    assert_eq!(verify_bundle_with_key(&bad_sig, &key.public()).err(), Some(BundleError::BadSignature));

    // ResourcePack round-trip.
    let pack = ResourcePack::build(&[("res/about.txt", about), ("res/license.txt", b"GPL-3.0")]);
    assert_eq!(ResourcePack::get(&pack, "res/about.txt"), Some(&about[..]));
    assert_eq!(ResourcePack::get(&pack, "res/license.txt"), Some(&b"GPL-3.0"[..]));
    assert_eq!(ResourcePack::get(&pack, "res/missing.txt"), None);
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
fn fuzz_dapp_bundle_manifest_and_ledger_10000_rounds() {
    let key = SigningKey::from_seed(&[0x77u8; 32]);
    let bin = b"\x7fELFtest";
    let bsig = dsig::sign(&key, KIND_PROGRAM, "files.dx", bin);
    let seed_bundle = build_bundle(
        &key,
        "files.dapp",
        &[
            BundleInput { kind: ENTRY_MANIFEST, name: "manifest.dman", data: SAMPLE_MANIFEST },
            BundleInput { kind: ENTRY_BINARY, name: "files.dx", data: bin },
            BundleInput { kind: ENTRY_BINARY_SIG, name: "files.dx.dsig", data: &bsig },
            BundleInput { kind: ENTRY_RESOURCE, name: "res/about.txt", data: b"hi" },
        ],
    )
    .unwrap();
    let seed_pack = ResourcePack::build(&[("res/about.txt", b"hi")]);
    let mut rng = Rng(0xDA99_5EED_9876_5432);

    for _ in 0..4000 {
        let mut b = seed_bundle.clone();
        for _ in 0..1 + rng.below(5) {
            if !b.is_empty() && rng.below(3) != 0 {
                let i = rng.below(b.len());
                b[i] ^= 1 << rng.below(8);
            } else {
                let at = rng.below(b.len() + 1);
                b.truncate(at);
            }
        }
        let _ = parse_bundle(&b);
        let _ = verify_bundle_with_key(&b, &key.public());
    }
    for _ in 0..3000 {
        let mut m = SAMPLE_MANIFEST.to_vec();
        for _ in 0..1 + rng.below(6) {
            if !m.is_empty() && rng.below(2) == 0 {
                let i = rng.below(m.len());
                m[i] ^= 1 << rng.below(8);
            } else {
                let at = rng.below(m.len() + 1);
                m.insert(at, rng.next() as u8);
            }
        }
        let _ = parse_manifest(&m);
    }
    for _ in 0..3000 {
        let mut p = seed_pack.clone();
        if !p.is_empty() {
            let i = rng.below(p.len());
            p[i] ^= 1 << rng.below(8);
        }
        let _ = ResourcePack::get(&p, "res/about.txt");
        let len = rng.below(128);
        let rand_buf: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
        let _ = PermissionLedger::from_toml(&rand_buf);
    }
}
