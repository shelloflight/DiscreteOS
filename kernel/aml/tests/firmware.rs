//! Real firmware: the build machine's own DSDT and SSDTs, when they have been dumped to
//! `build/host/acpi` (build.ps1 does it on Windows from `HKLM\HARDWARE\ACPI`; never committed).
//! Also the mutation fuzzers, on built tables and on real ones.

mod common;

use std::path::PathBuf;

use aml::{ErrorKind, Interpreter, Limits, Object};
use common::*;

fn tables() -> Vec<(String, Vec<u8>)> {
    let dir = std::env::var_os("AML_TABLES")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../build/host/acpi"));
    let Ok(rd) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut v: Vec<(String, Vec<u8>)> = rd
        .filter_map(|e| e.ok())
        .map(|e| (e.file_name().to_string_lossy().into_owned(), e.path()))
        .filter(|(n, _)| n.starts_with("DSDT") || n.starts_with("SSD"))
        .filter_map(|(n, p)| std::fs::read(p).ok().map(|b| (n, b)))
        .collect();
    // DSDT first, then the SSDTs in name order (the firmware's own order).
    v.sort_by_key(|(n, _)| (!n.starts_with("DSDT"), n.clone()));
    v
}

fn load_all(t: &[(String, Vec<u8>)]) -> Interpreter<Sim> {
    let mut i = Interpreter::new(Sim::default());
    for (n, b) in t {
        if let Err(e) = i.load_table(b) {
            println!("aml firmware: {n}: {e}");
        }
    }
    i
}

#[test]
fn firmware_tables_load_and_initialise() {
    let t = tables();
    if t.is_empty() {
        println!("aml firmware: no tables in build/host/acpi (skipped)");
        return;
    }
    let bytes: usize = t.iter().map(|(_, b)| b.len()).sum();
    let start = std::time::Instant::now();
    let mut i = load_all(&t);
    let loaded = start.elapsed();
    println!(
        "aml firmware: {} tables, {} KiB, {} objects in {:?}; {} load errors, {} duplicates",
        t.len(),
        bytes / 1024,
        i.namespace().len(),
        loaded,
        i.stats.load_errors,
        i.stats.duplicates
    );
    for (p, e) in &i.stats.errors {
        println!("aml firmware:   {p}: {e}");
    }
    assert_eq!(
        i.stats.load_errors, 0,
        "every definition in real firmware loads"
    );

    i.stats.errors.clear();
    let r = i.initialize();
    println!(
        "aml firmware: _REG {}, {} devices, {} present, {} _INI, {} failures ({} method calls)",
        r.regs, r.devices, r.present, r.inits, r.failures, i.stats.calls
    );
    for (p, e) in &i.stats.errors {
        println!("aml firmware:   {p}: {e}");
    }
    let s5 = i.sleep_type(5);
    println!("aml firmware: \\_S5 = {s5:?}");
    assert!(s5.is_some(), "\\_S5 evaluates");
    let pwrb = i.find_devices(&["PNP0C0C"]);
    let tpm = i.find_devices(&["MSFT0101"]);
    println!(
        "aml firmware: power button devices {:?}, TPM {:?}",
        pwrb.iter().map(|&n| i.path(n)).collect::<Vec<_>>(),
        tpm.iter().map(|&n| i.path(n)).collect::<Vec<_>>()
    );
}

/// Call every method that takes no arguments (simulated hardware reads as zero): nothing panics,
/// every failure is a clean error.
#[test]
fn firmware_every_method_runs_or_fails_cleanly() {
    let t = tables();
    if t.is_empty() {
        return;
    }
    let mut i = load_all(&t);
    i.limits.steps = 200_000;
    let all = i.namespace().walk(aml::ROOT);
    let (mut ok, mut failed) = (0, 0);
    let mut kinds = std::collections::BTreeMap::<String, u32>::new();
    for n in all {
        if !i.namespace().exists(n) {
            continue;
        }
        let Object::Method(m) = i.namespace().obj(n) else {
            continue;
        };
        let nargs = m.args;
        let args = vec![Object::Integer(0); nargs as usize];
        match i.evaluate_node(n, args) {
            Ok(_) => ok += 1,
            Err(e) => {
                failed += 1;
                let k = match &e.kind {
                    ErrorKind::NotFound(_) => "not found".to_string(),
                    ErrorKind::Type(t) => format!("type: {t}"),
                    ErrorKind::Range(r) => format!("range: {r}"),
                    ErrorKind::Limit(l) => format!("limit: {l}"),
                    k => format!("{k:?}"),
                };
                *kinds.entry(k).or_default() += 1;
            }
        }
    }
    println!(
        "aml firmware: every method with zero arguments: {ok} ran, {failed} failed cleanly; deepest stack use {} KiB (host build)",
        i.handler().stack_deepest / 1024
    );
    for (k, c) in kinds {
        println!("aml firmware:   {c:5} {k}");
    }
    assert!(ok > 0);
}

fn sample() -> Vec<u8> {
    dsdt(&cat(&[
        &name("INT0", int(5)),
        &name(
            "PKG0",
            package(&[int(1), string("two"), buffer(&[3, 4, 5])]),
        ),
        &opregion("PRT0", 1, 0x80, 4),
        &field("PRT0", 0x01, &[("LOW_", 4), ("HIGH", 4), ("BYT1", 8)]),
        &scope(
            "\\_SB",
            cat(&[
                &device(
                    "DEV0",
                    cat(&[
                        &name("_HID", string("PNP0C0C")),
                        &method("_STA", 0, ret(int(0x0F))),
                        &method("_INI", 0, store(int(3), ns("\\INT0"))),
                    ]),
                ),
                &method(
                    "LOOP",
                    1,
                    cat(&[
                        &store(int(0), local(0)),
                        &while_(
                            lless(local(0), arg(0)),
                            cat(&[&incr(local(0)), &store(local(0), ns("\\HIGH"))]),
                        ),
                        &ret(derefof(index(ns("\\PKG0"), int(0), ZERO.to_vec()))),
                    ]),
                ),
                &method("CALL", 0, ret(call("LOOP", &[int(4)]))),
            ]),
        ),
        &name("_S5", package(&[int(5), int(5)])),
    ]))
}

fn fuzz_one(table: &[u8], extra: &[(String, Vec<u8>)], limits: Limits) {
    let mut i = Interpreter::new(Sim::default());
    i.limits = limits;
    for (_, t) in extra {
        let _ = i.load_table(t);
    }
    let _ = i.load_table(table);
    let _ = i.initialize();
    let _ = i.sleep_type(5);
    for n in i.namespace().walk(aml::ROOT) {
        if !i.namespace().exists(n) {
            continue;
        }
        if let Object::Method(m) = i.namespace().obj(n) {
            let args = vec![Object::Integer(1); m.args as usize];
            let _ = i.evaluate_node(n, args);
        }
    }
}

fn mutate(rng: &mut Rng, t: &[u8]) -> Vec<u8> {
    let mut m = t.to_vec();
    for _ in 0..1 + rng.below(6) {
        let p = 36 + rng.below((m.len() - 36) as u64) as usize;
        match rng.below(4) {
            0 => m[p] = rng.next() as u8,
            1 => m[p] ^= 1 << rng.below(8),
            2 => m[p] = [0x00, 0xFF, 0x5B, 0x14, 0x12, 0x11, 0xA2, 0x7F][rng.below(8) as usize],
            _ => {
                let q = 36 + rng.below((m.len() - 36) as u64) as usize;
                m.swap(p, q);
            }
        }
    }
    if rng.below(8) == 0 {
        let cut = 36 + rng.below((m.len() - 36) as u64) as usize;
        m.truncate(cut);
        let len = (m.len() as u32).to_le_bytes();
        m[4..8].copy_from_slice(&len);
    }
    m
}

#[test]
fn fuzz_built_tables() {
    let t = sample();
    let mut rng = Rng(0x0D05_A3E1_C0DE_0001);
    let limits = Limits {
        steps: 20_000,
        ..Limits::default()
    };
    for cut in 36..t.len() {
        let mut p = t[..cut].to_vec();
        p[4..8].copy_from_slice(&(cut as u32).to_le_bytes());
        fuzz_one(&p, &[], limits);
    }
    let n = 30_000;
    for _ in 0..n {
        let m = mutate(&mut rng, &t);
        fuzz_one(&m, &[], limits);
    }
    println!(
        "aml fuzz: {} truncations and {n} mutations of a built table: no panic",
        t.len() - 36
    );
}

#[test]
fn fuzz_firmware_ssdts() {
    let t = tables();
    if t.is_empty() {
        return;
    }
    // Mutate each SSDT on top of the real DSDT (the DSDT is loaded once per run, unmutated).
    let dsdt: Vec<_> = t
        .iter()
        .filter(|(n, _)| n.starts_with("DSDT"))
        .cloned()
        .collect();
    let ssdts: Vec<_> = t.iter().filter(|(n, _)| !n.starts_with("DSDT")).collect();
    let mut rng = Rng(0x0D05_A3E1_C0DE_0002);
    let limits = Limits {
        steps: 5_000,
        ..Limits::default()
    };
    let n = 40;
    for (_, s) in &ssdts {
        for _ in 0..n {
            let m = mutate(&mut rng, s);
            fuzz_one(&m, &dsdt, limits);
        }
    }
    println!(
        "aml fuzz: {} mutations of the firmware's SSDTs on its DSDT: no panic",
        n * ssdts.len()
    );
}
