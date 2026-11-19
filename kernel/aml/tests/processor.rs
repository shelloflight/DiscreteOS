//! Processor power objects (`aml::processor`): `_CST`, `_CPC`, `_PSS`/`_PCT` on built byte code,
//! shaped like a desktop's (an AMD Zen 5: C1 MWAIT, C2/C3 by I/O port, CPPC in MSRs); and the
//! build machine's own tables when they have been dumped (as `firmware.rs` does).

mod common;

use std::path::PathBuf;

use aml::processor::{CEntry, CpcValue, Gas, SPACE_FFH, SPACE_IO, SPACE_PCC};
use aml::Interpreter;
use common::*;

/// `Register (space, width, offset, address, access)` as a resource template buffer.
fn register(space: u8, width: u8, offset: u8, address: u64, access: u8) -> Vec<u8> {
    let mut b = vec![0x82, 0x0C, 0x00, space, width, offset, access];
    b.extend_from_slice(&address.to_le_bytes());
    b.extend_from_slice(&[0x79, 0x00]);
    buffer(&b)
}

fn null_register() -> Vec<u8> {
    register(0, 0, 0, 0, 0)
}

fn msr(width: u8, offset: u8, address: u64) -> Vec<u8> {
    register(SPACE_FFH, width, offset, address, 4)
}

fn processor_device(n: &str, uid: u64, body: &[u8]) -> Vec<u8> {
    device(n, cat(&[&name("_HID", string("ACPI0007")), &name("_UID", int(uid)), body]))
}

fn zen_like() -> Vec<u8> {
    let cst = package(&[
        int(3),
        package(&[register(SPACE_FFH, 2, 2, 0, 0), int(1), int(1), int(0)]),
        package(&[register(SPACE_IO, 8, 0, 0x414, 1), int(2), int(18), int(0)]),
        package(&[register(SPACE_IO, 8, 0, 0x415, 1), int(3), int(350), int(0)]),
    ]);
    let mut cpc = vec![int(23), int(3)];
    cpc.extend([
        msr(8, 24, 0xC001_02B0), // highest
        msr(8, 16, 0xC001_02B0), // nominal
        msr(8, 8, 0xC001_02B0),  // lowest non-linear
        msr(8, 0, 0xC001_02B0),  // lowest
        null_register(),         // guaranteed
        msr(8, 16, 0xC001_02B3), // desired
        msr(8, 8, 0xC001_02B3),  // minimum
        msr(8, 0, 0xC001_02B3),  // maximum
        null_register(),
        null_register(),
        null_register(),
        msr(64, 0, 0xE7),
        msr(64, 0, 0xE8),
        msr(2, 0, 0xC001_02B4),
        msr(1, 0, 0xC001_02B1), // CPPC enable
        int(1),                 // autonomous selection: always
        null_register(),
        msr(8, 24, 0xC001_02B3), // energy-performance preference
        null_register(),
        int(600),
        int(4400),
    ]);
    let pss = package(&[
        package(&[int(4400), int(5500), int(0), int(0), int(0), int(0)]),
        package(&[int(3000), int(2550), int(0), int(0), int(1), int(1)]),
    ]);
    let pct = package(&[register(SPACE_FFH, 64, 0, 0xC001_0062, 0), register(SPACE_FFH, 64, 0, 0xC001_0063, 0)]);
    let body = cat(&[&name("_CST", cst), &name("_CPC", package(&cpc)), &name("_PSS", pss), &method("_PCT", 0, ret(pct))]);
    scope("\\_SB", device("PLTF", cat(&[&processor_device("C000", 0, &cat(&[&name("_STA", int(0)), &body])), &processor_device("C001", 1, &body)])))
}

#[test]
fn processor_power_objects() {
    let mut i = Interpreter::new(Sim::default());
    i.load_table(&dsdt(&zen_like())).expect("table loads");
    assert_eq!(i.processors().len(), 2);
    let cpu = i.first_processor().expect("a present processor");
    assert_eq!(i.path(cpu), "\\_SB_.PLTF.C001", "C000 is not present (_STA 0)");

    let cst = i.cst(cpu).expect("_CST");
    assert_eq!(cst.len(), 3);
    assert_eq!((cst[0].kind, cst[0].entry, cst[0].latency_us), (1, CEntry::Mwait { hint: 0, flags: 0 }, 1));
    assert_eq!((cst[1].kind, cst[1].entry, cst[1].latency_us), (2, CEntry::Io { port: 0x414 }, 18));
    assert_eq!((cst[2].kind, cst[2].entry, cst[2].latency_us), (3, CEntry::Io { port: 0x415 }, 350));

    let cpc = i.cpc(cpu).expect("_CPC");
    let field = |offset, address| CpcValue::Reg(Gas { space: SPACE_FFH, bit_width: 8, bit_offset: offset, access: 4, address });
    assert_eq!(cpc.revision, 3);
    assert_eq!(cpc.highest, field(24, 0xC001_02B0));
    assert_eq!(cpc.lowest_nonlinear, field(8, 0xC001_02B0));
    assert_eq!((cpc.desired, cpc.min, cpc.max), (field(16, 0xC001_02B3), field(8, 0xC001_02B3), field(0, 0xC001_02B3)));
    assert_eq!(cpc.epp, field(24, 0xC001_02B3));
    assert!(matches!(cpc.enable, CpcValue::Reg(Gas { bit_width: 1, address: 0xC001_02B1, .. })));
    assert_eq!(cpc.autonomous, CpcValue::Int(1));
    assert_eq!((cpc.lowest_mhz, cpc.nominal_mhz), (600, 4400));

    let pss = i.pss(cpu).expect("_PSS + _PCT");
    assert_eq!(pss.states.len(), 2);
    assert_eq!((pss.states[0].mhz, pss.states[0].control), (4400, 0));
    assert_eq!((pss.states[1].mhz, pss.states[1].control), (3000, 1));
    assert_eq!((pss.control.space, pss.control.address), (SPACE_FFH, 0xC001_0062));
}

/// Malformed objects read as absent, never as something half-parsed.
#[test]
fn processor_power_objects_malformed() {
    let bad = cat(&[
        &name("_CST", package(&[int(9), package(&[buffer(&[1, 2, 3]), int(2), int(5), int(0)]), int(7)])),
        &name("_CPC", package(&[int(23), int(3), int(5)])),
        &name("_PSS", package(&[package(&[int(1), int(2)])])),
        &method("_PCT", 0, ret(package(&[register(SPACE_PCC, 8, 0, 1, 0), int(4)]))),
    ]);
    let mut i = Interpreter::new(Sim::default());
    i.load_table(&dsdt(&scope("\\_SB", processor_device("CPU0", 0, &bad)))).expect("table loads");
    let cpu = i.first_processor().expect("processor");
    assert_eq!(i.cst(cpu), Some(vec![]), "an entry without a register is skipped; the count is clipped");
    assert_eq!(i.cpc(cpu), None, "fewer than 21 elements");
    assert_eq!(i.pss(cpu), None, "the status register is not a register");
    assert!(Gas::from_template(&[0x82, 0x0C, 0x00]).is_none());
}

/// The build machine's own processors (skipped without dumped tables).
#[test]
fn firmware_processor_power() {
    let dir = std::env::var_os("AML_TABLES")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../build/host/acpi"));
    let Ok(rd) = std::fs::read_dir(&dir) else { return };
    let mut t: Vec<(String, Vec<u8>)> = rd
        .filter_map(|e| e.ok())
        .map(|e| (e.file_name().to_string_lossy().into_owned(), e.path()))
        .filter(|(n, _)| n.starts_with("DSDT") || n.starts_with("SSD"))
        .filter_map(|(n, p)| std::fs::read(p).ok().map(|b| (n, b)))
        .collect();
    if t.is_empty() {
        println!("aml firmware: no tables in build/host/acpi (skipped)");
        return;
    }
    t.sort_by_key(|(n, _)| (!n.starts_with("DSDT"), n.clone()));
    let mut i = Interpreter::new(Sim::default());
    for (_, b) in &t {
        let _ = i.load_table(b);
    }
    i.initialize();
    let n = i.processors().len();
    let Some(cpu) = i.first_processor() else {
        println!("aml firmware: no present processor object ({n} in all)");
        return;
    };
    let cst = i.cst(cpu);
    let cpc = i.cpc(cpu);
    let pss = i.pss(cpu);
    println!(
        "aml firmware: {} processors, first {}: _CST {:?}; _CPC {}; _PSS {}",
        n,
        i.path(cpu),
        cst.as_ref().map(|c| c.iter().map(|s| (s.kind, s.entry, s.latency_us)).collect::<Vec<_>>()),
        cpc.map_or("none".into(), |c| format!("rev {}, highest {:?}, {}-{} MHz", c.revision, c.highest, c.lowest_mhz, c.nominal_mhz)),
        pss.as_ref().map_or("none".into(), |p| format!("{} states, {}-{} MHz", p.states.len(), p.states.last().map_or(0, |s| s.mhz), p.states[0].mhz)),
    );
    if let Some(c) = &cst {
        assert!(!c.is_empty(), "a _CST that lists no state");
        assert!(c.iter().all(|s| (1..=3).contains(&s.kind)), "C-state types are 1-3");
    }
}
