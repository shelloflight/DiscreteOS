//! Interpreter unit tests on byte code built by `common` (each mirrors a small piece of ASL).

mod common;

use aml::{ErrorKind, Interpreter, Object};
use common::*;

fn load(body: Vec<u8>) -> Interpreter<Sim> {
    let mut i = Interpreter::new(Sim::default());
    i.load_table(&dsdt(&body)).expect("table loads");
    assert_eq!(i.stats.load_errors, 0, "{:?}", i.stats.errors);
    i
}

fn int_of(i: &mut Interpreter<Sim>, path: &str) -> u64 {
    i.evaluate(path, vec![])
        .unwrap_or_else(|e| panic!("{path}: {e}"))
        .as_integer()
        .expect("integer")
}

#[test]
fn names_and_data() {
    let mut i = load(cat(&[
        &name("INT0", int(0x1234_5678_9ABC)),
        &name("STR0", string("hello")),
        &name("PKG0", package(&[int(1), string("two"), buffer(&[3, 3])])),
        &scope("\\_SB", name("SUB0", int(7))),
    ]));
    assert_eq!(int_of(&mut i, "\\INT0"), 0x1234_5678_9ABC);
    assert_eq!(
        i.evaluate("\\STR0", vec![]).unwrap().as_bytes().unwrap(),
        b"hello"
    );
    let p = i.evaluate("\\PKG0", vec![]).unwrap().as_package().unwrap();
    assert_eq!(p.len(), 3);
    assert_eq!(p[2].as_bytes().unwrap(), vec![3, 3]);
    assert_eq!(int_of(&mut i, "\\_SB.SUB0"), 7);
}

#[test]
fn methods_arguments_and_control_flow() {
    let mut i = load(cat(&[
        &method("ADD2", 2, ret(add(arg(0), arg(1), ZERO.to_vec()))),
        // Sum 0..Arg0 with While, skipping 3 with Continue, stopping at 8 with Break.
        &method(
            "LOOP",
            1,
            cat(&[
                &store(int(0), local(0)),
                &store(int(0), local(1)),
                &while_(
                    lless(local(0), arg(0)),
                    cat(&[
                        &incr(local(0)),
                        &if_(lequal(local(0), int(3)), vec![0x9F]),
                        &if_(lequal(local(0), int(8)), vec![0xA5]),
                        &add(local(1), local(0), local(1)),
                    ]),
                ),
                &ret(local(1)),
            ]),
        ),
        &method(
            "ELSE",
            1,
            cat(&[&if_(arg(0), ret(string("yes"))), &else_(ret(string("no")))]),
        ),
        &method(
            "NEST",
            0,
            ret(call("ADD2", &[call("ADD2", &[int(1), int(2)]), int(10)])),
        ),
    ]));
    assert_eq!(
        i.evaluate("\\ADD2", vec![Object::int(40), Object::int(2)])
            .unwrap()
            .as_integer(),
        Some(42)
    );
    // 1+2+4+5+6+7 = 25 (3 skipped, stops at 8)
    assert_eq!(
        i.evaluate("\\LOOP", vec![Object::int(100)])
            .unwrap()
            .as_integer(),
        Some(25)
    );
    assert_eq!(
        i.evaluate("\\ELSE", vec![Object::int(1)])
            .unwrap()
            .as_bytes()
            .unwrap(),
        b"yes"
    );
    assert_eq!(
        i.evaluate("\\ELSE", vec![Object::int(0)])
            .unwrap()
            .as_bytes()
            .unwrap(),
        b"no"
    );
    assert_eq!(int_of(&mut i, "\\NEST"), 13);
}

#[test]
fn integers_are_32_bit_in_revision_1_tables() {
    let body = cat(&[
        &method("ONES", 0, ret(ONES.to_vec())),
        &method("NOT0", 0, ret(cat(&[&[0x80], &int(0), ZERO]))),
        &method("WRAP", 0, ret(add(int(0xFFFF_FFFF), int(2), ZERO.to_vec()))),
    ]);
    let mut i = Interpreter::new(Sim::default());
    i.load_table(&table(b"DSDT", 1, &body)).unwrap();
    assert_eq!(int_of(&mut i, "\\ONES"), 0xFFFF_FFFF);
    assert_eq!(int_of(&mut i, "\\NOT0"), 0xFFFF_FFFF);
    assert_eq!(int_of(&mut i, "\\WRAP"), 1);
}

#[test]
fn io_fields_preserve_and_index_fields() {
    let mut i = load(cat(&[
        &opregion("PRT0", 1, 0x80, 4),
        // ByteAcc, Preserve
        &field(
            "PRT0",
            0x01,
            &[("LOW_", 4), ("HIGH", 4), ("BYT1", 8), ("WRD1", 16)],
        ),
        &method("SETH", 1, store(arg(0), ns("HIGH"))),
        &method("GETH", 0, ret(ns("HIGH"))),
        &method("SETW", 1, store(arg(0), ns("WRD1"))),
        // CMOS-style index/data pair at 0x70/0x71 and an IndexField over it.
        &opregion("CMS0", 1, 0x70, 2),
        &field("CMS0", 0x01, &[("IDX_", 8), ("DAT_", 8)]),
        &index_field("IDX_", "DAT_", 0x01, &[("", 16), ("REG2", 8)]),
        &method("SETR", 1, store(arg(0), ns("REG2"))),
    ]));
    i.handler().io.insert(0x80, 0x05);
    i.evaluate("\\SETH", vec![Object::int(0xA)]).unwrap();
    assert_eq!(i.handler().io[&0x80], 0xA5, "low nibble preserved");
    assert_eq!(int_of(&mut i, "\\GETH"), 0xA);
    assert_eq!(int_of(&mut i, "\\LOW_"), 5);
    i.evaluate("\\SETW", vec![Object::int(0xBEEF)]).unwrap();
    assert_eq!((i.handler().io[&0x82], i.handler().io[&0x83]), (0xEF, 0xBE));
    i.evaluate("\\SETR", vec![Object::int(0x42)]).unwrap();
    let w = &i.handler().io_writes;
    assert_eq!(
        &w[w.len() - 2..],
        &[(0x70, 1, 2), (0x71, 1, 0x42)],
        "index 2 then data"
    );
}

#[test]
fn write_as_ones_and_out_of_region_fields() {
    let mut i = load(cat(&[
        &opregion("PRT0", 1, 0x90, 1),
        // ByteAcc, WriteAsOnes
        &field("PRT0", 0x21, &[("BIT0", 1), ("", 7), ("OVER", 8)]),
        &method("SET0", 0, store(int(0), ns("BIT0"))),
        &method("BAD_", 0, ret(ns("OVER"))),
    ]));
    i.evaluate("\\SET0", vec![]).unwrap();
    assert_eq!(i.handler().io[&0x90], 0xFE);
    let e = i.evaluate("\\BAD_", vec![]).unwrap_err();
    assert!(matches!(e.kind, ErrorKind::Range(_)), "{e}");
}

#[test]
fn pci_config_regions_find_their_device() {
    // \_SB.PCI0 (PNP0A08, _BBN 0) -> bridge at 1.2 (secondary bus 5) -> device at 0.0 on bus 5
    let mut i = load(scope(
        "\\_SB",
        device(
            "PCI0",
            cat(&[
                &name("_HID", cat(&[&[0x0C], &0x080A_D041u32.to_le_bytes()])),
                &name("_BBN", int(0)),
                &device(
                    "BRG0",
                    cat(&[
                        &name("_ADR", int(0x0001_0002)),
                        &device(
                            "DEV0",
                            cat(&[
                                &name("_ADR", int(0)),
                                &opregion("CFG0", 2, 0, 0x100),
                                &field("CFG0", 0x03, &[("VID_", 16), ("DID_", 16)]),
                            ]),
                        ),
                    ]),
                ),
            ]),
        ),
    ));
    let bridge = (0u16, 0u8, 1u8, 2u8);
    i.handler().pci.insert((bridge, 0x0E), 1);
    i.handler().pci.insert((bridge, 0x19), 5);
    i.handler().pci.insert(((0, 5, 0, 0), 0), 0x86);
    i.handler().pci.insert(((0, 5, 0, 0), 1), 0x80);
    assert_eq!(int_of(&mut i, "\\_SB.PCI0.BRG0.DEV0.VID_"), 0x8086);
}

#[test]
fn buffers_packages_and_references() {
    let mut i = load(cat(&[
        &name("BUF0", buffer(&[0x11, 0x22, 0x33, 0x44, 0x55])),
        &name("PKG0", package(&[int(10), int(20), int(30)])),
        &method(
            "BFLD",
            0,
            cat(&[
                // CreateWordField(BUF0, 1, WRD0); Store(0xBEEF, WRD0); Return(BUF0)
                &[0x8B],
                &ns("BUF0"),
                &int(1),
                &ns("WRD0"),
                &store(int(0xBEEF), ns("WRD0")),
                &ret(ns("BUF0")),
            ]),
        ),
        &method(
            "IDX0",
            0,
            ret(derefof(index(ns("PKG0"), int(2), ZERO.to_vec()))),
        ),
        &method(
            "SETI",
            0,
            cat(&[
                &store(int(99), index(ns("PKG0"), int(0), ZERO.to_vec())),
                &ret(derefof(index(ns("PKG0"), int(0), ZERO.to_vec()))),
            ]),
        ),
        &method(
            "SIZE",
            0,
            ret(add(sizeof(ns("BUF0")), sizeof(ns("PKG0")), ZERO.to_vec())),
        ),
        &method(
            "CAT0",
            0,
            ret(op2(0x73, string("ab"), string("cd"), ZERO.to_vec())),
        ),
        &method("TOIN", 0, ret(cat(&[&[0x99], &string("0x1F"), ZERO]))),
        &method("TODS", 0, ret(cat(&[&[0x97], &int(1234), ZERO]))),
        // Store a package into a local, change the copy: the named package is unchanged.
        &method(
            "COPY",
            0,
            cat(&[
                &store(ns("PKG0"), local(0)),
                &store(int(7), index(local(0), int(1), ZERO.to_vec())),
                &ret(derefof(index(ns("PKG0"), int(1), ZERO.to_vec()))),
            ]),
        ),
        // Match(PKG0, MEQ, 30, MTR, 0, 0) -> 2
        &method(
            "MTCH",
            0,
            ret(cat(&[
                &[0x89],
                &ns("PKG0"),
                &[1],
                &int(30),
                &[0],
                &int(0),
                &int(0),
            ])),
        ),
    ]));
    assert_eq!(
        i.evaluate("\\BFLD", vec![]).unwrap().as_bytes().unwrap(),
        vec![0x11, 0xEF, 0xBE, 0x44, 0x55]
    );
    assert_eq!(int_of(&mut i, "\\IDX0"), 30);
    assert_eq!(int_of(&mut i, "\\SETI"), 99);
    assert_eq!(int_of(&mut i, "\\SIZE"), 8);
    assert_eq!(
        i.evaluate("\\CAT0", vec![]).unwrap().as_bytes().unwrap(),
        b"abcd"
    );
    assert_eq!(int_of(&mut i, "\\TOIN"), 0x1F);
    assert_eq!(
        i.evaluate("\\TODS", vec![]).unwrap().as_bytes().unwrap(),
        b"1234"
    );
    assert_eq!(int_of(&mut i, "\\COPY"), 20);
    assert_eq!(int_of(&mut i, "\\MTCH"), 2);
}

#[test]
fn osi_os_rev_and_sleep_types() {
    let mut i = load(cat(&[
        &method("OSI1", 0, ret(call("_OSI", &[string("Windows 2015")]))),
        &method("OSI2", 0, ret(call("_OSI", &[string("Linux")]))),
        &name("_S5", package(&[int(5), int(7), int(0), int(0)])),
        &method("_S4", 0, ret(package(&[int(4), int(4)]))),
    ]));
    assert_eq!(int_of(&mut i, "\\OSI1"), u64::MAX);
    assert_eq!(int_of(&mut i, "\\OSI2"), 0);
    assert_eq!(
        i.evaluate("\\_OS", vec![]).unwrap().as_bytes().unwrap(),
        b"Microsoft Windows NT"
    );
    assert_eq!(i.sleep_type(5), Some((5, 7)));
    assert_eq!(i.sleep_type(4), Some((4, 4)), "\\_S4 as a method");
    assert_eq!(i.sleep_type(3), None);
}

#[test]
fn notify_debug_and_temporaries() {
    let mut i = load(cat(&[
        &device("PWRB", name("_HID", string("PNP0C0C"))),
        &method("NTFY", 0, cat(&[&[0x86], &ns("PWRB"), &int(0x80)])),
        &method("DBG0", 0, store(string("hi"), vec![0x5B, 0x31])),
        &method("TEMP", 0, cat(&[&name("TMP0", int(5)), &ret(ns("TMP0"))])),
    ]));
    i.evaluate("\\NTFY", vec![]).unwrap();
    assert_eq!(i.handler().notifies, vec![("\\PWRB".to_string(), 0x80)]);
    i.evaluate("\\DBG0", vec![]).unwrap();
    assert_eq!(i.handler().debug, vec!["hi".to_string()]);
    let before = i.namespace().len();
    for _ in 0..3 {
        assert_eq!(
            int_of(&mut i, "\\TEMP"),
            5,
            "a method's names are created anew each call"
        );
    }
    assert_eq!(i.namespace().len(), before, "temporaries removed");
    assert_eq!(i.find_devices(&["PNP0C0C"]).len(), 1);
}

#[test]
fn budgets_fail_closed_and_the_namespace_survives() {
    let mut i = load(cat(&[
        &name("GOOD", int(1)),
        &method("SPIN", 0, while_(ONES.to_vec(), vec![0xA3])),
        &method("RECU", 0, ret(call("RECU", &[]))),
        &method("HUGE", 0, ret(pkg(&[0x11], int(0xFFFF_FFFF)))),
        &method(
            "DIV0",
            0,
            ret(cat(&[&[0x78], &int(1), &int(0), ZERO, ZERO])),
        ),
        &method("MISS", 0, ret(ns("NOPE"))),
        &method(
            "FATL",
            0,
            cat(&[&[0x5B, 0x32, 1], &7u32.to_le_bytes(), &int(0)]),
        ),
    ]));
    let kind = |i: &mut Interpreter<Sim>, p: &str| i.evaluate(p, vec![]).unwrap_err().kind;
    assert_eq!(kind(&mut i, "\\SPIN"), ErrorKind::Limit("steps"));
    assert_eq!(kind(&mut i, "\\RECU"), ErrorKind::Limit("call depth"));
    assert_eq!(kind(&mut i, "\\HUGE"), ErrorKind::Limit("buffer size"));
    assert!(matches!(kind(&mut i, "\\DIV0"), ErrorKind::Range(_)));
    assert!(matches!(kind(&mut i, "\\MISS"), ErrorKind::NotFound(_)));
    assert_eq!(kind(&mut i, "\\FATL"), ErrorKind::Fatal(1, 7, 0));
    assert_eq!(int_of(&mut i, "\\GOOD"), 1);
}

#[test]
fn device_initialisation_follows_sta() {
    let mut i = load(cat(&[
        &name("CNT0", int(0)),
        &scope(
            "\\_SB",
            cat(&[
                &method("_INI", 0, add(ns("CNT0"), int(1), ns("CNT0"))),
                &device(
                    "ABSN",
                    cat(&[
                        &method("_STA", 0, ret(int(0))),
                        &device(
                            "CHLD",
                            method("_INI", 0, add(ns("CNT0"), int(100), ns("CNT0"))),
                        ),
                    ]),
                ),
                &device(
                    "FUNC",
                    cat(&[
                        &method("_STA", 0, ret(int(8))),
                        &device(
                            "CHLD",
                            method("_INI", 0, add(ns("CNT0"), int(10), ns("CNT0"))),
                        ),
                    ]),
                ),
                &device(
                    "PRES",
                    cat(&[
                        &method("_STA", 0, ret(int(0x0F))),
                        &method("_INI", 0, add(ns("CNT0"), int(1000), ns("CNT0"))),
                    ]),
                ),
            ]),
        ),
    ]));
    let r = i.initialize();
    // \_SB._INI (1), FUNC's child (10, functional parent walked), PRES (1000); not ABSN's child.
    assert_eq!(int_of(&mut i, "\\CNT0"), 1011);
    assert_eq!(r.failures, 0);
}

#[test]
fn load_errors_skip_one_definition_only() {
    let mut i = Interpreter::new(Sim::default());
    let body = cat(&[
        &name("AAAA", int(1)),
        &scope("\\NOPE", name("XXXX", int(2))), // missing scope: skipped
        &device(
            "DEV0",
            cat(&[&name("BBBB", int(3)), &[0x5B, 0xFE], &name("CCCC", int(4))]),
        ), // bad opcode in the body
        &name("DDDD", int(5)),
        &name("AAAA", int(9)), // duplicate: the first stays
    ]);
    i.load_table(&dsdt(&body)).unwrap();
    assert_eq!(i.stats.load_errors, 2, "{:?}", i.stats.errors);
    assert_eq!(i.stats.duplicates, 1);
    assert_eq!(int_of(&mut i, "\\AAAA"), 1);
    assert_eq!(int_of(&mut i, "\\DEV0.BBBB"), 3);
    assert!(i.find("\\DEV0.CCCC").is_none());
    assert_eq!(int_of(&mut i, "\\DDDD"), 5);
}

#[test]
fn ssdt_extends_the_dsdt() {
    let mut i = load(scope("\\_SB", device("PCI0", name("_ADR", int(0)))));
    let ssdt = table(
        b"SSDT",
        2,
        &scope("\\_SB.PCI0", method("XTRA", 0, ret(int(77)))),
    );
    i.load_table(&ssdt).unwrap();
    assert_eq!(int_of(&mut i, "\\_SB.PCI0.XTRA"), 77);
}
