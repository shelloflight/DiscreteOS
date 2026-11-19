//! Rust in-kernel tests. Compiled only into test images (`--cfg ktest --cfg ktest_<case>`),
//! called from kernel/ktest.c.

#[cfg(ktest_selftest)]
mod selftest {
    use alloc::boxed::Box;
    use alloc::string::String;
    use alloc::vec::Vec;
    use core::fmt::Write;
    use core::hint::black_box;

    use crate::ffi::{KLOG_DEBUG, KLOG_WARN, rank};
    use crate::fmtbuf::FmtBuf;
    use crate::klog::{self, SLOTS};
    use crate::sync::SpinLock;

    struct T {
        failures: u32,
    }

    impl T {
        #[track_caller]
        fn check(&mut self, ok: bool, what: &str) {
            if !ok {
                let l = core::panic::Location::caller();
                crate::kprintln!("  FAIL {}:{}: {}", l.file(), l.line(), what);
                self.failures += 1;
            }
        }
    }

    macro_rules! check {
        ($t:expr, $c:expr) => {
            $t.check($c, stringify!($c))
        };
    }

    fn allocator(t: &mut T) {
        let b = Box::new([7u64; 4]);
        check!(t, b.iter().all(|&x| x == 7));

        let mut v: Vec<u32> = Vec::new();
        for i in 0..1000 {
            v.push(i);
        }
        check!(
            t,
            v.len() == 1000 && v.iter().copied().sum::<u32>() == 499_500
        );
        v.truncate(10);
        v.shrink_to_fit();
        check!(t, v.capacity() >= 10 && v[9] == 9);

        let mut s = String::new();
        let _ = write!(s, "dkrnl-{:#x}", 255);
        check!(t, s == "dkrnl-0xff");

        #[repr(align(64))]
        struct Big([u8; 100]);
        for _ in 0..8 {
            let p = Box::new(Big([1; 100]));
            check!(
                t,
                (&*p as *const Big as usize).is_multiple_of(64) && p.0[99] == 1
            );
        }
        #[repr(align(4096))]
        struct Page([u8; 16]);
        let pg = Box::new(Page([2; 16]));
        check!(
            t,
            (&*pg as *const Page as usize).is_multiple_of(4096) && pg.0[15] == 2
        );

        let z: Box<[u8]> = alloc::vec![0u8; 5000].into_boxed_slice();
        check!(t, z.iter().all(|&b| b == 0));
    }

    fn fmtbuf(t: &mut T) {
        let mut b = FmtBuf::<8>::new();
        let _ = write!(b, "truncated text");
        check!(t, b.as_bytes() == b"truncate");
    }

    static COUNTER: SpinLock<u64> = SpinLock::new(c"ktest.counter", rank::TEST, 0);

    fn spinlock(t: &mut T) {
        for _ in 0..100 {
            *COUNTER.lock() += 1;
        }
        check!(t, *COUNTER.lock() == 100);
        {
            let _g = COUNTER.lock();
            check!(t, COUNTER.try_lock().is_none()); // held: try_lock must fail, not deadlock
        }
        check!(t, COUNTER.try_lock().is_some()); // guard dropped: free again
    }

    fn klog_ring(t: &mut T) {
        let start = klog::next_seq();
        crate::klog!(KLOG_WARN, "rust selftest marker {}", 1);
        crate::klog!(KLOG_DEBUG, "rust selftest marker {}", 2);
        let a = klog::read(start);
        let b = a.and_then(|e| klog::read(e.seq + 1));
        check!(
            t,
            a.is_some_and(|e| e.seq == start
                && e.level == KLOG_WARN as u8
                && e.text() == b"rust selftest marker 1")
        );
        check!(
            t,
            b.is_some_and(|e| e.level == KLOG_DEBUG as u8 && e.text() == b"rust selftest marker 2")
        );
        check!(t, a.zip(b).is_some_and(|(a, b)| b.time_us >= a.time_us));

        // Long messages are split, not lost.
        let long = [b'x'; 300];
        let s = klog::next_seq();
        klog::write(KLOG_DEBUG, &long);
        check!(t, klog::next_seq() == s + 3);

        // Overflow: the oldest records are overwritten; readers skip ahead and see the loss.
        let before = klog::dropped();
        let first = klog::next_seq();
        for i in 0..(SLOTS + 10) {
            let mut m = FmtBuf::<32>::new();
            let _ = write!(m, "flood {}", i);
            crate::klog::capture(m.as_bytes());
            crate::klog::capture(b"\n");
        }
        check!(t, klog::dropped() > before);
        check!(t, klog::read(first).is_some_and(|e| e.seq > first)); // skipped to the oldest survivor
        let last = klog::read(klog::next_seq() - 1);
        let mut want = FmtBuf::<32>::new();
        let _ = write!(want, "flood {}", SLOTS + 9);
        check!(t, last.is_some_and(|e| e.text() == want.as_bytes()));
        check!(t, klog::read(klog::next_seq()).is_none());
    }

    fn overflow_checks(t: &mut T) {
        // Release builds keep overflow checks on; checked math must still report overflow.
        let x: u8 = black_box(255);
        check!(t, x.checked_add(1).is_none());
    }

    fn threads(t: &mut T) {
        use crate::ffi::now_ns;
        use crate::sync::{Event, Mutex, Semaphore};
        use crate::thread::{prio, sleep_ns, spawn, yield_now};
        use alloc::sync::Arc;

        // Mutex<T> across threads, with yields inside the critical section.
        static COUNTER: Mutex<u64> = Mutex::new(c"rust.counter", 0);
        let workers: Vec<_> = (0..4)
            .map(|i| {
                spawn(c"rust.worker", prio::NORMAL, move || {
                    for _ in 0..100 {
                        let mut g = COUNTER.lock();
                        let v = *g;
                        yield_now();
                        *g = v + 1;
                    }
                    i
                })
            })
            .collect();
        check!(t, workers.iter().all(|w| w.is_some()));
        let sum: i32 = workers.into_iter().flatten().map(|h| h.join()).sum();
        check!(t, sum == 6 && *COUNTER.lock() == 400);
        check!(t, COUNTER.try_lock().is_some());

        // Semaphore shared through an Arc; timeouts.
        let sem = Arc::new(Semaphore::new(c"rust.sem", 0));
        let poster = sem.clone();
        let h = spawn(c"rust.poster", prio::NORMAL, move || {
            for _ in 0..10 {
                poster.up();
            }
            0
        });
        for _ in 0..10 {
            sem.down();
        }
        check!(t, h.map(|h| h.join()) == Some(0));
        check!(t, !sem.down_timeout(0));
        let t0 = now_ns();
        check!(t, !sem.down_timeout(1_000_000));
        check!(t, now_ns() - t0 >= 1_000_000);

        // Auto-reset event wakes one waiter per signal.
        let ev = Arc::new(Event::new(c"rust.ev", true));
        let waiter = ev.clone();
        let h = spawn(c"rust.waiter", prio::HIGH, move || {
            waiter.wait();
            waiter.wait();
            2
        });
        ev.signal();
        ev.signal();
        check!(t, h.map(|h| h.join()) == Some(2));
        check!(t, !ev.wait_timeout(0));

        // A dropped handle detaches; sleeping works.
        drop(spawn(c"rust.detached", prio::NORMAL, || 0));
        let t0 = now_ns();
        sleep_ns(1_000_000);
        check!(t, now_ns() - t0 >= 1_000_000);
    }

    /// The crypto the kernel uses, the TPM 2.0 command layer against the simulator
    /// (normal answers and broken ones), and the measurement log replayed into a TPM.
    fn measured_boot(t: &mut T) {
        use crate::security::measure;
        use crate::security::tpm::{Error, Sim, SimFault, Tpm};
        // RFC 8032 test 1 (empty message) verifies; a flipped bit does not.
        let unhex = |s: &str| -> Vec<u8> { (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap_or(0)).collect() };
        let pk: [u8; 32] = unhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a").try_into().unwrap_or([0; 32]);
        let mut sig: [u8; 64] = unhex(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        )
        .try_into()
        .unwrap_or([0; 64]);
        check!(t, doscrypt::ed25519::verify(&pk, b"", &sig));
        sig[40] ^= 1;
        check!(t, !doscrypt::ed25519::verify(&pk, b"", &sig));
        // The TPM command layer.
        let tpm = Tpm::new(Box::new(Sim::new()));
        check!(t, tpm.as_ref().is_ok_and(|x| &x.manufacturer == b"DOSS"));
        if let Ok(mut tpm) = tpm {
            let d = [0x5Au8; 32];
            check!(t, tpm.pcr_extend(16, &d).is_ok());
            check!(t, tpm.pcr_read(16) == Ok(measure::extend(&[0; 32], &d)));
            check!(t, tpm.pcr_read(24).is_err());
        }
        for (f, want) in [
            (SimFault::Truncated, Error::Protocol("short response")),
            (SimFault::BadTag, Error::Protocol("malformed response header")),
            (SimFault::Timeout, Error::Timeout),
        ] {
            let mut s = Sim::new();
            s.fault = f;
            check!(t, Tpm::new(Box::new(s)).err() == Some(want));
        }
        // The kernel's log (PCR 8 from boot) replayed into a fresh TPM: hardware == software.
        let before = measure::for_each(|_, _| {}).0;
        check!(t, before >= 1 && !measure::tpm_present());
        if let Ok(tpm) = Tpm::new(Box::new(Sim::new())) {
            check!(t, measure::attach_tpm(tpm) == before);
            check!(t, measure::tpm_matches() == Some(true));
            measure::measure(23, &[7; 32], "ktest", false);
            check!(t, measure::tpm_matches() == Some(true));
            measure::detach_tpm();
        }
        check!(t, measure::pcr(23) == measure::extend(&[0; 32], &[7; 32]));
        crate::kprintln!("  measured boot: Ed25519 vectors, TPM 2.0 commands vs the simulator (3 broken TPMs refused), log replay matches");
        attestation_with_tpm(t);
    }

    /// Hardware-rooted attestation against the simulated TPM (TEST keys): the report carries a
    /// quote for the nonce and the EK certificate; a verifier's challenge is answered by the TPM
    /// and only for its own EK and AK.
    fn attestation_with_tpm(t: &mut T) {
        use crate::security::{attest, measure};
        use crate::security::tpm::{Sim, Tpm};
        use doscrypt::{attest as rep, testkeys, tpm as dtpm, x509};
        let Ok(tpm) = Tpm::new(Box::new(Sim::new())) else {
            check!(t, false);
            return;
        };
        measure::attach_tpm(tpm);
        let nonce = [0x6Bu8; 32];
        let r = attest::report(&nonce);
        check!(t, r.is_some());
        let r = r.unwrap_or_default();
        let ev = rep::tpm_evidence(&r);
        check!(t, ev.is_some());
        if let Some(ev) = ev {
            let p = |o: usize| -> [u8; 32] { r[o..o + 32].try_into().unwrap_or([0; 32]) };
            let pcrs = [(rep::PCR_KERNEL, p(120)), (rep::PCR_CODE, p(152))];
            check!(t, dtpm::verify_quote(ev.ak_public, ev.quote, ev.quote_sig, &nonce, &pcrs).is_ok());
            check!(t, dtpm::verify_quote(ev.ak_public, ev.quote, ev.quote_sig, &[0; 32], &pcrs).is_err());
            let ca = x509::parse(&testkeys::CA_CERT);
            let cert = x509::parse(ev.ek_cert);
            check!(t, matches!((cert, ca), (Some(c), Some(ca)) if c.signed_by(&ca)));
            check!(t, r[12] & (rep::F_TPM | rep::F_TPM_MATCH) as u8 == (rep::F_TPM | rep::F_TPM_MATCH) as u8);
        }
        // The challenge round: the right challenge opens, a damaged or foreign one does not.
        let cred = [0x42u8; 32];
        if let Some((blob, secret)) = rep::challenge(&r, &cred, &[1; 32], &[2; 32]) {
            check!(t, attest::activate(&blob, &secret) == Ok(cred));
            let mut bad = blob;
            bad[10] ^= 1;
            check!(t, attest::activate(&bad, &secret) == Err(attest::ActivateError::Refused));
            // The same credential for another AK (another name) is refused too.
            let ek = dtpm::parse_rsa_ek(ev.map_or(&[][..], |e| e.ek_public));
            if let Some(ek) = ek {
                let other = dtpm::make_credential(&ek, &[0x77; 34], &cred, &[3; 32], &[4; 32]);
                check!(t, other.is_some_and(|(b, s)| attest::activate(&b, &s) == Err(attest::ActivateError::Refused)));
            } else {
                check!(t, false);
            }
            check!(t, attest::activate(&blob, &secret) == Ok(cred)); // still usable afterwards
        } else {
            check!(t, false);
        }
        attest::forget_tpm();
        measure::detach_tpm();
        check!(t, attest::activate(&[0; dtpm::ID_OBJECT], &[0; dtpm::SECRET]) == Err(attest::ActivateError::NoTpm));
        attest::forget_tpm();
        crate::kprintln!("  attestation: TPM quote for the nonce, EK certificate chain, credential challenge (foreign ones refused)");
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn rust_selftest() -> u32 {
        let mut t = T { failures: 0 };
        measured_boot(&mut t);
        allocator(&mut t);
        fmtbuf(&mut t);
        spinlock(&mut t);
        klog_ring(&mut t);
        overflow_checks(&mut t);
        threads(&mut t);
        check!(t, crate::nospec::selftest());
        if t.failures == 0 {
            crate::kprintln!("KTEST rust selftest: PASSED");
        } else {
            crate::kprintln!("KTEST rust selftest: FAILED ({})", t.failures);
        }
        t.failures
    }
}

#[cfg(ktest_rustpanic)]
#[unsafe(no_mangle)]
pub extern "C" fn rust_ktest_panic() {
    crate::kprintln!("KTEST rustpanic: failing a kassert! in Rust");
    let one = core::hint::black_box(1);
    crate::kassert!(one == 2);
    crate::kprintln!("KTEST rustpanic: FAILED (kassert returned)");
}

#[cfg(any(ktest_bench, ktest_hwbench))]
mod bench {
    use alloc::boxed::Box;
    use core::hint::black_box;

    use crate::ffi::rank;
    use crate::sync::SpinLock;

    /// One Box<[u8; 32]> allocate + free (Rust allocator over kmalloc).
    #[unsafe(no_mangle)]
    pub extern "C" fn rust_bench_box(_ctx: *mut core::ffi::c_void) {
        drop(black_box(Box::new([0u8; 32])));
    }

    static L: SpinLock<u64> = SpinLock::new(c"bench", rank::TEST, 0);

    /// One uncontended SpinLock<T> lock + unlock (IRQ-safe) from Rust.
    #[unsafe(no_mangle)]
    pub extern "C" fn rust_bench_spinlock(_ctx: *mut core::ffi::c_void) {
        *L.lock() += 1;
    }

    /// One klog record (no console echo: captured only).
    #[unsafe(no_mangle)]
    pub extern "C" fn rust_bench_spawn(_ctx: *mut core::ffi::c_void) {
        let h = crate::thread::spawn(c"bench.rs", crate::thread::prio::NORMAL, || 0);
        black_box(h.map(|h| h.join()));
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn rust_bench_klog(_ctx: *mut core::ffi::c_void) {
        crate::klog::capture(b"bench record\n");
    }
}
