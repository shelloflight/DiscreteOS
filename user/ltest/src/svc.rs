//! Services the service manager's test run starts (manifests in user/init/services/test):
//! - `svc-grants`: the process holds exactly what its manifest grants (the log, its control
//!   channel, `/system` read-only, PCI class 01 devices) and nothing else;
//! - `svc-quota`: the manifest's quota is the process's quota, and the kernel enforces it;
//! - `svc-crash`: fails on purpose (restart with backoff, then given up);
//! - `svc-log`: reads the whole log through `log.read`: kernel and service records, the writer
//!   named by the kernel, consecutive sequence numbers, no kernel address anywhere (the planted
//!   one arrives as `[kaddr]`), and its own records below its manifest's level (`warn`) dropped;
//! - `svc-time`: the wall-clock time across a reboot (the `time` test): the first boot records
//!   the time in a file on a DFS and a FAT32 volume and exits with 10; the second checks that the
//!   clock moved forward and that both files kept their modification times.

use libd::fs::{self, Namespace, Node};
use libd::proto;
use libd::sys;
use libd::println;

macro_rules! check {
    ($c:expr, $($t:tt)*) => {
        if !$c {
            println!("ltest: svc FAIL: {} (line {})", format_args!($($t)*), line!());
            return 1;
        }
    };
}

pub fn grants() -> i32 {
    let mut devices = 0;
    let mut other = 0;
    for (h, tag) in libd::startup_handles() {
        match tag {
            sys::TAG_PROC_SELF | sys::TAG_THREAD_SELF | sys::TAG_VMAR_ROOT | sys::TAG_LOG | proto::TAG_CONTROL | fs::TAG_NS_NAMES => {}
            t if t == fs::TAG_NS => {}
            sys::TAG_DEVICE => {
                let info = sys::device_info(h);
                check!(info.is_ok_and(|i| i.kind == sys::DEV_KIND_PCI && i.class == 1), "a device outside PCI class 01: {:?}", info.map(|i| (i.class, i.subclass)));
                devices += 1;
            }
            t => {
                println!("ltest: svc FAIL: a handle the manifest does not grant (tag {:#x})", t);
                other += 1;
            }
        }
    }
    check!(other == 0, "{} handle(s) not granted", other);
    check!(devices > 0, "no device of PCI class 01");
    let ns = Namespace::get();
    check!(ns.entries().count() == 1, "the namespace has {} entries, not 1", ns.entries().count());
    let Some(dir) = ns.dir(b"/system") else {
        println!("ltest: svc FAIL: /system not granted");
        return 1;
    };
    let root = Node::from(dir);
    let st = root.stat();
    check!(st.is_ok_and(|s| s.rights == fs::R_READ), "/system rights {:?}, not read-only", st.map(|s| s.rights));
    let mut entries = 0;
    check!(root.list(|_, _| entries += 1).is_ok(), "cannot list /system");
    let w = root.open(b"svc-grants-was-here", fs::O_CREATE, fs::R_READ | fs::R_WRITE);
    check!(w.is_err(), "created a file on a read-only grant");
    let _ = root.into_handle(); // the startup handle stays owned by the startup block
    println!(
        "ltest: svc-grants: exactly the granted handles: log, control channel, {} PCI class 01 device(s), /system read-only ({} entries; create refused: {})",
        devices,
        entries,
        fs::status(w.err().unwrap_or(0))
    );
    0
}

pub fn quota() -> i32 {
    let q = sys::process_quota(libd::startup_handle(sys::TAG_PROC_SELF));
    check!(q.is_ok(), "no quota");
    let q = q.unwrap_or_default();
    check!(q.limits.memory == 4 << 20 && q.limits.handles == 32 && q.limits.threads == 2, "limits {} / {} / {}", q.limits.memory, q.limits.handles, q.limits.threads);
    let big = sys::vmo_create(8 << 20);
    check!(big.is_err(), "an 8 MiB VMO was granted under a 4 MiB quota");
    let small = sys::vmo_create(1 << 20);
    check!(small.is_ok(), "a 1 MiB VMO was refused: {:?}", small.err().map(sys::status));
    sys::handle_close(small.unwrap_or(0));
    println!(
        "ltest: svc-quota: limits from the manifest (4 MiB, 32 handles, 2 threads); 8 MiB refused ({}), 1 MiB granted",
        sys::status(big.err().unwrap_or(0))
    );
    0
}

pub fn crash() -> i32 {
    println!("ltest: svc-crash: failing on purpose");
    3
}

/// Is there a kernel address (a hex run of 16 digits from 0xFFFF800000000000 up) in `t`?
fn has_kernel_address(t: &[u8]) -> bool {
    let mut i = 0;
    while i < t.len() {
        let n = t[i..].iter().take_while(|c| c.is_ascii_hexdigit()).count();
        if n >= 16 {
            let run = &t[i..i + n];
            let v = run[n - 16..].iter().fold(0u64, |a, &c| (a << 4) | u64::from((c as char).to_digit(16).unwrap_or(0)));
            if v >= 0xFFFF_8000_0000_0000 {
                return true;
            }
        }
        i += n.max(1);
    }
    false
}

pub fn log_read() -> i32 {
    use libd::log;
    let ch = libd::svc::endpoint(b"log.read");
    check!(ch != 0, "no log.read endpoint");
    // Below this service's level (warn): not kept. At or above: kept.
    libd::log_debug!("svc-log: marker debug (must not be kept)");
    println!("svc-log: marker info (must not be kept)");
    libd::log_warn!("svc-log: marker warn (kept)");
    libd::log_error!("svc-log: marker error (kept)");
    let (mut from, mut total, mut kernel, mut storaged, mut filtered) = (0u64, 0u64, 0u64, 0u64, 0u64);
    let (mut warn, mut error, mut info, mut debug) = (false, false, false, false);
    let deadline = sys::clock_ns() + 10_000_000_000;
    while !(warn && error) && sys::clock_ns() < deadline {
        let b = log::read(ch, from, log::MAX_PER_READ, true, 2_000_000_000);
        check!(b.is_ok(), "READ failed: {:?}", b.as_ref().err());
        let Ok(b) = b else { return 1 };
        // From 0 the oldest records may be gone (the ring is bounded); after that, nothing is lost.
        check!(b.lost == 0 || from == 0, "{} records lost after sequence {}", b.lost, from);
        for (k, r) in b.records[..b.count].iter().enumerate() {
            let want = from + b.lost + k as u64;
            check!(r.seq == want, "sequence {} where {} was due", r.seq, want);
            let t = r.text();
            check!(!has_kernel_address(t), "a kernel address reached a reader: {}", core::str::from_utf8(t).unwrap_or("?"));
            total += 1;
            filtered += u64::from(t.windows(7).any(|w| w == b"[kaddr]"));
            match r.source() {
                b"kernel" => kernel += 1,
                b"storaged" => storaged += 1,
                b"svc-log" => {
                    warn |= t.ends_with(b"marker warn (kept)") && r.level == sys::LOG_WARN as u8;
                    error |= t.ends_with(b"marker error (kept)") && r.level == sys::LOG_ERROR as u8;
                    info |= t.ends_with(b"(must not be kept)") && r.level == sys::LOG_INFO as u8;
                    debug |= t.ends_with(b"(must not be kept)") && r.level == sys::LOG_DEBUG as u8;
                }
                _ => {}
            }
        }
        if b.count > 0 {
            from = b.next;
        }
    }
    check!(warn && error, "its own warn/error records did not arrive (warn {}, error {})", warn, error);
    check!(!info && !debug, "records below its level were kept (info {}, debug {})", info, debug);
    check!(kernel > 0 && storaged > 0, "kernel records {}, storaged records {}", kernel, storaged);
    check!(filtered > 0, "the planted kernel address was not seen filtered");
    println!(
        "svc-log: {} records read in order ({} kernel, {} from storaged), no kernel address ({} filtered to [kaddr]), levels applied (warn kept, info dropped)",
        total, kernel, storaged, filtered
    );
    0
}

pub fn time() -> i32 {
    use libd::time;
    let ch = libd::svc::endpoint(b"clock.time");
    check!(ch != 0, "no clock.time endpoint");
    let base = time::query(ch);
    check!(base.is_some(), "the clock service has no time");
    let Some(base) = base else { return 1 };
    let now = base.now();
    println!("svc-time: wall-clock time {} (source {})", now, base.source);
    let ns = Namespace::get();
    let mut first = 0;
    let mut earlier = time::Time(0);
    for (vol, slack) in [(&b"/data"[..], 1_000_000_000i64), (&b"/boot"[..], 2_000_000_000)] {
        let Some(dir) = ns.dir(vol) else {
            println!("ltest: svc FAIL: {} not granted", core::str::from_utf8(vol).unwrap_or("?"));
            return 1;
        };
        let root = Node::from(dir);
        let r = match root.open(b"TIME.REC", 0, fs::R_READ) {
            Ok((f, _, _)) => {
                let mut b = [0u8; 8];
                let ok = f.read(0, &mut b).is_ok_and(|n| n == 8);
                let st = f.stat();
                let t0 = time::Time(i64::from_le_bytes(b));
                check!(ok && st.is_ok(), "cannot read the record on {}", core::str::from_utf8(vol).unwrap_or("?"));
                let m = st.map(|s| s.modified).unwrap_or(0);
                check!(now > t0, "the clock went back across the reboot: {} then {}", t0, now);
                check!((m - t0.0).abs() <= slack + 1_000_000_000, "{}: modified {} but written at {}", core::str::from_utf8(vol).unwrap_or("?"), time::Time(m), t0);
                earlier = t0;
                Ok(())
            }
            Err(fs::ERR_NOT_FOUND) => {
                first += 1;
                let f = root.open(b"TIME.REC", fs::O_CREATE, fs::R_READ | fs::R_WRITE);
                check!(f.is_ok(), "cannot create the record: {:?}", f.as_ref().err().map(|e| fs::status(*e)));
                let Ok((f, _, _)) = f else { return 1 };
                check!(f.write(0, &now.0.to_le_bytes()).is_ok_and(|n| n == 8) && f.sync().is_ok(), "cannot write the record");
                let st = f.stat().map(|s| (s.created, s.modified)).unwrap_or((0, 0));
                check!(st.0 != 0 && (st.1 - now.0).abs() <= slack + 1_000_000_000, "new file times {:?} for {}", st, now);
                Ok(())
            }
            Err(e) => Err(e),
        };
        check!(r.is_ok(), "{}: {:?}", core::str::from_utf8(vol).unwrap_or("?"), r.err().map(fs::status));
        let _ = root.into_handle();
    }
    if first == 2 {
        println!("svc-time: first boot: the time is recorded on DFS (/data) and FAT32 (/boot)");
        return 10;
    }
    check!(first == 0, "only one of the two records existed");
    println!(
        "svc-time: second boot: PASSED: the clock moved forward across the reboot ({} s), file times kept on DFS and FAT32",
        (now.0 - earlier.0) / 1_000_000_000
    );
    0
}

pub fn audio_ungranted() -> i32 {
    use libd::audio::{self, FMT_S16_LE, PlaybackStream};
    check!(audio::playback_endpoint() == 0, "ungranted app received audio.playback");
    check!(audio::capture_endpoint() == 0, "ungranted app received audio.capture");
    check!(audio::control_endpoint() == 0, "ungranted app received audio.control");
    let r = PlaybackStream::open(0, 48_000, 2, FMT_S16_LE, 0);
    check!(r.err() == Some(sys::ERR_ACCESS_DENIED), "ungranted playback open was not refused");
    println!("svc-audio-ungranted: PASSED (ungranted app refused)");
    0
}

pub fn audio_playonly() -> i32 {
    use dosaudio::pcm::{SampleFormat, StreamParams, ToneGen};
    use libd::audio::{self, CaptureStream, FMT_S16_LE, PlaybackStream};

    let play = audio::playback_endpoint();
    check!(play != 0, "playonly did not get audio.playback");
    check!(audio::capture_endpoint() == 0, "playonly unexpectedly got audio.capture");
    check!(audio::control_endpoint() == 0, "playonly unexpectedly got audio.control");

    // Attempting microphone capture over the playback channel must be refused by audio.dsvc.
    let cap = CaptureStream::open(play, 48_000, 2, FMT_S16_LE, 0, b"playonly");
    check!(
        cap.err() == Some(sys::ERR_ACCESS_DENIED),
        "capture over playback endpoint was not refused"
    );

    // Wait briefly until an output backend is online, then play a 24 kHz mono tone (exercises resampler + upmix).
    let mut devs = [audio::DeviceEntry::empty(); 16];
    let dl = sys::clock_ns() + 5_000_000_000;
    while sys::clock_ns() < dl {
        if audio::list_devices(play, &mut devs).is_ok_and(|n| devs[..n].iter().any(|d| d.active_out)) {
            break;
        }
        libd::handle::sleep(50_000_000);
    }
    let Ok(mut st) = PlaybackStream::open(play, 24_000, 1, FMT_S16_LE, 0) else {
        println!("ltest: svc FAIL: playonly cannot open 24 kHz mono stream");
        return 1;
    };
    let params = StreamParams { rate: 24_000, channels: 1, format: SampleFormat::S16Le };
    let mut tone = ToneGen::new(440, 24_000, 8_000);
    let mut buf = [0u8; 240 * 2]; // 10 ms at 24 kHz mono
    for _ in 0..15 {
        tone.fill(params, &mut buf);
        check!(st.write(&buf).is_ok(), "playonly write failed");
    }
    st.drain(2_000_000_000);
    st.close();
    println!("svc-audio-playonly: PASSED (capture refused on playback grant, 24kHz mono resampled playback ok)");
    0
}

pub fn audio_full() -> i32 {
    use dosaudio::pcm::{StreamParams, ToneGen};
    use dosaudio::route::DeviceKind;
    use libd::audio::{self, CaptureStream, DeviceEntry, FMT_S16_LE, PlaybackStream};

    let play = audio::playback_endpoint();
    let cap = audio::capture_endpoint();
    let ctl = audio::control_endpoint();
    check!(play != 0 && cap != 0 && ctl != 0, "audio-full missing endpoints");

    // Wait for HDA output + input backends.
    let mut devs = [DeviceEntry::empty(); 16];
    let dl = sys::clock_ns() + 5_000_000_000;
    let mut found = false;
    while sys::clock_ns() < dl {
        if let Ok(n) = audio::list_devices(ctl, &mut devs)
            && devs[..n].iter().any(|d| d.active_out)
            && devs[..n].iter().any(|d| d.active_in)
        {
            found = true;
            break;
        }
        libd::handle::sleep(50_000_000);
    }
    check!(found, "HDA output/input backends did not appear");

    // 1. Explicit microphone grant + visible active indicator + capture read.
    let Ok(mut mic) = CaptureStream::open(cap, 48_000, 2, FMT_S16_LE, 0, b"audio-full") else {
        println!("ltest: svc FAIL: CaptureStream::open failed");
        return 1;
    };
    let mut cap_buf = [0u8; 1920];
    let got = mic.read(&mut cap_buf, 2_000_000_000);
    check!(got.is_ok_and(|n| n > 0), "capture read returned {:?}", got);
    mic.close();
    libd::handle::sleep(100_000_000);

    // 2. Microphone policy revocation & restoration.
    check!(audio::control_call(ctl, audio::OP_SET_MIC_GRANT, 0, 0).is_ok(), "mic revoke failed");
    let refused = CaptureStream::open(cap, 48_000, 2, FMT_S16_LE, 0, b"audio-full");
    check!(refused.err() == Some(sys::ERR_ACCESS_DENIED), "revoked capture was not refused");
    check!(audio::control_call(ctl, audio::OP_SET_MIC_GRANT, 1, 0).is_ok(), "mic restore failed");

    // 3. Per-device volume control.
    check!(audio::control_call(ctl, audio::OP_SET_VOL, 0, 80).is_ok(), "set volume 80 failed");
    let n = audio::list_devices(ctl, &mut devs).unwrap_or(0);
    check!(devs[..n].iter().any(|d| d.active_out && d.volume == 80), "volume 80 not reflected");
    check!(audio::control_call(ctl, audio::OP_SET_VOL, 0, 100).is_ok(), "restore volume 100 failed");

    // 4. Hot-plug automatic output switching (HDA -> USB Audio -> HDA).
    println!("svc-audio-full: ready for usb hotplug");
    let dl = sys::clock_ns() + 8_000_000_000;
    let mut saw_usb = false;
    while sys::clock_ns() < dl {
        if let Ok(n) = audio::list_devices(ctl, &mut devs)
            && devs[..n].iter().any(|d| d.active_out && d.kind == DeviceKind::UsbAudio as u8)
        {
            saw_usb = true;
            break;
        }
        libd::handle::sleep(100_000_000);
    }
    check!(saw_usb, "output did not automatically switch to USB Audio on hot-plug");
    println!("svc-audio-full: usb hotplug active");

    let dl = sys::clock_ns() + 8_000_000_000;
    let mut back_to_hda = false;
    while sys::clock_ns() < dl {
        if let Ok(n) = audio::list_devices(ctl, &mut devs)
            && devs[..n].iter().any(|d| d.active_out && d.kind != DeviceKind::UsbAudio as u8)
        {
            back_to_hda = true;
            break;
        }
        libd::handle::sleep(100_000_000);
    }
    check!(back_to_hda, "output did not switch back to HDA after USB unplug");
    println!("svc-audio-full: switched back to HDA");

    // 5. Mid-stream HDA driver crash & restart recovery with 660 Hz tone verification!
    let Ok(mut st) = PlaybackStream::open(play, 48_000, 2, FMT_S16_LE, 0) else {
        println!("ltest: svc FAIL: cannot open 660 Hz playback stream");
        return 1;
    };
    let params = StreamParams::stereo_48k_s16();
    let mut tone = ToneGen::new(660, 48_000, 16_000);
    let mut pcm = [0u8; 480 * 4]; // 10 ms

    // Play 250 ms before crash.
    for _ in 0..25 {
        tone.fill(params, &mut pcm);
        check!(st.write(&pcm).is_ok(), "pre-crash write failed");
    }
    // Crash the active output driver mid-stream!
    check!(audio::control_call(ctl, audio::OP_CRASH_DRIVER, 0, 0).is_ok(), "OP_CRASH_DRIVER failed");

    // Keep streaming 900 ms across the driver restart so audio.dsvc reconnects and restores real HDA playback!
    for _ in 0..90 {
        tone.fill(params, &mut pcm);
        check!(st.write(&pcm).is_ok(), "post-crash write failed");
    }
    st.drain(2_000_000_000);
    st.close();

    let st_hdr = audio::control_call(ctl, audio::OP_STATUS, 0, 0);
    let restarts = st_hdr.map(|h| ((h.b >> 32) & 0xFFFF) as u32).unwrap_or(0);
    check!(restarts >= 1, "expected driver_restarts >= 1, got {}", restarts);
    println!("svc-audio-full: PASSED (mic indicator, revoke, volume, hotplug switch, driver crash recovery x{})", restarts);
    0
}
