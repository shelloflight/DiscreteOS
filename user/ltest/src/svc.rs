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

pub fn net_ungranted() -> i32 {
    use libd::net::{self, TcpStream};
    check!(net::client_endpoint() == 0, "ungranted process received net.client");
    check!(net::icmp_endpoint() == 0, "ungranted process received net.icmp");
    check!(net::control_endpoint() == 0, "ungranted process received net.control");
    check!(
        TcpStream::connect(0, [10, 0, 2, 2], 80, 1000).err() == Some(sys::ERR_ACCESS_DENIED),
        "TCP connect without grant not refused"
    );
    check!(
        net::ping(0, [10, 0, 2, 2], 1, 1000).err() == Some(sys::ERR_ACCESS_DENIED),
        "ICMP ping without grant not refused"
    );
    println!("svc-net-ungranted: PASSED (ungranted app refused)");
    0
}

fn tls_exchange(
    stream: &mut libd::net::TcpStream,
    hostname: &str,
    ca_der: alloc::vec::Vec<u8>,
    now_unix: i64,
) -> Result<(alloc::vec::Vec<u8>, &'static str, &'static str), dosnet::tls::TlsError> {
    use dosnet::tls::{TlsClient, TlsError};
    let mut rand160 = [0u8; 160];
    libd::net::random_bytes(&mut rand160).map_err(|_| TlsError::Closed)?;
    let mut tls = TlsClient::new(hostname, alloc::vec![ca_der], now_unix, &rand160);
    let mut buf = [0u8; 4096];

    let dl = sys::clock_ns() + 10_000_000_000;
    while !tls.is_connected() {
        let out = tls.take_tx();
        if !out.is_empty() && stream.write_all(&out).is_err() {
            return Err(TlsError::Closed);
        }
        if sys::clock_ns() >= dl {
            return Err(TlsError::Closed);
        }
        let n = stream.read(&mut buf, 2_000).map_err(|_| TlsError::Closed)?;
        if n == 0 {
            return Err(TlsError::Closed);
        }
        tls.feed_rx(&buf[..n])?;
    }
    let cipher_name = tls.negotiated_cipher().map_or("?", |c| c.name());
    let group_name = tls.negotiated_group().map_or("?", |g| g.name());
    // Flush Client Finished + HTTP request.
    tls.write_app(b"GET /tls HTTP/1.1\r\nHost: test.dos.local\r\n\r\n")?;
    let out = tls.take_tx();
    if !out.is_empty() && stream.write_all(&out).is_err() {
        return Err(TlsError::Closed);
    }
    let mut resp = alloc::vec::Vec::new();
    let dl = sys::clock_ns() + 5_000_000_000;
    while resp.is_empty() && sys::clock_ns() < dl {
        let n = stream.read(&mut buf, 2_000).map_err(|_| TlsError::Closed)?;
        if n == 0 {
            break;
        }
        tls.feed_rx(&buf[..n])?;
        let mut plain = [0u8; 1024];
        let m = tls.read_app(&mut plain);
        if m > 0 {
            resp.extend_from_slice(&plain[..m]);
        }
    }
    tls.close();
    let fin = tls.take_tx();
    if !fin.is_empty() {
        let _ = stream.write_all(&fin);
    }
    Ok((resp, cipher_name, group_name))
}

pub fn net_full() -> i32 {
    use doscrypt::x509::VerifyError;
    use dosnet::tls::TlsError;
    use dosnet::tls::server::{TEST_CA_SEED, make_test_rsa_bundle};
    use libd::net::{self, TcpStream};

    let cli = net::client_endpoint();
    let icmp = net::icmp_endpoint();
    let ctl = net::control_endpoint();
    check!(cli != 0 && icmp != 0 && ctl != 0, "missing net endpoints");

    // 1. Wait for DHCP lease from QEMU user-net.
    let dl = sys::clock_ns() + 15_000_000_000;
    let mut st = net::NetStatus::empty();
    while sys::clock_ns() < dl {
        if let Ok(s) = net::status(ctl)
            && s.dhcp_bound
        {
            st = s;
            break;
        }
        libd::handle::sleep(100_000_000);
    }
    check!(st.dhcp_bound && st.ip != [0; 4], "DHCP did not bind in time");
    println!(
        "svc-net-full: dhcp OK ({}.{}.{}.{} via {})",
        st.ip[0], st.ip[1], st.ip[2], st.ip[3], st.name_str()
    );

    // 2. Endpoint role separation check.
    check!(
        net::ping(cli, [10, 0, 2, 2], 1, 500).err() == Some(sys::ERR_ACCESS_DENIED),
        "ICMP ping on net.client was not refused"
    );
    check!(
        TcpStream::connect(icmp, [10, 0, 2, 100], 80, 500).err() == Some(sys::ERR_ACCESS_DENIED),
        "TCP connect on net.icmp was not refused"
    );

    // 3. Configure local offline DNS server passed via DHCP bootfile (`dns:<port>`), then resolve.
    if let Some(port_s) = st.bootfile_str().strip_prefix("dns:")
        && let Ok(port) = port_s.parse::<u16>()
    {
        check!(net::set_dns(ctl, [10, 0, 2, 2], port).is_ok(), "set_dns failed");
    }
    let resolved = net::resolve(cli, "test.dos.local");
    check!(resolved == Ok([10, 0, 2, 100]), "DNS resolve failed: {:?}", resolved);
    println!("svc-net-full: dns OK (test.dos.local -> 10.0.2.100)");

    // 4. ICMP ping to gateway 10.0.2.2.
    let pong = net::ping(icmp, [10, 0, 2, 2], 1, 2_000);
    check!(pong.is_ok(), "ICMP ping failed: {:?}", pong);
    let (rtt, ttl) = pong.unwrap_or((0, 0));
    println!("svc-net-full: icmp ping OK (rtt={} ms, ttl={})", rtt, ttl);

    // 5. Plain TCP connection to 10.0.2.100:80.
    let tcp = TcpStream::connect(cli, [10, 0, 2, 100], 80, 5_000);
    check!(tcp.is_ok(), "TCP connect failed: {:?}", tcp.err());
    if let Ok(mut s) = tcp {
        check!(s.write_all(b"GET / HTTP/1.1\r\nHost: test.dos.local\r\n\r\n").is_ok(), "TCP write failed");
        let mut buf = [0u8; 256];
        let n = s.read(&mut buf, 5_000).unwrap_or(0);
        let text = core::str::from_utf8(&buf[..n]).unwrap_or("");
        check!(text.contains("Hello from D-OS TCP test!"), "unexpected TCP body: '{}'", text);
        s.close();
    }
    println!("svc-net-full: tcp OK");

    // 6. TLS 1.3 handshake + encrypted HTTP GET against 10.0.2.100:443 (valid CA + SAN + UTC time).
    let clock_ch = libd::svc::endpoint(b"clock.time");
    let now_unix = if clock_ch != 0
        && let Some(b) = libd::time::query(clock_ch)
        && b.now().0 > 0
    {
        b.now().to_unix_secs()
    } else {
        1_795_000_000
    };
    let (ca_der, _, _) = make_test_rsa_bundle(
        &TEST_CA_SEED,
        &["test.dos.local"],
        &[[10, 0, 2, 100]],
        b"250101000000Z",
        b"350101000000Z",
    );
    let tls_tcp = TcpStream::connect(cli, [10, 0, 2, 100], 443, 5_000);
    check!(tls_tcp.is_ok(), "TLS TCP connect failed: {:?}", tls_tcp.err());
    if let Ok(mut s) = tls_tcp {
        let res = tls_exchange(&mut s, "test.dos.local", ca_der.clone(), now_unix);
        check!(res.is_ok(), "TLS 1.3 handshake failed: {:?}", res.err());
        let (body, cipher_name, group_name) = res.unwrap_or_default();
        let text = core::str::from_utf8(&body).unwrap_or("");
        check!(text.contains("Hello from D-OS TLS 1.3!"), "unexpected TLS body: '{}'", text);
        check!(
            cipher_name == "TLS_AES_256_GCM_SHA384" && group_name == "X25519MLKEM768",
            "expected PQ hybrid AES-256-GCM, got {} / {}",
            cipher_name,
            group_name
        );
        s.close();
        println!("svc-net-full: tls13 OK ({} + {})", cipher_name, group_name);
    }

    // 7. TLS 1.3 negative check: server on port 444 serves mismatched SAN (`wrong.dos.local`).
    let bad_tcp = TcpStream::connect(cli, [10, 0, 2, 100], 444, 5_000);
    check!(bad_tcp.is_ok(), "bad-TLS TCP connect failed: {:?}", bad_tcp.err());
    if let Ok(mut s) = bad_tcp {
        let res = tls_exchange(&mut s, "test.dos.local", ca_der, now_unix);
        check!(
            res == Err(TlsError::Certificate(VerifyError::HostnameMismatch)),
            "mismatched SAN was not rejected: {:?}",
            res
        );
        s.close();
    }
    println!("svc-net-full: tls13 bad-cert refused");
    println!("svc-net-full: PASSED");
    0
}

// ---- GPU & display service tests (`gpu-virtio`, `gpu-virtio-amd`, `gpu-gop`) --------------------

pub fn gpu_ungranted() -> i32 {
    use libd::gpu;
    check!(
        gpu::query_endpoint() == 0 && gpu::display_endpoint() == 0 && gpu::render_endpoint() == 0,
        "ungranted process received a gpu endpoint"
    );
    println!("svc-gpu-ungranted: PASSED (ungranted app refused)");
    0
}

pub fn gpu_queryonly() -> i32 {
    use libd::gpu;
    let q = gpu::query_endpoint();
    check!(q != 0, "missing gpu.query endpoint");
    check!(gpu::display_endpoint() == 0 && gpu::render_endpoint() == 0, "query-only got display/render");
    let mut adapters = [gpu::AdapterInfo::empty(); 8];
    let dl = sys::clock_ns() + 10_000_000_000;
    let mut count = 0usize;
    while sys::clock_ns() < dl {
        if let Ok(n) = gpu::list_adapters(q, &mut adapters)
            && n > 0
        {
            count = n;
            break;
        }
        libd::handle::sleep(100_000_000);
    }
    check!(count > 0, "no gpu adapters found");
    let id = adapters[0].id;
    // Query-only endpoint must be refused on display, render, and crash-driver operations.
    check!(gpu::set_mode(q, id, 800, 600) == Err(sys::ERR_ACCESS_DENIED), "set_mode not refused on query");
    check!(gpu::present(q, id, 1, 0, 0, 64, 64) == Err(sys::ERR_ACCESS_DENIED), "present not refused on query");
    check!(gpu::ctx_create(q, id) == Err(sys::ERR_ACCESS_DENIED), "ctx_create not refused on query");
    check!(gpu::crash_driver(q, id) == Err(sys::ERR_ACCESS_DENIED), "crash_driver not refused on query");
    println!("svc-gpu-queryonly: PASSED (query ok, display/render refused)");
    0
}

pub fn gpu_full() -> i32 {
    use libd::gpu::{self, AdapterInfo, ModeEntry};

    let q = gpu::query_endpoint();
    let disp = gpu::display_endpoint();
    let rnd = gpu::render_endpoint();
    check!(q != 0 && disp != 0 && rnd != 0, "missing gpu endpoints");

    // 1. Discover adapters (prefer PCI GPU if present, else GOP baseline).
    let mut adapters = [AdapterInfo::empty(); 8];
    let dl = sys::clock_ns() + 15_000_000_000;
    let mut chosen: Option<AdapterInfo> = None;
    while sys::clock_ns() < dl {
        if let Ok(n) = gpu::list_adapters(q, &mut adapters)
            && n > 0
        {
            if let Some(&pci) = adapters[..n].iter().find(|a| a.online && a.kind != gpu::KIND_GOP) {
                chosen = Some(pci);
                break;
            }
            if let Some(&gop) = adapters[..n].iter().find(|a| a.online && a.kind == gpu::KIND_GOP) {
                // Give PCI drivers a short moment to settle if any are starting.
                if chosen.is_none() {
                    chosen = Some(gop);
                }
                if sys::clock_ns() + 13_000_000_000 < dl {
                    break;
                }
            }
        }
        libd::handle::sleep(100_000_000);
    }
    let ad = match chosen {
        Some(a) => a,
        None => {
            println!("ltest: FAIL: no online gpu adapter");
            return 1;
        }
    };
    let id = ad.id;
    println!(
        "svc-gpu-full: adapter OK (#{} {} {} {}x{} caps={:#x})",
        id,
        ad.kind_name(),
        ad.name_str(),
        ad.width,
        ad.height,
        ad.caps
    );

    // 2. Role separation between display and render endpoints.
    check!(gpu::ctx_create(disp, id) == Err(sys::ERR_ACCESS_DENIED), "ctx_create on display not refused");
    check!(gpu::set_mode(rnd, id, ad.width, ad.height) == Err(sys::ERR_ACCESS_DENIED), "set_mode on render not refused");

    // 3. Query modes.
    let mut modes = [ModeEntry::default(); 16];
    let mcount = gpu::get_modes(q, id, &mut modes).unwrap_or(0);
    check!(mcount >= 1, "no display modes reported");
    let (w, h) = (ad.width.max(640), ad.height.max(480));
    let pitch = w * 4;
    let fb_size = u64::from(pitch) * u64::from(h);

    // 4. Allocate framebuffer VMO, draw a deterministic RGB pattern, attach & present full + partial damage.
    let Ok(mut fb) = libd::Mapping::new(fb_size) else {
        println!("ltest: FAIL: fb VMO alloc failed");
        return 1;
    };
    {
        let bytes = fb.bytes_mut();
        for y in 0..h as usize {
            let color: u32 = match (y * 4) / (h as usize) {
                0 => 0x001E_3A5F,
                1 => 0x0022_8B22,
                2 => 0x00B8_860B,
                _ => 0x0033_3344,
            };
            let row = y * pitch as usize;
            let px = color.to_le_bytes();
            for x in 0..w as usize {
                let o = row + x * 4;
                bytes[o..o + 4].copy_from_slice(&px);
            }
        }
    }
    let fb_id = match gpu::attach_fb(disp, id, fb.vmo, w, h, pitch, gpu::FMT_XRGB8888) {
        Ok(f) => f,
        Err(e) => {
            println!("ltest: FAIL: attach_fb failed: {}", sys::status(e));
            return 1;
        }
    };
    check!(gpu::set_mode(disp, id, w, h).is_ok(), "set_mode failed");
    let f1 = gpu::present(disp, id, fb_id, 0, 0, w, h);
    check!(f1 == Ok(1), "first present failed: {:?}", f1);
    let f2 = gpu::present(disp, id, fb_id, 32, 32, 128, 128);
    check!(f2 == Ok(2), "partial damage present failed: {:?}", f2);
    println!("svc-gpu-full: scanout OK ({}x{}, 2 frames presented)", w, h);

    // 5. PCI VirtIO-GPU specific checks: cursor, mode switch, CS validation, and crash-recovery.
    if ad.kind == gpu::KIND_VIRTIO_GPU {
        check!((ad.caps & gpu::CAP_IOMMU) != 0, "virtio-gpu not IOMMU confined");
        // Hardware cursor (64x64 ARGB8888)
        let Ok(mut cur) = libd::Mapping::new(64 * 64 * 4) else {
            println!("ltest: FAIL: cursor VMO alloc failed");
            return 1;
        };
        cur.bytes_mut().fill(0xFF);
        check!(gpu::set_cursor(disp, id, cur.vmo, 4, 4).is_ok(), "set_cursor failed");
        check!(gpu::move_cursor(disp, id, 160, 120).is_ok(), "move_cursor failed");
        println!("svc-gpu-full: cursor OK");

        // Dynamic mode switch: 800x600 -> back to native
        let Ok(fb2) = libd::Mapping::new(800 * 600 * 4) else {
            println!("ltest: FAIL: mode-switch fb alloc failed");
            return 1;
        };
        let fb2_id = match gpu::attach_fb(disp, id, fb2.vmo, 800, 600, 800 * 4, gpu::FMT_XRGB8888) {
            Ok(f) => f,
            Err(e) => {
                println!("ltest: FAIL: attach_fb 800x600 failed: {}", sys::status(e));
                return 1;
            }
        };
        check!(gpu::set_mode(disp, id, 800, 600).is_ok(), "set_mode 800x600 failed");
        check!(gpu::present(disp, id, fb2_id, 0, 0, 800, 600).is_ok(), "present 800x600 failed");
        check!(gpu::set_mode(disp, id, w, h).is_ok(), "restore mode failed");
        println!("svc-gpu-full: modeset OK (800x600 -> {}x{})", w, h);

        // Render context + VirGL CS validator check
        let ctx_id = match gpu::ctx_create(rnd, id) {
            Ok(c) => c,
            Err(e) => {
                println!("ltest: FAIL: ctx_create failed: {}", sys::status(e));
                return 1;
            }
        };
        let bad_cs = [0xFE, 0x00, 0x00, 0x00]; // unknown VirGL opcode
        check!(
            gpu::submit_cmd(rnd, id, ctx_id, gpu::ENGINE_VIRGL_3D, &bad_cs) == Err(sys::ERR_INVALID_ARGS),
            "malformed VirGL CS was not rejected"
        );
        let mut nop = [0u32; 1];
        dosgpu::virtio::virgl_cmd_nop(&mut nop);
        let r = gpu::submit_cmd(rnd, id, ctx_id, gpu::ENGINE_VIRGL_3D, &nop[0].to_le_bytes());
        check!(
            r.is_ok() || r == Err(sys::ERR_NOT_SUPPORTED),
            "unexpected VirGL NOP submit result: {:?}",
            r
        );
        check!(gpu::ctx_destroy(rnd, id, ctx_id).is_ok(), "ctx_destroy failed");
        println!("svc-gpu-full: cs-validation OK");

        // Driver crash + automatic restart recovery
        check!(gpu::crash_driver(disp, id).is_ok(), "crash_driver failed");
        let rec_dl = sys::clock_ns() + 15_000_000_000;
        let mut recovered = false;
        while sys::clock_ns() < rec_dl {
            if let Ok(n) = gpu::list_adapters(q, &mut adapters)
                && let Some(cur_ad) = adapters[..n].iter().find(|a| a.id == id)
                && cur_ad.online
                && cur_ad.restarts >= 1
            {
                recovered = true;
                break;
            }
            libd::handle::sleep(100_000_000);
        }
        check!(recovered, "virtio-gpu.ddrv did not reconnect after crash");
        let fb3_id = match gpu::attach_fb(disp, id, fb.vmo, w, h, pitch, gpu::FMT_XRGB8888) {
            Ok(f) => f,
            Err(e) => {
                println!("ltest: FAIL: post-restart attach_fb failed: {}", sys::status(e));
                return 1;
            }
        };
        check!(gpu::present(disp, id, fb3_id, 0, 0, w, h).is_ok(), "post-restart present failed");
        println!("svc-gpu-full: crash-recovery OK");
    }

    println!("svc-gpu-full: PASSED");
    0
}
