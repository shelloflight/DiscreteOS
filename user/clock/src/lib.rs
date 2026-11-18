//! The clock service (`clock.dx`, docs/services.md): wall-clock time, UTC.
//!
//! - Source, in order: the boot-time record (UEFI: what the firmware's GetTime said while the
//!   loader ran, and the monotonic time it corresponds to; manifest grant `boot-time`), else the
//!   CMOS real-time clock (the `rtc` platform device: ports 0x70-0x71; manifest grant
//!   `devices = ["platform:rtc"]`). Read once at start: from then on the time is that reading plus
//!   the monotonic clock (no drift correction yet).
//! - Serves `time::TIME_BASE` on every `clock.time` channel the manager hands it: (wall-clock time,
//!   the monotonic time it was): a client adds the monotonic time elapsed since, without a call
//!   per reading.
//! - Without either source, it answers `SOURCE_NONE` and clients keep "unknown" (0) times.

#![no_std]

extern crate alloc;

use alloc::vec::Vec;

use libd::proto::{self, HEADER, Header};
use libd::sys::{self, BootTime, Handle};
use libd::time::{self, Civil, Time};
use libd::{Port, Startup, println, svc};

libd::entry!(_start, main);

const KEY_CTL: u64 = 1;
const KEY_CLIENT: u64 = 0x100;
const MAX_CLIENTS: usize = 64;

/// The UEFI boot-time record, as a base (wall-clock time at monotonic time 0).
fn from_boot_record() -> Option<(Time, &'static str)> {
    let v = libd::startup_handle(sys::TAG_BOOT_TIME);
    if v == 0 {
        return None;
    }
    let mut b = [0u8; 32];
    if sys::vmo_read(v, 0, &mut b) != 0 {
        return None;
    }
    let u16_at = |o: usize| u16::from_le_bytes([b[o], b[o + 1]]);
    let r = BootTime {
        magic: u32::from_le_bytes(b[0..4].try_into().ok()?),
        source: u32::from_le_bytes(b[4..8].try_into().ok()?),
        year: u16_at(8),
        month: b[10],
        day: b[11],
        hour: b[12],
        minute: b[13],
        second: b[14],
        pad: 0,
        nanosecond: u32::from_le_bytes(b[16..20].try_into().ok()?),
        time_zone: i16::from_le_bytes([b[20], b[21]]),
        pad2: 0,
        mono_ns: i64::from_le_bytes(b[24..32].try_into().ok()?),
    };
    if r.magic != sys::BOOT_TIME_MAGIC || r.source != 1 {
        return None;
    }
    let c = Civil { year: i32::from(r.year), month: r.month, day: r.day, hour: r.hour, minute: r.minute, second: r.second, nanosecond: r.nanosecond };
    let local = Time::from_civil(&c)?;
    // UEFI: local time = UTC - time_zone (minutes); 2047 = unspecified, taken as UTC.
    let utc = if r.time_zone == 2047 { local } else { local.add_ns(i64::from(r.time_zone) * 60 * 1_000_000_000) };
    Some((utc.add_ns(-r.mono_ns), "UEFI GetTime at boot"))
}

/// The CMOS RTC: (wall-clock time, monotonic time of the reading).
fn from_rtc() -> Option<(Time, u64)> {
    let dev = libd::startup_handles().filter(|&(_, t)| t == sys::TAG_DEVICE).map(|(h, _)| h).find(|&h| sys::device_info(h).is_ok_and(|i| i.name() == "rtc"))?;
    let reg = |r: u8| -> Option<u8> {
        sys::io_write(dev, 0, 0, 1, u64::from(r)).ok()?;
        sys::io_read(dev, 0, 1, 1).ok().map(|v| v as u8)
    };
    let read_all = || -> Option<[u8; 7]> {
        // Wait while an update is in progress (status A bit 7; at most ~2 ms each second).
        let deadline = sys::clock_ns() + 20_000_000;
        while reg(0x0A)? & 0x80 != 0 {
            if sys::clock_ns() > deadline {
                return None;
            }
        }
        Some([reg(0x00)?, reg(0x02)?, reg(0x04)?, reg(0x07)?, reg(0x08)?, reg(0x09)?, reg(0x32)?])
    };
    // Two identical readings in a row: not torn by an update between registers.
    let mut prev = read_all()?;
    let mut now;
    let mut tries = 0;
    loop {
        let mono = sys::clock_ns();
        now = read_all()?;
        if now == prev {
            let status_b = reg(0x0B)?;
            return decode(now, status_b).map(|t| (t, mono));
        }
        prev = now;
        tries += 1;
        if tries > 5 {
            return None;
        }
    }
}

/// Registers (second, minute, hour, day, month, year, century) with status register B.
fn decode(r: [u8; 7], status_b: u8) -> Option<Time> {
    let binary = status_b & 0x04 != 0;
    let h24 = status_b & 0x02 != 0;
    let bcd = |v: u8| if binary { v } else { (v & 0x0F) + (v >> 4) * 10 };
    let pm = r[2] & 0x80 != 0;
    let mut hour = bcd(r[2] & 0x7F);
    if !h24 {
        hour %= 12;
        if pm {
            hour += 12;
        }
    }
    let century = bcd(r[6]);
    let year = if (19..=23).contains(&century) { i32::from(century) * 100 } else { 2000 } + i32::from(bcd(r[5]));
    let c = Civil { year, month: bcd(r[4]), day: bcd(r[3]), hour, minute: bcd(r[1]), second: bcd(r[0]), nanosecond: 0 };
    Time::from_civil(&c)
}

fn main(s: *const Startup) -> i32 {
    // SAFETY: `s` is the startup block pointer the kernel passed to the entry point.
    if !unsafe { libd::init(s, "clock") } {
        return 1;
    }
    // The base: wall-clock time `wall` at monotonic time `mono`.
    let (wall, mono, source, what) = match from_boot_record() {
        Some((w, what)) => (w, 0u64, time::SOURCE_UEFI, what),
        None => match from_rtc() {
            Some((w, m)) => (w, m, time::SOURCE_RTC, "the CMOS real-time clock"),
            None => (Time::UNKNOWN, 0, time::SOURCE_NONE, "none"),
        },
    };
    let base = time::Base { wall, mono, source };
    if source == time::SOURCE_NONE {
        println!("clock: no wall-clock source (no UEFI boot time, no CMOS RTC): times stay unknown");
    } else {
        println!("clock: {} (from {})", base.now(), what);
    }
    let ctl = libd::startup_handle(proto::TAG_CONTROL);
    let Ok(port) = Port::new(128) else { return 1 };
    if ctl != 0 {
        port.arm(ctl, sys::READABLE | sys::PEER_CLOSED, KEY_CTL);
    }
    let mut clients: Vec<Option<Handle>> = Vec::new();
    loop {
        let Some((key, _)) = port.wait(sys::WAIT_FOREVER) else { continue };
        if key == KEY_CTL {
            let mut buf = [0u8; HEADER + 64];
            loop {
                let mut hs = [0 as Handle; 1];
                match sys::channel_read_h(ctl, &mut buf, &mut hs, 0) {
                    Ok((n, nh)) => {
                        let handle = if nh > 0 { hs[0] } else { 0 };
                        match Header::get(&buf[..n]) {
                            Some(h) if h.op == svc::CONNECT && &buf[HEADER..n] == b"time" && handle != 0 => {
                                let slot = clients.iter().position(|c| c.is_none()).or_else(|| {
                                    (clients.len() < MAX_CLIENTS).then(|| {
                                        clients.push(None);
                                        clients.len() - 1
                                    })
                                });
                                match slot {
                                    Some(i) => {
                                        clients[i] = Some(handle);
                                        port.arm(handle, sys::READABLE | sys::PEER_CLOSED, KEY_CLIENT + i as u64);
                                    }
                                    None => {
                                        sys::handle_close(handle);
                                    }
                                }
                            }
                            Some(h) if h.op == svc::SHUTDOWN => {
                                println!("clock: shutdown");
                                return 0;
                            }
                            _ => {
                                if handle != 0 {
                                    sys::handle_close(handle);
                                }
                            }
                        }
                    }
                    Err(sys::ERR_SHOULD_WAIT) => {
                        port.arm(ctl, sys::READABLE | sys::PEER_CLOSED, KEY_CTL);
                        break;
                    }
                    Err(_) => break,
                }
            }
            continue;
        }
        let i = (key - KEY_CLIENT) as usize;
        let Some(Some(ch)) = clients.get(i).copied() else { continue };
        let mut buf = [0u8; HEADER + 16];
        loop {
            match sys::channel_read(ch, &mut buf, 0) {
                Ok(n) => {
                    if let Some(h) = Header::get(&buf[..n as usize])
                        && h.op == time::TIME_BASE
                    {
                        let mut rep = [0u8; HEADER];
                        Header { txid: h.txid, op: time::TIME_BASE, status: source, a: base.wall.0 as u64, b: base.mono }.put(&mut rep);
                        sys::channel_write(ch, &rep);
                    }
                }
                Err(sys::ERR_SHOULD_WAIT) => {
                    port.arm(ch, sys::READABLE | sys::PEER_CLOSED, key);
                    break;
                }
                Err(_) => {
                    sys::handle_close(ch);
                    clients[i] = None;
                    break;
                }
            }
        }
    }
}
