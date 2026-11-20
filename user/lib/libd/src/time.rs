//! Wall-clock time (docs/services.md, the clock service).
//!
//! D-OS time is a signed count of nanoseconds since **2000-01-01 00:00:00 UTC** (`Time`), UTC only
//! for now (no time zones, no leap seconds). 0 means "unknown" where a time is stored (files
//! written without a clock). It covers 1708 to 2292.
//!
//! The clock service (`clock.time` endpoint) answers `TIME_BASE` with a pair: a wall-clock time
//! and the monotonic time (`sys::clock_ns`) it corresponds to. A program asks once and adds the
//! monotonic time elapsed since: no call per reading.

use core::sync::atomic::{AtomicI64, AtomicU64, Ordering};

use crate::proto::{HEADER, Header};
use crate::sys::{self, Handle};

/// Nanoseconds since 2000-01-01 00:00:00 UTC.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct Time(pub i64);

/// A calendar date and time of day, UTC.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Civil {
    pub year: i32,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
    pub nanosecond: u32,
}

const NS: i64 = 1_000_000_000;
const DAY: i64 = 86_400;
/// Unix timestamp (seconds since 1970-01-01 00:00:00 UTC) of the D-OS epoch (2000-01-01 00:00:00 UTC).
pub const UNIX_EPOCH_OFFSET_SECS: i64 = 946_684_800;
/// Days from 0000-03-01 (the proleptic Gregorian civil-days origin used below) to 2000-01-01.
const EPOCH_DAYS: i64 = 730_425;

impl Time {
    /// Convert D-OS `Time` (ns since 2000-01-01 UTC) to Unix seconds (since 1970-01-01 UTC).
    pub const fn to_unix_secs(self) -> i64 {
        self.0.div_euclid(NS) + UNIX_EPOCH_OFFSET_SECS
    }
}

/// Days since 0000-03-01 for a date (any year; months 1-12).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe
}

fn civil_from_days(z: i64) -> (i64, u8, u8) {
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u8;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u8;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn days_in_month(y: i32, m: u8) -> u8 {
    match m {
        2 if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

impl Civil {
    /// Whether every field is in range (a real date).
    pub fn valid(&self) -> bool {
        (1..=12).contains(&self.month)
            && self.day >= 1
            && self.day <= days_in_month(self.year, self.month)
            && self.hour < 24
            && self.minute < 60
            && self.second < 60
            && self.nanosecond < NS as u32
    }
}

impl Time {
    pub const UNKNOWN: Time = Time(0);

    /// The time of a calendar date, if it is a real one inside the range.
    pub fn from_civil(c: &Civil) -> Option<Time> {
        if !c.valid() {
            return None;
        }
        let days = days_from_civil(i64::from(c.year), i64::from(c.month), i64::from(c.day)) - EPOCH_DAYS;
        let secs = days.checked_mul(DAY)? + i64::from(c.hour) * 3600 + i64::from(c.minute) * 60 + i64::from(c.second);
        secs.checked_mul(NS)?.checked_add(i64::from(c.nanosecond)).map(Time)
    }

    pub fn to_civil(self) -> Civil {
        let secs = self.0.div_euclid(NS);
        let ns = self.0.rem_euclid(NS) as u32;
        let days = secs.div_euclid(DAY);
        let s = secs.rem_euclid(DAY);
        let (y, m, d) = civil_from_days(days + EPOCH_DAYS);
        Civil { year: y as i32, month: m, day: d, hour: (s / 3600) as u8, minute: (s % 3600 / 60) as u8, second: (s % 60) as u8, nanosecond: ns }
    }

    pub fn add_ns(self, ns: i64) -> Time {
        Time(self.0.saturating_add(ns))
    }
}

impl core::fmt::Display for Time {
    /// `2026-11-18 14:03:07 UTC` (ISO 8601 date and time).
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let c = self.to_civil();
        write!(f, "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC", c.year, c.month, c.day, c.hour, c.minute, c.second)
    }
}

// ---- the clock service protocol -----------------------------------------------------------------

/// Client -> clock service (a call): the current base. Reply: `a` = the wall-clock time (`Time`, as
/// u64 bits), `b` = the monotonic time it corresponds to (`clock_ns`), `status` = the source
/// (`SOURCE_*`); payload: the source's name.
pub const TIME_BASE: u32 = 420;
pub const SOURCE_NONE: i32 = 0;
pub const SOURCE_RTC: i32 = 1;
pub const SOURCE_UEFI: i32 = 2;

/// A base from the clock service: wall-clock time `wall` was monotonic time `mono`.
#[derive(Clone, Copy, Debug)]
pub struct Base {
    pub wall: Time,
    pub mono: u64,
    pub source: i32,
}

impl Base {
    pub fn now(&self) -> Time {
        self.wall.add_ns(sys::clock_ns().wrapping_sub(self.mono) as i64)
    }
}

/// Ask the clock service over `ch` (a `clock.time` channel).
pub fn query(ch: Handle) -> Option<Base> {
    let mut req = [0u8; HEADER];
    Header { txid: 0, op: TIME_BASE, status: 0, a: 0, b: 0 }.put(&mut req);
    let mut rep = [0u8; HEADER + 32];
    let n = sys::channel_call(ch, &req, &mut rep, 5 * 1_000_000_000).ok()? as usize;
    let h = Header::get(&rep[..n])?;
    (h.op == TIME_BASE && h.status != SOURCE_NONE).then_some(Base { wall: Time(h.a as i64), mono: h.b, source: h.status })
}

static WALL: AtomicI64 = AtomicI64::new(0);
static MONO: AtomicU64 = AtomicU64::new(0);

/// Remember a base for `now` (from `query`).
pub fn set_base(b: &Base) {
    MONO.store(b.mono, Ordering::Relaxed);
    WALL.store(b.wall.0, Ordering::Release);
}

/// The current wall-clock time, or `Time::UNKNOWN` until a base was set.
pub fn now() -> Time {
    let w = WALL.load(Ordering::Acquire);
    if w == 0 {
        return Time::UNKNOWN;
    }
    Base { wall: Time(w), mono: MONO.load(Ordering::Relaxed), source: 0 }.now()
}

