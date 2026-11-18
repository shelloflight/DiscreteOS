//! D-OS time (nanoseconds since 2000-01-01 00:00:00 UTC; 0 = unknown) and the FAT date/time
//! fields. The same calendar arithmetic as libd's `time` module (this crate has no dependencies);
//! the host tests check it.

const NS: i64 = 1_000_000_000;
const DAY: i64 = 86_400;
/// Days from 0000-03-01 to 2000-01-01.
const EPOCH_DAYS: i64 = 730_425;

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// (year, month, day, hour, minute, second) of a D-OS time.
pub fn to_civil(t: i64) -> (i64, u32, u32, u32, u32, u32) {
    let secs = t.div_euclid(NS);
    let days = secs.div_euclid(DAY);
    let s = secs.rem_euclid(DAY);
    let (y, m, d) = civil_from_days(days + EPOCH_DAYS);
    (y, m, d, (s / 3600) as u32, (s % 3600 / 60) as u32, (s % 60) as u32)
}

/// The D-OS time of a date (fields assumed valid).
pub fn from_civil(y: i64, m: u32, d: u32, hh: u32, mm: u32, ss: u32) -> i64 {
    let days = days_from_civil(y, i64::from(m), i64::from(d)) - EPOCH_DAYS;
    (days * DAY + i64::from(hh) * 3600 + i64::from(mm) * 60 + i64::from(ss)) * NS
}

/// FAT (date, time) fields of a D-OS time: years 1980-2107, 2-second steps, UTC. `None` for an
/// unknown time or one FAT cannot hold.
pub fn to_fat(t: i64) -> Option<(u16, u16)> {
    if t == 0 {
        return None;
    }
    let (y, mo, d, h, mi, s) = to_civil(t);
    if !(1980..=2107).contains(&y) {
        return None;
    }
    let date = (((y - 1980) as u16) << 9) | ((mo as u16) << 5) | d as u16;
    let time = ((h as u16) << 11) | ((mi as u16) << 5) | (s / 2) as u16;
    Some((date, time))
}

/// The D-OS time of FAT (date, time) fields; 0 if they do not hold a real date.
pub fn from_fat(date: u16, time: u16) -> i64 {
    let y = 1980 + i64::from(date >> 9);
    let (mo, d) = (u32::from((date >> 5) & 0xF), u32::from(date & 0x1F));
    let (h, mi, s) = (u32::from(time >> 11), u32::from((time >> 5) & 0x3F), u32::from(time & 0x1F) * 2);
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let dim = match mo {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    if !(1..=12).contains(&mo) || d == 0 || d > dim || h > 23 || mi > 59 || s > 59 {
        return 0;
    }
    from_civil(y, mo, d, h, mi, s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calendar() {
        assert_eq!(from_civil(2000, 1, 1, 0, 0, 0), 0);
        let t = from_civil(2026, 11, 18, 14, 3, 7);
        assert_eq!(t / (NS * DAY), 9818);
        assert_eq!(to_civil(t), (2026, 11, 18, 14, 3, 7));
        assert_eq!(to_civil(-NS), (1999, 12, 31, 23, 59, 59));
        assert_eq!(to_civil(from_civil(2024, 2, 29, 0, 0, 0)), (2024, 2, 29, 0, 0, 0));
        // Every day from 1727 to 2273 (the range of the 64-bit count) round-trips.
        for day in -100_000..100_000i64 {
            let t = day * DAY * NS;
            let (y, m, d, ..) = to_civil(t);
            assert_eq!(from_civil(y, m, d, 0, 0, 0), t);
        }
    }

    #[test]
    fn fat_fields() {
        let t = from_civil(2026, 11, 18, 14, 3, 7);
        let (d, tm) = to_fat(t).unwrap();
        assert_eq!(d, ((2026 - 1980) << 9) | (11 << 5) | 18);
        assert_eq!(from_fat(d, tm), from_civil(2026, 11, 18, 14, 3, 6)); // 2-second steps
        assert_eq!(to_fat(0), None);
        assert_eq!(to_fat(from_civil(1979, 12, 31, 0, 0, 0)), None);
        assert_eq!(from_fat(0, 0), 0); // month 0: not a date
        assert_eq!(from_fat((46 << 9) | (2 << 5) | 30, 0), 0); // 30 February
    }
}
