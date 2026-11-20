//! How records look at the end of a pipeline: values in words (sizes in KiB/MiB, times as
//! `2026-11-18 09:14` UTC), tables with a header, results of the file tools as `✓` lines.
//! Also the other direction for `where`: a typed word (`1M`, `2026-11-18`) as a value.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use libd::rec::{Record, Value};
use libd::term;
use libd::time::{Civil, Time};

/// Style markers for the terminal.
pub fn style(attr: u8) -> String {
    let mut s = String::new();
    s.push(term::STYLE as char);
    s.push(attr as char);
    s
}
pub fn plain() -> String {
    String::from(term::PLAIN as char)
}
pub fn coloured(attr: u8, text: &str) -> String {
    format!("{}{}{}", style(attr), text, plain())
}

pub fn ok_line(text: &str) -> String {
    format!("{} {}\n", coloured(term::LIGHT_GREEN, "✓"), text)
}
pub fn err_line(text: &str) -> String {
    format!("{} {}\n", coloured(term::LIGHT_RED, "✗"), text)
}

pub fn size(b: u64) -> String {
    const U: [&str; 4] = ["KiB", "MiB", "GiB", "TiB"];
    if b < 1024 {
        return format!("{} B", b);
    }
    let mut v = b as f64 / 1024.0;
    let mut u = 0;
    while v >= 1024.0 && u + 1 < U.len() {
        v /= 1024.0;
        u += 1;
    }
    if v < 10.0 { format!("{:.1} {}", v, U[u]) } else { format!("{} {}", v as u64, U[u]) }
}

pub fn time(t: i64) -> String {
    if t == 0 {
        return String::from("—");
    }
    let c = Time(t).to_civil();
    format!("{:04}-{:02}-{:02} {:02}:{:02}", c.year, c.month, c.day, c.hour, c.minute)
}

pub fn time_seconds(t: i64) -> String {
    if t == 0 {
        return String::from("unknown");
    }
    let c = Time(t).to_civil();
    format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC", c.year, c.month, c.day, c.hour, c.minute, c.second)
}

pub fn value(v: &Value) -> String {
    match v {
        Value::Text(s) | Value::Path(s) => s.clone(),
        Value::Int(i) => i.to_string(),
        Value::Size(b) => size(*b),
        Value::Time(t) => time(*t),
        Value::Bool(b) => String::from(if *b { "yes" } else { "no" }),
    }
}

fn right_aligned(v: &Value) -> bool {
    matches!(v, Value::Int(_) | Value::Size(_))
}

/// A size typed by a person: `512`, `4K`, `1.5M`, `2G` (powers of 1024, like the display).
pub fn parse_size(s: &str) -> Option<u64> {
    let s = s.trim().trim_end_matches(['B', 'b']).trim_end_matches("i");
    let (num, mul) = match s.as_bytes().last()? {
        b'K' | b'k' => (&s[..s.len() - 1], 1u64 << 10),
        b'M' | b'm' => (&s[..s.len() - 1], 1 << 20),
        b'G' | b'g' => (&s[..s.len() - 1], 1 << 30),
        b'T' | b't' => (&s[..s.len() - 1], 1 << 40),
        _ => (s, 1),
    };
    let num = num.trim();
    if num.is_empty() || !num.bytes().all(|c| c.is_ascii_digit() || c == b'.') {
        return None;
    }
    let (int, frac) = num.split_once('.').unwrap_or((num, ""));
    let i: u64 = if int.is_empty() { 0 } else { int.parse().ok()? };
    let mut v = i.checked_mul(mul)?;
    if !frac.is_empty() {
        let f: u64 = frac.parse().ok()?;
        let scale = 10u64.checked_pow(frac.len() as u32)?;
        v = v.checked_add(f.checked_mul(mul)? / scale)?;
    }
    Some(v)
}

/// A time typed by a person: `2026-11-18`, `2026-11-18 09:14` or `2026-11-18T09:14:05` (UTC).
pub fn parse_time(s: &str) -> Option<i64> {
    let s = s.trim();
    let (date, rest) = s.split_once([' ', 'T']).unwrap_or((s, ""));
    let mut d = date.split('-');
    let (y, mo, da) = (d.next()?.parse().ok()?, d.next()?.parse().ok()?, d.next()?.parse().ok()?);
    let mut t = rest.split(':');
    let h = t.next().filter(|x| !x.is_empty()).map_or(Some(0), |x| x.parse().ok())?;
    let mi = t.next().map_or(Some(0), |x| x.parse().ok())?;
    let se = t.next().map_or(Some(0), |x| x.parse().ok())?;
    Time::from_civil(&Civil { year: y, month: mo, day: da, hour: h, minute: mi, second: se, nanosecond: 0 }).map(|t| t.0)
}

/// Render records for the terminal, `cols` wide.
pub fn records(rs: &[Record], cols: usize) -> String {
    if rs.is_empty() {
        return String::new();
    }
    // Results of the file tools: `✓ copied /data/b.txt (1.2 KiB)`.
    const DONE: [&str; 5] = ["copied", "moved", "deleted", "made", "created"];
    if rs.iter().all(|r| r.fields.first().is_some_and(|(n, _)| DONE.contains(&n.as_str()))) {
        let mut s = String::new();
        for r in rs {
            let mut line = String::new();
            for (k, (n, v)) in r.fields.iter().enumerate() {
                match (k, v) {
                    (0, _) => line.push_str(&format!("{} {}", n, value(v))),
                    (_, Value::Size(_)) => line.push_str(&format!(" ({})", value(v))),
                    _ => line.push_str(&format!(" {} {}", n, value(v))),
                }
            }
            s.push_str(&ok_line(&line));
        }
        return s;
    }
    // A table: the columns are every field name, in first-seen order.
    let mut names: Vec<&str> = Vec::new();
    for r in rs {
        for (n, _) in &r.fields {
            if !names.contains(&n.as_str()) {
                names.push(n);
            }
        }
    }
    let cells: Vec<Vec<String>> = rs.iter().map(|r| names.iter().map(|n| r.get(n).map_or(String::new(), value)).collect()).collect();
    let right: Vec<bool> = names.iter().map(|n| rs.iter().find_map(|r| r.get(n)).is_some_and(right_aligned)).collect();
    let mut width: Vec<usize> = names.iter().map(|n| n.chars().count()).collect();
    for row in &cells {
        for (w, c) in width.iter_mut().zip(row) {
            *w = (*w).max(c.chars().count());
        }
    }
    // Fit the screen: the last column gives way first (shown cut with `~`).
    let total: usize = width.iter().map(|w| w + 2).sum::<usize>() + 1;
    if total > cols && !width.is_empty() {
        let over = total - cols;
        let last = width.len() - 1;
        width[last] = width[last].saturating_sub(over).max(4);
    }
    let cell = |s: &str, w: usize, right: bool| -> String {
        let n = s.chars().count();
        let text: String = if n > w { s.chars().take(w.saturating_sub(1)).chain(core::iter::once('~')).collect() } else { String::from(s) };
        let pad = w.saturating_sub(text.chars().count());
        if right { format!("{}{}", " ".repeat(pad), text) } else { format!("{}{}", text, " ".repeat(pad)) }
    };
    let mut out = String::new();
    out.push_str(&style(term::DARK_GREY));
    out.push(' ');
    for (k, n) in names.iter().enumerate() {
        out.push_str(&cell(n, width[k], right[k]));
        out.push_str("  ");
    }
    out = String::from(out.trim_end());
    out.push_str(&plain());
    out.push('\n');
    for row in &cells {
        let mut line = String::from(" ");
        for (k, c) in row.iter().enumerate() {
            line.push_str(&cell(c, width[k], right[k]));
            line.push_str("  ");
        }
        out.push_str(line.trim_end());
        out.push('\n');
    }
    out
}
