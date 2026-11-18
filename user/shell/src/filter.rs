//! Filters: the stages after `|`, in plain words, over typed records.
//!
//! - `where <field> <op> <value>`: `=`, `!=`, `<`, `>`, `<=`, `>=`, `contains`. The value is read
//!   as the field's type: sizes understand `1M`, times `2026-11-18 09:00`, text compares without
//!   case.
//! - `sort <field> [desc]`, `take <n>`, `pick <field>...`, `count`.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::cmp::Ordering;

use libd::rec::{Record, Value};

use crate::show;

pub const NAMES: [&str; 5] = ["where", "sort", "take", "pick", "count"];

pub fn is_filter(w: &str) -> bool {
    NAMES.contains(&w)
}

pub fn usage(name: &str) -> &'static str {
    match name {
        "where" => "where <field> <=|!=|<|>|<=|>=|contains> <value>",
        "sort" => "sort <field> [desc]",
        "take" => "take <count>",
        "pick" => "pick <field>...",
        _ => "count",
    }
}

fn cmp_values(a: &Value, b: &Value) -> Ordering {
    match (a, b) {
        (Value::Int(x), Value::Int(y)) => x.cmp(y),
        (Value::Size(x), Value::Size(y)) => x.cmp(y),
        (Value::Time(x), Value::Time(y)) => x.cmp(y),
        (Value::Bool(x), Value::Bool(y)) => x.cmp(y),
        (Value::Text(x) | Value::Path(x), Value::Text(y) | Value::Path(y)) => x.to_lowercase().cmp(&y.to_lowercase()),
        // Mixed types (an empty text where a size is missing): typed values first.
        (Value::Text(_), _) => Ordering::Greater,
        (_, Value::Text(_)) => Ordering::Less,
        _ => Ordering::Equal,
    }
}

/// `want` (typed by the user) as a value of the same type as `like`.
fn typed(like: &Value, want: &str) -> Option<Value> {
    Some(match like {
        Value::Int(_) => Value::Int(want.parse().ok()?),
        Value::Size(_) => Value::Size(show::parse_size(want)?),
        Value::Time(_) => Value::Time(show::parse_time(want)?),
        Value::Bool(_) => Value::Bool(matches!(want, "yes" | "true" | "on" | "1")),
        Value::Path(_) => Value::Path(String::from(want)),
        Value::Text(_) => Value::Text(String::from(want)),
    })
}

/// Run one filter stage. Err: a message for the user.
pub fn apply(stage: &[String], rs: Vec<Record>) -> Result<Vec<Record>, String> {
    let name = stage[0].as_str();
    let args = &stage[1..];
    let bad = || format!("{}: usage: {}", name, usage(name));
    match name {
        "where" => {
            let [field, op, want @ ..] = args else { return Err(bad()) };
            if want.is_empty() {
                return Err(bad());
            }
            let want = want.join(" ");
            let op = op.as_str();
            if !matches!(op, "=" | "==" | "!=" | "<" | ">" | "<=" | ">=" | "contains") {
                return Err(format!("where: unknown comparison '{}' (=, !=, <, >, <=, >=, contains)", op));
            }
            if !rs.is_empty() && !rs.iter().any(|r| r.get(field).is_some()) {
                return Err(format!("where: no field '{}' (fields: {})", field, fields(&rs)));
            }
            let mut out = Vec::new();
            for r in rs {
                let Some(v) = r.get(field) else { continue };
                if matches!(v, Value::Text(t) if t.is_empty()) && !matches!(op, "=" | "==" | "!=" | "contains") {
                    continue; // no value (e.g. the size of a directory): not comparable
                }
                let keep = if op == "contains" {
                    show::value(v).to_lowercase().contains(&want.to_lowercase())
                } else {
                    let Some(w) = typed(v, &want) else {
                        return Err(format!("where: '{}' is not a {} (like the field '{}')", want, v.type_name(), field));
                    };
                    let o = cmp_values(v, &w);
                    match op {
                        "=" | "==" => o == Ordering::Equal,
                        "!=" => o != Ordering::Equal,
                        "<" => o == Ordering::Less,
                        ">" => o == Ordering::Greater,
                        "<=" => o != Ordering::Greater,
                        _ => o != Ordering::Less,
                    }
                };
                if keep {
                    out.push(r);
                }
            }
            Ok(out)
        }
        "sort" => {
            let (field, desc) = match args {
                [f] => (f, false),
                [f, d] if d == "desc" || d == "reverse" => (f, true),
                _ => return Err(bad()),
            };
            if !rs.is_empty() && !rs.iter().any(|r| r.get(field).is_some()) {
                return Err(format!("sort: no field '{}' (fields: {})", field, fields(&rs)));
            }
            let mut rs = rs;
            let empty = Value::Text(String::new());
            rs.sort_by(|a, b| {
                let o = cmp_values(a.get(field).unwrap_or(&empty), b.get(field).unwrap_or(&empty));
                if desc { o.reverse() } else { o }
            });
            Ok(rs)
        }
        "take" => {
            let [n] = args else { return Err(bad()) };
            let n: usize = n.parse().map_err(|_| bad())?;
            Ok(rs.into_iter().take(n).collect())
        }
        "pick" => {
            if args.is_empty() {
                return Err(bad());
            }
            if let Some(f) = args.iter().find(|f| !rs.is_empty() && !rs.iter().any(|r| r.get(f).is_some())) {
                return Err(format!("pick: no field '{}' (fields: {})", f, fields(&rs)));
            }
            Ok(rs
                .into_iter()
                .map(|r| Record { fields: args.iter().filter_map(|f| r.get(f).map(|v| (f.clone(), v.clone()))).collect() })
                .collect())
        }
        "count" => {
            if !args.is_empty() {
                return Err(bad());
            }
            Ok(alloc::vec![Record::new().with("count", Value::Int(rs.len() as i64))])
        }
        _ => Err(format!("{}: not a filter", name)),
    }
}

/// The field names of these records (for messages).
pub fn fields(rs: &[Record]) -> String {
    let mut names: Vec<&str> = Vec::new();
    for r in rs {
        for (n, _) in &r.fields {
            if !names.contains(&n.as_str()) {
                names.push(n);
            }
        }
    }
    names.join(", ")
}
