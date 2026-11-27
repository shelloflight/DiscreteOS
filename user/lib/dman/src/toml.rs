//! The TOML subset manifests are written in: `key = value` lines, `[table]` headers (one level),
//! `#` comments, and values that are strings (`"..."` with `\"`, `\\`, `\n`, `\t`), non-negative
//! integers (decimal, `_` separators), booleans and arrays of those (may span lines, trailing
//! comma allowed). Everything else is an error: inline tables, dotted keys, floats, dates,
//! literal and multi-line strings. A key may appear once per table, a table once per file.
//!
//! Input is untrusted (a manifest may come from a disk): sizes are bounded and every error names
//! its line.

use alloc::string::String;
use alloc::vec::Vec;

/// Largest manifest accepted.
pub const MAX_SIZE: usize = 16 * 1024;
/// Longest string value.
pub const MAX_STRING: usize = 256;
/// Most elements in one array.
pub const MAX_ARRAY: usize = 64;
/// Most `key = value` entries in one file.
pub const MAX_ENTRIES: usize = 128;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    Str(String),
    Int(u64),
    Bool(bool),
    Array(Vec<Value>),
}

impl Value {
    pub fn type_name(&self) -> &'static str {
        match self {
            Value::Str(_) => "a string",
            Value::Int(_) => "an integer",
            Value::Bool(_) => "a boolean",
            Value::Array(_) => "an array",
        }
    }
}

/// One `key = value` with the table it is in ("" for the top) and its line (1-based).
#[derive(Clone, Debug)]
pub struct Entry {
    pub table: String,
    pub key: String,
    pub value: Value,
    pub line: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error {
    pub line: u32,
    pub msg: String,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.line == 0 { f.write_str(&self.msg) } else { write!(f, "line {}: {}", self.line, self.msg) }
    }
}

pub fn err(line: u32, msg: impl Into<String>) -> Error {
    Error { line, msg: msg.into() }
}

struct P<'a> {
    s: &'a [u8],
    i: usize,
    line: u32,
    max_string: usize,
}

fn bare_key_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_' || c == b'-'
}

impl P<'_> {
    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }

    fn e(&self, msg: impl Into<String>) -> Error {
        err(self.line, msg)
    }

    /// Spaces and tabs (not newlines).
    fn blank(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t')) {
            self.i += 1;
        }
    }

    /// Spaces, comments and newlines (between array elements, between entries).
    fn space(&mut self) {
        loop {
            self.blank();
            match self.peek() {
                Some(b'#') => {
                    while !matches!(self.peek(), None | Some(b'\n')) {
                        self.i += 1;
                    }
                }
                Some(b'\r') if self.s.get(self.i + 1) == Some(&b'\n') => self.i += 1,
                Some(b'\n') => {
                    self.i += 1;
                    self.line += 1;
                }
                _ => return,
            }
        }
    }

    /// The rest of the line must be blank or a comment.
    fn end_of_line(&mut self) -> Result<(), Error> {
        self.blank();
        if self.peek() == Some(b'#') {
            while !matches!(self.peek(), None | Some(b'\n')) {
                self.i += 1;
            }
        }
        if self.peek() == Some(b'\r') && self.s.get(self.i + 1) == Some(&b'\n') {
            self.i += 1;
        }
        match self.peek() {
            None => Ok(()),
            Some(b'\n') => {
                self.i += 1;
                self.line += 1;
                Ok(())
            }
            Some(_) => Err(self.e("unexpected text after the value")),
        }
    }

    fn key(&mut self) -> Result<String, Error> {
        let start = self.i;
        while self.peek().is_some_and(bare_key_char) {
            self.i += 1;
        }
        if self.i == start || self.i - start > 64 {
            return Err(self.e("expected a key (letters, digits, '-', '_')"));
        }
        // Only ASCII bytes were accepted above.
        Ok(String::from_utf8_lossy(&self.s[start..self.i]).into_owned())
    }

    fn string(&mut self) -> Result<String, Error> {
        self.i += 1; // the opening quote
        let mut out: Vec<u8> = Vec::new();
        loop {
            let Some(c) = self.peek() else { return Err(self.e("unterminated string")) };
            self.i += 1;
            match c {
                b'"' => break,
                b'\\' => {
                    let Some(n) = self.peek() else { return Err(self.e("unterminated string")) };
                    self.i += 1;
                    out.push(match n {
                        b'"' => b'"',
                        b'\\' => b'\\',
                        b'n' => b'\n',
                        b't' => b'\t',
                        _ => return Err(self.e("unknown escape in a string (only \\\" \\\\ \\n \\t)")),
                    });
                }
                b'\n' | b'\r' => return Err(self.e("unterminated string")),
                c if c < 0x20 || c == 0x7F => return Err(self.e("control character in a string")),
                c => out.push(c),
            }
            if out.len() > self.max_string {
                return Err(self.e(alloc::format!("string longer than {} bytes", self.max_string)));
            }
        }
        String::from_utf8(out).map_err(|_| self.e("string is not valid UTF-8"))
    }

    fn integer(&mut self) -> Result<u64, Error> {
        let mut v: u64 = 0;
        let mut digits = 0;
        let mut last_us = false;
        while let Some(c) = self.peek() {
            match c {
                b'0'..=b'9' => {
                    v = v.checked_mul(10).and_then(|v| v.checked_add(u64::from(c - b'0'))).ok_or_else(|| self.e("integer too large"))?;
                    digits += 1;
                    last_us = false;
                }
                b'_' if digits > 0 && !last_us => last_us = true,
                _ => break,
            }
            self.i += 1;
        }
        if last_us {
            return Err(self.e("an integer may not end with '_'"));
        }
        if self.peek().is_some_and(|c| bare_key_char(c) || c == b'.') {
            return Err(self.e("not an integer (only non-negative decimal integers)"));
        }
        Ok(v)
    }

    fn value(&mut self, depth: u32) -> Result<Value, Error> {
        match self.peek() {
            Some(b'"') => self.string().map(Value::Str),
            Some(b'0'..=b'9') => self.integer().map(Value::Int),
            Some(b't') if self.s[self.i..].starts_with(b"true") => {
                self.i += 4;
                self.word_end().map(|_| Value::Bool(true))
            }
            Some(b'f') if self.s[self.i..].starts_with(b"false") => {
                self.i += 5;
                self.word_end().map(|_| Value::Bool(false))
            }
            Some(b'[') if depth == 0 => self.array(),
            Some(b'[') => Err(self.e("nested arrays are not allowed")),
            Some(b'{') => Err(self.e("inline tables are not allowed")),
            Some(b'\'') => Err(self.e("literal strings ('...') are not allowed: use \"...\"")),
            _ => Err(self.e("expected a value (a \"string\", an integer, true/false or an array)")),
        }
    }

    fn word_end(&self) -> Result<(), Error> {
        if self.peek().is_some_and(bare_key_char) { Err(self.e("expected a value")) } else { Ok(()) }
    }

    fn array(&mut self) -> Result<Value, Error> {
        self.i += 1;
        let mut v = Vec::new();
        loop {
            self.space();
            if self.peek() == Some(b']') {
                self.i += 1;
                return Ok(Value::Array(v));
            }
            if v.len() == MAX_ARRAY {
                return Err(self.e("array with more than 64 elements"));
            }
            v.push(self.value(1)?);
            self.space();
            match self.peek() {
                Some(b',') => self.i += 1,
                Some(b']') => {}
                _ => return Err(self.e("expected ',' or ']' in an array")),
            }
        }
    }
}

/// A parsed document: its entries in order, and every table header with its line.
pub struct Doc {
    pub entries: Vec<Entry>,
    pub tables: Vec<(String, u32)>,
}

/// Parse a whole document with the default manifest limits (`MAX_SIZE`, `MAX_STRING`).
pub fn parse(s: &[u8]) -> Result<Doc, Error> {
    parse_with_limits(s, MAX_SIZE, MAX_STRING)
}

/// Parse a whole document with explicit upper bounds on total byte size and string length
/// (used by stores that persist hex-encoded hardware-sealed blobs such as TPM 2.0 credentials).
pub fn parse_with_limits(s: &[u8], max_size: usize, max_string: usize) -> Result<Doc, Error> {
    if s.len() > max_size {
        return Err(err(0, "manifest larger than 16 KiB"));
    }
    let mut p = P { s, i: 0, line: 1, max_string };
    // A UTF-8 byte-order mark is tolerated (editors add one).
    if s.starts_with(&[0xEF, 0xBB, 0xBF]) {
        p.i = 3;
    }
    let mut table = String::new();
    let mut tables: Vec<(String, u32)> = Vec::new();
    let mut out: Vec<Entry> = Vec::new();
    loop {
        p.space();
        let Some(c) = p.peek() else { break };
        if c == b'[' {
            p.i += 1;
            if p.peek() == Some(b'[') {
                return Err(p.e("arrays of tables ([[...]]) are not allowed"));
            }
            p.blank();
            let name = p.key()?;
            p.blank();
            if p.peek() != Some(b']') {
                return Err(p.e("expected ']' after the table name (one level, no dots)"));
            }
            p.i += 1;
            if tables.iter().any(|(t, _)| *t == name) {
                return Err(p.e(alloc::format!("table [{}] appears twice", name)));
            }
            tables.push((name.clone(), p.line));
            table = name;
            p.end_of_line()?;
            continue;
        }
        let line = p.line;
        let key = p.key()?;
        p.blank();
        if p.peek() != Some(b'=') {
            return Err(p.e(if p.peek() == Some(b'.') { "dotted keys are not allowed" } else { "expected '=' after the key" }));
        }
        p.i += 1;
        p.blank();
        let value = p.value(0)?;
        p.end_of_line()?;
        if out.iter().any(|e| e.table == table && e.key == key) {
            return Err(err(line, alloc::format!("key '{}' appears twice", key)));
        }
        if out.len() == MAX_ENTRIES {
            return Err(err(line, "more than 128 entries"));
        }
        out.push(Entry { table: table.clone(), key, value, line });
    }
    Ok(Doc { entries: out, tables })
}
