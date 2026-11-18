//! Typed records: what commands exchange in the shell (docs/shell.md), instead of byte streams.
//!
//! A record is an ordered list of named fields, each with a typed value: text, integer, size
//! (bytes), time (`time::Time`), path or boolean. A program's output channel carries messages
//! with the usual 32-byte header (`proto::Header`):
//!
//! | Op | Payload |
//! |---|---|
//! | `BATCH` | records, encoded one after another |
//! | `TEXT` | plain text (UTF-8), shown as it is |
//! | `ERROR` | one error message (UTF-8); `a` = a status if there is one |
//!
//! Encoding of a record: `u8` field count, then per field `u8` name length, the name, `u8` type and
//! the value: text and path `u16` length + bytes, integer/size/time 8 bytes little-endian, bool one
//! byte. Input is untrusted: decoding never panics and stops at the first malformed byte.

use alloc::string::String;
use alloc::vec::Vec;

use crate::proto::{HEADER, Header};
use crate::sys::{self, Handle};

pub const BATCH: u32 = 600;
pub const TEXT: u32 = 601;
pub const ERROR: u32 = 602;

/// Largest payload of one message (a channel message is at most 64 KiB with the header).
pub const MAX_PAYLOAD: usize = 60 * 1024;

const T_TEXT: u8 = 1;
const T_INT: u8 = 2;
const T_SIZE: u8 = 3;
const T_TIME: u8 = 4;
const T_PATH: u8 = 5;
const T_BOOL: u8 = 6;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    Text(String),
    Int(i64),
    /// Bytes.
    Size(u64),
    /// D-OS time (ns since 2000-01-01 UTC; 0 = unknown).
    Time(i64),
    Path(String),
    Bool(bool),
}

impl Value {
    pub fn type_name(&self) -> &'static str {
        match self {
            Value::Text(_) => "text",
            Value::Int(_) => "integer",
            Value::Size(_) => "size",
            Value::Time(_) => "time",
            Value::Path(_) => "path",
            Value::Bool(_) => "bool",
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Record {
    pub fields: Vec<(String, Value)>,
}

impl Record {
    pub fn new() -> Record {
        Record { fields: Vec::new() }
    }

    /// Add a field (builder style).
    pub fn with(mut self, name: &str, v: Value) -> Record {
        self.fields.push((String::from(name), v));
        self
    }

    pub fn get(&self, name: &str) -> Option<&Value> {
        self.fields.iter().find(|(n, _)| n == name).map(|(_, v)| v)
    }

    /// Append the encoding to `out`; false (nothing appended) if a name or text is too long.
    pub fn encode(&self, out: &mut Vec<u8>) -> bool {
        if self.fields.len() > 255 {
            return false;
        }
        let start = out.len();
        out.push(self.fields.len() as u8);
        for (n, v) in &self.fields {
            if n.len() > 255 {
                out.truncate(start);
                return false;
            }
            out.push(n.len() as u8);
            out.extend_from_slice(n.as_bytes());
            match v {
                Value::Text(s) | Value::Path(s) => {
                    if s.len() > u16::MAX as usize {
                        out.truncate(start);
                        return false;
                    }
                    out.push(if matches!(v, Value::Text(_)) { T_TEXT } else { T_PATH });
                    out.extend_from_slice(&(s.len() as u16).to_le_bytes());
                    out.extend_from_slice(s.as_bytes());
                }
                Value::Int(x) => {
                    out.push(T_INT);
                    out.extend_from_slice(&x.to_le_bytes());
                }
                Value::Size(x) => {
                    out.push(T_SIZE);
                    out.extend_from_slice(&x.to_le_bytes());
                }
                Value::Time(x) => {
                    out.push(T_TIME);
                    out.extend_from_slice(&x.to_le_bytes());
                }
                Value::Bool(x) => {
                    out.push(T_BOOL);
                    out.push(u8::from(*x));
                }
            }
        }
        true
    }

    /// Decode one record from the front of `b`: (record, bytes used).
    pub fn decode(b: &[u8]) -> Option<(Record, usize)> {
        let mut i = 0;
        let take = |i: &mut usize, n: usize| -> Option<&[u8]> {
            let s = b.get(*i..*i + n)?;
            *i += n;
            Some(s)
        };
        let count = *take(&mut i, 1)?.first()?;
        let mut r = Record { fields: Vec::with_capacity(usize::from(count)) };
        for _ in 0..count {
            let nl = usize::from(*take(&mut i, 1)?.first()?);
            let name = String::from_utf8_lossy(take(&mut i, nl)?).into_owned();
            let t = *take(&mut i, 1)?.first()?;
            let num = |i: &mut usize| -> Option<u64> { Some(u64::from_le_bytes(take(i, 8)?.try_into().ok()?)) };
            let v = match t {
                T_TEXT | T_PATH => {
                    let l = take(&mut i, 2)?;
                    let l = usize::from(u16::from_le_bytes([l[0], l[1]]));
                    let s = String::from_utf8_lossy(take(&mut i, l)?).into_owned();
                    if t == T_TEXT { Value::Text(s) } else { Value::Path(s) }
                }
                T_INT => Value::Int(num(&mut i)? as i64),
                T_SIZE => Value::Size(num(&mut i)?),
                T_TIME => Value::Time(num(&mut i)? as i64),
                T_BOOL => Value::Bool(*take(&mut i, 1)?.first()? != 0),
                _ => return None,
            };
            r.fields.push((name, v));
        }
        Some((r, i))
    }
}

/// Every record in a `BATCH` payload (stops at the first malformed one).
pub fn decode_all(mut b: &[u8]) -> Vec<Record> {
    let mut v = Vec::new();
    while !b.is_empty() {
        let Some((r, n)) = Record::decode(b) else { break };
        v.push(r);
        b = &b[n..];
    }
    v
}

/// What a program writes to its output channel: records (batched), text and errors. Dropping it
/// flushes what is pending.
pub struct Out {
    ch: Handle,
    buf: Vec<u8>,
}

impl Out {
    pub fn new(ch: Handle) -> Out {
        Out { ch, buf: Vec::new() }
    }

    /// The output channel this program was started with (`TAG_OUTPUT`), if any.
    pub fn startup() -> Out {
        Out::new(crate::startup_handle(crate::tool::TAG_OUTPUT))
    }

    pub fn is_connected(&self) -> bool {
        self.ch != 0
    }

    pub fn record(&mut self, r: &Record) {
        let before = self.buf.len();
        if !r.encode(&mut self.buf) {
            return;
        }
        if self.buf.len() > MAX_PAYLOAD {
            let tail = self.buf.split_off(before);
            self.flush();
            self.buf = tail;
        }
        if self.buf.len() >= MAX_PAYLOAD / 2 {
            self.flush();
        }
    }

    /// Plain text (after any pending records).
    pub fn text(&mut self, s: &str) {
        self.flush();
        for part in s.as_bytes().chunks(MAX_PAYLOAD) {
            self.send(TEXT, 0, part);
        }
    }

    /// An error message (after any pending records).
    pub fn error(&mut self, status: i64, s: &str) {
        self.flush();
        let n = s.len().min(1024);
        self.send(ERROR, status as u64, &s.as_bytes()[..n]);
    }

    pub fn flush(&mut self) {
        if !self.buf.is_empty() {
            let b = core::mem::take(&mut self.buf);
            self.send(BATCH, 0, &b);
        }
    }

    /// Send one message, waiting while the reader's queue is full (it drains it).
    fn send(&self, op: u32, a: u64, payload: &[u8]) {
        if self.ch == 0 {
            return;
        }
        let mut m = Vec::with_capacity(HEADER + payload.len());
        m.resize(HEADER, 0);
        Header { txid: 0, op, status: 0, a, b: 0 }.put(&mut m);
        m.extend_from_slice(payload);
        loop {
            match sys::channel_write(self.ch, &m) {
                r if r >= 0 => return,
                sys::ERR_SHOULD_WAIT | sys::ERR_NO_RESOURCES => {
                    let _ = sys::object_wait(self.ch, sys::WRITABLE | sys::PEER_CLOSED, 100_000_000);
                }
                _ => return, // the reader is gone
            }
        }
    }
}

impl Drop for Out {
    fn drop(&mut self) {
        self.flush();
    }
}
