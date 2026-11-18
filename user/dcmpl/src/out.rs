//! The foreign program's console output: standard output and standard error as text, line by
//! line, to the output channel the spawner gave (`tool::TAG_OUTPUT`, the shell shows it) or else
//! to the log. A partial line waits for its end (or `flush_all`, at exit), so lines from several
//! threads are not cut into each other.

use alloc::vec::Vec;

use libd::rec;
use libd::sync::Mutex;

struct Sink {
    pending: Vec<u8>,
    out: Option<rec::Out>,
}

static SINK: Mutex<Sink> = Mutex::new(Sink { pending: Vec::new(), out: None });

/// Longest line kept back before it is sent anyway.
const MAX_LINE: usize = 4096;

fn send(s: &mut Sink, bytes: &[u8]) {
    if bytes.is_empty() {
        return;
    }
    let out = s.out.get_or_insert_with(rec::Out::startup);
    if out.is_connected() {
        out.text(&alloc::string::String::from_utf8_lossy(bytes));
    } else {
        let log = libd::startup_handle(libd::sys::TAG_LOG);
        if log != 0 {
            libd::sys::log_write(log, bytes);
        }
    }
}

/// Text written by the program (any thread). Complete lines go out at once.
pub fn write(bytes: &[u8]) {
    let mut s = SINK.lock();
    if s.pending.try_reserve(bytes.len()).is_err() {
        return;
    }
    s.pending.extend_from_slice(bytes);
    if let Some(last) = s.pending.iter().rposition(|&c| c == b'\n') {
        let rest = s.pending.split_off(last + 1);
        let lines = core::mem::replace(&mut s.pending, rest);
        send(&mut s, &lines);
    }
    if s.pending.len() > MAX_LINE {
        let p = core::mem::take(&mut s.pending);
        send(&mut s, &p);
    }
}

/// Send what is pending (a last line without its end).
pub fn flush_all() {
    let mut s = SINK.lock();
    let p = core::mem::take(&mut s.pending);
    send(&mut s, &p);
    if let Some(o) = s.out.as_mut() {
        o.flush();
    }
}
