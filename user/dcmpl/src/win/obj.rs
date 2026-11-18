//! Windows handles: a table of D-CMPL objects (files and directories through the namespace,
//! threads, events, directory searches) and the console's pseudo handles.

use alloc::sync::Arc;
use alloc::vec::Vec;

use libd::fs::Node;
use libd::handle::Owned;
use libd::sync::Mutex;
use libd::sys::{self, Handle};
use libd::thread::JoinHandle;

pub const H_STDIN: u64 = 0x50;
pub const H_STDOUT: u64 = 0x54;
pub const H_STDERR: u64 = 0x58;
pub const H_NUL: u64 = 0x5C;
pub const CURRENT_PROCESS: u64 = u64::MAX;
pub const CURRENT_THREAD: u64 = u64::MAX - 1;
const FIRST: u64 = 0x100;

pub struct File {
    pub node: Node,
    pub pos: Mutex<u64>,
    pub dir: bool,
    pub write: bool,
    pub path: Vec<u8>,
}

pub struct Thread {
    /// The kernel thread (waits, exit code).
    pub kernel: Handle,
    pub join: Mutex<Option<JoinHandle<()>>>,
    pub gate: Option<Owned>,
    pub id: u32,
}

pub struct Event {
    pub ev: Owned,
    pub manual: bool,
}

pub struct Find {
    pub dir: Vec<u8>,
    pub names: Vec<(Vec<u8>, u64)>,
    pub next: Mutex<usize>,
}

pub enum Obj {
    File(File),
    Thread(Thread),
    Event(Event),
    Find(Find),
}

static TABLE: Mutex<Vec<Option<Arc<Obj>>>> = Mutex::new(Vec::new());

pub fn insert(o: Obj) -> Option<u64> {
    let a = Arc::new(o);
    let mut t = TABLE.lock();
    let i = match t.iter().position(Option::is_none) {
        Some(i) => i,
        None => {
            if t.len() >= 4096 || t.try_reserve(1).is_err() {
                return None;
            }
            t.push(None);
            t.len() - 1
        }
    };
    t[i] = Some(a);
    Some(FIRST + 4 * i as u64)
}

fn index(h: u64) -> Option<usize> {
    (h >= FIRST && h.is_multiple_of(4)).then(|| ((h - FIRST) / 4) as usize)
}

pub fn get(h: u64) -> Option<Arc<Obj>> {
    let i = index(h)?;
    TABLE.lock().get(i).cloned().flatten()
}

pub fn remove(h: u64) -> bool {
    let Some(i) = index(h) else { return false };
    let o = TABLE.lock().get_mut(i).and_then(Option::take);
    o.is_some() // dropped here, outside the lock (closing a node talks to the storage service)
}

/// A second handle to the same object (DuplicateHandle).
pub fn dup(h: u64) -> Option<u64> {
    let a = get(h)?;
    let mut t = TABLE.lock();
    let i = match t.iter().position(Option::is_none) {
        Some(i) => i,
        None => {
            if t.len() >= 4096 || t.try_reserve(1).is_err() {
                return None;
            }
            t.push(None);
            t.len() - 1
        }
    };
    t[i] = Some(a);
    Some(FIRST + 4 * i as u64)
}

/// What a wait on `h` waits for: (kernel handle, signal, auto-reset event).
pub fn waitable(h: u64) -> Option<(Arc<Obj>, Handle, u32, bool)> {
    let o = get(h)?;
    let (k, s, auto) = match &*o {
        Obj::Thread(t) => (t.kernel, sys::TERMINATED, false),
        Obj::Event(e) => (e.ev.raw(), sys::SIGNALED, !e.manual),
        _ => return None,
    };
    Some((o, k, s, auto))
}
