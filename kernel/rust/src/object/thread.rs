//! Thread object: a thread that belongs to a process. It counts against the process's thread
//! quota while it runs, and sets `TERMINATED` (with its exit code) when it finishes.
//!
//! Two kinds: kernel closures (`spawn`, used by kernel tests and services) and user threads
//! (`crate::user::thread`), which run in the process's address space in ring 3.

use core::ffi::CStr;
use core::sync::atomic::{AtomicI32, Ordering};

use super::quota::{Charge, Res};
use super::signals::Signals;
use super::{Header, KRef, KResult, Name, ObjType, Process, Status, sig};
use crate::thread::{self, prio};

pub struct ThreadObj {
    pub header: Header,
    pub signals: Signals,
    name: Name,
    exit_code: AtomicI32,
}

impl ThreadObj {
    pub(crate) fn new(name: &str) -> KResult<KRef<ThreadObj>> {
        KRef::try_new(ThreadObj {
            header: Header::new(ObjType::Thread),
            signals: Signals::new(c"thread"),
            name: Name::new(name),
            exit_code: AtomicI32::new(0),
        })
        .map_err(|_| Status::NoMemory)
    }

    /// Start `f` on a new kernel thread in `proc`.
    pub fn spawn<F>(proc: &Process, name: &'static CStr, f: F) -> KResult<KRef<ThreadObj>>
    where
        F: FnOnce() -> i32 + Send + 'static,
    {
        if proc.is_dead() {
            return Err(Status::BadState);
        }
        let charge = Charge::new(proc.account(), Res::Threads, 1)?;
        let obj = ThreadObj::new(name.to_str().unwrap_or("thread"))?;
        let me = obj.clone();
        let started = thread::spawn(name, prio::NORMAL, move || {
            let code = f();
            drop(charge); // the thread no longer counts once its work is done
            me.finish(code);
            code
        });
        // A dropped JoinHandle detaches: the thread is reaped when it exits. On failure the
        // closure (with the charge and the extra reference) has already been dropped.
        started.map(drop).ok_or(Status::NoMemory)?;
        Ok(obj)
    }

    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    /// Record the exit code and set `TERMINATED` (once the thread no longer counts anywhere).
    pub(crate) fn finish(&self, code: i32) {
        self.exit_code.store(code, Ordering::Relaxed);
        self.signals.update(0, sig::TERMINATED);
    }

    /// Exit code, once `TERMINATED` is set.
    pub fn exit_code(&self) -> Option<i32> {
        (self.signals.get() & sig::TERMINATED != 0).then(|| self.exit_code.load(Ordering::Relaxed))
    }
}
