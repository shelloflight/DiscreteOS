//! Exception: a user thread stopped by a fault or a forwarded syscall, waiting for its
//! process's supervisor (the holder of the exception channel: a debugger, a crash reporter, the
//! D-CMPL Linux server).
//!
//! The supervisor receives an `ExceptionObj` handle in a message on the exception channel. With it
//! it can read the thread's registers (`READ`), change them (`WRITE`) and resolve the exception:
//! resume the thread, or kill the process with an exit code. If the handle is closed without
//! resolving (or the message is never read, or the supervisor dies), the process is killed: an
//! exception can never be forgotten and leave the thread stopped for ever (fail closed).
//!
//! The stopped thread waits on `ExcCore` (it never holds the `ExceptionObj`), interruptibly: a
//! kill of its process ends the wait.

use core::sync::atomic::{AtomicBool, Ordering};

use super::signals::Signals;
use super::{Header, KRef, KResult, ObjType, Status};
use crate::ffi::{self, USER_TOP};
use crate::sync::SpinLock;

/// Registers of a stopped thread (ABI: `struct dos_regs`).
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct Regs {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub rsp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub rflags: u64,
    pub fs_base: u64,
    pub gs_base: u64,
}
const _: () = assert!(core::mem::size_of::<Regs>() == 160);

/// RFLAGS bits a program may set (CF PF AF ZF SF TF DF OF AC ID), as in syscall.asm.
pub const USER_FLAGS: u64 = 0x24_0DD5;

impl Regs {
    /// Registers from a supervisor or a handler are untrusted: RIP and the segment bases must be
    /// user addresses (a non-canonical base would fault in the kernel's WRMSR), RFLAGS only keeps
    /// what user mode may set.
    pub fn validate(&mut self) -> KResult<()> {
        if self.rip >= USER_TOP || self.fs_base >= USER_TOP || self.gs_base >= USER_TOP {
            return Err(Status::InvalidArgs);
        }
        self.rflags = (self.rflags & USER_FLAGS) | 0x202;
        Ok(())
    }
}

/// What the stopped thread does once the exception is resolved.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Action {
    Resume,
    Kill(i32),
    /// End only the stopped thread, with this exit code (ABI v10: a Linux `exit` of one thread).
    ExitThread(i32),
}

/// Exception kinds (ABI).
pub const KIND_FAULT: u32 = 1;
pub const KIND_SYSCALL: u32 = 2;
/// The first thread of a process spawned with `SPAWN_START_EXCEPTION`, before its first
/// instruction (lets a supervisor build a foreign initial stack, e.g. Linux argv/auxv).
pub const KIND_START: u32 = 3;

#[derive(Clone, Copy, Default)]
pub struct Info {
    pub kind: u32,
    pub vector: u32,
    pub error: u64,
    pub cr2: u64,
    pub pid: u64,
    pub tid: u64,
}

struct State {
    regs: Regs,
    action: Option<Action>,
}

pub struct ExcCore {
    pub signals: Signals,
    pub info: Info,
    resolved: AtomicBool,
    state: SpinLock<State>,
}

impl ExcCore {
    pub fn new(info: Info, regs: Regs) -> KResult<KRef<ExcCore>> {
        KRef::try_new(ExcCore {
            signals: Signals::new(c"exception"),
            info,
            resolved: AtomicBool::new(false),
            state: SpinLock::new(c"exception", ffi::rank::OBJECT, State { regs, action: None }),
        })
        .map_err(|_| Status::NoMemory)
    }

    pub fn is_resolved(&self) -> bool {
        self.resolved.load(Ordering::Acquire)
    }

    /// Resolve once; later calls are `BadState`.
    pub fn resolve(&self, a: Action) -> KResult<()> {
        {
            let mut s = self.state.lock();
            if s.action.is_some() {
                return Err(Status::BadState);
            }
            s.action = Some(a);
            self.resolved.store(true, Ordering::Release);
        }
        self.signals.wake(true); // the supervisor goes back to its loop: run the thread here
        Ok(())
    }

    pub fn regs(&self) -> KResult<Regs> {
        let s = self.state.lock();
        if s.action.is_some() { Err(Status::BadState) } else { Ok(s.regs) }
    }

    pub fn set_regs(&self, mut r: Regs) -> KResult<()> {
        r.validate()?;
        let mut s = self.state.lock();
        if s.action.is_some() {
            return Err(Status::BadState);
        }
        s.regs = r;
        Ok(())
    }

    /// The outcome (once resolved) and the registers to resume with.
    pub fn outcome(&self) -> (Option<Action>, Regs) {
        let s = self.state.lock();
        (s.action, s.regs)
    }

    /// Wait (interruptibly) until resolved. `Err(BadState)`: the waiting thread was killed.
    pub fn wait(&self) -> KResult<()> {
        self.signals.wait_for(|| self.resolved.load(Ordering::Acquire), 0)
    }
}

/// The supervisor's handle to an exception.
pub struct ExceptionObj {
    pub header: Header,
    pub core: KRef<ExcCore>,
}

impl ExceptionObj {
    pub fn new(core: KRef<ExcCore>) -> KResult<KRef<ExceptionObj>> {
        KRef::try_new(ExceptionObj { header: Header::new(ObjType::Exception), core }).map_err(|_| Status::NoMemory)
    }
}

impl Drop for ExceptionObj {
    /// Closed without being resolved: the process dies (as if no supervisor existed).
    fn drop(&mut self) {
        let _ = self.core.resolve(Action::Kill(ffi::EXIT_FAULT));
    }
}
