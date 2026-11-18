//! Exception delivery for user threads (design in docs/compat.md).
//!
//! When a user thread faults, or makes a syscall in a `FORWARD` process, the kernel tries in turn:
//!
//! 1. **The thread's own handler** (faults only), registered with `thread_set_exception_handler`:
//!    the thread resumes at the handler with an exception record (kind, vector, error code, CR2,
//!    all registers) on the handler's stack and RDI pointing at it. The handler returns with
//!    `exception_return(record)`, which resumes the (possibly edited) registers. A fault while
//!    the handler runs skips the handler. FPU/SSE/AVX registers are left as they were (live): a
//!    handler that uses them saves and restores them itself.
//! 2. **The process's supervisor** (the exception channel): the thread stops, the supervisor gets
//!    a message with an `Exception` handle, reads and edits the registers and resolves it.
//! 3. Otherwise the fault kills the process (with the crash report).
//!
//! Everything a handler or supervisor hands back is validated (`Regs::validate`): RIP and the
//! FS/GS bases must be user addresses, RFLAGS keeps only user bits. The return to user mode after
//! a change goes through IRETQ (all registers exact), never SYSRET (which clobbers RCX and R11).

use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use super::syscall::Frame;
use super::thread::{UserThread, current};
use super::uaccess::{self, Pod};
use crate::ffi;
use crate::object::channel::Message;
use crate::object::exception::{Action, ExcCore, Info, KIND_FAULT, KIND_START, KIND_SYSCALL, Regs};
use crate::object::{ExceptionObj, Object, ObjType, default_rights};

// SAFETY: repr(C), u64 fields only.
unsafe impl Pod for Regs {}

/// In-process exception record (ABI: `struct dos_exception_record`, 192 bytes).
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Record {
    pub kind: u32,
    pub vector: u32,
    pub error: u64,
    pub cr2: u64,
    pub regs: Regs,
    pub reserved: u64,
}
const _: () = assert!(core::mem::size_of::<Record>() == 192);
// SAFETY: as above.
unsafe impl Pod for Record {}

/// Exception channel message (ABI: `struct dos_exception_msg`, 208 bytes). The first word is the
/// usual channel transaction-id slot (0: not a reply to anything).
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Msg {
    txid: u32,
    kind: u32,
    vector: u32,
    reserved: u32,
    error: u64,
    cr2: u64,
    pid: u64,
    tid: u64,
    regs: Regs,
}
const _: () = assert!(core::mem::size_of::<Msg>() == 208);

pub fn regs_from(f: &Frame) -> Regs {
    // SAFETY: plain reads of the current thread's segment bases.
    let (fs, gs) = unsafe { (ffi::uthread_get_base(0), ffi::uthread_get_base(1)) };
    Regs {
        rax: f.rax,
        rbx: f.rbx,
        rcx: f.rcx,
        rdx: f.rdx,
        rsi: f.rsi,
        rdi: f.rdi,
        rbp: f.rbp,
        rsp: f.rsp,
        r8: f.r8,
        r9: f.r9,
        r10: f.r10,
        r11: f.r11,
        r12: f.r12,
        r13: f.r13,
        r14: f.r14,
        r15: f.r15,
        rip: f.rip,
        rflags: f.rflags,
        fs_base: fs,
        gs_base: gs,
    }
}

/// Load validated registers into the frame (and the segment bases into the thread).
pub fn apply(f: &mut Frame, r: &Regs) {
    f.rax = r.rax;
    f.rbx = r.rbx;
    f.rcx = r.rcx;
    f.rdx = r.rdx;
    f.rsi = r.rsi;
    f.rdi = r.rdi;
    f.rbp = r.rbp;
    f.rsp = r.rsp;
    f.r8 = r.r8;
    f.r9 = r.r9;
    f.r10 = r.r10;
    f.r11 = r.r11;
    f.r12 = r.r12;
    f.r13 = r.r13;
    f.r14 = r.r14;
    f.r15 = r.r15;
    f.rip = r.rip;
    f.rflags = r.rflags;
    // SAFETY: validated user addresses (canonical), the current thread's own bases.
    unsafe {
        ffi::uthread_set_base(0, r.fs_base);
        ffi::uthread_set_base(1, r.gs_base);
    }
}

/// Deliver to the thread's own handler. False if it has none, is already in it, or its handler
/// stack is unusable.
fn to_handler(u: &UserThread, f: &mut Frame, info: &Info) -> bool {
    let entry = u.handler_entry.load(Ordering::Relaxed);
    let stack = u.handler_stack.load(Ordering::Relaxed);
    if entry == 0 || u.in_handler.load(Ordering::Relaxed) {
        return false;
    }
    let rec = Record { kind: info.kind, vector: info.vector, error: info.error, cr2: info.cr2, regs: regs_from(f), reserved: 0 };
    let at = (stack - core::mem::size_of::<Record>() as u64) & !15;
    if at < ffi::USER_BASE || uaccess::write(at, &rec).is_err() {
        return false;
    }
    u.in_handler.store(true, Ordering::Relaxed);
    f.rip = entry;
    f.rsp = at - 8; // as after a call: RSP + 8 is 16-byte aligned at the entry point
    f.rdi = at;
    f.rflags &= !(1 << 8 | 1 << 10); // TF, DF clear (the ABI's entry state)
    true
}

/// Stop and hand the exception to the supervisor. None: there is none (or it is gone).
fn to_supervisor(u: &UserThread, f: &mut Frame, info: Info) -> Option<Action> {
    let ch = u.proc.exception_channel()?;
    let core = ExcCore::new(info, regs_from(f)).ok()?;
    let exc = ExceptionObj::new(core.clone()).ok()?;
    let msg = Msg {
        txid: 0,
        kind: info.kind,
        vector: info.vector,
        reserved: 0,
        error: info.error,
        cr2: info.cr2,
        pid: info.pid,
        tid: info.tid,
        regs: regs_from(f),
    };
    let mut data = Vec::new();
    data.try_reserve_exact(core::mem::size_of::<Msg>()).ok()?;
    // SAFETY: Msg is repr(C) plain data without padding (asserted size).
    let bytes = unsafe {
        core::slice::from_raw_parts((&raw const msg).cast::<u8>(), core::mem::size_of::<Msg>())
    };
    data.extend_from_slice(bytes);
    let mut handles = Vec::new();
    handles.try_reserve_exact(1).ok()?;
    handles.push((Object::Exception(exc), default_rights(ObjType::Exception)));
    // Charged to the faulting process (it caused the message).
    let m = Message::new(u.proc.account(), data, handles).ok()?;
    if ch.write(m).is_err() {
        return None; // dropping the message drops the exception: resolved as Kill, not waited on
    }
    drop(ch);
    if core.wait().is_err() {
        return Some(Action::Kill(u.proc.pending_exit_code())); // the process was killed meanwhile
    }
    let (action, regs) = core.outcome();
    let action = action.unwrap_or(Action::Kill(ffi::EXIT_FAULT));
    if action == Action::Resume {
        apply(f, &regs);
    }
    Some(action)
}

fn info_for(u: &UserThread, kind: u32, vector: u32, error: u64, cr2: u64) -> Info {
    Info { kind, vector, error, cr2, pid: u.proc.header.koid, tid: u.obj.header.koid }
}

/// A fault in ring 3 (user.c, interrupts on). True: resume (the frame was updated); false: the
/// caller reports the fault and kills the process.
///
/// # Safety
/// `f` is the frame of the current thread's entry from ring 3 (user.c), alive for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dkrnl_user_exception(f: *mut Frame, cr2: u64) -> bool {
    let Some(u) = current() else { return false };
    // SAFETY: the C fault path passes the frame of this thread's entry from ring 3.
    let f = unsafe { &mut *f };
    let info = info_for(u, KIND_FAULT, f.vector as u32, f.error, cr2);
    if to_handler(u, f, &info) {
        return true;
    }
    match to_supervisor(u, f, info) {
        Some(Action::Resume) => true,
        Some(Action::Kill(code)) => {
            u.proc.kill_with(code);
            // SAFETY: the thread's own exit, from the fault path (no Rust state alive above).
            unsafe { ffi::uthread_exit(ffi::UTHREAD_EXIT_KILLED) }
        }
        // SAFETY: as above; only this thread ends.
        Some(Action::ExitThread(code)) => unsafe { ffi::uthread_exit(code) },
        None => false,
    }
}

/// A syscall of a `FORWARD` process: the supervisor runs it. Returns normally only to resume.
pub fn forward_syscall(u: &UserThread, f: &mut Frame) {
    let info = info_for(u, KIND_SYSCALL, 0, f.rax, 0);
    match to_supervisor(u, f, info) {
        Some(Action::Resume) => {}
        Some(Action::Kill(code)) => u.proc.kill_with(code),
        // SAFETY: called from the syscall dispatcher's top level: no Rust state is alive above.
        Some(Action::ExitThread(code)) => unsafe { ffi::uthread_exit(code) },
        None => u.proc.kill_with(ffi::EXIT_FAULT), // no supervisor: nothing can run its syscalls
    }
}

/// User-mode selectors (GDT_UCODE | 3, GDT_UDATA | 3), as pushed by syscall_entry.
const UCODE: u64 = 0x23;
const UDATA: u64 = 0x1B;

/// First entry of a thread spawned with `SPAWN_START_EXCEPTION` (or made by
/// `thread_create_stopped`): before its first instruction the
/// supervisor gets a `START` exception with the initial registers (RIP = entry, RSP, RDI, RSI) and
/// may change them and the process's memory (a foreign initial stack: Linux argc/argv/auxv). No
/// supervisor (gone already): the thread starts as usual. Never returns.
pub fn start_trap(u: &UserThread, entry: u64, stack: u64, a0: u64, a1: u64) -> ! {
    let mut f = Frame {
        r15: 0,
        r14: 0,
        r13: 0,
        r12: 0,
        r11: 0,
        r10: 0,
        r9: 0,
        r8: 0,
        rbp: 0,
        rdi: a0,
        rsi: a1,
        rdx: 0,
        rcx: 0,
        rbx: 0,
        rax: 0,
        vector: 0,
        error: 0,
        rip: entry,
        cs: UCODE,
        rflags: 0x202,
        rsp: stack,
        ss: UDATA,
    };
    let info = info_for(u, KIND_START, 0, 0, 0);
    match to_supervisor(u, &mut f, info) {
        // SAFETY: a frame on this thread's kernel stack with user selectors; `apply` took only
        // validated registers (user RIP and bases, user RFLAGS bits + IF). Nothing on this Rust
        // frame needs dropping.
        Some(Action::Resume) => unsafe { ffi::user_enter_frame(&f) },
        Some(Action::Kill(code)) => {
            u.proc.kill_with(code);
            // SAFETY: the thread's own exit before it ever ran user code.
            unsafe { ffi::uthread_exit(ffi::UTHREAD_EXIT_KILLED) }
        }
        // SAFETY: as above; only this thread ends.
        Some(Action::ExitThread(code)) => unsafe { ffi::uthread_exit(code) },
        // SAFETY: into ring 3 as a thread without a START stop would; never returns.
        None => unsafe { ffi::user_enter(entry, stack, a0, a1) },
    }
}

/// `exception_return`: resume the registers in the handler's record.
pub fn handler_return(u: &UserThread, f: &mut Frame, rec_ptr: u64) -> crate::object::KResult<()> {
    if !u.in_handler.load(Ordering::Relaxed) {
        return Err(crate::object::Status::BadState);
    }
    let rec: Record = uaccess::read(rec_ptr)?;
    let mut regs = rec.regs;
    regs.validate()?;
    u.in_handler.store(false, Ordering::Relaxed);
    apply(f, &regs);
    Ok(())
}
