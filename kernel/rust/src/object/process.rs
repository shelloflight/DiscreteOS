//! Process: a handle table, a root address-space region, a quota account, and the operations a
//! process can perform on objects **through its own handles**. These methods are the kernel side
//! of the syscalls: `self` is the calling process, every object is named by a handle, and
//! every handle is checked for its type and rights before anything happens.
//!
//! Rights rules: a handle never gains rights. Duplicate/replace/grant take a subset of the
//! source's rights (or `Rights::SAME`); requesting more is `AccessDenied`.
//!
//! Lifetime: a process lives until it is killed (later also: until its last thread exits). Killing
//! closes every handle in its table, which also breaks reference cycles through the table, tears
//! down its address space and sets `TERMINATED`. Threads already running finish on their own
//! (kernel threads cannot be interrupted; user threads are stopped).

use core::ffi::CStr;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicPtr, AtomicU32, Ordering};

use super::handle::{Handle, HandleTable};
use super::quota::{Account, Limits, Res};
use super::signals::Signals;
use super::vmar::PERM_MASK;
use super::{
    ChannelObj, DeviceObj, EventObj, ExceptionObj, Header, InterruptObj, KRef, KResult, LogObj, Name, ObjType, Object, PortObj, ResourceObj,
    Rights, Status, ThreadObj, TimerObj, Vmar, Vmo, default_rights, sig,
};
use crate::ffi::{self, RawThread, rank};
use crate::sync::SpinLock;

pub struct Process {
    pub header: Header,
    pub signals: Signals,
    name: Name,
    acct: KRef<Account>,
    handles: SpinLock<HandleTable>,
    root_vmar: KRef<Vmar>,
    dead: AtomicBool,
    /// User threads running in it (C thread pointers); `dead` only changes under this lock.
    threads: SpinLock<Vec<ThreadPtr>>,
    exit_code: AtomicI32,
    /// Kill in progress: user threads still to finish + 1 for the teardown; 0 = TERMINATED.
    term_pending: AtomicU32,
    /// Syscall personality `FORWARD` (fixed before the first thread starts): every syscall of the
    /// process goes to its supervisor as an exception instead of being run by the kernel.
    forward: AtomicBool,
    /// The kernel's end of the exception channel (the supervisor holds the other end).
    exc: SpinLock<Option<KRef<ChannelObj>>>,
}

/// A user thread's C thread, valid while it is in its process's list (it removes itself,
/// under the list lock, before it exits).
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct ThreadPtr(pub *mut RawThread);

// SAFETY: only used under the process's thread-list lock, while the thread is alive.
unsafe impl Send for ThreadPtr {}

/// Quota usage snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Usage {
    pub memory: u64,
    pub handles: u64,
    pub threads: u64,
}

static KERNEL_PROC: AtomicPtr<KRef<Process>> = AtomicPtr::new(core::ptr::null_mut());

pub(super) fn init_kernel_process() {
    let p = Process::new(None, "kernel", Limits::UNLIMITED)
        .unwrap_or_else(|e| panic!("cannot create the kernel process: {}", e.name()));
    // The kernel process is never destroyed: its reference is kept forever (a leaked box).
    let ptr = alloc::boxed::Box::into_raw(alloc::boxed::Box::new(p));
    KERNEL_PROC.store(ptr, Ordering::Release);
}

fn kernel_kref() -> &'static KRef<Process> {
    let p = KERNEL_PROC.load(Ordering::Acquire);
    crate::kassert!(!p.is_null());
    // SAFETY: set once by init_kernel_process from a leaked (never freed) box.
    unsafe { &*p }
}

/// The kernel process: root of the quota tree; parent of everything the kernel starts.
pub fn kernel_process() -> &'static Process {
    kernel_kref()
}

/// A counted reference to the kernel process (to make it the parent of init).
pub fn kernel_process_ref() -> KRef<Process> {
    kernel_kref().clone()
}

/// Typed handle lookups: `(object, rights)`. Checked in this order: the handle is valid
/// (`BadHandle`), the object has the type (`WrongType`), the handle has `need` (`AccessDenied`).
macro_rules! typed_get {
    ($fn:ident, $variant:ident, $ty:ty) => {
        pub fn $fn(&self, h: Handle, need: Rights) -> KResult<(KRef<$ty>, Rights)> {
            let (obj, rights) = self.handles.lock().get(h)?;
            // Error paths drop `obj` with the table unlocked; the table still holds a reference.
            let Object::$variant(o) = obj else {
                return Err(Status::WrongType);
            };
            if !rights.contains(need) {
                return Err(Status::AccessDenied);
            }
            Ok((o, rights))
        }
    };
}

/// Rights for a derived handle: `SAME`, or a subset of what the source has.
fn derive(have: Rights, want: Rights) -> KResult<Rights> {
    if want == Rights::SAME {
        return Ok(have);
    }
    if want.0 & !Rights::ALL.0 != 0 || !have.contains(want) {
        return Err(Status::AccessDenied);
    }
    Ok(want)
}

impl Process {
    /// Kernel-internal constructor. `parent`: the account this one is charged through.
    pub fn new(parent: Option<&Process>, name: &str, limits: Limits) -> KResult<KRef<Process>> {
        let acct = KRef::try_new(Account::new(parent.map(|p| p.acct.clone()), limits))
            .map_err(|_| Status::NoMemory)?;
        let root_vmar = Vmar::new_root(&acct)?;
        // SAFETY: plain call; returns 64 random bits (RDRAND, or a TSC mix without it).
        let random = unsafe { ffi::cpu_random64() };
        KRef::try_new(Process {
            header: Header::new(ObjType::Process),
            signals: Signals::new(c"process"),
            name: Name::new(name),
            handles: SpinLock::new(c"handles", rank::OBJECT, HandleTable::new(acct.clone(), random)),
            acct,
            root_vmar,
            dead: AtomicBool::new(false),
            threads: SpinLock::new(c"process.threads", rank::PROC_THREADS, Vec::new()),
            exit_code: AtomicI32::new(0),
            term_pending: AtomicU32::new(0),
            forward: AtomicBool::new(false),
            exc: SpinLock::new(c"process.exc", rank::OBJECT, None),
        })
        .map_err(|_| Status::NoMemory)
    }

    /// FORWARD personality: set by the loader before the first thread runs, never cleared.
    pub(crate) fn set_forward(&self) {
        self.forward.store(true, Ordering::Release);
    }

    pub fn forwards_syscalls(&self) -> bool {
        self.forward.load(Ordering::Acquire)
    }

    /// Create the exception channel; returns the supervisor's end. `BadState` if the process
    /// already has a supervisor (one whose end is still open).
    pub fn create_exception_channel(&self) -> KResult<KRef<ChannelObj>> {
        self.check_alive()?;
        let (kernel_end, user_end) = ChannelObj::create()?;
        let old = {
            let mut g = self.exc.lock();
            if g.as_ref().is_some_and(|c| !c.peer_closed()) {
                return Err(Status::BadState); // `kernel_end`, `user_end` drop after unlocking
            }
            g.replace(kernel_end)
        };
        drop(old);
        Ok(user_end)
    }

    /// The kernel's end of the exception channel, if a supervisor is listening.
    pub fn exception_channel(&self) -> Option<KRef<ChannelObj>> {
        let c = self.exc.lock().clone();
        c.filter(|c| !c.peer_closed())
    }

    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    pub fn is_dead(&self) -> bool {
        self.dead.load(Ordering::Acquire)
    }

    pub fn account(&self) -> &KRef<Account> {
        &self.acct
    }

    pub fn usage(&self) -> Usage {
        Usage {
            memory: self.acct.used(Res::Memory),
            handles: self.acct.used(Res::Handles),
            threads: self.acct.used(Res::Threads),
        }
    }

    pub fn handle_count(&self) -> u32 {
        self.handles.lock().count()
    }

    /// Kill with `EXIT_KILLED`. Idempotent.
    pub fn kill(&self) {
        self.kill_with(ffi::EXIT_KILLED);
    }

    /// Kill (or exit) with `code`: stop every user thread, close every handle, tear down the
    /// address space. `TERMINATED` is set once the teardown is done and every user thread has
    /// left (so a waiter sees the quota usage already given back). The first code wins.
    pub fn kill_with(&self, code: i32) {
        {
            let threads = self.threads.lock();
            if self.dead.swap(true, Ordering::AcqRel) {
                return;
            }
            self.exit_code.store(code, Ordering::Relaxed);
            self.term_pending
                .store(threads.len() as u32 + 1, Ordering::Release);
            for t in threads.iter() {
                // SAFETY: a listed thread is alive: it unlists itself (under this lock) first.
                unsafe { ffi::thread_kill(t.0) };
            }
        }
        let closed = self.handles.lock().close_all();
        drop(closed); // outside the lock: may free pages, cancel timers, kill nothing else
        // Channels this process left in cycles (each holding the other's end, nobody outside)
        // can never be read again: break them now, before TERMINATED tells anyone we are gone.
        super::channel::collect_cycles();
        let exc = self.exc.lock().take();
        drop(exc); // the supervisor sees PEER_CLOSED
        self.root_vmar.destroy();
        self.term_step();
    }

    fn term_step(&self) {
        if self.term_pending.fetch_sub(1, Ordering::AcqRel) == 1 {
            // Nothing runs in the address space any more and nothing is mapped: its page tables
            // go now (not when the last reference to the process does), so a waiter sees every
            // charge given back.
            self.root_vmar.aspace().free_tables();
            self.signals.update(0, sig::TERMINATED);
        }
    }

    /// Exit code once `TERMINATED` (`EXIT_KILLED`, `EXIT_FAULT`, or what the program chose).
    pub fn exit_code(&self) -> Option<i32> {
        (self.signals.get() & sig::TERMINATED != 0).then(|| self.exit_code.load(Ordering::Relaxed))
    }

    /// The code a killed thread of this process ends with.
    pub(crate) fn pending_exit_code(&self) -> i32 {
        self.exit_code.load(Ordering::Relaxed)
    }

    pub fn root_vmar(&self) -> &KRef<Vmar> {
        &self.root_vmar
    }

    /// Start a user thread: `create` makes the C thread (it may start running at once) while
    /// the thread list is locked, so a kill either sees it or happens before and refuses it.
    pub(crate) fn add_thread(&self, create: impl FnOnce() -> Option<*mut RawThread>) -> KResult<()> {
        let mut threads = self.threads.lock();
        if self.is_dead() {
            return Err(Status::BadState);
        }
        threads.try_reserve(1).map_err(|_| Status::NoMemory)?;
        let t = create().ok_or(Status::NoMemory)?;
        threads.push(ThreadPtr(t));
        Ok(())
    }

    /// A user thread ended (its own last step before exiting). The last one to leave a live
    /// process makes it exit with its code.
    pub(crate) fn thread_gone(&self, t: *mut RawThread, code: i32) {
        let (dead, last) = {
            let mut threads = self.threads.lock();
            if let Some(i) = threads.iter().position(|x| x.0 == t) {
                threads.swap_remove(i);
            }
            (self.is_dead(), threads.is_empty())
        };
        if dead {
            self.term_step();
        } else if last {
            self.kill_with(code);
        }
    }

    pub fn user_threads(&self) -> usize {
        self.threads.lock().len()
    }

    // ---- handle table ---------------------------------------------------------------------

    /// Install `obj` with `rights`; the object is dropped (outside the lock) on failure.
    pub fn add(&self, obj: Object, rights: Rights) -> KResult<Handle> {
        let r = self.handles.lock().insert(obj, rights);
        r.map_err(|(e, obj)| {
            drop(obj);
            e
        })
    }

    /// Look up a handle that must carry `need`.
    pub fn get(&self, h: Handle, need: Rights) -> KResult<(Object, Rights)> {
        let (obj, rights) = self.handles.lock().get(h)?;
        if !rights.contains(need) {
            drop(obj); // never the last reference: the table still holds one
            return Err(Status::AccessDenied);
        }
        Ok((obj, rights))
    }

    typed_get!(get_process, Process, Process);
    typed_get!(get_thread, Thread, ThreadObj);
    typed_get!(get_vmo, Vmo, Vmo);
    typed_get!(get_vmar, Vmar, Vmar);
    typed_get!(get_event, Event, EventObj);
    typed_get!(get_timer, Timer, TimerObj);
    typed_get!(get_log, Log, LogObj);
    typed_get!(get_channel, Channel, ChannelObj);
    typed_get!(get_port, Port, PortObj);
    typed_get!(get_exception, Exception, ExceptionObj);
    typed_get!(get_resource, Resource, ResourceObj);
    typed_get!(get_device, Device, DeviceObj);
    typed_get!(get_interrupt, Interrupt, InterruptObj);

    /// Remove a handle and return its object (moving it somewhere else, e.g. into a spawned
    /// process). The caller drops or re-installs the object.
    pub fn take(&self, h: Handle) -> KResult<(Object, Rights)> {
        self.handles.lock().remove(h)
    }

    pub fn handle_close(&self, h: Handle) -> KResult<()> {
        let r = self.handles.lock().remove(h);
        r.map(drop) // the object (possibly the last reference) drops after unlocking
    }

    /// New handle to the same object with `rights` (a subset); needs `DUPLICATE`.
    pub fn handle_duplicate(&self, h: Handle, rights: Rights) -> KResult<Handle> {
        let (obj, have) = self.get(h, Rights::DUPLICATE)?;
        let rights = derive(have, rights)?;
        self.add(obj, rights)
    }

    /// Swap `h` for a new handle with `rights` (a subset); `h` is invalid afterwards. Needs no
    /// right: it can only remove rights. On error `h` stays as it was.
    pub fn handle_replace(&self, h: Handle, rights: Rights) -> KResult<Handle> {
        let mut t = self.handles.lock();
        let rights = derive(t.rights(h)?, rights)?;
        let (obj, _) = t.remove(h)?;
        // The slot and the quota unit just freed are reused, so this cannot fail for lack of room;
        // keep the error path anyway (fail closed: the handle is gone).
        let r = t.insert(obj, rights);
        drop(t);
        r.map_err(|(e, obj)| {
            drop(obj);
            e
        })
    }

    /// Move `h` into the process behind `dest` (needs `MANAGE` on it) with `rights` (a subset).
    /// Needs `TRANSFER` on `h`. `h` is consumed even if the destination refuses it (as Fuchsia
    /// does): a capability never ends up in two places by accident.
    pub fn handle_grant(&self, h: Handle, rights: Rights, dest: Handle) -> KResult<Handle> {
        let (target, _) = self.get_process(dest, Rights::MANAGE)?;
        {
            let t = self.handles.lock();
            let have = t.rights(h)?;
            if !have.contains(Rights::TRANSFER) {
                return Err(Status::AccessDenied);
            }
            derive(have, rights)?;
        }
        let (obj, have) = self.handles.lock().remove(h)?;
        let rights = match derive(have, rights) {
            Ok(r) => r,
            Err(e) => {
                drop(obj);
                return Err(e);
            }
        };
        target.add(obj, rights)
    }

    /// (type, koid, rights) of a handle. Needs no right.
    pub fn object_info(&self, h: Handle) -> KResult<(ObjType, u64, Rights)> {
        let (obj, rights) = self.get(h, Rights::NONE)?;
        Ok((obj.obj_type(), obj.koid(), rights))
    }

    /// Wait until the object has any of the `mask` signals; returns its signals. Needs `WAIT`.
    pub fn object_wait(&self, h: Handle, mask: u32, timeout_ns: u64) -> KResult<u32> {
        let (obj, rights) = self.get(h, Rights::NONE)?;
        let s = obj.signals().ok_or(Status::WrongType)?;
        if !rights.contains(Rights::WAIT) {
            return Err(Status::AccessDenied);
        }
        s.wait(mask, timeout_ns) // the reference in `obj` keeps the object alive while waiting
    }

    // ---- object creation (inside this process, charged to its quota) ------------------------

    pub(crate) fn check_alive(&self) -> KResult<()> {
        if self.is_dead() { Err(Status::BadState) } else { Ok(()) }
    }

    pub fn event_create(&self) -> KResult<Handle> {
        self.check_alive()?;
        let e = EventObj::create()?;
        self.add(Object::Event(e), default_rights(ObjType::Event))
    }

    /// Set/clear the event's `SIGNALED` bit. Needs `SIGNAL`.
    pub fn event_signal(&self, h: Handle, clear: u32, set: u32) -> KResult<()> {
        if (clear | set) & !sig::SIGNALED != 0 {
            return Err(Status::InvalidArgs);
        }
        let (e, _) = self.get_event(h, Rights::SIGNAL)?;
        e.signals.update(clear, set);
        Ok(())
    }

    pub fn timer_create(&self) -> KResult<Handle> {
        self.check_alive()?;
        let t = TimerObj::create()?;
        self.add(Object::Timer(t), default_rights(ObjType::Timer))
    }

    /// Arm the timer to signal `delay_ns` from now. Needs `WRITE`.
    pub fn timer_set(&self, h: Handle, delay_ns: u64) -> KResult<()> {
        let (t, _) = self.get_timer(h, Rights::WRITE)?;
        t.set(delay_ns);
        Ok(())
    }

    pub fn timer_cancel(&self, h: Handle) -> KResult<bool> {
        let (t, _) = self.get_timer(h, Rights::WRITE)?;
        Ok(t.cancel())
    }

    pub fn vmo_create(&self, size: u64) -> KResult<Handle> {
        self.check_alive()?;
        let v = Vmo::create(&self.acct, size)?;
        self.add(Object::Vmo(v), default_rights(ObjType::Vmo))
    }

    pub fn vmo_read(&self, h: Handle, off: u64, buf: &mut [u8]) -> KResult<()> {
        self.get_vmo(h, Rights::READ)?.0.read(off, buf)
    }

    pub fn vmo_write(&self, h: Handle, off: u64, data: &[u8]) -> KResult<()> {
        self.get_vmo(h, Rights::WRITE)?.0.write(off, data)
    }

    pub fn vmo_size(&self, h: Handle) -> KResult<u64> {
        Ok(self.get_vmo(h, Rights::NONE)?.0.size())
    }

    /// Map `len` bytes of the VMO at `vmo_off` into the region with `perms` (READ/WRITE/EXECUTE,
    /// never WRITE+EXECUTE). Both handles need `MAP` plus every right in `perms`. Returns the address.
    pub fn vmar_map(
        &self,
        vmar: Handle,
        offset: Option<u64>,
        vmo: Handle,
        vmo_off: u64,
        len: u64,
        perms: Rights,
    ) -> KResult<u64> {
        if !PERM_MASK.contains(perms) {
            return Err(Status::InvalidArgs);
        }
        let need = Rights::MAP | perms;
        let (r, _) = self.get_vmar(vmar, need)?;
        let (v, _) = self.get_vmo(vmo, need)?;
        if perms.contains(Rights::EXECUTE) && !v.executable() {
            return Err(Status::AccessDenied);
        }
        r.map(offset, v, vmo_off, len, perms)
    }

    pub fn vmar_unmap(&self, vmar: Handle, addr: u64, len: u64) -> KResult<u32> {
        self.get_vmar(vmar, Rights::MAP)?.0.unmap(addr, len)
    }

    /// Carve out a child region; its handle gets `rights` (a subset of the parent handle's).
    /// Returns (handle, base address). Needs `MAP`.
    pub fn vmar_allocate(&self, vmar: Handle, offset: Option<u64>, len: u64, rights: Rights) -> KResult<(Handle, u64)> {
        self.check_alive()?;
        let (r, have) = self.get_vmar(vmar, Rights::MAP)?;
        let rights = derive(have, rights)?;
        let child = r.allocate(offset, len)?;
        let base = child.base();
        let h = self.add(Object::Vmar(child.clone()), rights);
        if h.is_err() {
            child.destroy(); // nobody can reach it: release its range again
            r.remove_child(base);
        }
        Ok((h?, base))
    }

    /// Create a child process of the process behind `parent` (needs `MANAGE` on it), charged
    /// through its quota. The child starts with an empty handle table (nothing inherited).
    /// Returns handles (in *this* process) to the child and to its root VMAR.
    pub fn process_create(&self, parent: Handle, name: &str, limits: Limits) -> KResult<(Handle, Handle)> {
        self.check_alive()?;
        let (p, _) = self.get_process(parent, Rights::MANAGE)?;
        if p.is_dead() {
            return Err(Status::BadState);
        }
        let child = Process::new(Some(&*p), name, limits)?;
        let vmar = child.root_vmar.clone();
        let hp = self.add(Object::Process(child.clone()), default_rights(ObjType::Process));
        let hp = match hp {
            Ok(h) => h,
            Err(e) => {
                child.kill();
                return Err(e);
            }
        };
        match self.add(Object::Vmar(vmar), default_rights(ObjType::Vmar)) {
            Ok(hv) => Ok((hp, hv)),
            Err(e) => {
                let _ = self.handle_close(hp);
                child.kill();
                Err(e)
            }
        }
    }

    /// Needs `MANAGE`.
    pub fn process_kill(&self, h: Handle) -> KResult<()> {
        self.get_process(h, Rights::MANAGE)?.0.kill();
        Ok(())
    }

    /// (limits, usage) of a process. Needs `INSPECT`.
    pub fn process_quota(&self, h: Handle) -> KResult<(Limits, Usage)> {
        let (p, _) = self.get_process(h, Rights::INSPECT)?;
        Ok((p.acct.limits(), p.usage()))
    }

    /// Start a thread running `f` in the process behind `proc` (needs `MANAGE`).
    pub fn thread_create<F>(&self, proc: Handle, name: &'static CStr, f: F) -> KResult<Handle>
    where
        F: FnOnce() -> i32 + Send + 'static,
    {
        self.check_alive()?;
        let (p, _) = self.get_process(proc, Rights::MANAGE)?;
        let t = ThreadObj::spawn(&p, name, f)?;
        self.add(Object::Thread(t), default_rights(ObjType::Thread))
    }

    /// Exit code of a finished thread (`BadState` while it runs). Needs `INSPECT`.
    pub fn thread_exit_code(&self, h: Handle) -> KResult<i32> {
        self.get_thread(h, Rights::INSPECT)?.0.exit_code().ok_or(Status::BadState)
    }
}
