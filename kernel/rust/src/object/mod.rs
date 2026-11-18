//! Kernel objects and capabilities: everything is an object behind a handle.
//!
//! - **Objects** (`Object`): reference-counted (`KRef`), typed kernel objects: Process, Thread,
//!   Vmo (pages that can be mapped), Vmar (a region of an address space), Event, Timer, Log,
//!   Channel (messages + handles), Port (shared-memory rings, async waits), Exception
//!   (a stopped thread waiting for its supervisor) and Resource (special authority: VMEX).
//! - **Handles** (`handle.rs`): a process reaches an object only through a handle in its own
//!   handle table. A handle carries **rights**; rights can only shrink (duplicate, replace, grant).
//!   Handle values are scrambled per process and carry a generation, so they are not guessable
//!   indices and a closed handle value stays invalid.
//! - **Quotas** (`quota.rs`): every process has limits for memory, handles and threads, charged
//!   hierarchically (a child also counts against its parent and every ancestor).
//! - **No ambient authority**: an operation needs a handle with the right rights. Creating a
//!   process or a thread needs a handle with `MANAGE` to the process it goes into. The only
//!   un-handled authority is a process creating objects inside itself, bounded by its quota.
//!
//! Every operation returns `KResult<T>`; `Status` codes are negative `i32`s so they can become the
//! syscall ABI unchanged. Out of memory is always `Status::NoMemory`, never a panic:
//! every allocation on these paths is fallible (`KRef::try_new`, `Vec::try_reserve`), and the
//! `objects` test proves it by failing each allocation in turn (fault injection).
//!
//! Locking: handle tables and VMARs use one spinlock rank (`ffi::rank::OBJECT`, below the heap,
//! so they may allocate while held) and are never nested; objects are never dropped while one is
//! held (a drop can free pages or cancel timers).

pub mod aspace;
pub mod channel;
pub mod device;
pub mod event;
pub mod exception;
pub mod handle;
pub mod kref;
pub mod log;
pub mod port;
pub mod process;
pub mod quota;
pub mod resource;
pub mod signals;
pub mod thread;
pub mod timer;
pub mod vmar;
pub mod vmo;

#[cfg(ktest_objects)]
mod tests;
#[cfg(any(ktest_bench, ktest_hwbench, ktest_soak))]
pub mod ktest_hooks;

use core::sync::atomic::{AtomicU64, Ordering};

pub use channel::ChannelObj;
pub use device::{DeviceObj, InterruptObj, PinObj};
pub use event::EventObj;
pub use exception::ExceptionObj;
pub use port::PortObj;
pub use resource::ResourceObj;
pub use log::LogObj;
pub use handle::Handle;
pub use kref::KRef;
pub use process::{Process, kernel_process, kernel_process_ref};
pub use quota::Limits;
pub use thread::ThreadObj;
pub use timer::TimerObj;
pub use vmar::Vmar;
pub use vmo::Vmo;

/// Result codes (future syscall ABI: 0 = OK, errors are negative).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(i32)]
pub enum Status {
    NoMemory = -1,
    InvalidArgs = -2,
    BadHandle = -3,
    WrongType = -4,
    AccessDenied = -5,
    /// A quota (memory, handles, threads) would be exceeded.
    NoResources = -6,
    OutOfRange = -7,
    TimedOut = -8,
    /// The object is in the wrong state (e.g. its process was killed).
    BadState = -9,
    /// No room in an address-space region, or the range overlaps a mapping.
    NoSpace = -10,
    /// A user pointer is not valid user memory (unmapped, kernel address, overflowing range).
    BadAddress = -11,
    /// Unknown syscall, or a feature this kernel does not have.
    NotSupported = -12,
    /// Nothing to do right now (empty channel, full queue): try again later or wait.
    ShouldWait = -13,
    /// The caller's buffer is too small (the sizes needed are reported back).
    BufferTooSmall = -14,
    /// The other end of a channel is closed.
    PeerClosed = -15,
    /// A signature (`.dsig`) does not match the content or the D-OS key (ABI v4).
    BadSignature = -16,
    /// The image is neither signed nor allowed unsigned (ABI v4: spawn).
    NotSigned = -17,
}

pub type KResult<T> = Result<T, Status>;

impl Status {
    pub fn name(self) -> &'static str {
        match self {
            Status::NoMemory => "NO_MEMORY",
            Status::InvalidArgs => "INVALID_ARGS",
            Status::BadHandle => "BAD_HANDLE",
            Status::WrongType => "WRONG_TYPE",
            Status::AccessDenied => "ACCESS_DENIED",
            Status::NoResources => "NO_RESOURCES",
            Status::OutOfRange => "OUT_OF_RANGE",
            Status::TimedOut => "TIMED_OUT",
            Status::BadState => "BAD_STATE",
            Status::NoSpace => "NO_SPACE",
            Status::BadAddress => "BAD_ADDRESS",
            Status::NotSupported => "NOT_SUPPORTED",
            Status::ShouldWait => "SHOULD_WAIT",
            Status::BufferTooSmall => "BUFFER_TOO_SMALL",
            Status::PeerClosed => "PEER_CLOSED",
            Status::BadSignature => "BAD_SIGNATURE",
            Status::NotSigned => "NOT_SIGNED",
        }
    }
}

/// Rights carried by a handle. A right that is not in the handle can never be gained through it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Rights(pub u32);

impl Rights {
    pub const NONE: Rights = Rights(0);
    /// May be duplicated (`handle_duplicate`).
    pub const DUPLICATE: Rights = Rights(1 << 0);
    /// May be moved to another process (`handle_grant`, channel messages).
    pub const TRANSFER: Rights = Rights(1 << 1);
    pub const READ: Rights = Rights(1 << 2);
    pub const WRITE: Rights = Rights(1 << 3);
    pub const EXECUTE: Rights = Rights(1 << 4);
    /// May be mapped into an address space (VMO), or have mappings added (VMAR).
    pub const MAP: Rights = Rights(1 << 5);
    /// May set or clear user signals (Event).
    pub const SIGNAL: Rights = Rights(1 << 6);
    /// May wait on the object's signals.
    pub const WAIT: Rights = Rights(1 << 7);
    /// May read the object's details and statistics (quota usage, sizes).
    pub const INSPECT: Rights = Rights(1 << 8);
    /// May control the object: kill a process, create processes/threads inside it.
    pub const MANAGE: Rights = Rights(1 << 9);
    pub const ALL: Rights = Rights((1 << 10) - 1);

    /// Ask for the same rights as the source handle (duplicate/replace/grant).
    pub const SAME: Rights = Rights(1 << 31);

    pub const fn union(self, o: Rights) -> Rights {
        Rights(self.0 | o.0)
    }
    pub const fn contains(self, o: Rights) -> bool {
        self.0 & o.0 == o.0
    }
    pub const fn intersect(self, o: Rights) -> Rights {
        Rights(self.0 & o.0)
    }
}

impl core::ops::BitOr for Rights {
    type Output = Rights;
    fn bitor(self, o: Rights) -> Rights {
        self.union(o)
    }
}

/// Signal bits observed by `object_wait`.
pub mod sig {
    /// Event: signaled by its owner. Timer: the deadline passed.
    pub const SIGNALED: u32 = 1 << 0;
    /// Process: killed or exited. Thread: finished.
    pub const TERMINATED: u32 = 1 << 1;
    /// Channel: a message is waiting. Port: a completion is waiting.
    pub const READABLE: u32 = 1 << 2;
    /// Channel: the peer's queue has room.
    pub const WRITABLE: u32 = 1 << 3;
    /// Channel: the other end is closed.
    pub const PEER_CLOSED: u32 = 1 << 4;
    /// Bits a program may wait for (the rest are kernel-internal).
    pub const USER_MASK: u32 = (1 << 5) - 1;
    /// Kernel-internal: an exception was resolved; a channel call got its reply.
    pub const RESOLVED: u32 = 1 << 30;
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u32)]
pub enum ObjType {
    Process = 1,
    Thread = 2,
    Vmo = 3,
    Vmar = 4,
    Event = 5,
    Timer = 6,
    Log = 7,
    Channel = 8,
    Port = 9,
    Exception = 10,
    Resource = 11,
    // ABI v3: devices for user-space drivers
    Device = 12,
    Interrupt = 13,
    Pin = 14,
}

pub const OBJ_TYPES: usize = 15;

impl ObjType {
    pub fn name(self) -> &'static str {
        match self {
            ObjType::Process => "process",
            ObjType::Thread => "thread",
            ObjType::Vmo => "vmo",
            ObjType::Vmar => "vmar",
            ObjType::Event => "event",
            ObjType::Timer => "timer",
            ObjType::Log => "log",
            ObjType::Channel => "channel",
            ObjType::Port => "port",
            ObjType::Exception => "exception",
            ObjType::Resource => "resource",
            ObjType::Device => "device",
            ObjType::Interrupt => "interrupt",
            ObjType::Pin => "pin",
        }
    }
}

/// A reference to some kernel object. Typed (no downcasting): the enum is the type check.
#[derive(Clone)]
pub enum Object {
    Process(KRef<Process>),
    Thread(KRef<ThreadObj>),
    Vmo(KRef<Vmo>),
    Vmar(KRef<Vmar>),
    Event(KRef<EventObj>),
    Timer(KRef<TimerObj>),
    Log(KRef<LogObj>),
    Channel(KRef<ChannelObj>),
    Port(KRef<PortObj>),
    Exception(KRef<ExceptionObj>),
    Resource(KRef<ResourceObj>),
    Device(KRef<DeviceObj>),
    Interrupt(KRef<InterruptObj>),
    Pin(KRef<PinObj>),
}

impl Object {
    pub fn obj_type(&self) -> ObjType {
        match self {
            Object::Process(_) => ObjType::Process,
            Object::Thread(_) => ObjType::Thread,
            Object::Vmo(_) => ObjType::Vmo,
            Object::Vmar(_) => ObjType::Vmar,
            Object::Event(_) => ObjType::Event,
            Object::Timer(_) => ObjType::Timer,
            Object::Log(_) => ObjType::Log,
            Object::Channel(_) => ObjType::Channel,
            Object::Port(_) => ObjType::Port,
            Object::Exception(_) => ObjType::Exception,
            Object::Resource(_) => ObjType::Resource,
            Object::Device(_) => ObjType::Device,
            Object::Interrupt(_) => ObjType::Interrupt,
            Object::Pin(_) => ObjType::Pin,
        }
    }

    pub fn koid(&self) -> u64 {
        match self {
            Object::Process(o) => o.header.koid,
            Object::Thread(o) => o.header.koid,
            Object::Vmo(o) => o.header.koid,
            Object::Vmar(o) => o.header.koid,
            Object::Event(o) => o.header.koid,
            Object::Timer(o) => o.header.koid,
            Object::Log(o) => o.header.koid,
            Object::Channel(o) => o.header.koid,
            Object::Port(o) => o.header.koid,
            Object::Exception(o) => o.header.koid,
            Object::Resource(o) => o.header.koid,
            Object::Device(o) => o.header.koid,
            Object::Interrupt(o) => o.header.koid,
            Object::Pin(o) => o.header.koid,
        }
    }

    /// The object's signal state, if it has one.
    pub fn signals(&self) -> Option<&signals::Signals> {
        match self {
            Object::Process(o) => Some(&o.signals),
            Object::Thread(o) => Some(&o.signals),
            Object::Event(o) => Some(&o.signals),
            Object::Timer(o) => Some(&o.signals),
            Object::Channel(o) => Some(o.signals()),
            Object::Port(o) => Some(&o.core.signals),
            Object::Interrupt(o) => Some(&o.signals),
            Object::Vmo(_)
            | Object::Vmar(_)
            | Object::Log(_)
            | Object::Exception(_)
            | Object::Resource(_)
            | Object::Device(_)
            | Object::Pin(_) => None,
        }
    }
}

/// Rights a fresh handle to a new object of each type gets.
pub fn default_rights(t: ObjType) -> Rights {
    let base = Rights::DUPLICATE | Rights::TRANSFER;
    match t {
        ObjType::Process | ObjType::Thread => base | Rights::WAIT | Rights::INSPECT | Rights::MANAGE,
        // No EXECUTE: executable VMOs only come from the kernel's program loader.
        ObjType::Vmo => base | Rights::READ | Rights::WRITE | Rights::MAP | Rights::INSPECT,
        ObjType::Vmar => {
            base | Rights::READ | Rights::WRITE | Rights::EXECUTE | Rights::MAP | Rights::INSPECT
        }
        ObjType::Event => base | Rights::SIGNAL | Rights::WAIT,
        ObjType::Timer => base | Rights::WRITE | Rights::WAIT,
        ObjType::Log => base | Rights::WRITE,
        ObjType::Channel => base | Rights::READ | Rights::WRITE | Rights::WAIT,
        ObjType::Port => base | Rights::READ | Rights::WRITE | Rights::WAIT,
        ObjType::Exception => base | Rights::READ | Rights::WRITE | Rights::MANAGE,
        ObjType::Resource => base | Rights::MANAGE,
        ObjType::Device => base | Rights::READ | Rights::WRITE | Rights::MAP | Rights::INSPECT | Rights::MANAGE,
        ObjType::Interrupt => base | Rights::WRITE | Rights::WAIT | Rights::INSPECT,
        ObjType::Pin => base | Rights::INSPECT,
    }
}

// ---- object header: id + live accounting ------------------------------------------------------

static NEXT_KOID: AtomicU64 = AtomicU64::new(1);
static LIVE: [AtomicU64; OBJ_TYPES] = [const { AtomicU64::new(0) }; OBJ_TYPES];

/// Embedded in every object: its kernel object id (unique, never reused) and the live counter
/// of its type (decremented when the object is destroyed, so leaks are visible).
pub struct Header {
    pub koid: u64,
    ty: ObjType,
}

impl Header {
    pub fn new(ty: ObjType) -> Header {
        LIVE[ty as usize].fetch_add(1, Ordering::Relaxed);
        Header {
            koid: NEXT_KOID.fetch_add(1, Ordering::Relaxed),
            ty,
        }
    }
}

impl Drop for Header {
    fn drop(&mut self) {
        LIVE[self.ty as usize].fetch_sub(1, Ordering::Relaxed);
    }
}

/// Live objects of a type (leak checks, inspection).
pub fn live(t: ObjType) -> u64 {
    LIVE[t as usize].load(Ordering::Relaxed)
}

/// Live objects of every type, indexed by `ObjType as usize`.
pub fn live_all() -> [u64; OBJ_TYPES] {
    core::array::from_fn(|i| LIVE[i].load(Ordering::Relaxed))
}

/// Leak check (ktest fuzz): live objects before user space starts...
#[cfg(ktest)]
static LEAK_BASE: [AtomicU64; OBJ_TYPES] = [const { AtomicU64::new(0) }; OBJ_TYPES];

#[cfg(ktest)]
#[unsafe(no_mangle)]
pub extern "C" fn rust_objects_snapshot() {
    for (i, n) in live_all().iter().enumerate() {
        LEAK_BASE[i].store(*n, Ordering::Relaxed);
    }
}

/// ...and after init (and everything it started) has exited: the types user space creates must
/// be back to their count. Waits up to 2 s for exiting processes to be torn down. Returns how
/// many types leaked (each one printed).
#[cfg(ktest)]
#[unsafe(no_mangle)]
pub extern "C" fn rust_channels_collected() -> u64 {
    channel::collected()
}

#[cfg(ktest)]
#[unsafe(no_mangle)]
pub extern "C" fn rust_objects_leaked() -> u32 {
    const CHECKED: [ObjType; 7] =
        [ObjType::Channel, ObjType::Port, ObjType::Event, ObjType::Timer, ObjType::Vmo, ObjType::Exception, ObjType::Process];
    let excess = || CHECKED.iter().filter(|t| live(**t) > LEAK_BASE[**t as usize].load(Ordering::Relaxed)).count();
    for _ in 0..200 {
        if excess() == 0 {
            break;
        }
        // SAFETY: plain sleep of the calling kernel thread.
        unsafe { crate::ffi::thread_sleep_ns(10_000_000) };
    }
    let mut leaked = 0;
    for t in CHECKED {
        let (now, before) = (live(t), LEAK_BASE[t as usize].load(Ordering::Relaxed));
        if now > before {
            crate::kprintln!("  leak: {} live {}s after user space ended (before: {})", now, t.name(), before);
            leaked += 1;
        }
    }
    leaked
}

/// Fixed-size object name (no allocation; truncated at 31 bytes).
#[derive(Clone, Copy)]
pub struct Name {
    len: u8,
    bytes: [u8; 31],
}

impl Name {
    pub fn new(s: &str) -> Name {
        let mut n = Name {
            len: 0,
            bytes: [0; 31],
        };
        let b = s.as_bytes();
        let len = b.len().min(31);
        n.bytes[..len].copy_from_slice(&b[..len]);
        n.len = len as u8;
        n
    }

    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.bytes[..usize::from(self.len)]).unwrap_or("?")
    }
}

/// Bring the object layer up: the kernel process (root of the quota tree). Called by dkrnl_init.
pub fn init() {
    process::init_kernel_process();
    crate::kprintln!(
        "Objects: handles with rights, {} object types, hierarchical quotas; kernel process koid {}",
        OBJ_TYPES - 1,
        kernel_process().header.koid
    );
}

/// Inspection (`kdb`-style): live objects per type and the process tree's handle and quota use.
pub fn print_summary() {
    let l = live_all();
    crate::kprintln!(
        "Objects: {} processes, {} threads, {} vmos ({} frames), {} vmars, {} events, {} timers, {} channels, {} ports, {} exceptions, {} devices, {} interrupts, {} pins",
        l[ObjType::Process as usize],
        l[ObjType::Thread as usize],
        l[ObjType::Vmo as usize],
        vmo::committed_frames(),
        l[ObjType::Vmar as usize],
        l[ObjType::Event as usize],
        l[ObjType::Timer as usize],
        l[ObjType::Channel as usize],
        l[ObjType::Port as usize],
        l[ObjType::Exception as usize],
        l[ObjType::Device as usize],
        l[ObjType::Interrupt as usize],
        l[ObjType::Pin as usize]
    );
}

#[unsafe(no_mangle)]
pub extern "C" fn dkrnl_objects_print() {
    print_summary();
}
