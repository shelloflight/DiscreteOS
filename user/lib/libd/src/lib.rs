//! `libd`: the D-OS user runtime. See Cargo.toml. Modules:
//! - `sys`: every raw syscall and structure of the ABI (docs/abi.md);
//! - `handle`: owned handles (closed on drop), events, timers, `sleep`;
//! - `chan`: channels whose messages carry owned handles;
//! - startup block access (`init`, `startup_handles`, `args`), the debug log (`println!`);
//! - `Mapping`, `Dma`: VMOs mapped here (and pinned for a device);
//! - `Port`: wait on many objects at once (async waits on a port);
//! - `sync`: `Mutex` (futex-style, sleeps on a kernel event when contended), `Once`;
//! - `thread` (feature `alloc`): threads with guarded stacks and a TCB at the FS base;
//! - `heap` (feature `alloc`): the global allocator, safe for many threads;
//! - `proto`: the device manager <-> driver messages; `fs`: files as handles, namespaces;
//! - `svc`: the service manager <-> service messages and endpoint lookup;
//! - `rec` (feature `alloc`): typed records, what shell commands exchange; `term`: the
//!   terminal's session protocol; `tool`: how the shell starts a tool;
//! - `capi` (feature `capi`): the C binding (user/include/libd.h).
//!
//! A program defines its entry with `libd::entry!(symbol, main)`; `main` returns the exit code
//! and calls `libd::init` first.

#![no_std]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "capi")]
pub mod capi;
pub mod chan;
pub mod fs;
pub mod handle;
#[cfg(feature = "alloc")]
pub mod heap;
pub mod log;
pub mod proto;
#[cfg(feature = "alloc")]
pub mod rec;
pub mod svc;
pub mod sync;
pub mod sys;
pub mod term;
#[cfg(feature = "alloc")]
pub mod thread;
pub mod time;
pub mod tool;

use core::fmt::{self, Write};
use core::sync::atomic::{AtomicPtr, AtomicU32, AtomicU64, Ordering};

pub use chan::Channel;
pub use handle::{Event, Owned, Timer};
pub use sys::Handle;

#[repr(C)]
pub struct Startup {
    pub magic: u32,
    pub abi_version: u32,
    pub nhandles: u32,
    pub args_len: u32,
    pub args: u64,
    pub image_base: u64,
    pub stack_base: u64,
    pub stack_size: u64,
}

static STARTUP: AtomicU64 = AtomicU64::new(0);
static LOG: AtomicU32 = AtomicU32::new(0);
static NAME: AtomicPtr<u8> = AtomicPtr::new(core::ptr::null_mut());
static NAME_LEN: AtomicU64 = AtomicU64::new(0);

/// Program entry: `entry!(ddrv_ps2, main)` makes the ELF entry symbol `ddrv_ps2`, which aligns
/// the stack and calls `main(startup) -> i32`; the result is the exit code.
#[macro_export]
macro_rules! entry {
    ($sym:ident, $main:path) => {
        #[unsafe(naked)]
        #[unsafe(no_mangle)]
        pub extern "C" fn $sym() -> ! {
            extern "C" fn trampoline(s: *const $crate::Startup) -> ! {
                $crate::sys::process_exit($main(s))
            }
            core::arch::naked_asm!("xor ebp, ebp", "and rsp, -16", "call {t}", "ud2", t = sym trampoline)
        }
    };
}

/// Validate and remember the startup block; `name` prefixes panics. False if it is not ours (or
/// the kernel's ABI is older than this library's). With `alloc`, the first thread also gets its
/// thread control block (FS base), so `thread::current_id()` works everywhere.
///
/// # Safety
/// `s` is NULL or the startup block pointer the kernel passed to the program's entry point.
pub unsafe fn init(s: *const Startup, name: &'static str) -> bool {
    // SAFETY: the kernel passes its startup block in RDI; checked before any other use.
    let ok = !s.is_null() && unsafe { (*s).magic == sys::STARTUP_MAGIC && (*s).abi_version >= sys::ABI_VERSION };
    if !ok {
        return false;
    }
    STARTUP.store(s as u64, Ordering::Relaxed);
    NAME.store(name.as_ptr().cast_mut(), Ordering::Relaxed);
    NAME_LEN.store(name.len() as u64, Ordering::Relaxed);
    LOG.store(startup_handle(sys::TAG_LOG), Ordering::Relaxed);
    #[cfg(feature = "alloc")]
    {
        let st = startup();
        thread::init_main(st.stack_base, st.stack_base + st.stack_size);
    }
    true
}

fn startup() -> &'static Startup {
    // SAFETY: set once in `init` to the kernel's startup block, which lives (read-only for us) at
    // the top of the initial stack for the life of the process.
    unsafe { &*(STARTUP.load(Ordering::Relaxed) as *const Startup) }
}

/// Startup handles as (handle, tag).
pub fn startup_handles() -> impl Iterator<Item = (Handle, u32)> {
    let s = startup();
    let base = (s as *const Startup as u64) + core::mem::size_of::<Startup>() as u64;
    (0..u64::from(s.nhandles)).map(move |i| {
        // SAFETY: the kernel writes nhandles (handle, tag) pairs right after the header.
        unsafe { (*((base + 8 * i) as *const u32), *((base + 8 * i + 4) as *const u32)) }
    })
}

pub fn startup_handle(tag: u32) -> Handle {
    startup_handles().find(|&(_, t)| t == tag).map_or(0, |(h, _)| h)
}

pub fn args() -> &'static [u8] {
    let s = startup();
    // SAFETY: args_len bytes at `args` (kernel-written, NUL-terminated copy).
    unsafe { core::slice::from_raw_parts(s.args as *const u8, s.args_len as usize) }
}

pub fn root_vmar() -> Handle {
    startup_handle(sys::TAG_VMAR_ROOT)
}

/// The embedded program named `name` (a PROGRAM VMO, found by object name).
pub fn find_program(name: &[u8]) -> Option<Handle> {
    let mut buf = [0u8; 64];
    startup_handles().filter(|&(_, t)| t == sys::TAG_PROGRAM).map(|(h, _)| h).find(|&h| {
        let n = sys::object_name(h, &mut buf);
        n >= 0 && n as usize == name.len() && buf[..name.len()] == *name
    })
}

// ---- output -----------------------------------------------------------------------------------

pub struct Out {
    buf: [u8; 512],
    n: usize,
    level: u32,
}

impl Out {
    pub const fn new() -> Out {
        Out { buf: [0; 512], n: 0, level: sys::LOG_INFO }
    }
    /// Output at a log level (`sys::LOG_*`; the kernel records it with the level).
    pub const fn with_level(level: u32) -> Out {
        Out { buf: [0; 512], n: 0, level }
    }
    pub fn flush(&mut self) {
        let log = LOG.load(Ordering::Relaxed);
        if self.n > 0 && log != 0 {
            if self.level == sys::LOG_INFO {
                sys::log_write(log, &self.buf[..self.n]);
            } else {
                sys::log_record(log, self.level, &self.buf[..self.n]);
            }
        }
        self.n = 0;
    }
}

impl Default for Out {
    fn default() -> Self {
        Out::new()
    }
}

impl Write for Out {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for &b in s.as_bytes() {
            if self.n == self.buf.len() {
                self.flush();
            }
            self.buf[self.n] = b;
            self.n += 1;
        }
        Ok(())
    }
}

pub fn print(args: fmt::Arguments<'_>) {
    let mut o = Out::new();
    let _ = o.write_fmt(args);
    o.flush();
}

#[macro_export]
macro_rules! println {
    ($($t:tt)*) => { $crate::print(format_args!("{}\n", format_args!($($t)*))) };
}

/// A line at a log level (`sys::LOG_*`): the log service keeps it if the program's manifest
/// level allows (`println` is `LOG_INFO`).
pub fn log_line(level: u32, args: fmt::Arguments<'_>) {
    let mut o = Out::with_level(level);
    let _ = o.write_fmt(format_args!("{}\n", args));
    o.flush();
}

#[macro_export]
macro_rules! log_error {
    ($($t:tt)*) => { $crate::log_line($crate::sys::LOG_ERROR, format_args!($($t)*)) };
}
#[macro_export]
macro_rules! log_warn {
    ($($t:tt)*) => { $crate::log_line($crate::sys::LOG_WARN, format_args!($($t)*)) };
}
#[macro_export]
macro_rules! log_debug {
    ($($t:tt)*) => { $crate::log_line($crate::sys::LOG_DEBUG, format_args!($($t)*)) };
}

fn name() -> &'static str {
    let p = NAME.load(Ordering::Relaxed);
    if p.is_null() {
        return "?";
    }
    // SAFETY: set in `init` from a &'static str.
    unsafe { core::str::from_utf8_unchecked(core::slice::from_raw_parts(p, NAME_LEN.load(Ordering::Relaxed) as usize)) }
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo<'_>) -> ! {
    println!("{}: PANIC: {}", name(), info);
    sys::process_exit(127)
}

// ---- memory -------------------------------------------------------------------------------------

/// A VMO mapped read/write into this process.
pub struct Mapping {
    pub vmo: Handle,
    pub addr: u64,
    pub len: u64,
}

impl Mapping {
    pub fn new(len: u64) -> Result<Mapping, i64> {
        let len = len.div_ceil(sys::PAGE) * sys::PAGE;
        let vmo = sys::vmo_create(len)?;
        let addr = sys::vmar_map(root_vmar(), sys::ANY, vmo, 0, len, sys::RIGHT_READ | sys::RIGHT_WRITE)?;
        Ok(Mapping { vmo, addr, len })
    }

    /// Map an existing VMO (e.g. a device BAR) read/write.
    pub fn of(vmo: Handle, len: u64) -> Result<Mapping, i64> {
        let len = len.div_ceil(sys::PAGE) * sys::PAGE;
        let addr = sys::vmar_map(root_vmar(), sys::ANY, vmo, 0, len, sys::RIGHT_READ | sys::RIGHT_WRITE)?;
        Ok(Mapping { vmo, addr, len })
    }

    pub fn r8(&self, off: u64) -> u8 {
        assert!(off < self.len);
        // SAFETY: inside the mapping (checked).
        unsafe { core::ptr::read_volatile((self.addr + off) as *const u8) }
    }
    pub fn r16(&self, off: u64) -> u16 {
        assert!(off + 2 <= self.len && off.is_multiple_of(2));
        // SAFETY: as above, aligned.
        unsafe { core::ptr::read_volatile((self.addr + off) as *const u16) }
    }
    pub fn r32(&self, off: u64) -> u32 {
        assert!(off + 4 <= self.len && off.is_multiple_of(4));
        // SAFETY: as above.
        unsafe { core::ptr::read_volatile((self.addr + off) as *const u32) }
    }
    pub fn r64(&self, off: u64) -> u64 {
        assert!(off + 8 <= self.len && off.is_multiple_of(8));
        // SAFETY: as above.
        unsafe { core::ptr::read_volatile((self.addr + off) as *const u64) }
    }
    pub fn w8(&self, off: u64, v: u8) {
        assert!(off < self.len);
        // SAFETY: as above.
        unsafe { core::ptr::write_volatile((self.addr + off) as *mut u8, v) }
    }
    pub fn w16(&self, off: u64, v: u16) {
        assert!(off + 2 <= self.len && off.is_multiple_of(2));
        // SAFETY: as above.
        unsafe { core::ptr::write_volatile((self.addr + off) as *mut u16, v) }
    }
    pub fn w32(&self, off: u64, v: u32) {
        assert!(off + 4 <= self.len && off.is_multiple_of(4));
        // SAFETY: as above.
        unsafe { core::ptr::write_volatile((self.addr + off) as *mut u32, v) }
    }
    pub fn w64(&self, off: u64, v: u64) {
        assert!(off + 8 <= self.len && off.is_multiple_of(8));
        // SAFETY: as above.
        unsafe { core::ptr::write_volatile((self.addr + off) as *mut u64, v) }
    }
    pub fn bytes(&self) -> &[u8] {
        // SAFETY: the whole mapping is ours, readable, for the life of the process (never
        // unmapped). Device-visible memory: callers synchronise with the device by protocol.
        unsafe { core::slice::from_raw_parts(self.addr as *const u8, self.len as usize) }
    }
    pub fn bytes_mut(&mut self) -> &mut [u8] {
        // SAFETY: as above, writable; `&mut self` makes this the only slice into the mapping
        // (a `&self` version handing out `&mut` slices let two of them alias: clippy mut_from_ref).
        unsafe { core::slice::from_raw_parts_mut(self.addr as *mut u8, self.len as usize) }
    }
}

/// Memory a device may reach: a mapping plus the device address of each page (pinned).
pub struct Dma {
    pub map: Mapping,
    pub pin: Handle,
    pub addrs: [u64; Dma::MAX_PAGES],
    pub pages: usize,
}

impl Dma {
    pub const MAX_PAGES: usize = 32;

    pub fn new(dev: Handle, len: u64, flags: u32) -> Result<Dma, i64> {
        let map = Mapping::new(len)?;
        let pages = (map.len / sys::PAGE) as usize;
        if pages > Self::MAX_PAGES {
            return Err(sys::ERR_INVALID_ARGS);
        }
        let mut addrs = [0u64; Self::MAX_PAGES];
        let pin = sys::dma_map(dev, map.vmo, 0, map.len, flags, &mut addrs[..pages])?;
        Ok(Dma { map, pin, addrs, pages })
    }

    /// Device address of byte `off`.
    pub fn dev_addr(&self, off: u64) -> u64 {
        self.addrs[(off / sys::PAGE) as usize] + off % sys::PAGE
    }
}

// ---- waiting on many objects --------------------------------------------------------------------

/// A port with one-shot async waits: `arm` an object, `wait` for the next completion.
pub struct Port {
    pub h: Handle,
    map: Mapping,
}

/// Port header (`struct dos_port_header`).
const CQ_HEAD: u64 = 12;
const CQ_TAIL: u64 = 16;
const CQ_MASK: u64 = 20;
const CQ_OFF: u64 = 40;

impl Port {
    pub fn new(entries: u32) -> Result<Port, i64> {
        let (h, vmo) = sys::port_create(entries)?;
        let size = 4096 + u64::from(entries) * 64 + u64::from(entries) * 32;
        let map = Mapping::of(vmo, size)?;
        sys::handle_close(vmo);
        Ok(Port { h, map })
    }

    /// One completion (`key`, signals) when a signal in `mask` is set on `obj`.
    pub fn arm(&self, obj: Handle, mask: u32, key: u64) -> i64 {
        sys::object_wait_async(obj, mask, self.h, key)
    }

    /// The next completion: (key, signals), or None after `timeout` ns.
    pub fn wait(&self, timeout: u64) -> Option<(u64, u32)> {
        loop {
            let head = self.map.r32(CQ_HEAD);
            if head != self.map.r32(CQ_TAIL) {
                let mask = self.map.r32(CQ_MASK);
                let off = self.map.r64(CQ_OFF) + u64::from(head & mask) * 16;
                if off + 16 > self.map.len {
                    return None; // the kernel never does this; refuse rather than read outside
                }
                let (key, sigs) = (self.map.r64(off), self.map.r64(off + 8));
                self.map.w32(CQ_HEAD, head.wrapping_add(1));
                return Some((key, sigs as u32));
            }
            match sys::port_enter(self.h, 0, 1, timeout) {
                Ok(_) if self.map.r32(CQ_HEAD) != self.map.r32(CQ_TAIL) => continue,
                _ if timeout == sys::WAIT_FOREVER => continue,
                _ => return None,
            }
        }
    }
}
