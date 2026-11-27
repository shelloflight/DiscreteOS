//! Windows personality (docs/compat.md): a user-space PE32+ executable & DLL loader plus
//! D-CMPL's `kernel32` / `kernelbase` / `ntdll` / `vcruntime140` / `ucrtbase`, running unmodified
//! Windows programs (static `/MT` and dynamic `/MD`, plus custom PE DLLs) inside this process.
//!
//! Loading:
//! 1. parse and validate the PE32+ image (`pe.rs`);
//! 2. reserve its span at the preferred ImageBase (a VMAR sub-region at a fixed address), or
//!    anywhere if that is taken (then base relocations are applied);
//! 3. lay the image out in a private staging buffer, relocate, bind imports against built-in
//!    D-CMPL shims (`kernel32`, `kernelbase`, `ntdll`, `vcruntime140`, `vcruntime140_1`,
//!    `ucrtbase`, and Windows API sets) and recursively loaded PE `.dll` modules following the
//!    Windows DLL search order (loaded -> built-ins -> explicit path -> app dir -> embedded ->
//!    prefix system32 -> CWD -> PATH);
//! 4. map page-exactly: headers R, each section in its own VMO with exact permissions; code is
//!    **sealed and made executable with VMEX** before mapping so W^X holds for all foreign code;
//! 5. initialize PEB, main thread stack (with guard pages), TEB at GS, per-module TLS blocks for
//!    the EXE and all loaded DLLs, and in-process SEH handler (`seh.rs`);
//! 6. run `DllMain(DLL_PROCESS_ATTACH)` + TLS callbacks in dependency order, then call the EXE
//!    entry point on its stack.

pub mod crt;
pub mod k32;
pub mod obj;
pub mod seh;

use alloc::alloc::{Layout, alloc_zeroed, dealloc};
use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::arch::asm;
use core::sync::atomic::{AtomicPtr, AtomicU32, AtomicUsize, Ordering};

use libd::sync::Mutex;
use libd::sys::{self, Handle};
use libd::println;

use crate::pe::{self, ExportRef, PeError};
use crate::{EXIT_REFUSED, EXIT_USAGE, PAGE, USER_BASE, USER_TOP, find_image, path, read_image, text};
use seh::Context;

/// Lightweight copy of a loaded PE module's address & `.pdata` span (used by SEH without holding
/// any lock while executing language handlers).
#[derive(Clone, Copy)]
pub struct ModSpan {
    pub base: u64,
    pub size: u64,
    pub pdata_rva: u32,
    pub pdata_count: u64,
}

/// The main executable's metadata (kept lock-free for fast access).
pub struct ImageInfo {
    pub base: u64,
    pub size: u64,
    pub entry: u64,
    pub pdata_rva: u32,
    pub pdata_count: u64,
    pub tls: Option<pe::Tls>,
    pub stack_reserve: u64,
    pub name: String,
}

static NO_IMAGE: ImageInfo = ImageInfo {
    base: 0,
    size: 0,
    entry: 0,
    pdata_rva: 0,
    pdata_count: 0,
    tls: None,
    stack_reserve: 0,
    name: String::new(),
};
static IMAGE: AtomicPtr<ImageInfo> = AtomicPtr::new(core::ptr::null_mut());
static VMEX_HANDLE: AtomicU32 = AtomicU32::new(0);

pub fn image() -> &'static ImageInfo {
    let p = IMAGE.load(Ordering::Acquire);
    // SAFETY: set once (a leaked box) before the program runs; never freed.
    if p.is_null() { &NO_IMAGE } else { unsafe { &*p } }
}

pub fn println_unhandled(args: core::fmt::Arguments<'_>) {
    println!("dcmpl: {}: {}", image().name, args);
}

// ---- built-in shim modules & Windows DLL registry -----------------------------------------------

pub const HMOD_KERNEL32: u64 = 0x0D05_1000_0000;
pub const HMOD_KERNELBASE: u64 = 0x0D05_1001_0000;
pub const HMOD_NTDLL: u64 = 0x0D05_1002_0000;
pub const HMOD_UCRTBASE: u64 = 0x0D05_1003_0000;
pub const HMOD_VCRUNTIME140: u64 = 0x0D05_1004_0000;
pub const HMOD_VCRUNTIME140_1: u64 = 0x0D05_1005_0000;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum BuiltinDll {
    Kernel32,
    KernelBase,
    Ntdll,
    UcrtBase,
    VcRuntime140,
    VcRuntime140_1,
}

impl BuiltinDll {
    pub fn hmod(self) -> u64 {
        match self {
            Self::Kernel32 => HMOD_KERNEL32,
            Self::KernelBase => HMOD_KERNELBASE,
            Self::Ntdll => HMOD_NTDLL,
            Self::UcrtBase => HMOD_UCRTBASE,
            Self::VcRuntime140 => HMOD_VCRUNTIME140,
            Self::VcRuntime140_1 => HMOD_VCRUNTIME140_1,
        }
    }

    pub fn from_hmod(h: u64) -> Option<Self> {
        match h {
            HMOD_KERNEL32 => Some(Self::Kernel32),
            HMOD_KERNELBASE => Some(Self::KernelBase),
            HMOD_NTDLL => Some(Self::Ntdll),
            HMOD_UCRTBASE => Some(Self::UcrtBase),
            HMOD_VCRUNTIME140 => Some(Self::VcRuntime140),
            HMOD_VCRUNTIME140_1 => Some(Self::VcRuntime140_1),
            _ => None,
        }
    }

    pub fn canonical_win_path(self) -> &'static str {
        match self {
            Self::Kernel32 => "C:\\Windows\\System32\\kernel32.dll",
            Self::KernelBase => "C:\\Windows\\System32\\kernelbase.dll",
            Self::Ntdll => "C:\\Windows\\System32\\ntdll.dll",
            Self::UcrtBase => "C:\\Windows\\System32\\ucrtbase.dll",
            Self::VcRuntime140 => "C:\\Windows\\System32\\vcruntime140.dll",
            Self::VcRuntime140_1 => "C:\\Windows\\System32\\vcruntime140_1.dll",
        }
    }

    pub fn resolve(self, func: &[u8]) -> Option<u64> {
        match self {
            Self::Kernel32 => k32::lookup_builtin(func),
            Self::KernelBase => k32::lookup_builtin(func).or_else(|| crt::lookup_kernelbase(func)),
            Self::Ntdll => crt::lookup_ntdll(func).or_else(|| k32::lookup_builtin(func)),
            Self::UcrtBase => crt::lookup_ucrt(func),
            Self::VcRuntime140 => crt::lookup_vcruntime(func),
            Self::VcRuntime140_1 => crt::lookup_vcruntime_1(func).or_else(|| crt::lookup_vcruntime(func)),
        }
    }
}

/// Extract ASCII lowercase basename (with `.dll` appended if no extension).
fn norm_dll_name(raw: &[u8]) -> String {
    let base = match raw.iter().rposition(|&c| c == b'\\' || c == b'/') {
        Some(i) => &raw[i + 1..],
        None => raw,
    };
    let mut s = String::with_capacity(base.len() + 4);
    for &c in base {
        s.push(c.to_ascii_lowercase() as char);
    }
    if !s.is_empty() && !s.contains('.') {
        s.push_str(".dll");
    }
    s
}

/// Map a DLL or Windows API-set name to a built-in D-CMPL shim DLL, if any.
pub fn builtin_for(raw: &[u8]) -> Option<BuiltinDll> {
    let n = norm_dll_name(raw);
    let b = n.as_bytes();
    if b == b"kernel32.dll" {
        return Some(BuiltinDll::Kernel32);
    }
    if b == b"kernelbase.dll" {
        return Some(BuiltinDll::KernelBase);
    }
    if b == b"ntdll.dll" {
        return Some(BuiltinDll::Ntdll);
    }
    if b == b"ucrtbase.dll" || b == b"ucrtbased.dll" || b.starts_with(b"api-ms-win-crt-") {
        return Some(BuiltinDll::UcrtBase);
    }
    if b == b"vcruntime140.dll" || b == b"vcruntime140d.dll" {
        return Some(BuiltinDll::VcRuntime140);
    }
    if b == b"vcruntime140_1.dll" || b == b"vcruntime140_1d.dll" {
        return Some(BuiltinDll::VcRuntime140_1);
    }
    if b.starts_with(b"api-ms-win-core-") || b.starts_with(b"api-ms-win-security-") {
        return Some(BuiltinDll::KernelBase);
    }
    None
}

/// A loaded PE32+ image (either the main EXE or a loaded DLL).
struct Module {
    base: u64,
    size: u64,
    entry: u64,
    is_dll: bool,
    img: pe::Image,
    tls: Option<(usize, pe::Tls)>,
    refcount: u32,
    attached: bool,
    name: String,
    win_path: Vec<u16>,
    region: Handle,
}

static MODULES: Mutex<Vec<Module>> = Mutex::new(Vec::new());
static NEXT_TLS_INDEX: AtomicUsize = AtomicUsize::new(0);
/// Guards against circular or deeply nested `LoadLibrary` / forwarder resolution.
const MAX_FORWARD_DEPTH: usize = 8;

/// Find the loaded module covering instruction pointer `pc` (for multi-module SEH).
pub fn module_for_pc(pc: u64) -> Option<ModSpan> {
    let im = image();
    if pc >= im.base && pc < im.base + im.size {
        return Some(ModSpan { base: im.base, size: im.size, pdata_rva: im.pdata_rva, pdata_count: im.pdata_count });
    }
    let mods = MODULES.lock();
    mods.iter().find(|m| pc >= m.base && pc < m.base + m.size).map(|m| ModSpan {
        base: m.base,
        size: m.size,
        pdata_rva: m.img.exception.rva,
        pdata_count: u64::from(m.img.exception.size / 12),
    })
}

/// Find a loaded module by its exact base address (`HMODULE`).
pub fn module_for_base(base: u64) -> Option<ModSpan> {
    let im = image();
    if base == im.base && base != 0 {
        return Some(ModSpan { base: im.base, size: im.size, pdata_rva: im.pdata_rva, pdata_count: im.pdata_count });
    }
    let mods = MODULES.lock();
    mods.iter().find(|m| m.base == base).map(|m| ModSpan {
        base: m.base,
        size: m.size,
        pdata_rva: m.img.exception.rva,
        pdata_count: u64::from(m.img.exception.size / 12),
    })
}

/// Lookup an already-loaded module handle by name (built-in or PE module).
pub fn find_loaded_module(name: &[u8]) -> Option<u64> {
    if let Some(b) = builtin_for(name) {
        return Some(b.hmod());
    }
    let want = norm_dll_name(name);
    let mods = MODULES.lock();
    if let Some(m) = mods.iter().find(|m| m.name == want) {
        return Some(m.base);
    }
    // Also match main EXE without `.dll` suffix (e.g. `GetModuleHandleA("w3.exe")`).
    let raw_lower: String = name.iter().map(|&c| c.to_ascii_lowercase() as char).collect();
    mods.iter().find(|m| m.name == raw_lower).map(|m| m.base)
}

/// Return the UTF-16 Windows path of a module handle (`0` = main EXE).
pub fn module_win_path(hmod: u64) -> Option<Vec<u16>> {
    if hmod == 0 || hmod == image().base {
        let mods = MODULES.lock();
        if let Some(m) = mods.first() {
            return Some(m.win_path.clone());
        }
        return None;
    }
    if let Some(b) = BuiltinDll::from_hmod(hmod) {
        return Some(b.canonical_win_path().encode_utf16().collect());
    }
    let mods = MODULES.lock();
    mods.iter().find(|m| m.base == hmod).map(|m| m.win_path.clone())
}

// ---- threads & multi-module TLS ------------------------------------------------------------------

pub const TEB_SIZE: usize = 0x2000;
const TEB_STACK_BASE: usize = 0x08;
const TEB_STACK_LIMIT: usize = 0x10;
const TEB_SELF: usize = 0x30;
const TEB_PID: usize = 0x40;
const TEB_TID: usize = 0x48;
const TEB_TLS_POINTER: usize = 0x58;
const TEB_PEB: usize = 0x60;
pub const TEB_LAST_ERROR: usize = 0x68;
pub const TEB_TLS_SLOTS: usize = 0x1480;
/// D-CMPL's own per-thread block (past the end of the real TEB).
const TEB_PRIVATE: usize = 0x1900;
pub const TLS_SLOTS: usize = 64;
pub const FLS_SLOTS: usize = 128;
pub const MAX_TLS_MODULES: usize = 32;
/// The in-process exception handler's stack (filters, `__finally` blocks and catch blocks of a
/// fault run on it).
const HANDLER_STACK: usize = 256 * 1024;

/// D-CMPL's per-thread state for a Windows thread.
pub struct WinThread {
    pub teb: u64,
    pub stack_lo: u64,
    pub stack_hi: u64,
    pub id: u32,
    /// Dispatching an exception (its CONTEXT), and whether it came from a fault (then
    /// `fault_rec` is the kernel's record, resumed with exception_return).
    pub dispatch_ctx: *mut Context,
    pub in_fault: bool,
    pub fault_rec: *mut sys::ExceptionRecord,
    /// Current C++ exception record & context (for `__current_exception` / `_context`).
    pub cur_exc_rec: u64,
    pub cur_exc_ctx: u64,
    /// Per-thread `errno` for `ucrtbase::_errno`.
    pub crt_errno: i32,
    tls_array: [u64; MAX_TLS_MODULES],
    tls_sizes: [usize; MAX_TLS_MODULES],
    pub fls: [u64; FLS_SLOTS],
    handler_stack: Vec<u8>,
}

/// The calling thread's state (None outside a Windows thread).
pub fn current_thread() -> Option<&'static mut WinThread> {
    let teb: u64;
    // SAFETY: Windows threads have GS = their TEB, whose self pointer is at 0x30; only called
    // from code running on a Windows thread (kernel32 exports, the fault handler).
    unsafe { asm!("mov {}, gs:[0x30]", out(reg) teb, options(nostack, readonly, preserves_flags)) };
    if teb == 0 {
        return None;
    }
    // SAFETY: the TEB is ours (TEB_SIZE bytes); the private slot holds a leaked WinThread.
    let p = unsafe { ((teb + TEB_PRIVATE as u64) as *const u64).read() } as *mut WinThread;
    // SAFETY: as above; only this thread uses its own block mutably.
    unsafe { p.as_mut() }
}

static THREADS: Mutex<Vec<usize>> = Mutex::new(Vec::new());
static TLS_USED: Mutex<u64> = Mutex::new(0);
static FLS: Mutex<(u128, [u64; FLS_SLOTS])> = Mutex::new((0, [0; FLS_SLOTS]));
static PEB: AtomicPtr<u8> = AtomicPtr::new(core::ptr::null_mut());
static NEXT_TID: AtomicU32 = AtomicU32::new(1);

pub fn peb() -> u64 {
    PEB.load(Ordering::Relaxed) as u64
}

/// A new thread id: small and unique, a multiple of 4 like Windows'.
pub fn new_tid() -> u32 {
    NEXT_TID.fetch_add(1, Ordering::Relaxed) * 4
}

pub fn current_tid() -> u32 {
    current_thread().map_or(0, |t| t.id)
}

fn teb_put(teb: u64, off: usize, v: u64) {
    // SAFETY: inside the TEB allocation (offsets below TEB_SIZE).
    unsafe { ((teb + off as u64) as *mut u64).write(v) }
}

fn alloc_tls_block(base: u64, tls: pe::Tls) -> Result<(u64, usize), i64> {
    let len = (tls.template_len + tls.zero_fill).max(16) as usize;
    let l = Layout::from_size_align(len, 64).map_err(|_| sys::ERR_NO_MEMORY)?;
    // SAFETY: non-zero aligned size.
    let b = unsafe { alloc_zeroed(l) };
    if b.is_null() {
        return Err(sys::ERR_NO_MEMORY);
    }
    if tls.template_len > 0 {
        // SAFETY: the template lies inside the mapped image (checked by pe::Image::tls).
        unsafe {
            core::ptr::copy_nonoverlapping((base + u64::from(tls.template_rva)) as *const u8, b, tls.template_len as usize);
        }
    }
    Ok((b as u64, len))
}

/// Make the calling thread a Windows thread on the stack [lo, hi): TEB at GS, TLS blocks for
/// every loaded module, FLS data, exception handler.
fn setup_thread(lo: u64, hi: u64, id: u32) -> Result<(), i64> {
    let lay = Layout::from_size_align(TEB_SIZE, 64).map_err(|_| sys::ERR_NO_MEMORY)?;
    // SAFETY: a non-zero size.
    let teb = unsafe { alloc_zeroed(lay) } as u64;
    if teb == 0 {
        return Err(sys::ERR_NO_MEMORY);
    }
    let mut hs: Vec<u8> = Vec::new();
    hs.try_reserve_exact(HANDLER_STACK).map_err(|_| sys::ERR_NO_MEMORY)?;
    hs.resize(HANDLER_STACK, 0);
    let mut t = Box::new(WinThread {
        teb,
        stack_lo: lo,
        stack_hi: hi,
        id,
        dispatch_ctx: core::ptr::null_mut(),
        in_fault: false,
        fault_rec: core::ptr::null_mut(),
        cur_exc_rec: 0,
        cur_exc_ctx: 0,
        crt_errno: 0,
        tls_array: [0; MAX_TLS_MODULES],
        tls_sizes: [0; MAX_TLS_MODULES],
        fls: [0; FLS_SLOTS],
        handler_stack: hs,
    });
    let tls_mods: Vec<(usize, u64, pe::Tls)> = {
        let mods = MODULES.lock();
        mods.iter().filter_map(|m| m.tls.map(|(idx, tls)| (idx, m.base, tls))).collect()
    };
    for (idx, base, tls) in tls_mods {
        if idx < MAX_TLS_MODULES {
            let (ptr, len) = alloc_tls_block(base, tls)?;
            t.tls_array[idx] = ptr;
            t.tls_sizes[idx] = len;
        }
    }
    teb_put(teb, TEB_STACK_BASE, hi);
    teb_put(teb, TEB_STACK_LIMIT, lo);
    teb_put(teb, TEB_SELF, teb);
    teb_put(teb, TEB_PID, 4);
    teb_put(teb, TEB_TID, u64::from(id));
    teb_put(teb, TEB_TLS_POINTER, t.tls_array.as_ptr() as u64);
    teb_put(teb, TEB_PEB, peb());
    let hs_top = (t.handler_stack.as_ptr() as u64 + HANDLER_STACK as u64) & !15;
    let raw = Box::into_raw(t);
    teb_put(teb, TEB_PRIVATE, raw as u64);
    let r = sys::thread_set_base(sys::BASE_GS, teb);
    if r < 0 {
        return Err(r);
    }
    sys::thread_set_exception_handler(seh::dcmpl_fault_entry as *const () as u64, hs_top);
    THREADS.lock().push(raw as usize);
    Ok(())
}

type TlsCallback = extern "win64" fn(u64, u32, u64);
type DllMainFn = extern "win64" fn(u64, u32, u64) -> i32;

const DLL_PROCESS_DETACH: u32 = 0;
const DLL_PROCESS_ATTACH: u32 = 1;
const DLL_THREAD_ATTACH: u32 = 2;
const DLL_THREAD_DETACH: u32 = 3;

fn call_module_tls(base: u64, t: pe::Tls, reason: u32) {
    for &cb in &t.callbacks[..t.ncallbacks] {
        // SAFETY: checked by pe::Image::tls to lie in an executable section of the image.
        let f: TlsCallback = unsafe { core::mem::transmute::<u64, TlsCallback>(base + u64::from(cb)) };
        f(base, reason, 0);
    }
}

/// Call TLS callbacks and `DllMain` for all attached modules on thread attach/detach.
fn notify_threads(reason: u32) {
    let list: Vec<(u64, u64, bool, Option<pe::Tls>)> = {
        let mods = MODULES.lock();
        mods.iter()
            .filter(|m| m.attached || !m.is_dll)
            .map(|m| (m.base, m.entry, m.is_dll, m.tls.map(|(_, t)| t)))
            .collect()
    };
    if reason == DLL_THREAD_DETACH {
        for &(base, entry, is_dll, tls) in list.iter().rev() {
            if let Some(t) = tls {
                call_module_tls(base, t, reason);
            }
            if is_dll && entry != 0 {
                // SAFETY: validated PE entry point inside an executable section.
                let f: DllMainFn = unsafe { core::mem::transmute::<u64, DllMainFn>(entry) };
                let _ = f(base, reason, 0);
            }
        }
    } else {
        for &(base, entry, is_dll, tls) in &list {
            if let Some(t) = tls {
                call_module_tls(base, t, reason);
            }
            if is_dll && entry != 0 {
                // SAFETY: validated PE entry point inside an executable section.
                let f: DllMainFn = unsafe { core::mem::transmute::<u64, DllMainFn>(entry) };
                let _ = f(base, reason, 0);
            }
        }
    }
}

/// Attach all pending DLLs (loaded statically before the main thread TEB existed) in dependency
/// order, then run the main EXE's TLS callbacks.
fn attach_initial_modules() {
    let list: Vec<(u64, u64, bool, Option<pe::Tls>)> = {
        let mut mods = MODULES.lock();
        let mut out = Vec::new();
        for m in mods.iter_mut() {
            if m.is_dll && !m.attached {
                m.attached = true;
                out.push((m.base, m.entry, true, m.tls.map(|(_, t)| t)));
            }
        }
        if let Some(exe) = mods.first_mut() {
            exe.attached = true;
            out.push((exe.base, exe.entry, false, exe.tls.map(|(_, t)| t)));
        }
        out
    };
    for (base, entry, is_dll, tls) in list {
        if let Some(t) = tls {
            call_module_tls(base, t, DLL_PROCESS_ATTACH);
        }
        if is_dll && entry != 0 {
            // SAFETY: validated DLL entry point inside an executable section.
            let f: DllMainFn = unsafe { core::mem::transmute::<u64, DllMainFn>(entry) };
            let _ = f(base, DLL_PROCESS_ATTACH, 1);
        }
    }
}

/// Detach loaded DLLs on process exit (reverse order).
pub fn detach_all_dlls() {
    let list: Vec<(u64, u64, Option<pe::Tls>)> = {
        let mut mods = MODULES.lock();
        let mut out = Vec::new();
        for m in mods.iter_mut().rev() {
            if m.is_dll && m.attached {
                m.attached = false;
                out.push((m.base, m.entry, m.tls.map(|(_, t)| t)));
            }
        }
        out
    };
    for (base, entry, tls) in list {
        if entry != 0 {
            // SAFETY: validated DLL entry point.
            let f: DllMainFn = unsafe { core::mem::transmute::<u64, DllMainFn>(entry) };
            let _ = f(base, DLL_PROCESS_DETACH, 1);
        }
        if let Some(t) = tls {
            call_module_tls(base, t, DLL_PROCESS_DETACH);
        }
    }
}

/// End the calling Windows thread: thread-detach callbacks, FLS callbacks, then its state.
pub fn finish_thread(code: u32) -> ! {
    notify_threads(DLL_THREAD_DETACH);
    if let Some(t) = current_thread() {
        let cbs = FLS.lock().1;
        for i in 0..FLS_SLOTS {
            let v = t.fls[i];
            if v != 0 && cbs[i] != 0 {
                t.fls[i] = 0;
                type Cb = extern "win64" fn(u64);
                // SAFETY: the program's own FLS callback (FlsAlloc).
                let f: Cb = unsafe { core::mem::transmute::<u64, Cb>(cbs[i]) };
                f(v);
            }
        }
        sys::thread_set_exception_handler(0, 0);
        let raw = t as *mut WinThread;
        THREADS.lock().retain(|&p| p != raw as usize);
        // SAFETY: made by setup_thread; nothing uses it after this (the thread ends below).
        let t = unsafe { Box::from_raw(raw) };
        for i in 0..MAX_TLS_MODULES {
            let ptr = t.tls_array[i];
            let len = t.tls_sizes[i];
            if ptr != 0 && len > 0
                && let Ok(l) = Layout::from_size_align(len, 64)
            {
                // SAFETY: allocated in alloc_tls_block with this layout.
                unsafe { dealloc(ptr as *mut u8, l) };
            }
        }
        let teb = t.teb;
        drop(t);
        sys::thread_set_base(sys::BASE_GS, 0);
        if let Ok(l) = Layout::from_size_align(TEB_SIZE, 64) {
            // SAFETY: allocated in setup_thread with this layout; GS no longer points at it.
            unsafe { dealloc(teb as *mut u8, l) };
        }
    }
    sys::thread_exit(code as i32)
}

/// TlsAlloc / TlsFree / FlsAlloc / FlsFree: slot bookkeeping, and clearing a freed slot in every
/// thread (as Windows does).
pub fn tls_alloc() -> Option<usize> {
    let mut m = TLS_USED.lock();
    let i = (!*m).trailing_zeros() as usize;
    if i >= TLS_SLOTS {
        return None;
    }
    *m |= 1 << i;
    for &p in THREADS.lock().iter() {
        // SAFETY: a live thread's block; the slot is unused, nobody else writes it.
        teb_put(unsafe { (*(p as *const WinThread)).teb }, TEB_TLS_SLOTS + 8 * i, 0);
    }
    Some(i)
}
pub fn tls_free(i: usize) -> bool {
    let mut m = TLS_USED.lock();
    if i >= TLS_SLOTS || *m & (1 << i) == 0 {
        return false;
    }
    *m &= !(1 << i);
    true
}
pub fn tls_valid(i: usize) -> bool {
    i < TLS_SLOTS && *TLS_USED.lock() & (1 << i) != 0
}
pub fn fls_alloc(cb: u64) -> Option<usize> {
    let mut f = FLS.lock();
    let i = (!f.0).trailing_zeros() as usize;
    if i >= FLS_SLOTS {
        return None;
    }
    f.0 |= 1 << i;
    f.1[i] = cb;
    for &p in THREADS.lock().iter() {
        // SAFETY: a live thread's block; the slot was unused.
        unsafe { (*(p as *mut WinThread)).fls[i] = 0 };
    }
    Some(i)
}
pub fn fls_valid(i: usize) -> bool {
    i < FLS_SLOTS && FLS.lock().0 & (1 << i) != 0
}
pub fn fls_free(i: usize) -> bool {
    let cb = {
        let mut f = FLS.lock();
        if i >= FLS_SLOTS || f.0 & (1 << i) == 0 {
            return false;
        }
        f.0 &= !(1 << i);
        core::mem::take(&mut f.1[i])
    };
    if let Some(t) = current_thread() {
        let v = core::mem::take(&mut t.fls[i]);
        if v != 0 && cb != 0 {
            type Cb = extern "win64" fn(u64);
            // SAFETY: the program's own FLS callback.
            let f: Cb = unsafe { core::mem::transmute::<u64, Cb>(cb) };
            f(v);
        }
    }
    true
}

/// The body of a thread made by CreateThread / _beginthreadex: become a Windows thread, notify
/// loaded DLLs, wait for ResumeThread if suspended, run the start routine, end.
pub fn thread_main(start: u64, param: u64, gate: Option<Handle>, id: u32) -> ! {
    let tcb = libd::thread::current();
    if setup_thread(tcb.stack_lo, tcb.stack_hi, id).is_err() {
        sys::thread_exit(sys::ERR_NO_MEMORY as i32);
    }
    notify_threads(DLL_THREAD_ATTACH);
    if let Some(g) = gate {
        let _ = sys::object_wait(g, sys::SIGNALED, sys::WAIT_FOREVER);
    }
    type Start = extern "win64" fn(u64) -> u32;
    // SAFETY: the program's own thread routine (CreateThread's lpStartAddress).
    let f: Start = unsafe { core::mem::transmute::<u64, Start>(start) };
    let code = f(param);
    finish_thread(code)
}

// ---- loader & DLL search order ------------------------------------------------------------------

struct Loaded {
    base: u64,
    preferred: bool,
    relocs: u32,
    imports: u32,
    /// Parse + map + bind in TSC cycles.
    image_cycles: u64,
}

fn rdtsc() -> u64 {
    let (lo, hi): (u32, u32);
    // SAFETY: rdtsc is allowed in ring 3 (docs/abi.md); it only writes EAX and EDX.
    unsafe { asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack)) };
    (u64::from(hi) << 32) | u64::from(lo)
}

fn fail(name: &[u8], what: &str, r: i64) -> i32 {
    println!("dcmpl: {}: {}: {}", text(name), what, sys::status(r));
    EXIT_REFUSED
}

fn refused(name: &[u8], e: PeError) -> i32 {
    match e {
        PeError::Import { .. } => println!("dcmpl: {} refused: {} (not in D-CMPL's kernel32: {} functions)", text(name), e, k32::count()),
        _ => println!("dcmpl: {} refused: {}", text(name), e),
    }
    EXIT_REFUSED
}

/// Memory VirtualProtect may remap: one VMO mapped at `start` in `region` (based at
/// `region_base`), with its permissions at map time.
#[derive(Clone, Copy)]
pub struct Piece {
    pub start: u64,
    pub len: u64,
    pub vmo: Handle,
    pub perms: u32,
    pub region: Handle,
    pub region_base: u64,
}

pub static PIECES: Mutex<Vec<Piece>> = Mutex::new(Vec::new());
/// Pages whose protection VirtualProtect changed: (page, Windows protection).
pub static PROTECTED: Mutex<Vec<(u64, u32)>> = Mutex::new(Vec::new());

fn map_piece(region: Handle, base: u64, staged: &[u8], rva: u32, pages: u32, perms: u32, vmex: Handle) -> Result<(), i64> {
    let mut v = sys::vmo_create(u64::from(pages))?;
    let (from, len) = (rva as usize, pages as usize);
    let mut off = 0;
    while off < len {
        let n = (len - off).min(64 * 1024);
        let r = sys::vmo_write(v, off as u64, &staged[from + off..from + off + n]);
        if r < 0 {
            sys::handle_close(v);
            return Err(r);
        }
        off += n;
    }
    if perms & sys::RIGHT_EXECUTE != 0 {
        match sys::vmo_make_executable(v, vmex) {
            // seals: never writable again, through any alias
            Ok(x) => v = x,
            Err(e) => {
                sys::handle_close(v);
                return Err(e);
            }
        }
    }
    let r = sys::vmar_map(region, u64::from(rva), v, 0, u64::from(pages), perms);
    if r.is_err() {
        sys::handle_close(v);
    }
    r?;
    PIECES.lock().push(Piece { start: base + u64::from(rva), len: u64::from(pages), vmo: v, perms, region, region_base: base });
    Ok(())
}

/// Search for a DLL file bytes following Windows DLL search order:
/// 1. Explicit path (if `raw` contains `/` or `\`)
/// 2. Application directory (`APP_DIR`)
/// 3. Embedded program VMOs (for `utest` embedded DLLs)
/// 4. Prefix system directories (`<prefix>/drive_c/windows/system32`, `<prefix>/system32`, `<prefix>`)
/// 5. Current working directory (`CWD`)
/// 6. Directories in `PATH` environment variable
fn find_dll_bytes(raw: &[u8]) -> Option<(Vec<u8>, String)> {
    let has_sep = raw.iter().any(|&c| c == b'/' || c == b'\\');
    let leaf = norm_dll_name(raw);
    let try_file = |abs: &[u8]| -> Option<(Vec<u8>, String)> {
        if let Ok(bytes) = path::read_file(abs, pe::MAX_FILE) {
            return Some((bytes, String::from_utf8_lossy(abs).into_owned()));
        }
        // FAT32 / case-insensitive filename fallback (e.g. `W3LIB.DLL` vs `w3lib.dll`)
        if let Some(slash) = abs.iter().rposition(|&c| c == b'/') {
            let dir = &abs[..slash];
            let fname = &abs[slash + 1..];
            let upper: Vec<u8> = fname.iter().map(|c| c.to_ascii_uppercase()).collect();
            if upper != fname {
                let mut alt = Vec::with_capacity(dir.len() + 1 + upper.len());
                alt.extend_from_slice(dir);
                alt.push(b'/');
                alt.extend_from_slice(&upper);
                if let Ok(bytes) = path::read_file(&alt, pe::MAX_FILE) {
                    return Some((bytes, String::from_utf8_lossy(&alt).into_owned()));
                }
            }
        }
        None
    };

    if has_sep {
        let mut p = k32::win_path_pub(raw);
        if let Some(r) = try_file(&p) {
            return Some(r);
        }
        if !p.ends_with(b".dll") && !p.ends_with(b".DLL") {
            p.extend_from_slice(b".dll");
            if let Some(r) = try_file(&p) {
                return Some(r);
            }
        }
        return None;
    }

    // 1. Application directory
    if let Some(app_dir) = path::app_dir() {
        let p = path::join_abs(app_dir.as_bytes(), leaf.as_bytes());
        if let Some(r) = try_file(&p) {
            return Some(r);
        }
    }
    // 2. Embedded program VMO (case-insensitive)
    let mut embedded: Option<(Handle, String)> = None;
    crate::programs(|h, pname| {
        if embedded.is_none() && norm_dll_name(pname) == leaf {
            embedded = Some((h, String::from(text(pname))));
        }
    });
    if let Some((h, pname)) = embedded
        && let Ok(bytes) = read_image(h, pe::MAX_FILE as u64)
    {
        let mut p = String::from("/");
        p.push_str(&pname);
        return Some((bytes, p));
    }
    // 3. Prefix system directories
    if let Some(pfx) = path::prefix() {
        for sub in ["drive_c/windows/system32", "drive_c/Windows/System32", "system32", ""] {
            let dir = if sub.is_empty() { pfx.as_bytes().to_vec() } else { path::join_abs(pfx.as_bytes(), sub.as_bytes()) };
            let p = path::join_abs(&dir, leaf.as_bytes());
            if let Some(r) = try_file(&p) {
                return Some(r);
            }
        }
    }
    // 4. Current working directory
    let cwd = path::cwd();
    if cwd != "/" {
        let p = path::join_abs(cwd.as_bytes(), leaf.as_bytes());
        if let Some(r) = try_file(&p) {
            return Some(r);
        }
    }
    // 5. PATH environment variable (`;` separated)
    if let Some(path_env) = k32::env_value(b"PATH") {
        for dir in path_env.split(|&c| c == b';') {
            if dir.is_empty() {
                continue;
            }
            let d = k32::win_path_pub(dir);
            let p = path::join_abs(&d, leaf.as_bytes());
            if let Some(r) = try_file(&p) {
                return Some(r);
            }
        }
    }
    None
}

fn dos_to_win_path_w(dos_path: &str) -> Vec<u16> {
    let mut m = String::from("C:");
    m.push_str(&dos_path.replace('/', "\\"));
    m.encode_utf16().collect()
}

/// Load a DLL by name (used both for static import binding and runtime `LoadLibrary*`).
/// Returns the module's HMODULE (load base or built-in sentinel).
pub fn load_dll(raw: &[u8], attach_now: bool) -> Result<u64, PeError> {
    if let Some(b) = builtin_for(raw) {
        return Ok(b.hmod());
    }
    let key = norm_dll_name(raw);
    {
        let mut mods = MODULES.lock();
        if let Some(m) = mods.iter_mut().find(|m| m.name == key) {
            m.refcount = m.refcount.saturating_add(1);
            return Ok(m.base);
        }
    }
    let Some((data, dos_path)) = find_dll_bytes(raw) else {
        return Err(PeError::Bad("DLL not found"));
    };
    let vmex = VMEX_HANDLE.load(Ordering::Acquire);
    if vmex == 0 {
        return Err(PeError::Bad("no VMEX resource"));
    }
    let img = pe::parse_dll(&data)?;
    let root = libd::root_vmar();
    let size = u64::from(img.size_of_image);
    let fixed = (img.image_base >= USER_BASE && img.image_base + size <= USER_TOP)
        .then(|| sys::vmar_allocate(root, img.image_base - USER_BASE, size, sys::RIGHTS_SAME).ok())
        .flatten();
    let (region, base) = match fixed {
        Some(r) => r,
        None => sys::vmar_allocate(root, sys::ANY, size, sys::RIGHTS_SAME)
            .map_err(|_| PeError::Bad("cannot reserve DLL address space"))?,
    };
    let delta = base.wrapping_sub(img.image_base);

    let mut staged: Vec<u8> = Vec::new();
    if staged.try_reserve_exact(size as usize).is_err() {
        sys::handle_close(region);
        return Err(PeError::Bad("out of memory staging DLL"));
    }
    staged.resize(size as usize, 0);
    if let Err(e) = img.layout(&data, &mut staged).and_then(|()| img.relocate(&mut staged, delta).map(|_| ())) {
        sys::handle_close(region);
        return Err(e);
    }
    drop(data);

    let tls = match img.tls(&staged, base) {
        Ok(Some(t)) => {
            let idx = NEXT_TLS_INDEX.fetch_add(1, Ordering::Relaxed);
            if idx >= MAX_TLS_MODULES {
                sys::handle_close(region);
                return Err(PeError::Unsupported("too many TLS modules"));
            }
            staged[t.index_rva as usize..t.index_rva as usize + 4].copy_from_slice(&(idx as u32).to_le_bytes());
            Some((idx, t))
        }
        Ok(None) => None,
        Err(e) => {
            sys::handle_close(region);
            return Err(e);
        }
    };

    // Bind DLL's own imports (recursively loading dependency DLLs before mapping).
    let bind_res = img.bind_ex(
        &mut staged,
        |dll, func| resolve_import_name(dll, func, attach_now),
        |dll, ord| resolve_import_ord(dll, ord, attach_now),
    );
    if let Err(e) = bind_res {
        sys::handle_close(region);
        return Err(e);
    }

    let hdr = img.size_of_headers.div_ceil(PAGE as u32) * PAGE as u32;
    if map_piece(region, base, &staged, 0, hdr, sys::RIGHT_READ, vmex).is_err() {
        sys::handle_close(region);
        return Err(PeError::Bad("cannot map DLL headers"));
    }
    for s in img.sections() {
        let perms = if s.executable() {
            sys::RIGHT_READ | sys::RIGHT_EXECUTE
        } else if s.writable() {
            sys::RIGHT_READ | sys::RIGHT_WRITE
        } else {
            sys::RIGHT_READ
        };
        if map_piece(region, base, &staged, s.rva, s.pages(), perms, vmex).is_err() {
            return Err(PeError::Bad("cannot map DLL section"));
        }
    }
    drop(staged);

    let entry = if img.entry != 0 { base + u64::from(img.entry) } else { 0 };
    let win_path = dos_to_win_path_w(&dos_path);
    MODULES.lock().push(Module {
        base,
        size,
        entry,
        is_dll: true,
        img,
        tls,
        refcount: 1,
        attached: attach_now,
        name: key,
        win_path,
        region,
    });

    if attach_now {
        // Allocate static TLS block for every currently live thread.
        if let Some((idx, t)) = tls {
            for &p in THREADS.lock().iter() {
                if let Ok((ptr, len)) = alloc_tls_block(base, t) {
                    // SAFETY: live thread struct; `idx` is newly assigned to this DLL.
                    unsafe {
                        let th = &mut *(p as *mut WinThread);
                        th.tls_array[idx] = ptr;
                        th.tls_sizes[idx] = len;
                    }
                }
            }
            call_module_tls(base, t, DLL_PROCESS_ATTACH);
        }
        if entry != 0 {
            // SAFETY: validated DLL entry point inside an executable section.
            let f: DllMainFn = unsafe { core::mem::transmute::<u64, DllMainFn>(entry) };
            if f(base, DLL_PROCESS_ATTACH, 0) == 0 {
                let _ = free_dll(base);
                return Err(PeError::Bad("DllMain returned FALSE"));
            }
        }
    }
    Ok(base)
}

/// Decrement a DLL's reference count, detaching and unmapping it when it reaches 0.
pub fn free_dll(hmod: u64) -> bool {
    if hmod == 0 || hmod == image().base || BuiltinDll::from_hmod(hmod).is_some() {
        return true;
    }
    let unload = {
        let mut mods = MODULES.lock();
        let Some(pos) = mods.iter().position(|m| m.base == hmod && m.is_dll) else {
            return false;
        };
        if mods[pos].refcount > 1 {
            mods[pos].refcount -= 1;
            return true;
        }
        mods.remove(pos)
    };
    if unload.attached {
        if unload.entry != 0 {
            // SAFETY: validated DLL entry point.
            let f: DllMainFn = unsafe { core::mem::transmute::<u64, DllMainFn>(unload.entry) };
            let _ = f(unload.base, DLL_PROCESS_DETACH, 0);
        }
        if let Some((_, t)) = unload.tls {
            call_module_tls(unload.base, t, DLL_PROCESS_DETACH);
        }
    }
    // Unmap and close all pieces belonging to this DLL's VMAR region.
    let mut pieces = PIECES.lock();
    let mut i = 0;
    while i < pieces.len() {
        if pieces[i].region == unload.region {
            let p = pieces.swap_remove(i);
            sys::vmar_unmap(p.region, p.start, p.len);
            sys::handle_close(p.vmo);
        } else {
            i += 1;
        }
    }
    drop(pieces);
    PROTECTED.lock().retain(|&(pg, _)| pg < unload.base || pg >= unload.base + unload.size);
    sys::handle_close(unload.region);
    true
}

/// Resolve a forwarded export string (`"OTHERDLL.Func"` or `"OTHERDLL.#123"`).
fn resolve_forward(fwd: &[u8], attach_now: bool, depth: usize) -> Option<u64> {
    if depth >= MAX_FORWARD_DEPTH {
        return None;
    }
    let dot = fwd.iter().rposition(|&c| c == b'.')?;
    let target_dll = &fwd[..dot];
    let target_sym = &fwd[dot + 1..];
    if target_dll.is_empty() || target_sym.is_empty() {
        return None;
    }
    let hmod = load_dll(target_dll, attach_now).ok()?;
    if let Some(ord_bytes) = target_sym.strip_prefix(b"#") {
        let ord = crate::parse_u(ord_bytes) as u16;
        get_proc_address_ord_inner(hmod, ord, attach_now, depth + 1)
    } else {
        get_proc_address_inner(hmod, target_sym, attach_now, depth + 1)
    }
}

fn get_proc_address_inner(hmod: u64, func: &[u8], attach_now: bool, depth: usize) -> Option<u64> {
    if let Some(b) = BuiltinDll::from_hmod(hmod) {
        return b.resolve(func);
    }
    let (base, size, img) = {
        let mods = MODULES.lock();
        let m = mods.iter().find(|m| m.base == hmod)?;
        (m.base, m.size, m.img)
    };
    // SAFETY: mapped PE module `[base, base + size)` is readable.
    let slice = unsafe { core::slice::from_raw_parts(base as *const u8, size as usize) };
    match img.export_by_name(slice, func).ok()? {
        Some(ExportRef::Rva(rva)) => Some(base + u64::from(rva)),
        Some(ExportRef::Forward(fwd)) => {
            let owned = fwd.to_vec();
            resolve_forward(&owned, attach_now, depth)
        }
        None => None,
    }
}

fn get_proc_address_ord_inner(hmod: u64, ord: u16, attach_now: bool, depth: usize) -> Option<u64> {
    if BuiltinDll::from_hmod(hmod).is_some() {
        return None;
    }
    let (base, size, img) = {
        let mods = MODULES.lock();
        let m = mods.iter().find(|m| m.base == hmod)?;
        (m.base, m.size, m.img)
    };
    // SAFETY: mapped PE module `[base, base + size)` is readable.
    let slice = unsafe { core::slice::from_raw_parts(base as *const u8, size as usize) };
    match img.export_by_ordinal(slice, ord).ok()? {
        Some(ExportRef::Rva(rva)) => Some(base + u64::from(rva)),
        Some(ExportRef::Forward(fwd)) => {
            let owned = fwd.to_vec();
            resolve_forward(&owned, attach_now, depth)
        }
        None => None,
    }
}

pub fn get_proc_address(hmod: u64, func: &[u8]) -> Option<u64> {
    get_proc_address_inner(hmod, func, true, 0)
}

pub fn get_proc_address_ord(hmod: u64, ord: u16) -> Option<u64> {
    get_proc_address_ord_inner(hmod, ord, true, 0)
}

fn resolve_import_name(dll: &[u8], func: &[u8], attach_now: bool) -> Option<u64> {
    if let Some(b) = builtin_for(dll) {
        return b.resolve(func);
    }
    let hmod = load_dll(dll, attach_now).ok()?;
    get_proc_address_inner(hmod, func, attach_now, 0)
}

fn resolve_import_ord(dll: &[u8], ord: u16, attach_now: bool) -> Option<u64> {
    if builtin_for(dll).is_some() {
        return None;
    }
    let hmod = load_dll(dll, attach_now).ok()?;
    get_proc_address_ord_inner(hmod, ord, attach_now, 0)
}

fn load(name: &[u8], data: &[u8], vmex: Handle) -> Result<Loaded, i32> {
    let t0 = rdtsc();
    VMEX_HANDLE.store(vmex, Ordering::Release);
    let img = pe::parse(data).map_err(|e| refused(name, e))?;
    let root = libd::root_vmar();
    let size = u64::from(img.size_of_image);

    // Preferred base if it is free and inside the user half, else anywhere (relocated).
    let fixed = (img.image_base >= USER_BASE && img.image_base + size <= USER_TOP)
        .then(|| sys::vmar_allocate(root, img.image_base - USER_BASE, size, sys::RIGHTS_SAME).ok())
        .flatten();
    let (region, base) = match fixed {
        Some(r) => r,
        None => sys::vmar_allocate(root, sys::ANY, size, sys::RIGHTS_SAME).map_err(|r| fail(name, "cannot reserve the image", r))?,
    };
    let delta = base.wrapping_sub(img.image_base);

    let mut staged: Vec<u8> = Vec::new();
    staged.try_reserve_exact(size as usize).map_err(|_| fail(name, "no memory to stage the image", sys::ERR_NO_MEMORY))?;
    staged.resize(size as usize, 0);
    img.layout(data, &mut staged).map_err(|e| refused(name, e))?;
    let relocs = img.relocate(&mut staged, delta).map_err(|e| refused(name, e))?;
    let imports = img
        .bind_ex(&mut staged, |d, f| resolve_import_name(d, f, false), |d, o| resolve_import_ord(d, o, false))
        .map_err(|e| refused(name, e))?;
    let tls = img.tls(&staged, base).map_err(|e| refused(name, e))?;
    let mod_tls = if let Some(t) = tls {
        let idx = NEXT_TLS_INDEX.fetch_add(1, Ordering::Relaxed);
        staged[t.index_rva as usize..t.index_rva as usize + 4].copy_from_slice(&(idx as u32).to_le_bytes());
        Some((idx, t))
    } else {
        None
    };

    let hdr = img.size_of_headers.div_ceil(PAGE as u32) * PAGE as u32;
    map_piece(region, base, &staged, 0, hdr, sys::RIGHT_READ, vmex).map_err(|r| fail(name, "cannot map the headers", r))?;
    for s in img.sections() {
        let perms = if s.executable() {
            sys::RIGHT_READ | sys::RIGHT_EXECUTE
        } else if s.writable() {
            sys::RIGHT_READ | sys::RIGHT_WRITE
        } else {
            sys::RIGHT_READ
        };
        map_piece(region, base, &staged, s.rva, s.pages(), perms, vmex).map_err(|r| {
            println!("dcmpl: {}: section {}", text(name), s.name());
            fail(name, "cannot map a section", r)
        })?;
    }
    drop(staged);
    let exe_dir = path::app_dir().unwrap_or_else(path::cwd);
    let exe_dos = if exe_dir == "/" {
        let mut s = String::from("/");
        s.push_str(text(name));
        s
    } else {
        let mut s = exe_dir;
        s.push('/');
        s.push_str(text(name));
        s
    };
    let exe_entry = base + u64::from(img.entry);
    // Insert main EXE at index 0 of MODULES (before any dependency DLLs loaded during bind_ex).
    MODULES.lock().insert(
        0,
        Module {
            base,
            size,
            entry: exe_entry,
            is_dll: false,
            img,
            tls: mod_tls,
            refcount: 1,
            attached: false,
            name: text(name).to_ascii_lowercase(),
            win_path: dos_to_win_path_w(&exe_dos),
            region,
        },
    );
    let info = Box::new(ImageInfo {
        base,
        size,
        entry: exe_entry,
        pdata_rva: img.exception.rva,
        pdata_count: u64::from(img.exception.size / 12),
        tls,
        stack_reserve: img.stack_reserve.clamp(256 * 1024, 16 << 20).div_ceil(PAGE) * PAGE,
        name: String::from(text(name)),
    });
    IMAGE.store(Box::into_raw(info), Ordering::Release);
    Ok(Loaded { base, preferred: delta == 0, relocs, imports, image_cycles: rdtsc() - t0 })
}

/// A stack of `size` bytes with an unmapped guard page below and above: (low, high).
pub fn new_stack(size: u64) -> Result<(u64, u64), i64> {
    let root = libd::root_vmar();
    let (reg, base) = sys::vmar_allocate(root, sys::ANY, size + 2 * PAGE, sys::RIGHTS_SAME)?;
    let v = sys::vmo_create(size);
    let v = match v {
        Ok(v) => v,
        Err(e) => {
            sys::handle_close(reg);
            return Err(e);
        }
    };
    let m = sys::vmar_map(reg, PAGE, v, 0, size, sys::RIGHT_READ | sys::RIGHT_WRITE);
    sys::handle_close(v);
    sys::handle_close(reg);
    m?;
    Ok((base + PAGE, base + PAGE + size))
}

/// Call the entry point on its own stack with the Windows x64 convention (32 bytes of shadow
/// space, RSP + 8 16-byte aligned at entry). RCX = PEB, as Windows passes it.
fn call_entry(entry: u64, stack_top: u64, peb: u64) -> u32 {
    let ret: u64;
    // SAFETY: the entry point of the image just mapped, on its own stack. Callee-saved registers
    // (Windows x64: RBX, RBP, RDI, RSI, R12-R15, XMM6-15) survive; R12 keeps our RSP.
    unsafe {
        asm!(
            "mov r12, rsp",
            "mov rsp, {st}",
            "sub rsp, 32",
            "call {e}",
            "mov rsp, r12",
            st = in(reg) stack_top,
            e = in(reg) entry,
            in("rcx") peb,
            out("r12") _,
            lateout("rax") ret,
            clobber_abi("win64"),
        );
    }
    ret as u32
}

/// `win <exe> [args]`.
pub fn run(name: &[u8], args: &[u8]) -> i32 {
    if name.is_empty() {
        println!("dcmpl: win: which program?");
        return EXIT_USAGE;
    }
    let Some(h) = find_image(name) else {
        println!("dcmpl: win: no program '{}'", text(name));
        return EXIT_USAGE;
    };
    let vmex = libd::startup_handle(sys::TAG_VMEX);
    if vmex == 0 {
        println!("dcmpl: win: no VMEX resource: cannot make code executable");
        return EXIT_REFUSED;
    }
    let file = match read_image(h, pe::MAX_FILE as u64) {
        Ok(f) => f,
        Err(r) => return fail(name, "cannot read the image", r),
    };
    k32::init(name, args);
    let ns0 = sys::clock_ns();
    let l = match load(name, &file, vmex) {
        Ok(l) => l,
        Err(code) => return code,
    };
    drop(file);
    let pl = Layout::from_size_align(0x2000, 64).unwrap_or(Layout::new::<u64>());
    // SAFETY: a non-zero size.
    let p = unsafe { alloc_zeroed(pl) };
    if p.is_null() {
        return fail(name, "no PEB", sys::ERR_NO_MEMORY);
    }
    // SAFETY: inside the fresh PEB allocation.
    unsafe {
        (p.add(0x10) as *mut u64).write(l.base);
        (p.add(0x20) as *mut u64).write(p.add(0x1000) as u64);
        (p.add(0x30) as *mut u64).write(k32::PROCESS_HEAP);
        (p.add(0xB8) as *mut u32).write(1);
        (p.add(0x118) as *mut u32).write(10);
        (p.add(0x120) as *mut u16).write(19041);
        k32::fill_process_parameters(p.add(0x1000));
    }
    PEB.store(p, Ordering::Relaxed);
    let t1 = rdtsc();
    let (lo, hi) = match new_stack(image().stack_reserve) {
        Ok(s) => s,
        Err(r) => return fail(name, "no stack", r),
    };
    if let Err(r) = setup_thread(lo, hi, new_tid()) {
        return fail(name, "cannot set up the main thread", r);
    }
    let setup_cycles = rdtsc() - t1;
    let ns = sys::clock_ns() - ns0;
    let dll_count = MODULES.lock().len().saturating_sub(1);
    println!(
        "dcmpl: {}: PE32+ loaded at {:#x} ({}), {} relocations, {} imports bound{}{}; TEB at GS",
        text(name),
        l.base,
        if l.preferred { "preferred base" } else { "relocated" },
        l.relocs,
        l.imports,
        if dll_count > 0 { ", DLLs" } else { "" },
        if image().tls.is_some() { ", TLS" } else { "" }
    );
    println!(
        "BENCH compat: PE load of {} (parse + map + bind): {} cycles; stack + TEB: {} cycles; total {} us",
        text(name),
        l.image_cycles,
        setup_cycles,
        ns / 1000
    );
    attach_initial_modules();
    let code = call_entry(image().entry, hi, peb());
    k32::exit_process(code)
}
