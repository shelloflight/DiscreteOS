//! Windows personality (docs/compat.md): a user-space PE32+ loader and D-CMPL's `kernel32`,
//! running a Windows console program inside this process on libd.
//!
//! Loading (parse + map + bind, measured):
//! 1. parse and validate the image (`pe.rs`);
//! 2. reserve its span at the preferred ImageBase (a VMAR sub-region at a fixed address), or
//!    anywhere if that is taken (then the base relocations are applied);
//! 3. lay the image out in a private staging buffer, relocate, read the TLS directory, and bind
//!    the imports to `k32` (any other import refuses the program, naming the DLL and function);
//! 4. map it page-exactly: headers R, each section in its own VMO with the section's
//!    permissions; code is **sealed and made executable with the VMEX resource** before it is
//!    mapped, so it is never writable through any alias (W^X holds for foreign code too); the
//!    pieces are kept (`Piece`) for VirtualProtect, which remaps a piece's own VMO with other
//!    permissions (data never executable, code never writable);
//! 5. the main thread: a stack of SizeOfStackReserve with unmapped guard pages, a TEB at GS
//!    (`gs:[0x30]` the TEB, `gs:[0x58]` its TLS block array, `gs:[0x60]` the PEB, whose
//!    ImageBaseAddress is the load address), the TLS callbacks (process attach), and this
//!    thread's in-process exception handler (`seh.rs`, on its own stack);
//! 6. call the entry point with the Windows x64 calling convention on the new stack; returning
//!    from it exits the process with the returned value (as ExitProcess would).
//!
//! Threads (`CreateThread`) are libd threads that get their own TEB, TLS block, TLS callbacks
//! (thread attach/detach), FLS data and exception handler. FS stays libd's (the thread control
//! block); a Windows program uses only GS.
//!
//! D-CMPL is not the security boundary (docs/compat.md): the program runs in this process and can
//! do anything this process can. Its authority is only the handles the process holds.

pub mod k32;
pub mod obj;
pub mod seh;

use alloc::alloc::{Layout, alloc_zeroed, dealloc};
use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::arch::asm;
use core::sync::atomic::{AtomicPtr, AtomicU32, Ordering};

use libd::sync::Mutex;
use libd::sys::{self, Handle};
use libd::println;

use crate::pe::{self, PeError};
use crate::{EXIT_REFUSED, EXIT_USAGE, PAGE, USER_BASE, USER_TOP, find_image, read_image, text};
use seh::Context;

/// The loaded program.
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

pub fn image() -> &'static ImageInfo {
    let p = IMAGE.load(Ordering::Acquire);
    // SAFETY: set once (a leaked box) before the program runs; never freed.
    if p.is_null() { &NO_IMAGE } else { unsafe { &*p } }
}

pub fn println_unhandled(args: core::fmt::Arguments<'_>) {
    println!("dcmpl: {}: {}", image().name, args);
}

// ---- threads --------------------------------------------------------------------------------------

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
    tls_array: [u64; 1],
    tls_block: u64,
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

/// Make the calling thread a Windows thread on the stack [lo, hi): TEB at GS, TLS block, FLS
/// data, exception handler.
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
        tls_array: [0],
        tls_block: 0,
        fls: [0; FLS_SLOTS],
        handler_stack: hs,
    });
    if let Some(tls) = image().tls {
        let len = (tls.template_len + tls.zero_fill).max(16) as usize;
        let l = Layout::from_size_align(len, 64).map_err(|_| sys::ERR_NO_MEMORY)?;
        // SAFETY: a non-zero size.
        let b = unsafe { alloc_zeroed(l) };
        if b.is_null() {
            return Err(sys::ERR_NO_MEMORY);
        }
        // SAFETY: the template lies inside the mapped image (checked by pe::Image::tls).
        unsafe {
            core::ptr::copy_nonoverlapping((image().base + u64::from(tls.template_rva)) as *const u8, b, tls.template_len as usize)
        };
        t.tls_block = b as u64;
        t.tls_array[0] = b as u64;
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

/// Call the image's TLS callbacks with `reason` (1 process attach, 2 thread attach, 3 thread
/// detach, 0 process detach).
fn tls_callbacks(reason: u32) {
    let im = image();
    if let Some(t) = im.tls {
        for &cb in &t.callbacks[..t.ncallbacks] {
            // SAFETY: checked by pe::Image::tls to lie in an executable section of the image.
            let f: TlsCallback = unsafe { core::mem::transmute::<u64, TlsCallback>(im.base + u64::from(cb)) };
            f(im.base, reason, 0);
        }
    }
}

/// End the calling Windows thread: thread-detach callbacks, FLS callbacks, then its state.
pub fn finish_thread(code: u32) -> ! {
    tls_callbacks(3);
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
        if t.tls_block != 0
            && let Some(tls) = image().tls
            && let Ok(l) = Layout::from_size_align((tls.template_len + tls.zero_fill).max(16) as usize, 64)
        {
            // SAFETY: allocated in setup_thread with this layout.
            unsafe { dealloc(t.tls_block as *mut u8, l) };
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
    // The callback for this thread's value (others' are dropped: their threads may be running).
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

/// The body of a thread made by CreateThread: become a Windows thread, wait for ResumeThread if
/// it was created suspended, run the start routine, end.
pub fn thread_main(start: u64, param: u64, gate: Option<Handle>, id: u32) -> ! {
    let tcb = libd::thread::current();
    if setup_thread(tcb.stack_lo, tcb.stack_hi, id).is_err() {
        sys::thread_exit(sys::ERR_NO_MEMORY as i32);
    }
    tls_callbacks(2);
    if let Some(g) = gate {
        let _ = sys::object_wait(g, sys::SIGNALED, sys::WAIT_FOREVER);
    }
    type Start = extern "win64" fn(u64) -> u32;
    // SAFETY: the program's own thread routine (CreateThread's lpStartAddress).
    let f: Start = unsafe { core::mem::transmute::<u64, Start>(start) };
    let code = f(param);
    finish_thread(code)
}

// ---- loader ---------------------------------------------------------------------------------------

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

/// Map `pages` bytes of the laid-out image at `rva` into `region`, in a VMO of their own.
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

fn load(name: &[u8], data: &[u8], vmex: Handle) -> Result<Loaded, i32> {
    let t0 = rdtsc();
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
    let imports = img.bind(&mut staged, k32::resolve).map_err(|e| refused(name, e))?;
    let tls = img.tls(&staged, base).map_err(|e| refused(name, e))?;
    if let Some(t) = tls {
        staged[t.index_rva as usize..t.index_rva as usize + 4].copy_from_slice(&0u32.to_le_bytes());
    }

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
    // The region stays open for VirtualProtect (D-CMPL's own use; the program never sees it).
    drop(staged);
    let info = Box::new(ImageInfo {
        base,
        size,
        entry: base + u64::from(img.entry),
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
    let ns0 = sys::clock_ns();
    let l = match load(name, &file, vmex) {
        Ok(l) => l,
        Err(code) => return code,
    };
    drop(file);
    k32::init(name, args);
    // The PEB (ImageBaseAddress at 0x10, ProcessParameters at 0x20, ProcessHeap at 0x30,
    // NumberOfProcessors at 0xB8, the OS version at 0x118), then the main thread.
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
    println!(
        "dcmpl: {}: PE32+ loaded at {:#x} ({}), {} relocations, {} imports bound{}; TEB at GS",
        text(name),
        l.base,
        if l.preferred { "preferred base" } else { "relocated" },
        l.relocs,
        l.imports,
        if image().tls.is_some() { ", TLS" } else { "" }
    );
    println!(
        "BENCH compat: PE load of {} (parse + map + bind): {} cycles; stack + TEB: {} cycles; total {} us",
        text(name),
        l.image_cycles,
        setup_cycles,
        ns / 1000
    );
    tls_callbacks(1);
    let code = call_entry(image().entry, hi, peb());
    k32::exit_process(code)
}
