//! D-CMPL's `kernel32`: the functions a Windows console program and the MSVC static C runtime
//! (`/MT`) import, implemented on libd. Everything a program can reach goes through the handles
//! this process holds: files through its namespace (`path.rs`), console output to the output
//! channel or the log (`out.rs`), memory from libd's heap.
//!
//! Conventions: the Windows x64 ABI (`extern "win64"`), errors through `SetLastError` (the TEB's
//! LastErrorValue), the ANSI and OEM code page is UTF-8 (65001, as with a UTF-8 manifest). Paths:
//! `\` is `/`, a drive letter is dropped, relative paths start at the working directory, and only
//! the namespace is reachable (anything else is ERROR_ACCESS_DENIED). Not provided: other DLLs
//! (LoadLibrary fails, GetProcAddress finds nothing), named objects shared between processes,
//! changing page protections (VirtualProtect fails), console input (standard input is empty).

use alloc::alloc::{Layout, alloc, alloc_zeroed, dealloc, realloc};
use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::arch::asm;
use core::sync::atomic::{AtomicU64, Ordering};

use libd::fs as fp;
use libd::handle::{Event as KEvent, Owned};
use libd::sync::{Mutex, RawMutex};
use libd::sys;

use super::obj::{self, CURRENT_PROCESS, CURRENT_THREAD, H_NUL, H_STDERR, H_STDIN, H_STDOUT, Obj};
use super::{current_thread, image, seh};
use crate::{out, path};

type Bool = i32;
const TRUE: Bool = 1;
const FALSE: Bool = 0;
const INVALID_HANDLE_VALUE: u64 = u64::MAX;
pub const PROCESS_HEAP: u64 = 0x0D05_0000;

// Error codes (winerror.h).
const ERROR_FILE_NOT_FOUND: u32 = 2;
const ERROR_PATH_NOT_FOUND: u32 = 3;
const ERROR_ACCESS_DENIED: u32 = 5;
const ERROR_INVALID_HANDLE: u32 = 6;
const ERROR_NOT_ENOUGH_MEMORY: u32 = 8;
const ERROR_NO_MORE_FILES: u32 = 18;
const ERROR_WRITE_PROTECT: u32 = 19;
const ERROR_GEN_FAILURE: u32 = 31;
const ERROR_NOT_SUPPORTED: u32 = 50;
const ERROR_FILE_EXISTS: u32 = 80;
const ERROR_INVALID_PARAMETER: u32 = 87;
const ERROR_DISK_FULL: u32 = 112;
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
const ERROR_INVALID_NAME: u32 = 123;
const ERROR_MOD_NOT_FOUND: u32 = 126;
const ERROR_PROC_NOT_FOUND: u32 = 127;
const ERROR_DIR_NOT_EMPTY: u32 = 145;
const ERROR_ALREADY_EXISTS: u32 = 183;
const ERROR_ENVVAR_NOT_FOUND: u32 = 203;
const ERROR_DIRECTORY: u32 = 267;
const ERROR_NO_UNICODE_TRANSLATION: u32 = 1113;

const WAIT_OBJECT_0: u32 = 0;
const WAIT_TIMEOUT: u32 = 0x102;
const WAIT_FAILED: u32 = 0xFFFF_FFFF;
const INFINITE: u32 = 0xFFFF_FFFF;
const STILL_ACTIVE: u32 = 259;

// ---- small helpers ----------------------------------------------------------------------------

fn set_err(e: u32) {
    // SAFETY: GS is this Windows thread's TEB; LastErrorValue is at 0x68.
    unsafe { asm!("mov dword ptr gs:[0x68], {:e}", in(reg) e, options(nostack, preserves_flags)) };
}
fn get_err() -> u32 {
    let e: u32;
    // SAFETY: as above.
    unsafe { asm!("mov {:e}, dword ptr gs:[0x68]", out(reg) e, options(nostack, readonly, preserves_flags)) };
    e
}

/// Write `v` through the program's out-pointer `p` (ignored if NULL). A bad pointer faults the
/// program, as an access violation would on Windows.
fn put<T>(p: *mut T, v: T) {
    if !p.is_null() {
        // SAFETY: the program's own out-pointer.
        unsafe { p.write_unaligned(v) };
    }
}

/// The program's NUL-terminated string at `p` (at most 32 KiB units).
fn cstr(p: *const u8) -> Vec<u8> {
    let mut v = Vec::new();
    if p.is_null() {
        return v;
    }
    for i in 0..32768 {
        // SAFETY: the program's string, read up to its NUL.
        let c = unsafe { p.add(i).read() };
        if c == 0 {
            break;
        }
        v.push(c);
    }
    v
}
fn wstr(p: *const u16) -> Vec<u16> {
    let mut v = Vec::new();
    if p.is_null() {
        return v;
    }
    for i in 0..32768 {
        // SAFETY: as above.
        let c = unsafe { p.add(i).read_unaligned() };
        if c == 0 {
            break;
        }
        v.push(c);
    }
    v
}

/// UTF-16 to UTF-8 (unpaired surrogates become U+FFFD).
fn from_wide(w: &[u16]) -> Vec<u8> {
    let mut s = String::new();
    for c in char::decode_utf16(w.iter().copied()) {
        s.push(c.unwrap_or('\u{FFFD}'));
    }
    s.into_bytes()
}
/// UTF-8 to UTF-16 (`None` if `strict` and the input is not valid UTF-8).
fn to_wide(b: &[u8], strict: bool) -> Option<Vec<u16>> {
    let s = match core::str::from_utf8(b) {
        Ok(s) => alloc::borrow::Cow::Borrowed(s),
        Err(_) if strict => return None,
        Err(_) => String::from_utf8_lossy(b),
    };
    Some(s.encode_utf16().collect())
}

/// A Windows path as an absolute D-OS path.
fn win_path(p: &[u8]) -> Vec<u8> {
    let mut s: Vec<u8> = p.iter().map(|&c| if c == b'\\' { b'/' } else { c }).collect();
    if s.starts_with(b"//?/") || s.starts_with(b"//./") {
        s.drain(..4);
    }
    if s.len() >= 2 && s[1] == b':' && s[0].is_ascii_alphabetic() {
        s.drain(..2);
    }
    path::absolute(&s)
}

fn fs_err(e: i64) -> u32 {
    match e {
        fp::ERR_NOT_FOUND => ERROR_FILE_NOT_FOUND,
        fp::ERR_EXISTS => ERROR_FILE_EXISTS,
        fp::ERR_NOT_DIR => ERROR_PATH_NOT_FOUND,
        fp::ERR_IS_DIR => ERROR_ACCESS_DENIED,
        fp::ERR_NOT_EMPTY => ERROR_DIR_NOT_EMPTY,
        fp::ERR_READ_ONLY => ERROR_WRITE_PROTECT,
        fp::ERR_BAD_NAME => ERROR_INVALID_NAME,
        sys::ERR_ACCESS_DENIED => ERROR_ACCESS_DENIED,
        sys::ERR_NO_SPACE => ERROR_DISK_FULL,
        sys::ERR_NO_MEMORY => ERROR_NOT_ENOUGH_MEMORY,
        sys::ERR_NOT_SUPPORTED => ERROR_NOT_SUPPORTED,
        _ => ERROR_GEN_FAILURE,
    }
}

fn ms_to_ns(ms: u32) -> u64 {
    if ms == INFINITE { sys::WAIT_FOREVER } else { u64::from(ms) * 1_000_000 }
}

// ---- process, command line, environment --------------------------------------------------------

struct Proc {
    cmd_a: Vec<u8>,
    cmd_w: Vec<u16>,
    module_w: Vec<u16>,
    env: Vec<(Vec<u8>, Vec<u8>)>,
    std: [u64; 3],
}

static PROC: Mutex<Proc> = Mutex::new(Proc { cmd_a: Vec::new(), cmd_w: Vec::new(), module_w: Vec::new(), env: Vec::new(), std: [H_STDIN, H_STDOUT, H_STDERR] });
static FILTER: AtomicU64 = AtomicU64::new(0);

pub fn init(name: &[u8], args: &[u8]) {
    let mut p = PROC.lock();
    let mut c = Vec::new();
    if name.contains(&b' ') {
        c.push(b'"');
        c.extend_from_slice(name);
        c.push(b'"');
    } else {
        c.extend_from_slice(name);
    }
    if !args.is_empty() {
        c.push(b' ');
        c.extend_from_slice(args);
    }
    p.cmd_w = to_wide(&c, false).unwrap_or_default();
    p.cmd_w.push(0);
    c.push(0);
    p.cmd_a = c;
    let mut m = String::from("C:");
    m.push_str(&path::cwd().replace('/', "\\"));
    if !m.ends_with('\\') {
        m.push('\\');
    }
    m.push_str(crate::text(name));
    p.module_w = m.encode_utf16().collect();
}

/// RTL_USER_PROCESS_PARAMETERS (in the PEB's second page): flags, the standard handles, the
/// image path and the command line (UNICODE_STRINGs into D-CMPL's copies, which never change).
pub(super) fn fill_process_parameters(pp: *mut u8) {
    let p = PROC.lock();
    let ustr = |at: usize, w: &[u16]| {
        let n = (w.len().saturating_sub(usize::from(w.last() == Some(&0))) * 2).min(0xFFFC) as u16;
        // SAFETY: inside the zeroed 4 KiB block the caller made for this.
        unsafe {
            (pp.add(at) as *mut u16).write(n);
            (pp.add(at + 2) as *mut u16).write(n + 2);
            (pp.add(at + 8) as *mut u64).write(w.as_ptr() as u64);
        }
    };
    // SAFETY: as above.
    unsafe {
        (pp as *mut u32).write(0x400);
        (pp.add(4) as *mut u32).write(0x400);
        (pp.add(8) as *mut u32).write(1); // PROCESS_PARAMETERS_NORMALIZED
        (pp.add(0x20) as *mut u64).write(H_STDIN);
        (pp.add(0x28) as *mut u64).write(H_STDOUT);
        (pp.add(0x30) as *mut u64).write(H_STDERR);
    }
    ustr(0x60, &p.module_w);
    ustr(0x70, &p.cmd_w);
}

pub fn unhandled_filter() -> u64 {
    FILTER.load(Ordering::Relaxed)
}

extern "win64" fn get_command_line_a() -> *const u8 {
    PROC.lock().cmd_a.as_ptr() // lives as long as the process (never changed after init)
}
extern "win64" fn get_command_line_w() -> *const u16 {
    PROC.lock().cmd_w.as_ptr()
}

fn env_find(env: &[(Vec<u8>, Vec<u8>)], name: &[u8]) -> Option<usize> {
    env.iter().position(|(n, _)| n.eq_ignore_ascii_case(name))
}
fn env_set(name: Vec<u8>, value: Option<Vec<u8>>) -> Bool {
    if name.is_empty() || name.contains(&b'=') {
        set_err(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    let mut p = PROC.lock();
    let i = env_find(&p.env, &name);
    match (i, value) {
        (Some(i), Some(v)) => p.env[i].1 = v,
        (None, Some(v)) => p.env.push((name, v)),
        (Some(i), None) => {
            p.env.remove(i);
        }
        (None, None) => {}
    }
    TRUE
}
/// The value as UTF-8, or None (ERROR_ENVVAR_NOT_FOUND set).
fn env_get(name: &[u8]) -> Option<Vec<u8>> {
    let p = PROC.lock();
    match env_find(&p.env, name) {
        Some(i) => Some(p.env[i].1.clone()),
        None => {
            set_err(ERROR_ENVVAR_NOT_FOUND);
            None
        }
    }
}

extern "win64" fn get_environment_variable_a(name: *const u8, buf: *mut u8, size: u32) -> u32 {
    let Some(v) = env_get(&cstr(name)) else { return 0 };
    if (size as usize) <= v.len() {
        return v.len() as u32 + 1;
    }
    // SAFETY: the program's buffer of `size` bytes.
    unsafe {
        core::ptr::copy_nonoverlapping(v.as_ptr(), buf, v.len());
        buf.add(v.len()).write(0);
    }
    v.len() as u32
}
extern "win64" fn get_environment_variable_w(name: *const u16, buf: *mut u16, size: u32) -> u32 {
    let Some(v) = env_get(&from_wide(&wstr(name))) else { return 0 };
    let w = to_wide(&v, false).unwrap_or_default();
    if (size as usize) <= w.len() {
        return w.len() as u32 + 1;
    }
    // SAFETY: the program's buffer of `size` units.
    unsafe {
        core::ptr::copy_nonoverlapping(w.as_ptr(), buf, w.len());
        buf.add(w.len()).write(0);
    }
    w.len() as u32
}
extern "win64" fn set_environment_variable_a(name: *const u8, value: *const u8) -> Bool {
    env_set(cstr(name), (!value.is_null()).then(|| cstr(value)))
}
extern "win64" fn set_environment_variable_w(name: *const u16, value: *const u16) -> Bool {
    env_set(from_wide(&wstr(name)), (!value.is_null()).then(|| from_wide(&wstr(value))))
}

/// The environment block: `name=value\0...\0\0`, in program-owned heap memory.
fn env_block(wide: bool) -> u64 {
    let p = PROC.lock();
    let mut b: Vec<u8> = Vec::new();
    for (n, v) in &p.env {
        b.extend_from_slice(n);
        b.push(b'=');
        b.extend_from_slice(v);
        b.push(0);
    }
    b.push(0);
    if b.len() == 1 {
        b.push(0);
    }
    drop(p);
    if wide {
        let w = to_wide(&b, false).unwrap_or_default();
        let m = heap_alloc(w.len() * 2, false);
        if !m.is_null() {
            // SAFETY: a fresh block of that size.
            unsafe { core::ptr::copy_nonoverlapping(w.as_ptr().cast::<u8>(), m, w.len() * 2) };
        }
        m as u64
    } else {
        let m = heap_alloc(b.len(), false);
        if !m.is_null() {
            // SAFETY: as above.
            unsafe { core::ptr::copy_nonoverlapping(b.as_ptr(), m, b.len()) };
        }
        m as u64
    }
}
extern "win64" fn get_environment_strings_w() -> u64 {
    env_block(true)
}
extern "win64" fn get_environment_strings_a() -> u64 {
    env_block(false)
}
extern "win64" fn free_environment_strings(p: *mut u8) -> Bool {
    heap_free(p);
    TRUE
}

extern "win64" fn get_startup_info_w(p: *mut u8) {
    if !p.is_null() {
        // SAFETY: the program's STARTUPINFOW (104 bytes).
        unsafe {
            core::ptr::write_bytes(p, 0, 104);
            (p as *mut u32).write_unaligned(104);
        }
    }
}

extern "win64" fn get_module_handle_w(name: *const u16) -> u64 {
    if name.is_null() {
        return image().base;
    }
    set_err(ERROR_MOD_NOT_FOUND);
    0
}
extern "win64" fn get_module_handle_a(name: *const u8) -> u64 {
    if name.is_null() {
        return image().base;
    }
    set_err(ERROR_MOD_NOT_FOUND);
    0
}
extern "win64" fn get_module_handle_ex_w(flags: u32, name: u64, out: *mut u64) -> Bool {
    let im = image();
    let ok = if flags & 4 != 0 { name >= im.base && name < im.base + im.size } else { name == 0 };
    put(out, if ok { im.base } else { 0 });
    if !ok {
        set_err(ERROR_MOD_NOT_FOUND);
    }
    Bool::from(ok)
}
extern "win64" fn get_module_file_name_w(h: u64, buf: *mut u16, size: u32) -> u32 {
    if h != 0 && h != image().base {
        set_err(ERROR_MOD_NOT_FOUND);
        return 0;
    }
    let m = PROC.lock().module_w.clone();
    if size == 0 {
        set_err(ERROR_INSUFFICIENT_BUFFER);
        return 0;
    }
    let n = m.len().min(size as usize - 1);
    // SAFETY: the program's buffer of `size` units.
    unsafe {
        core::ptr::copy_nonoverlapping(m.as_ptr(), buf, n);
        buf.add(n).write(0);
    }
    if n < m.len() {
        set_err(ERROR_INSUFFICIENT_BUFFER);
        return size;
    }
    n as u32
}
extern "win64" fn get_module_file_name_a(h: u64, buf: *mut u8, size: u32) -> u32 {
    if h != 0 && h != image().base {
        set_err(ERROR_MOD_NOT_FOUND);
        return 0;
    }
    let m = from_wide(&PROC.lock().module_w);
    if size == 0 {
        set_err(ERROR_INSUFFICIENT_BUFFER);
        return 0;
    }
    let n = m.len().min(size as usize - 1);
    // SAFETY: the program's buffer of `size` bytes.
    unsafe {
        core::ptr::copy_nonoverlapping(m.as_ptr(), buf, n);
        buf.add(n).write(0);
    }
    n as u32
}
extern "win64" fn get_proc_address(_h: u64, _name: u64) -> u64 {
    set_err(ERROR_PROC_NOT_FOUND);
    0
}
extern "win64" fn load_library_ex_w(_name: *const u16, _file: u64, _flags: u32) -> u64 {
    set_err(ERROR_MOD_NOT_FOUND);
    0
}
extern "win64" fn load_library_w(_name: *const u16) -> u64 {
    set_err(ERROR_MOD_NOT_FOUND);
    0
}
extern "win64" fn load_library_a(_name: *const u8) -> u64 {
    set_err(ERROR_MOD_NOT_FOUND);
    0
}
extern "win64" fn free_library(_h: u64) -> Bool {
    TRUE
}
extern "win64" fn free_library_and_exit_thread(_h: u64, code: u32) -> ! {
    super::finish_thread(code)
}

pub extern "win64" fn exit_process(code: u32) -> ! {
    out::flush_all();
    sys::process_exit(code as i32)
}
extern "win64" fn terminate_process(h: u64, code: u32) -> Bool {
    if h == CURRENT_PROCESS {
        exit_process(code);
    }
    set_err(ERROR_ACCESS_DENIED);
    FALSE
}
extern "win64" fn get_current_process() -> u64 {
    CURRENT_PROCESS
}
extern "win64" fn get_current_process_id() -> u32 {
    4
}
extern "win64" fn get_current_thread() -> u64 {
    CURRENT_THREAD
}
extern "win64" fn get_current_thread_id() -> u32 {
    super::current_tid()
}
extern "win64" fn is_debugger_present() -> Bool {
    FALSE
}
extern "win64" fn is_processor_feature_present(f: u32) -> Bool {
    let c1 = core::arch::x86_64::__cpuid(1);
    let c7 = core::arch::x86_64::__cpuid_count(7, 0);
    let osx = c1.ecx & (1 << 27) != 0;
    let ok = match f {
        2 | 3 | 6 | 8 | 9 | 10 | 12 => true, // CMPXCHG8B, MMX, SSE, RDTSC, PAE, SSE2, NX
        13 => c1.ecx & 1 != 0,
        14 => c1.ecx & (1 << 13) != 0,
        17 => osx,
        36 => c1.ecx & (1 << 9) != 0,
        37 => c1.ecx & (1 << 19) != 0,
        38 => c1.ecx & (1 << 20) != 0,
        39 => osx && c1.ecx & (1 << 28) != 0,
        40 => osx && c7.ebx & (1 << 5) != 0,
        41 => osx && c7.ebx & (1 << 16) != 0,
        _ => false, // 23 FASTFAIL: no (int 0x29 is not a D-OS service)
    };
    Bool::from(ok)
}
extern "win64" fn set_unhandled_exception_filter(f: u64) -> u64 {
    FILTER.swap(f, Ordering::Relaxed)
}
/// UnhandledExceptionFilter(EXCEPTION_POINTERS *): the program's own filter first, then report.
extern "win64" fn unhandled_exception_filter(ep: *mut [u64; 2]) -> i32 {
    let f = FILTER.load(Ordering::Relaxed);
    if f != 0 {
        type Filter = extern "win64" fn(*mut [u64; 2]) -> i32;
        // SAFETY: the program's own filter.
        let r = unsafe { core::mem::transmute::<u64, Filter>(f) }(ep);
        if r != 0 {
            return r;
        }
    }
    // SAFETY: the caller's EXCEPTION_POINTERS (record first).
    let code = unsafe { ep.as_ref() }.and_then(|e| unsafe { (e[0] as *const u32).as_ref() }).copied().unwrap_or(0);
    super::println_unhandled(format_args!("unhandled exception {:#010x}", code));
    1
}
extern "win64" fn encode_pointer(p: u64) -> u64 {
    p
}
extern "win64" fn initialize_slist_head(h: *mut [u64; 2]) {
    put(h, [0, 0]);
}
extern "win64" fn get_last_error() -> u32 {
    get_err()
}
extern "win64" fn set_last_error(e: u32) {
    set_err(e);
}
extern "win64" fn output_debug_string_a(s: *const u8) {
    super::println_unhandled(format_args!("debug: {}", String::from_utf8_lossy(&cstr(s))));
}
extern "win64" fn output_debug_string_w(s: *const u16) {
    super::println_unhandled(format_args!("debug: {}", String::from_utf8_lossy(&from_wide(&wstr(s)))));
}
extern "win64" fn get_system_info(p: *mut u8) {
    if p.is_null() {
        return;
    }
    // SAFETY: the program's SYSTEM_INFO (48 bytes).
    unsafe {
        core::ptr::write_bytes(p, 0, 48);
        (p as *mut u16).write_unaligned(9); // AMD64
        (p.add(4) as *mut u32).write_unaligned(4096);
        (p.add(8) as *mut u64).write_unaligned(0x1_0000);
        (p.add(16) as *mut u64).write_unaligned(0x7FFF_FFFE_FFFF);
        (p.add(24) as *mut u64).write_unaligned(1);
        (p.add(32) as *mut u32).write_unaligned(1);
        (p.add(36) as *mut u32).write_unaligned(8664);
        (p.add(40) as *mut u32).write_unaligned(65536);
        (p.add(44) as *mut u16).write_unaligned(6);
    }
}

// ---- heap -----------------------------------------------------------------------------------------

/// A heap block: 16 bytes of header (its size) before what the program gets (16-byte aligned).
fn heap_alloc(size: usize, zero: bool) -> *mut u8 {
    let Ok(l) = Layout::from_size_align(size.saturating_add(16), 16) else { return core::ptr::null_mut() };
    // SAFETY: a non-zero size.
    let p = unsafe { if zero { alloc_zeroed(l) } else { alloc(l) } };
    if p.is_null() {
        return p;
    }
    // SAFETY: the header of the fresh block.
    unsafe {
        (p as *mut u64).write(size as u64);
        p.add(16)
    }
}
fn heap_size_of(p: *mut u8) -> usize {
    // SAFETY: a block from heap_alloc (its header precedes it).
    unsafe { (p.sub(16) as *const u64).read() as usize }
}
fn heap_free(p: *mut u8) {
    if p.is_null() {
        return;
    }
    let size = heap_size_of(p);
    // SAFETY: allocated by heap_alloc with this layout.
    unsafe { dealloc(p.sub(16), Layout::from_size_align_unchecked(size + 16, 16)) };
}

const HEAP_ZERO_MEMORY: u32 = 8;
const HEAP_REALLOC_IN_PLACE_ONLY: u32 = 0x10;

extern "win64" fn get_process_heap() -> u64 {
    PROCESS_HEAP
}
extern "win64" fn heap_create(_opts: u32, _init: usize, _max: usize) -> u64 {
    PROCESS_HEAP // one heap for everything (libd's)
}
extern "win64" fn heap_destroy(_h: u64) -> Bool {
    TRUE
}
extern "win64" fn heap_alloc_w(_h: u64, flags: u32, size: usize) -> *mut u8 {
    let p = heap_alloc(size, flags & HEAP_ZERO_MEMORY != 0);
    if p.is_null() {
        set_err(ERROR_NOT_ENOUGH_MEMORY);
    }
    p
}
extern "win64" fn heap_free_w(_h: u64, _flags: u32, p: *mut u8) -> Bool {
    heap_free(p);
    TRUE
}
extern "win64" fn heap_size_w(_h: u64, _flags: u32, p: *mut u8) -> usize {
    if p.is_null() { usize::MAX } else { heap_size_of(p) }
}
extern "win64" fn heap_realloc_w(_h: u64, flags: u32, p: *mut u8, size: usize) -> *mut u8 {
    if p.is_null() {
        return heap_alloc_w(0, flags, size);
    }
    let old = heap_size_of(p);
    if flags & HEAP_REALLOC_IN_PLACE_ONLY != 0 {
        if size > old {
            set_err(ERROR_NOT_ENOUGH_MEMORY);
            return core::ptr::null_mut();
        }
        // SAFETY: the block's header.
        unsafe { (p.sub(16) as *mut u64).write(size as u64) };
        return p;
    }
    // SAFETY: a block from heap_alloc with this layout; the new size is checked below.
    let n = unsafe { realloc(p.sub(16), Layout::from_size_align_unchecked(old + 16, 16), size.saturating_add(16)) };
    if n.is_null() {
        set_err(ERROR_NOT_ENOUGH_MEMORY);
        return n;
    }
    // SAFETY: the (moved) block: header, then the new tail to zero if asked.
    unsafe {
        (n as *mut u64).write(size as u64);
        if flags & HEAP_ZERO_MEMORY != 0 && size > old {
            core::ptr::write_bytes(n.add(16 + old), 0, size - old);
        }
        n.add(16)
    }
}

// VirtualAlloc: whole mappings, read/write (executable memory only from the loader).
extern "win64" fn virtual_alloc(addr: u64, size: usize, kind: u32, prot: u32) -> u64 {
    const MEM_COMMIT: u32 = 0x1000;
    if addr != 0 && kind & MEM_COMMIT != 0 && super::PIECES.lock().iter().any(|p| addr >= p.start && addr < p.start + p.len) {
        return addr; // committing part of a region: everything is committed already
    }
    if addr != 0 || prot & 0xF0 != 0 || size == 0 {
        set_err(if prot & 0xF0 != 0 { ERROR_ACCESS_DENIED } else { ERROR_INVALID_PARAMETER });
        return 0;
    }
    let len = (size as u64).div_ceil(65536) * 65536;
    let root = libd::root_vmar();
    let Ok(v) = sys::vmo_create(len) else {
        set_err(ERROR_NOT_ENOUGH_MEMORY);
        return 0;
    };
    match sys::vmar_map(root, sys::ANY, v, 0, len, sys::RIGHT_READ | sys::RIGHT_WRITE) {
        Ok(a) => {
            let perms = sys::RIGHT_READ | sys::RIGHT_WRITE;
            super::PIECES.lock().push(super::Piece { start: a, len, vmo: v, perms, region: root, region_base: crate::USER_BASE });
            a
        }
        Err(_) => {
            sys::handle_close(v);
            set_err(ERROR_NOT_ENOUGH_MEMORY);
            0
        }
    }
}
extern "win64" fn virtual_free(addr: u64, _size: usize, kind: u32) -> Bool {
    const MEM_RELEASE: u32 = 0x8000;
    if kind & MEM_RELEASE == 0 {
        return TRUE; // decommit: the memory stays
    }
    let mut v = super::PIECES.lock();
    match v.iter().position(|p| p.start == addr && p.region == libd::root_vmar()) {
        Some(i) => {
            let p = v.remove(i);
            sys::vmar_unmap(p.region, p.start, p.len);
            sys::handle_close(p.vmo);
            super::PROTECTED.lock().retain(|&(pg, _)| pg < p.start || pg >= p.start + p.len);
            TRUE
        }
        None => {
            set_err(ERROR_INVALID_PARAMETER);
            FALSE
        }
    }
}
/// Windows protection of D-OS mapping permissions.
fn win_prot(perms: u32) -> u32 {
    match (perms & sys::RIGHT_WRITE != 0, perms & sys::RIGHT_EXECUTE != 0) {
        (_, true) => 0x20, // PAGE_EXECUTE_READ
        (true, _) => 0x04, // PAGE_READWRITE
        _ => 0x02,         // PAGE_READONLY
    }
}
/// VirtualProtect: remap the pages from their own VMO with the new permissions. Code never
/// becomes writable and data never executable (W^X); PAGE_NOACCESS unmaps the pages.
extern "win64" fn virtual_protect(addr: u64, size: usize, prot: u32, old: *mut u32) -> Bool {
    const PAGE: u64 = 4096;
    let (lo, hi) = (addr & !(PAGE - 1), (addr.saturating_add(size as u64) + PAGE - 1) & !(PAGE - 1));
    let new: Option<u32> = match prot & 0xFF {
        0x01 => None,
        0x02 => Some(sys::RIGHT_READ),
        0x04 | 0x08 => Some(sys::RIGHT_READ | sys::RIGHT_WRITE),
        0x10 | 0x20 => Some(sys::RIGHT_READ | sys::RIGHT_EXECUTE),
        _ => {
            set_err(ERROR_ACCESS_DENIED); // writable and executable: never
            return FALSE;
        }
    };
    if size == 0 || hi <= lo {
        set_err(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    let hit: Vec<super::Piece> = super::PIECES.lock().iter().copied().filter(|p| p.start < hi && lo < p.start + p.len).collect();
    let covered: u64 = hit.iter().map(|p| (p.start + p.len).min(hi) - p.start.max(lo)).sum();
    if covered != hi - lo {
        set_err(487); // ERROR_INVALID_ADDRESS
        return FALSE;
    }
    // Data stays data (never executable), code stays code (never writable).
    let bad = |p: &super::Piece| match new {
        Some(n) if p.perms & sys::RIGHT_EXECUTE != 0 => n & sys::RIGHT_WRITE != 0,
        Some(n) => n & sys::RIGHT_EXECUTE != 0,
        None => false,
    };
    if hit.iter().any(bad) {
        set_err(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    let mut prot_list = super::PROTECTED.lock();
    let first = hit.iter().find(|p| lo >= p.start).map_or(0x02, |p| win_prot(p.perms));
    let before = prot_list.iter().find(|&&(pg, _)| pg == lo).map_or(first, |&(_, w)| w);
    for p in &hit {
        let (a, b) = (p.start.max(lo), (p.start + p.len).min(hi));
        sys::vmar_unmap(p.region, a, b - a);
        if let Some(n) = new
            && sys::vmar_map(p.region, a - p.region_base, p.vmo, a - p.start, b - a, n).is_err()
        {
            set_err(ERROR_ACCESS_DENIED);
            return FALSE;
        }
        let mut pg = a;
        while pg < b {
            prot_list.retain(|&(x, _)| x != pg);
            prot_list.push((pg, prot & 0xFF));
            pg += PAGE;
        }
    }
    put(old, before);
    TRUE
}

// ---- critical sections -------------------------------------------------------------------------

/// CRITICAL_SECTION (40 bytes): DebugInfo holds D-CMPL's lock, RecursionCount (12) and
/// OwningThread (16) are kept as Windows keeps them.
fn cs_lock(cs: *mut u64) -> &'static RawMutex {
    // SAFETY: the program's CRITICAL_SECTION; its first word is ours (DebugInfo).
    let slot = unsafe { AtomicU64::from_ptr(cs) };
    let mut p = slot.load(Ordering::Acquire);
    if p == 0 {
        let b = Box::into_raw(Box::new(RawMutex::new())) as u64;
        match slot.compare_exchange(0, b, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => p = b,
            Err(other) => {
                // SAFETY: our box, never shared.
                drop(unsafe { Box::from_raw(b as *mut RawMutex) });
                p = other;
            }
        }
    }
    // SAFETY: a leaked RawMutex owned by this critical section until DeleteCriticalSection.
    unsafe { &*(p as *const RawMutex) }
}
fn cs_owner(cs: *mut u64) -> &'static AtomicU64 {
    // SAFETY: OwningThread, 8-byte aligned inside the program's CRITICAL_SECTION.
    unsafe { AtomicU64::from_ptr(cs.add(2)) }
}
fn cs_recursion(cs: *mut u64) -> *mut i32 {
    // SAFETY: RecursionCount, inside the CRITICAL_SECTION.
    unsafe { (cs as *mut i32).add(3) }
}
extern "win64" fn initialize_critical_section(cs: *mut u64) {
    // SAFETY: the program's CRITICAL_SECTION (40 bytes).
    unsafe { core::ptr::write_bytes(cs, 0, 5) };
    cs_lock(cs);
    // SAFETY: LockCount = -1 (free), as Windows initialises it.
    unsafe { (cs as *mut i32).add(2).write(-1) };
}
extern "win64" fn initialize_critical_section_ex(cs: *mut u64, _spin: u32, _flags: u32) -> Bool {
    initialize_critical_section(cs);
    TRUE
}
extern "win64" fn enter_critical_section(cs: *mut u64) {
    let me = u64::from(super::current_tid());
    if cs_owner(cs).load(Ordering::Relaxed) == me {
        // SAFETY: only the owner touches the count.
        unsafe { *cs_recursion(cs) += 1 };
        return;
    }
    cs_lock(cs).lock();
    cs_owner(cs).store(me, Ordering::Relaxed);
    // SAFETY: as above.
    unsafe { *cs_recursion(cs) = 1 };
}
extern "win64" fn try_enter_critical_section(cs: *mut u64) -> Bool {
    let me = u64::from(super::current_tid());
    if cs_owner(cs).load(Ordering::Relaxed) == me {
        // SAFETY: as above.
        unsafe { *cs_recursion(cs) += 1 };
        return TRUE;
    }
    if !cs_lock(cs).try_lock() {
        return FALSE;
    }
    cs_owner(cs).store(me, Ordering::Relaxed);
    // SAFETY: as above.
    unsafe { *cs_recursion(cs) = 1 };
    TRUE
}
extern "win64" fn leave_critical_section(cs: *mut u64) {
    // SAFETY: as above (the caller owns it).
    let r = unsafe {
        *cs_recursion(cs) -= 1;
        *cs_recursion(cs)
    };
    if r <= 0 {
        // SAFETY: as above.
        unsafe { *cs_recursion(cs) = 0 };
        cs_owner(cs).store(0, Ordering::Relaxed);
        cs_lock(cs).unlock();
    }
}
extern "win64" fn delete_critical_section(cs: *mut u64) {
    // SAFETY: the program's CRITICAL_SECTION; nobody holds it (Windows' rule).
    let slot = unsafe { AtomicU64::from_ptr(cs) };
    let p = slot.swap(0, Ordering::AcqRel);
    if p != 0 {
        // SAFETY: the box made by cs_lock.
        let m = unsafe { Box::from_raw(p as *mut RawMutex) };
        m.destroy();
    }
}

// ---- threads, waiting, TLS/FLS -------------------------------------------------------------------

extern "win64" fn create_thread(_sa: u64, stack: usize, start: u64, param: u64, flags: u32, tid: *mut u32) -> u64 {
    const CREATE_SUSPENDED: u32 = 4;
    let size = if stack == 0 { image().stack_reserve } else { (stack as u64).max(64 * 1024) };
    let gate = if flags & CREATE_SUSPENDED != 0 {
        match KEvent::new() {
            Ok(e) => Some(e.0),
            Err(_) => {
                set_err(ERROR_NOT_ENOUGH_MEMORY);
                return 0;
            }
        }
    } else {
        None
    };
    let gate_raw = gate.as_ref().map(Owned::raw);
    let id = super::new_tid();
    let r = libd::thread::Builder::new().stack_size(size).spawn(move || {
        super::thread_main(start, param, gate_raw, id);
    });
    let jh = match r {
        Ok(j) => j,
        Err(_) => {
            set_err(ERROR_NOT_ENOUGH_MEMORY);
            return 0;
        }
    };
    let kernel = jh.handle();
    put(tid, id);
    match obj::insert(Obj::Thread(obj::Thread { kernel, join: Mutex::new(Some(jh)), gate, id })) {
        Some(h) => h,
        None => {
            set_err(ERROR_NOT_ENOUGH_MEMORY);
            0
        }
    }
}
extern "win64" fn resume_thread(h: u64) -> u32 {
    match obj::get(h).as_deref() {
        Some(Obj::Thread(t)) => match &t.gate {
            Some(g) => {
                let was = u32::from(sys::object_wait(g.raw(), sys::SIGNALED, 0).is_err());
                sys::event_signal(g.raw(), 0, sys::SIGNALED);
                was
            }
            None => 0,
        },
        _ => {
            set_err(ERROR_INVALID_HANDLE);
            u32::MAX
        }
    }
}
extern "win64" fn exit_thread(code: u32) -> ! {
    super::finish_thread(code)
}
extern "win64" fn get_exit_code_thread(h: u64, code: *mut u32) -> Bool {
    match obj::get(h).as_deref() {
        Some(Obj::Thread(t)) => {
            let c = if sys::object_wait(t.kernel, sys::TERMINATED, 0).is_ok() { sys::thread_exit_code(t.kernel) as u32 } else { STILL_ACTIVE };
            put(code, c);
            TRUE
        }
        _ if h == CURRENT_THREAD => {
            put(code, STILL_ACTIVE);
            TRUE
        }
        _ => {
            set_err(ERROR_INVALID_HANDLE);
            FALSE
        }
    }
}
extern "win64" fn get_thread_id(h: u64) -> u32 {
    match obj::get(h).as_deref() {
        Some(Obj::Thread(t)) => t.id,
        _ if h == CURRENT_THREAD => super::current_tid(),
        _ => 0,
    }
}

/// Wait for one object until `deadline` (clock_ns, or WAIT_FOREVER).
fn wait_one(h: u64, deadline: u64) -> u32 {
    let Some((_o, k, s, auto)) = obj::waitable(h) else {
        set_err(ERROR_INVALID_HANDLE);
        return WAIT_FAILED;
    };
    let timeout = if deadline == sys::WAIT_FOREVER { deadline } else { deadline.saturating_sub(sys::clock_ns()) };
    match sys::object_wait(k, s, timeout) {
        Ok(_) => {
            if auto {
                sys::event_signal(k, sys::SIGNALED, 0);
            }
            WAIT_OBJECT_0
        }
        Err(sys::ERR_TIMED_OUT) => WAIT_TIMEOUT,
        Err(_) => WAIT_FAILED,
    }
}
fn deadline(ms: u32) -> u64 {
    if ms == INFINITE { sys::WAIT_FOREVER } else { sys::clock_ns() + u64::from(ms) * 1_000_000 }
}
extern "win64" fn wait_for_single_object(h: u64, ms: u32) -> u32 {
    wait_one(h, deadline(ms))
}
extern "win64" fn wait_for_single_object_ex(h: u64, ms: u32, _alertable: Bool) -> u32 {
    wait_one(h, deadline(ms))
}
extern "win64" fn wait_for_multiple_objects(n: u32, hs: *const u64, all: Bool, ms: u32) -> u32 {
    if n == 0 || n > 64 || hs.is_null() {
        set_err(ERROR_INVALID_PARAMETER);
        return WAIT_FAILED;
    }
    // SAFETY: the program's array of `n` handles.
    let hs = unsafe { core::slice::from_raw_parts(hs, n as usize) };
    let d = deadline(ms);
    if all != 0 {
        for &h in hs {
            let r = wait_one(h, d);
            if r != WAIT_OBJECT_0 {
                return r;
            }
        }
        return WAIT_OBJECT_0;
    }
    // Any of them: poll (every 200 us) until one is ready.
    loop {
        for (i, &h) in hs.iter().enumerate() {
            match wait_one(h, 0) {
                WAIT_OBJECT_0 => return WAIT_OBJECT_0 + i as u32,
                WAIT_FAILED => return WAIT_FAILED,
                _ => {}
            }
        }
        if d != sys::WAIT_FOREVER && sys::clock_ns() >= d {
            return WAIT_TIMEOUT;
        }
        libd::thread::sleep(200_000);
    }
}
extern "win64" fn sleep(ms: u32) {
    if ms == 0 {
        sys::yield_now();
    } else {
        libd::thread::sleep(ms_to_ns(ms));
    }
}
extern "win64" fn sleep_ex(ms: u32, _alertable: Bool) -> u32 {
    sleep(ms);
    0
}
extern "win64" fn switch_to_thread() -> Bool {
    sys::yield_now();
    TRUE
}
extern "win64" fn create_event_w(_sa: u64, manual: Bool, initial: Bool, _name: u64) -> u64 {
    let Ok(e) = KEvent::new() else {
        set_err(ERROR_NOT_ENOUGH_MEMORY);
        return 0;
    };
    if initial != 0 {
        e.signal();
    }
    obj::insert(Obj::Event(obj::Event { ev: e.0, manual: manual != 0 })).unwrap_or_else(|| {
        set_err(ERROR_NOT_ENOUGH_MEMORY);
        0
    })
}
fn event_op(h: u64, clear: u32, set: u32) -> Bool {
    match obj::get(h).as_deref() {
        Some(Obj::Event(e)) => {
            sys::event_signal(e.ev.raw(), clear, set);
            TRUE
        }
        _ => {
            set_err(ERROR_INVALID_HANDLE);
            FALSE
        }
    }
}
extern "win64" fn set_event(h: u64) -> Bool {
    event_op(h, 0, sys::SIGNALED)
}
extern "win64" fn reset_event(h: u64) -> Bool {
    event_op(h, sys::SIGNALED, 0)
}
extern "win64" fn close_handle(h: u64) -> Bool {
    if matches!(h, H_STDIN | H_STDOUT | H_STDERR | H_NUL | CURRENT_PROCESS | CURRENT_THREAD) || obj::remove(h) {
        return TRUE;
    }
    set_err(ERROR_INVALID_HANDLE);
    FALSE
}
extern "win64" fn duplicate_handle(sp: u64, h: u64, tp: u64, out: *mut u64, _access: u32, _inherit: Bool, options: u32) -> Bool {
    if sp != CURRENT_PROCESS || tp != CURRENT_PROCESS {
        set_err(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    let n = if matches!(h, H_STDIN | H_STDOUT | H_STDERR | H_NUL) { Some(h) } else { obj::dup(h) };
    let Some(n) = n else {
        set_err(ERROR_INVALID_HANDLE);
        return FALSE;
    };
    if options & 1 != 0 {
        obj::remove(h); // DUPLICATE_CLOSE_SOURCE
    }
    put(out, n);
    TRUE
}

extern "win64" fn tls_alloc() -> u32 {
    super::tls_alloc().map_or(u32::MAX, |i| i as u32)
}
extern "win64" fn tls_free(i: u32) -> Bool {
    Bool::from(super::tls_free(i as usize))
}
extern "win64" fn tls_get_value(i: u32) -> u64 {
    if i as usize >= super::TLS_SLOTS {
        set_err(ERROR_INVALID_PARAMETER);
        return 0;
    }
    let off = super::TEB_TLS_SLOTS as u64 + 8 * u64::from(i);
    let v: u64;
    // SAFETY: the slot in this thread's TEB (GS).
    unsafe { asm!("mov {}, gs:[{}]", out(reg) v, in(reg) off, options(nostack, readonly, preserves_flags)) };
    set_err(0);
    v
}
extern "win64" fn tls_set_value(i: u32, v: u64) -> Bool {
    if i as usize >= super::TLS_SLOTS {
        set_err(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    let off = super::TEB_TLS_SLOTS as u64 + 8 * u64::from(i);
    // SAFETY: as above.
    unsafe { asm!("mov gs:[{}], {}", in(reg) off, in(reg) v, options(nostack, preserves_flags)) };
    TRUE
}
extern "win64" fn fls_alloc(cb: u64) -> u32 {
    super::fls_alloc(cb).map_or(u32::MAX, |i| i as u32)
}
extern "win64" fn fls_free(i: u32) -> Bool {
    Bool::from(super::fls_free(i as usize))
}
extern "win64" fn fls_get_value(i: u32) -> u64 {
    if !super::fls_valid(i as usize) {
        set_err(ERROR_INVALID_PARAMETER);
        return 0;
    }
    set_err(0);
    current_thread().map_or(0, |t| t.fls[i as usize])
}
extern "win64" fn fls_set_value(i: u32, v: u64) -> Bool {
    if !super::fls_valid(i as usize) {
        set_err(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    if let Some(t) = current_thread() {
        t.fls[i as usize] = v;
    }
    TRUE
}

// ---- time -----------------------------------------------------------------------------------------

/// FILETIME of 2000-01-01 (100 ns units since 1601-01-01).
const FT_2000: u64 = 125_911_584_000_000_000;

fn filetime(ns_since_2000: i64) -> u64 {
    (FT_2000 as i64 + ns_since_2000 / 100) as u64
}
extern "win64" fn get_system_time_as_file_time(ft: *mut u64) {
    put(ft, filetime(crate::wall_ns()));
}
extern "win64" fn get_system_time(st: *mut [u16; 8]) {
    let c = libd::time::Time(crate::wall_ns()).to_civil();
    let days = crate::wall_ns().div_euclid(86_400_000_000_000);
    let dow = ((days + 6).rem_euclid(7)) as u16; // 2000-01-01 was a Saturday (6)
    put(st, [c.year as u16, u16::from(c.month), dow, u16::from(c.day), u16::from(c.hour), u16::from(c.minute), u16::from(c.second), (c.nanosecond / 1_000_000) as u16]);
}
extern "win64" fn query_performance_counter(v: *mut i64) -> Bool {
    put(v, (sys::clock_ns() / 100) as i64);
    TRUE
}
extern "win64" fn query_performance_frequency(v: *mut i64) -> Bool {
    put(v, 10_000_000);
    TRUE
}
extern "win64" fn get_tick_count() -> u32 {
    (sys::clock_ns() / 1_000_000) as u32
}
extern "win64" fn get_tick_count64() -> u64 {
    sys::clock_ns() / 1_000_000
}

// ---- console and files ---------------------------------------------------------------------------

fn std_handle(n: u32) -> u64 {
    let p = PROC.lock();
    match n as i32 {
        -10 => p.std[0],
        -11 => p.std[1],
        -12 => p.std[2],
        _ => {
            set_err(ERROR_INVALID_HANDLE);
            INVALID_HANDLE_VALUE
        }
    }
}
extern "win64" fn get_std_handle(n: u32) -> u64 {
    std_handle(n)
}
extern "win64" fn set_std_handle(n: u32, h: u64) -> Bool {
    let mut p = PROC.lock();
    match n as i32 {
        -10 => p.std[0] = h,
        -11 => p.std[1] = h,
        -12 => p.std[2] = h,
        _ => {
            set_err(ERROR_INVALID_HANDLE);
            return FALSE;
        }
    }
    TRUE
}
fn is_console(h: u64) -> bool {
    matches!(h, H_STDIN | H_STDOUT | H_STDERR)
}
extern "win64" fn get_file_type(h: u64) -> u32 {
    if is_console(h) || h == H_NUL {
        return 2; // FILE_TYPE_CHAR
    }
    match obj::get(h).as_deref() {
        Some(Obj::File(_)) => 1, // FILE_TYPE_DISK
        Some(_) => 0,
        None => {
            set_err(ERROR_INVALID_HANDLE);
            0
        }
    }
}
extern "win64" fn get_console_mode(h: u64, mode: *mut u32) -> Bool {
    if !is_console(h) {
        set_err(ERROR_INVALID_HANDLE);
        return FALSE;
    }
    put(mode, if h == H_STDIN { 7 } else { 3 });
    TRUE
}
extern "win64" fn set_console_mode(h: u64, _mode: u32) -> Bool {
    Bool::from(is_console(h))
}
extern "win64" fn get_console_cp() -> u32 {
    65001
}

/// Console text: CR LF becomes LF (the D-OS convention).
fn console_write(bytes: &[u8]) {
    let mut v: Vec<u8> = Vec::with_capacity(bytes.len());
    for (i, &c) in bytes.iter().enumerate() {
        if c == b'\r' && bytes.get(i + 1) == Some(&b'\n') {
            continue;
        }
        v.push(c);
    }
    out::write(&v);
}
extern "win64" fn write_console_w(h: u64, buf: *const u16, n: u32, written: *mut u32, _r: u64) -> Bool {
    if h != H_STDOUT && h != H_STDERR {
        set_err(ERROR_INVALID_HANDLE);
        return FALSE;
    }
    // SAFETY: the program's buffer of `n` units.
    let w = unsafe { core::slice::from_raw_parts(buf, n as usize) };
    console_write(&from_wide(w));
    put(written, n);
    TRUE
}
extern "win64" fn write_console_a(h: u64, buf: *const u8, n: u32, written: *mut u32, _r: u64) -> Bool {
    if h != H_STDOUT && h != H_STDERR {
        set_err(ERROR_INVALID_HANDLE);
        return FALSE;
    }
    // SAFETY: the program's buffer of `n` bytes.
    console_write(unsafe { core::slice::from_raw_parts(buf, n as usize) });
    put(written, n);
    TRUE
}
extern "win64" fn read_console_w(h: u64, _buf: *mut u16, _n: u32, read: *mut u32, _c: u64) -> Bool {
    if h != H_STDIN {
        set_err(ERROR_INVALID_HANDLE);
        return FALSE;
    }
    put(read, 0); // no console input yet: end of input
    TRUE
}

/// Special file names: the console and NUL.
fn device(name: &[u8]) -> Option<u64> {
    let leaf = name.rsplit(|&c| c == b'\\' || c == b'/').next().unwrap_or(name);
    if leaf.eq_ignore_ascii_case(b"CONOUT$") {
        Some(H_STDOUT)
    } else if leaf.eq_ignore_ascii_case(b"CONIN$") {
        Some(H_STDIN)
    } else if leaf.eq_ignore_ascii_case(b"NUL") {
        Some(H_NUL)
    } else {
        None
    }
}

fn create_file(name: &[u8], access: u32, disposition: u32, attrs: u32) -> u64 {
    const GENERIC_READ: u32 = 0x8000_0000;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const GENERIC_ALL: u32 = 0x1000_0000;
    const BACKUP_SEMANTICS: u32 = 0x0200_0000;
    if let Some(h) = device(name) {
        return h;
    }
    let abs = win_path(name);
    let write = access & (GENERIC_WRITE | GENERIC_ALL | 0x2 | 0x4 | 0x10000) != 0;
    let _ = GENERIC_READ;
    let rights = fp::R_READ | if write { fp::R_WRITE } else { 0 };
    let open = |flags: u64| path::open(&abs, flags, rights);
    let r = match disposition {
        1 => open(fp::O_CREATE | fp::O_EXCL), // CREATE_NEW
        2 | 4 => match open(0) {
            // CREATE_ALWAYS, OPEN_ALWAYS: say whether it existed
            Ok(n) => {
                set_err(ERROR_ALREADY_EXISTS);
                if disposition == 2 { n.0.truncate(0).map(|_| (n.0, n.1, 0)) } else { Ok(n) }
            }
            Err(fp::ERR_NOT_FOUND) => {
                set_err(0);
                open(fp::O_CREATE)
            }
            Err(e) => Err(e),
        },
        3 => open(0),                // OPEN_EXISTING
        5 => open(fp::O_TRUNCATE),   // TRUNCATE_EXISTING
        _ => Err(sys::ERR_INVALID_ARGS),
    };
    match r {
        Ok((node, kind, _)) => {
            let dir = kind == fp::KIND_DIR;
            if dir && attrs & BACKUP_SEMANTICS == 0 {
                set_err(ERROR_ACCESS_DENIED);
                return INVALID_HANDLE_VALUE;
            }
            let f = obj::File { node, pos: Mutex::new(0), dir, write, path: abs };
            match obj::insert(Obj::File(f)) {
                Some(h) => {
                    if disposition == 1 || disposition == 3 || disposition == 5 {
                        set_err(0);
                    }
                    h
                }
                None => {
                    set_err(ERROR_NOT_ENOUGH_MEMORY);
                    INVALID_HANDLE_VALUE
                }
            }
        }
        Err(sys::ERR_INVALID_ARGS) => {
            set_err(ERROR_INVALID_PARAMETER);
            INVALID_HANDLE_VALUE
        }
        Err(e) => {
            set_err(fs_err(e));
            INVALID_HANDLE_VALUE
        }
    }
}
extern "win64" fn create_file_w(name: *const u16, access: u32, _share: u32, _sa: u64, disp: u32, attrs: u32, _t: u64) -> u64 {
    create_file(&from_wide(&wstr(name)), access, disp, attrs)
}
extern "win64" fn create_file_a(name: *const u8, access: u32, _share: u32, _sa: u64, disp: u32, attrs: u32, _t: u64) -> u64 {
    create_file(&cstr(name), access, disp, attrs)
}

extern "win64" fn read_file(h: u64, buf: *mut u8, n: u32, read: *mut u32, ov: u64) -> Bool {
    put(read, 0);
    if h == H_STDIN || h == H_NUL {
        return TRUE; // end of input
    }
    if ov != 0 {
        set_err(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    let Some(o) = obj::get(h) else {
        set_err(ERROR_INVALID_HANDLE);
        return FALSE;
    };
    let Obj::File(f) = &*o else {
        set_err(ERROR_INVALID_HANDLE);
        return FALSE;
    };
    if f.dir {
        set_err(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    // SAFETY: the program's buffer of `n` bytes.
    let b = unsafe { core::slice::from_raw_parts_mut(buf, n as usize) };
    let mut pos = f.pos.lock();
    match f.node.read(*pos, b) {
        Ok(got) => {
            *pos += got as u64;
            put(read, got as u32);
            TRUE
        }
        Err(e) => {
            set_err(fs_err(e));
            FALSE
        }
    }
}
extern "win64" fn write_file(h: u64, buf: *const u8, n: u32, written: *mut u32, ov: u64) -> Bool {
    put(written, 0);
    // SAFETY: the program's buffer of `n` bytes.
    let b = unsafe { core::slice::from_raw_parts(buf, n as usize) };
    if h == H_STDOUT || h == H_STDERR {
        console_write(b);
        put(written, n);
        return TRUE;
    }
    if h == H_NUL {
        put(written, n);
        return TRUE;
    }
    if ov != 0 {
        set_err(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    let Some(o) = obj::get(h) else {
        set_err(ERROR_INVALID_HANDLE);
        return FALSE;
    };
    let Obj::File(f) = &*o else {
        set_err(ERROR_INVALID_HANDLE);
        return FALSE;
    };
    if f.dir || !f.write {
        set_err(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    let mut pos = f.pos.lock();
    match f.node.write(*pos, b) {
        Ok(w) => {
            *pos += w as u64;
            put(written, w as u32);
            TRUE
        }
        Err(e) => {
            set_err(fs_err(e));
            FALSE
        }
    }
}
fn with_file<R>(h: u64, fail: R, f: impl FnOnce(&obj::File) -> R) -> R {
    match obj::get(h).as_deref() {
        Some(Obj::File(file)) => f(file),
        _ => {
            set_err(ERROR_INVALID_HANDLE);
            fail
        }
    }
}
fn seek(file: &obj::File, dist: i64, method: u32) -> Option<u64> {
    let mut pos = file.pos.lock();
    let base = match method {
        0 => 0,
        1 => *pos as i64,
        2 => match file.node.stat() {
            Ok(s) => s.size as i64,
            Err(e) => {
                set_err(fs_err(e));
                return None;
            }
        },
        _ => {
            set_err(ERROR_INVALID_PARAMETER);
            return None;
        }
    };
    let n = base.checked_add(dist).filter(|&n| n >= 0);
    match n {
        Some(n) => {
            *pos = n as u64;
            Some(n as u64)
        }
        None => {
            set_err(131); // ERROR_NEGATIVE_SEEK
            None
        }
    }
}
extern "win64" fn set_file_pointer_ex(h: u64, dist: i64, newpos: *mut u64, method: u32) -> Bool {
    with_file(h, FALSE, |f| match seek(f, dist, method) {
        Some(n) => {
            put(newpos, n);
            TRUE
        }
        None => FALSE,
    })
}
extern "win64" fn set_file_pointer(h: u64, lo: i32, hi: *mut i32, method: u32) -> u32 {
    // SAFETY: the program's optional high half.
    let dist = match unsafe { hi.as_ref() } {
        Some(&h) => (i64::from(h) << 32) | i64::from(lo as u32),
        None => i64::from(lo),
    };
    with_file(h, u32::MAX, |f| match seek(f, dist, method) {
        Some(n) => {
            put(hi, (n >> 32) as i32);
            n as u32
        }
        None => u32::MAX,
    })
}
extern "win64" fn get_file_size_ex(h: u64, size: *mut i64) -> Bool {
    with_file(h, FALSE, |f| match f.node.stat() {
        Ok(s) => {
            put(size, s.size as i64);
            TRUE
        }
        Err(e) => {
            set_err(fs_err(e));
            FALSE
        }
    })
}
extern "win64" fn get_file_size(h: u64, hi: *mut u32) -> u32 {
    with_file(h, u32::MAX, |f| match f.node.stat() {
        Ok(s) => {
            put(hi, (s.size >> 32) as u32);
            s.size as u32
        }
        Err(e) => {
            set_err(fs_err(e));
            u32::MAX
        }
    })
}
extern "win64" fn set_end_of_file(h: u64) -> Bool {
    with_file(h, FALSE, |f| {
        let pos = *f.pos.lock();
        match f.node.truncate(pos) {
            Ok(()) => TRUE,
            Err(e) => {
                set_err(fs_err(e));
                FALSE
            }
        }
    })
}
extern "win64" fn flush_file_buffers(h: u64) -> Bool {
    if is_console(h) || h == H_NUL {
        out::flush_all();
        return TRUE;
    }
    with_file(h, FALSE, |f| if f.write { Bool::from(f.node.sync().is_ok()) } else { TRUE })
}

/// FILETIME of a D-OS time (0 = unknown: 2000-01-01).
fn ft_of(t: i64) -> u64 {
    filetime(t)
}
/// File attributes and the 36-byte WIN32_FILE_ATTRIBUTE_DATA of `abs`.
fn attributes(abs: &[u8]) -> Result<(u32, [u8; 36]), u32> {
    let (n, kind, _) = path::open(abs, 0, fp::R_READ).map_err(fs_err)?;
    let st = n.stat().map_err(fs_err)?;
    let attr = if kind == fp::KIND_DIR { 0x10 } else { 0x80 };
    let mut d = [0u8; 36];
    d[0..4].copy_from_slice(&u32::to_le_bytes(attr));
    d[4..12].copy_from_slice(&ft_of(st.created).to_le_bytes());
    d[12..20].copy_from_slice(&ft_of(st.modified).to_le_bytes());
    d[20..28].copy_from_slice(&ft_of(st.modified).to_le_bytes());
    d[28..32].copy_from_slice(&((st.size >> 32) as u32).to_le_bytes());
    d[32..36].copy_from_slice(&(st.size as u32).to_le_bytes());
    Ok((attr, d))
}
fn get_attrs(name: &[u8]) -> u32 {
    match attributes(&win_path(name)) {
        Ok((a, _)) => a,
        Err(e) => {
            set_err(e);
            u32::MAX
        }
    }
}
extern "win64" fn get_file_attributes_w(name: *const u16) -> u32 {
    get_attrs(&from_wide(&wstr(name)))
}
extern "win64" fn get_file_attributes_a(name: *const u8) -> u32 {
    get_attrs(&cstr(name))
}
fn get_attrs_ex(name: &[u8], data: *mut [u8; 36]) -> Bool {
    match attributes(&win_path(name)) {
        Ok((_, d)) => {
            put(data, d);
            TRUE
        }
        Err(e) => {
            set_err(e);
            FALSE
        }
    }
}
extern "win64" fn get_file_attributes_ex_w(name: *const u16, _level: u32, data: *mut [u8; 36]) -> Bool {
    get_attrs_ex(&from_wide(&wstr(name)), data)
}
extern "win64" fn get_file_attributes_ex_a(name: *const u8, _level: u32, data: *mut [u8; 36]) -> Bool {
    get_attrs_ex(&cstr(name), data)
}
fn delete_file(name: &[u8]) -> Bool {
    let abs = win_path(name);
    let r = path::parent(&abs, fp::R_READ | fp::R_WRITE).and_then(|(d, leaf)| d.unlink(&leaf));
    match r {
        Ok(()) => TRUE,
        Err(e) => {
            set_err(fs_err(e));
            FALSE
        }
    }
}
extern "win64" fn delete_file_w(name: *const u16) -> Bool {
    delete_file(&from_wide(&wstr(name)))
}
extern "win64" fn delete_file_a(name: *const u8) -> Bool {
    delete_file(&cstr(name))
}
fn create_directory(name: &[u8]) -> Bool {
    let abs = win_path(name);
    let r = path::parent(&abs, fp::R_READ | fp::R_WRITE).and_then(|(d, leaf)| d.open(&leaf, fp::O_CREATE | fp::O_EXCL | fp::O_DIRECTORY, fp::R_READ));
    match r {
        Ok(_) => TRUE,
        Err(fp::ERR_EXISTS) => {
            set_err(ERROR_ALREADY_EXISTS);
            FALSE
        }
        Err(e) => {
            set_err(fs_err(e));
            FALSE
        }
    }
}
extern "win64" fn create_directory_w(name: *const u16, _sa: u64) -> Bool {
    create_directory(&from_wide(&wstr(name)))
}
extern "win64" fn create_directory_a(name: *const u8, _sa: u64) -> Bool {
    create_directory(&cstr(name))
}
extern "win64" fn remove_directory_w(name: *const u16) -> Bool {
    delete_file(&from_wide(&wstr(name)))
}
extern "win64" fn remove_directory_a(name: *const u8) -> Bool {
    delete_file(&cstr(name))
}
fn move_file(from: &[u8], to: &[u8], flags: u32) -> Bool {
    match path::rename(&win_path(from), &win_path(to), flags & 1 != 0) {
        Ok(()) => TRUE,
        Err(fp::ERR_EXISTS) => {
            set_err(ERROR_ALREADY_EXISTS);
            FALSE
        }
        Err(e) => {
            set_err(fs_err(e));
            FALSE
        }
    }
}
extern "win64" fn move_file_ex_w(from: *const u16, to: *const u16, flags: u32) -> Bool {
    move_file(&from_wide(&wstr(from)), &from_wide(&wstr(to)), flags)
}
extern "win64" fn move_file_w(from: *const u16, to: *const u16) -> Bool {
    move_file(&from_wide(&wstr(from)), &from_wide(&wstr(to)), 0)
}
fn cwd_windows() -> Vec<u8> {
    let mut s = Vec::from(&b"C:"[..]);
    s.extend(path::cwd().bytes().map(|c| if c == b'/' { b'\\' } else { c }));
    s
}
extern "win64" fn get_current_directory_w(n: u32, buf: *mut u16) -> u32 {
    let w = to_wide(&cwd_windows(), false).unwrap_or_default();
    if (n as usize) <= w.len() {
        return w.len() as u32 + 1;
    }
    // SAFETY: the program's buffer of `n` units.
    unsafe {
        core::ptr::copy_nonoverlapping(w.as_ptr(), buf, w.len());
        buf.add(w.len()).write(0);
    }
    w.len() as u32
}
extern "win64" fn get_current_directory_a(n: u32, buf: *mut u8) -> u32 {
    let s = cwd_windows();
    if (n as usize) <= s.len() {
        return s.len() as u32 + 1;
    }
    // SAFETY: the program's buffer of `n` bytes.
    unsafe {
        core::ptr::copy_nonoverlapping(s.as_ptr(), buf, s.len());
        buf.add(s.len()).write(0);
    }
    s.len() as u32
}
fn set_cwd(name: &[u8]) -> Bool {
    match path::set_cwd(&win_path(name)) {
        Ok(()) => TRUE,
        Err(e) => {
            set_err(if e == fp::ERR_NOT_DIR { ERROR_DIRECTORY } else { fs_err(e) });
            FALSE
        }
    }
}
extern "win64" fn set_current_directory_w(name: *const u16) -> Bool {
    set_cwd(&from_wide(&wstr(name)))
}
extern "win64" fn set_current_directory_a(name: *const u8) -> Bool {
    set_cwd(&cstr(name))
}

/// `*` and `?` matching, case-insensitive (`*.*` matches names without a dot too).
fn glob(p: &[u8], n: &[u8]) -> bool {
    if p == b"*.*" {
        return true;
    }
    match (p.first(), n.first()) {
        (None, None) => true,
        (Some(b'*'), _) => glob(&p[1..], n) || (!n.is_empty() && glob(p, &n[1..])),
        (Some(b'?'), Some(_)) => glob(&p[1..], &n[1..]),
        (Some(a), Some(b)) if a.eq_ignore_ascii_case(b) => glob(&p[1..], &n[1..]),
        _ => false,
    }
}
/// Fill WIN32_FIND_DATAW (592 bytes) for `name` in `dir`.
fn fill_find(dir: &[u8], name: &[u8], kind: u64, data: *mut u8) {
    let mut full = dir.to_vec();
    if !full.ends_with(b"/") {
        full.push(b'/');
    }
    full.extend_from_slice(name);
    let d = attributes(&full).map(|(_, d)| d).unwrap_or_else(|_| {
        let mut d = [0u8; 36];
        d[..4].copy_from_slice(&u32::to_le_bytes(if kind == fp::KIND_DIR { 0x10 } else { 0x80 }));
        d
    });
    let w = to_wide(name, false).unwrap_or_default();
    // SAFETY: the program's WIN32_FIND_DATAW.
    unsafe {
        core::ptr::write_bytes(data, 0, 592);
        core::ptr::copy_nonoverlapping(d.as_ptr(), data, 36);
        let n = w.len().min(259);
        core::ptr::copy_nonoverlapping(w.as_ptr().cast::<u8>(), data.add(44), n * 2);
    }
}
extern "win64" fn find_first_file_ex_w(name: *const u16, _level: u32, data: *mut u8, _op: u32, _filter: u64, _flags: u32) -> u64 {
    let n = from_wide(&wstr(name));
    let n: Vec<u8> = n.iter().map(|&c| if c == b'\\' { b'/' } else { c }).collect();
    let (dir_part, pat) = match n.iter().rposition(|&c| c == b'/') {
        Some(i) => (&n[..i + 1], &n[i + 1..]),
        None => (&b""[..], &n[..]),
    };
    let dir = win_path(dir_part);
    let mut names: Vec<(Vec<u8>, u64)> = Vec::new();
    let r = path::open(&dir, fp::O_DIRECTORY, fp::R_READ).and_then(|(d, kind, _)| {
        if kind != fp::KIND_DIR {
            return Err(fp::ERR_NOT_DIR);
        }
        d.list(|nm, k| {
            if glob(pat, nm) {
                names.push((nm.to_vec(), k));
            }
        })
    });
    if let Err(e) = r {
        set_err(fs_err(e));
        return INVALID_HANDLE_VALUE;
    }
    if names.is_empty() {
        set_err(ERROR_FILE_NOT_FOUND);
        return INVALID_HANDLE_VALUE;
    }
    fill_find(&dir, &names[0].0, names[0].1, data);
    obj::insert(Obj::Find(obj::Find { dir, names, next: Mutex::new(1) })).unwrap_or_else(|| {
        set_err(ERROR_NOT_ENOUGH_MEMORY);
        INVALID_HANDLE_VALUE
    })
}
extern "win64" fn find_first_file_w(name: *const u16, data: *mut u8) -> u64 {
    find_first_file_ex_w(name, 0, data, 0, 0, 0)
}
extern "win64" fn find_next_file_w(h: u64, data: *mut u8) -> Bool {
    match obj::get(h).as_deref() {
        Some(Obj::Find(f)) => {
            let mut i = f.next.lock();
            match f.names.get(*i) {
                Some((n, k)) => {
                    fill_find(&f.dir, n, *k, data);
                    *i += 1;
                    TRUE
                }
                None => {
                    set_err(ERROR_NO_MORE_FILES);
                    FALSE
                }
            }
        }
        _ => {
            set_err(ERROR_INVALID_HANDLE);
            FALSE
        }
    }
}
extern "win64" fn find_close(h: u64) -> Bool {
    Bool::from(obj::remove(h))
}

// ---- code pages and strings --------------------------------------------------------------------

fn is_utf8(cp: u32) -> Option<bool> {
    match cp {
        0 | 1 | 2 | 3 | 65001 => Some(true),     // ACP, OEMCP, MACCP, THREAD_ACP: UTF-8 on D-OS
        437 | 850 | 1252 | 20127 | 28591 => Some(false), // treated as Latin-1
        _ => None,
    }
}
extern "win64" fn multi_byte_to_wide_char(cp: u32, flags: u32, src: *const u8, n: i32, dst: *mut u16, m: i32) -> i32 {
    let Some(utf8) = is_utf8(cp) else {
        set_err(ERROR_INVALID_PARAMETER);
        return 0;
    };
    if src.is_null() || n == 0 || m < 0 {
        set_err(ERROR_INVALID_PARAMETER);
        return 0;
    }
    let len = if n < 0 { cstr(src).len() + 1 } else { n as usize };
    // SAFETY: the program's string of `len` bytes.
    let s = unsafe { core::slice::from_raw_parts(src, len) };
    let w: Vec<u16> = if utf8 {
        match to_wide(s, flags & 8 != 0) {
            Some(w) => w,
            None => {
                set_err(ERROR_NO_UNICODE_TRANSLATION);
                return 0;
            }
        }
    } else {
        s.iter().map(|&c| u16::from(c)).collect()
    };
    if m == 0 {
        return w.len() as i32;
    }
    if (m as usize) < w.len() {
        set_err(ERROR_INSUFFICIENT_BUFFER);
        return 0;
    }
    // SAFETY: the program's buffer of `m` units.
    unsafe { core::ptr::copy_nonoverlapping(w.as_ptr(), dst, w.len()) };
    w.len() as i32
}
extern "win64" fn wide_char_to_multi_byte(cp: u32, _flags: u32, src: *const u16, n: i32, dst: *mut u8, m: i32, _def: u64, used: *mut Bool) -> i32 {
    let Some(utf8) = is_utf8(cp) else {
        set_err(ERROR_INVALID_PARAMETER);
        return 0;
    };
    if src.is_null() || n == 0 || m < 0 {
        set_err(ERROR_INVALID_PARAMETER);
        return 0;
    }
    let len = if n < 0 { wstr(src).len() + 1 } else { n as usize };
    // SAFETY: the program's string of `len` units.
    let s = unsafe { core::slice::from_raw_parts(src, len) };
    let mut used_def = false;
    let b: Vec<u8> = if utf8 {
        from_wide(s)
    } else {
        s.iter()
            .map(|&c| {
                if c > 0xFF {
                    used_def = true;
                    b'?'
                } else {
                    c as u8
                }
            })
            .collect()
    };
    put(used, Bool::from(used_def));
    if m == 0 {
        return b.len() as i32;
    }
    if (m as usize) < b.len() {
        set_err(ERROR_INSUFFICIENT_BUFFER);
        return 0;
    }
    // SAFETY: the program's buffer of `m` bytes.
    unsafe { core::ptr::copy_nonoverlapping(b.as_ptr(), dst, b.len()) };
    b.len() as i32
}
extern "win64" fn get_acp() -> u32 {
    65001
}
extern "win64" fn is_valid_code_page(cp: u32) -> Bool {
    Bool::from(cp != 0 && cp != 1 && cp != 2 && cp != 3 && is_utf8(cp).is_some())
}
extern "win64" fn get_cp_info(cp: u32, info: *mut u8) -> Bool {
    let Some(utf8) = is_utf8(cp) else {
        set_err(ERROR_INVALID_PARAMETER);
        return FALSE;
    };
    if info.is_null() {
        set_err(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    // SAFETY: the program's CPINFO (18 bytes).
    unsafe {
        core::ptr::write_bytes(info, 0, 18);
        (info as *mut u32).write_unaligned(if utf8 { 4 } else { 1 });
        info.add(4).write(b'?');
    }
    TRUE
}
fn ctype1(c: u16) -> u16 {
    let ch = char::from_u32(u32::from(c)).unwrap_or('\0');
    let mut t = 0;
    if ch.is_uppercase() {
        t |= 0x1;
    }
    if ch.is_lowercase() {
        t |= 0x2;
    }
    if ch.is_ascii_digit() {
        t |= 0x4;
    }
    if ch.is_whitespace() {
        t |= 0x8;
    }
    if ch.is_ascii_punctuation() {
        t |= 0x10;
    }
    if ch.is_control() {
        t |= 0x20;
    }
    if ch == ' ' || ch == '\t' {
        t |= 0x40;
    }
    if ch.is_ascii_hexdigit() {
        t |= 0x80;
    }
    if ch.is_alphabetic() {
        t |= 0x100;
    }
    t
}
extern "win64" fn get_string_type_w(kind: u32, src: *const u16, n: i32, out: *mut u16) -> Bool {
    if src.is_null() || out.is_null() {
        set_err(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    let len = if n < 0 { wstr(src).len() + 1 } else { n as usize };
    for i in 0..len {
        // SAFETY: the program's string and output array of `len` units.
        unsafe { out.add(i).write_unaligned(if kind == 1 { ctype1(src.add(i).read_unaligned()) } else { 0 }) };
    }
    TRUE
}
fn map_case(c: u16, upper: bool) -> u16 {
    let Some(ch) = char::from_u32(u32::from(c)) else { return c };
    let mut it: alloc::vec::Vec<char> = if upper { ch.to_uppercase().collect() } else { ch.to_lowercase().collect() };
    match (it.len(), it.pop()) {
        (1, Some(m)) if (m as u32) < 0x10000 => m as u16,
        _ => c,
    }
}
extern "win64" fn lc_map_string_w(_lcid: u32, flags: u32, src: *const u16, n: i32, dst: *mut u16, m: i32) -> i32 {
    const LOWER: u32 = 0x100;
    const UPPER: u32 = 0x200;
    const SORTKEY: u32 = 0x400;
    if flags & SORTKEY != 0 || src.is_null() {
        set_err(1004); // ERROR_INVALID_FLAGS
        return 0;
    }
    let len = if n < 0 { wstr(src).len() + 1 } else { n as usize };
    if m == 0 {
        return len as i32;
    }
    if (m as usize) < len {
        set_err(ERROR_INSUFFICIENT_BUFFER);
        return 0;
    }
    for i in 0..len {
        // SAFETY: the program's input and output of `len` units.
        unsafe {
            let c = src.add(i).read_unaligned();
            let c = if flags & UPPER != 0 { map_case(c, true) } else if flags & LOWER != 0 { map_case(c, false) } else { c };
            dst.add(i).write_unaligned(c);
        }
    }
    len as i32
}
extern "win64" fn compare_string_w(_lcid: u32, flags: u32, a: *const u16, na: i32, b: *const u16, nb: i32) -> i32 {
    let get = |p: *const u16, n: i32| -> Vec<u16> {
        if n < 0 {
            wstr(p)
        } else {
            // SAFETY: the program's string of `n` units.
            unsafe { core::slice::from_raw_parts(p, n as usize) }.to_vec()
        }
    };
    let (mut x, mut y) = (get(a, na), get(b, nb));
    if flags & 1 != 0 {
        x.iter_mut().for_each(|c| *c = map_case(*c, false));
        y.iter_mut().for_each(|c| *c = map_case(*c, false));
    }
    match x.cmp(&y) {
        core::cmp::Ordering::Less => 1,
        core::cmp::Ordering::Equal => 2,
        core::cmp::Ordering::Greater => 3,
    }
}

// ---- the export table ------------------------------------------------------------------------------

macro_rules! exports {
    ($($n:literal => $f:expr),* $(,)?) => {
        fn lookup(func: &[u8]) -> Option<u64> {
            match func {
                $( $n => Some($f as *const () as u64), )*
                _ => None,
            }
        }
        /// How many functions D-CMPL's kernel32 has.
        pub fn count() -> usize {
            [$(&$n[..]),*].len()
        }
    };
}

exports! {
    b"CloseHandle" => close_handle,
    b"CompareStringW" => compare_string_w,
    b"CreateDirectoryA" => create_directory_a,
    b"CreateDirectoryW" => create_directory_w,
    b"CreateEventW" => create_event_w,
    b"CreateFileA" => create_file_a,
    b"CreateFileW" => create_file_w,
    b"CreateThread" => create_thread,
    b"DecodePointer" => encode_pointer,
    b"DeleteCriticalSection" => delete_critical_section,
    b"DeleteFileA" => delete_file_a,
    b"DeleteFileW" => delete_file_w,
    b"DuplicateHandle" => duplicate_handle,
    b"EncodePointer" => encode_pointer,
    b"EnterCriticalSection" => enter_critical_section,
    b"ExitProcess" => exit_process,
    b"ExitThread" => exit_thread,
    b"FindClose" => find_close,
    b"FindFirstFileExW" => find_first_file_ex_w,
    b"FindFirstFileW" => find_first_file_w,
    b"FindNextFileW" => find_next_file_w,
    b"FlsAlloc" => fls_alloc,
    b"FlsFree" => fls_free,
    b"FlsGetValue" => fls_get_value,
    b"FlsSetValue" => fls_set_value,
    b"FlushFileBuffers" => flush_file_buffers,
    b"FreeEnvironmentStringsA" => free_environment_strings,
    b"FreeEnvironmentStringsW" => free_environment_strings,
    b"FreeLibrary" => free_library,
    b"FreeLibraryAndExitThread" => free_library_and_exit_thread,
    b"GetACP" => get_acp,
    b"GetCPInfo" => get_cp_info,
    b"GetCommandLineA" => get_command_line_a,
    b"GetCommandLineW" => get_command_line_w,
    b"GetConsoleCP" => get_console_cp,
    b"GetConsoleMode" => get_console_mode,
    b"GetConsoleOutputCP" => get_console_cp,
    b"GetCurrentDirectoryA" => get_current_directory_a,
    b"GetCurrentDirectoryW" => get_current_directory_w,
    b"GetCurrentProcess" => get_current_process,
    b"GetCurrentProcessId" => get_current_process_id,
    b"GetCurrentThread" => get_current_thread,
    b"GetCurrentThreadId" => get_current_thread_id,
    b"GetEnvironmentStrings" => get_environment_strings_a,
    b"GetEnvironmentStringsW" => get_environment_strings_w,
    b"GetEnvironmentVariableA" => get_environment_variable_a,
    b"GetEnvironmentVariableW" => get_environment_variable_w,
    b"GetExitCodeThread" => get_exit_code_thread,
    b"GetFileAttributesA" => get_file_attributes_a,
    b"GetFileAttributesExA" => get_file_attributes_ex_a,
    b"GetFileAttributesExW" => get_file_attributes_ex_w,
    b"GetFileAttributesW" => get_file_attributes_w,
    b"GetFileSize" => get_file_size,
    b"GetFileSizeEx" => get_file_size_ex,
    b"GetFileType" => get_file_type,
    b"GetLastError" => get_last_error,
    b"GetLocalTime" => get_system_time,
    b"GetModuleFileNameA" => get_module_file_name_a,
    b"GetModuleFileNameW" => get_module_file_name_w,
    b"GetModuleHandleA" => get_module_handle_a,
    b"GetModuleHandleExW" => get_module_handle_ex_w,
    b"GetModuleHandleW" => get_module_handle_w,
    b"GetNativeSystemInfo" => get_system_info,
    b"GetOEMCP" => get_acp,
    b"GetProcAddress" => get_proc_address,
    b"GetProcessHeap" => get_process_heap,
    b"GetStartupInfoW" => get_startup_info_w,
    b"GetStdHandle" => get_std_handle,
    b"GetStringTypeW" => get_string_type_w,
    b"GetSystemInfo" => get_system_info,
    b"GetSystemTime" => get_system_time,
    b"GetSystemTimeAsFileTime" => get_system_time_as_file_time,
    b"GetSystemTimePreciseAsFileTime" => get_system_time_as_file_time,
    b"GetThreadId" => get_thread_id,
    b"GetTickCount" => get_tick_count,
    b"GetTickCount64" => get_tick_count64,
    b"HeapAlloc" => heap_alloc_w,
    b"HeapCreate" => heap_create,
    b"HeapDestroy" => heap_destroy,
    b"HeapFree" => heap_free_w,
    b"HeapReAlloc" => heap_realloc_w,
    b"HeapSize" => heap_size_w,
    b"InitializeCriticalSection" => initialize_critical_section,
    b"InitializeCriticalSectionAndSpinCount" => initialize_critical_section_ex,
    b"InitializeCriticalSectionEx" => initialize_critical_section_ex,
    b"InitializeSListHead" => initialize_slist_head,
    b"IsDebuggerPresent" => is_debugger_present,
    b"IsProcessorFeaturePresent" => is_processor_feature_present,
    b"IsValidCodePage" => is_valid_code_page,
    b"LCMapStringW" => lc_map_string_w,
    b"LeaveCriticalSection" => leave_critical_section,
    b"LoadLibraryA" => load_library_a,
    b"LoadLibraryExW" => load_library_ex_w,
    b"LoadLibraryW" => load_library_w,
    b"MoveFileExW" => move_file_ex_w,
    b"MoveFileW" => move_file_w,
    b"MultiByteToWideChar" => multi_byte_to_wide_char,
    b"OutputDebugStringA" => output_debug_string_a,
    b"OutputDebugStringW" => output_debug_string_w,
    b"QueryPerformanceCounter" => query_performance_counter,
    b"QueryPerformanceFrequency" => query_performance_frequency,
    b"RaiseException" => seh::dcmpl_raise_exception,
    b"ReadConsoleW" => read_console_w,
    b"ReadFile" => read_file,
    b"RemoveDirectoryA" => remove_directory_a,
    b"RemoveDirectoryW" => remove_directory_w,
    b"ResetEvent" => reset_event,
    b"ResumeThread" => resume_thread,
    b"RtlCaptureContext" => seh::dcmpl_capture_context,
    b"RtlLookupFunctionEntry" => seh::rtl_lookup_function_entry,
    b"RtlPcToFileHeader" => seh::rtl_pc_to_file_header,
    b"RtlRestoreContext" => seh::dcmpl_restore_context,
    b"RtlUnwindEx" => seh::dcmpl_unwind_ex,
    b"RtlVirtualUnwind" => seh::rtl_virtual_unwind,
    b"SetConsoleMode" => set_console_mode,
    b"SetCurrentDirectoryA" => set_current_directory_a,
    b"SetCurrentDirectoryW" => set_current_directory_w,
    b"SetEndOfFile" => set_end_of_file,
    b"SetEnvironmentVariableA" => set_environment_variable_a,
    b"SetEnvironmentVariableW" => set_environment_variable_w,
    b"SetEvent" => set_event,
    b"SetFilePointer" => set_file_pointer,
    b"SetFilePointerEx" => set_file_pointer_ex,
    b"SetLastError" => set_last_error,
    b"SetStdHandle" => set_std_handle,
    b"SetUnhandledExceptionFilter" => set_unhandled_exception_filter,
    b"Sleep" => sleep,
    b"SleepEx" => sleep_ex,
    b"SwitchToThread" => switch_to_thread,
    b"TerminateProcess" => terminate_process,
    b"TlsAlloc" => tls_alloc,
    b"TlsFree" => tls_free,
    b"TlsGetValue" => tls_get_value,
    b"TlsSetValue" => tls_set_value,
    b"TryEnterCriticalSection" => try_enter_critical_section,
    b"UnhandledExceptionFilter" => unhandled_exception_filter,
    b"VirtualAlloc" => virtual_alloc,
    b"VirtualFree" => virtual_free,
    b"VirtualProtect" => virtual_protect,
    b"WaitForMultipleObjects" => wait_for_multiple_objects,
    b"WaitForSingleObject" => wait_for_single_object,
    b"WaitForSingleObjectEx" => wait_for_single_object_ex,
    b"WideCharToMultiByte" => wide_char_to_multi_byte,
    b"WriteConsoleA" => write_console_a,
    b"WriteConsoleW" => write_console_w,
    b"WriteFile" => write_file,
}

/// The import binder's resolver: KERNEL32.dll only.
pub fn resolve(dll: &[u8], func: &[u8]) -> Option<u64> {
    if dll.eq_ignore_ascii_case(b"kernel32.dll") { lookup(func) } else { None }
}
