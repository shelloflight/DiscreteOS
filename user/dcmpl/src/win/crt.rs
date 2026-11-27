//! Built-in D-CMPL dynamic Windows runtime shims:
//! - `ucrtbase.dll` (and `api-ms-win-crt-*` API sets)
//! - `vcruntime140.dll` & `vcruntime140_1.dll`
//! - `kernelbase.dll` & `ntdll.dll` additions
//!
//! Enables unmodified MSVC `/MD` dynamic executables and DLLs to run natively on D-OS without
//! redistributing proprietary runtime DLLs. All file I/O goes through `k32::win_path_pub` and
//! `path::open`, keeping strict namespace & prefix confinement.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicI32, AtomicU32, AtomicU64, Ordering};

use libd::fs::{self as fp, Node};
use libd::sync::Mutex;
use libd::sys;

use super::{current_thread, k32, seh};
use crate::{out, path};

// ---- helpers -----------------------------------------------------------------------------------

fn read_cstr(p: *const u8) -> Vec<u8> {
    let mut v = Vec::new();
    if p.is_null() {
        return v;
    }
    for i in 0..65536 {
        // SAFETY: caller's NUL-terminated C string.
        let c = unsafe { p.add(i).read() };
        if c == 0 {
            break;
        }
        v.push(c);
    }
    v
}

fn c_strlen(p: *const u8) -> usize {
    if p.is_null() {
        return 0;
    }
    let mut n = 0;
    // SAFETY: caller's NUL-terminated C string.
    while unsafe { p.add(n).read() } != 0 {
        n += 1;
    }
    n
}

fn set_errno(e: i32) {
    if let Some(t) = current_thread() {
        t.crt_errno = e;
    }
}

fn fs_to_errno(e: i64) -> i32 {
    match e {
        fp::ERR_NOT_FOUND => 2,      // ENOENT
        sys::ERR_ACCESS_DENIED => 13, // EACCES
        fp::ERR_EXISTS => 17,        // EEXIST
        fp::ERR_IS_DIR => 21,        // EISDIR
        fp::ERR_NOT_DIR => 20,       // ENOTDIR
        fp::ERR_READ_ONLY => 30,     // EROFS
        sys::ERR_NO_SPACE => 28,     // ENOSPC
        sys::ERR_NO_MEMORY => 12,    // ENOMEM
        _ => 22,                     // EINVAL
    }
}

// ---- heap & allocation -------------------------------------------------------------------------

static NEW_MODE: AtomicI32 = AtomicI32::new(0);

extern "win64" fn crt_malloc(size: usize) -> *mut u8 {
    k32::heap_alloc_pub(size.max(1), false)
}
extern "win64" fn crt_calloc(nmemb: usize, size: usize) -> *mut u8 {
    let Some(total) = nmemb.checked_mul(size) else {
        set_errno(12);
        return core::ptr::null_mut();
    };
    k32::heap_alloc_pub(total.max(1), true)
}
extern "win64" fn crt_realloc(p: *mut u8, size: usize) -> *mut u8 {
    if p.is_null() {
        return crt_malloc(size);
    }
    if size == 0 {
        k32::heap_free_pub(p);
        return core::ptr::null_mut();
    }
    k32::heap_realloc_pub(p, size)
}
extern "win64" fn crt_free(p: *mut u8) {
    k32::heap_free_pub(p);
}
extern "win64" fn crt_msize(p: *mut u8) -> usize {
    k32::heap_size_pub(p)
}
extern "win64" fn crt_set_new_mode(mode: i32) -> i32 {
    NEW_MODE.swap(mode, Ordering::Relaxed)
}
extern "win64" fn crt_query_new_mode() -> i32 {
    NEW_MODE.load(Ordering::Relaxed)
}
extern "win64" fn crt_strdup(s: *const u8) -> *mut u8 {
    if s.is_null() {
        return core::ptr::null_mut();
    }
    let n = c_strlen(s) + 1;
    let d = crt_malloc(n);
    if !d.is_null() {
        // SAFETY: freshly allocated buffer of `n` bytes.
        unsafe { core::ptr::copy_nonoverlapping(s, d, n) };
    }
    d
}

// ---- memory & string operations (vcruntime140 & ucrtbase) --------------------------------------

extern "win64" fn crt_memcpy(dst: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    if n > 0 && !dst.is_null() && !src.is_null() {
        // SAFETY: caller's buffers of `n` bytes.
        unsafe { core::ptr::copy(src, dst, n) };
    }
    dst
}
extern "win64" fn crt_memset(dst: *mut u8, c: i32, n: usize) -> *mut u8 {
    if n > 0 && !dst.is_null() {
        // SAFETY: caller's buffer of `n` bytes.
        unsafe { core::ptr::write_bytes(dst, c as u8, n) };
    }
    dst
}
extern "win64" fn crt_memcmp(a: *const u8, b: *const u8, n: usize) -> i32 {
    for i in 0..n {
        // SAFETY: caller's buffers of `n` bytes.
        let (x, y) = unsafe { (a.add(i).read(), b.add(i).read()) };
        if x != y {
            return i32::from(x) - i32::from(y);
        }
    }
    0
}
extern "win64" fn crt_memchr(p: *const u8, c: i32, n: usize) -> *const u8 {
    let want = c as u8;
    for i in 0..n {
        // SAFETY: caller's buffer of `n` bytes.
        if unsafe { p.add(i).read() } == want {
            // SAFETY: inside buffer.
            return unsafe { p.add(i) };
        }
    }
    core::ptr::null()
}
extern "win64" fn crt_memcpy_s(dst: *mut u8, dstsz: usize, src: *const u8, count: usize) -> i32 {
    if count == 0 {
        return 0;
    }
    if dst.is_null() || src.is_null() || count > dstsz {
        if !dst.is_null() && dstsz > 0 {
            // SAFETY: zero dst on failure per Annex K.
            unsafe { core::ptr::write_bytes(dst, 0, dstsz) };
        }
        return 22;
    }
    // SAFETY: checked non-null and `count <= dstsz`.
    unsafe { core::ptr::copy(src, dst, count) };
    0
}
extern "win64" fn crt_strlen(s: *const u8) -> usize {
    c_strlen(s)
}
extern "win64" fn crt_strnlen(s: *const u8, max: usize) -> usize {
    if s.is_null() {
        return 0;
    }
    let mut n = 0;
    // SAFETY: bounded by `max`.
    while n < max && unsafe { s.add(n).read() } != 0 {
        n += 1;
    }
    n
}
extern "win64" fn crt_strcmp(a: *const u8, b: *const u8) -> i32 {
    let mut i = 0;
    loop {
        // SAFETY: NUL-terminated strings.
        let (x, y) = unsafe { (a.add(i).read(), b.add(i).read()) };
        if x != y || x == 0 {
            return i32::from(x) - i32::from(y);
        }
        i += 1;
    }
}
extern "win64" fn crt_strncmp(a: *const u8, b: *const u8, n: usize) -> i32 {
    for i in 0..n {
        // SAFETY: bounded by `n` and NUL.
        let (x, y) = unsafe { (a.add(i).read(), b.add(i).read()) };
        if x != y || x == 0 {
            return i32::from(x) - i32::from(y);
        }
    }
    0
}
extern "win64" fn crt_stricmp(a: *const u8, b: *const u8) -> i32 {
    let mut i = 0;
    loop {
        // SAFETY: NUL-terminated strings.
        let (x, y) = unsafe { (a.add(i).read().to_ascii_lowercase(), b.add(i).read().to_ascii_lowercase()) };
        if x != y || x == 0 {
            return i32::from(x) - i32::from(y);
        }
        i += 1;
    }
}
extern "win64" fn crt_strnicmp(a: *const u8, b: *const u8, n: usize) -> i32 {
    for i in 0..n {
        // SAFETY: bounded by `n` and NUL.
        let (x, y) = unsafe { (a.add(i).read().to_ascii_lowercase(), b.add(i).read().to_ascii_lowercase()) };
        if x != y || x == 0 {
            return i32::from(x) - i32::from(y);
        }
    }
    0
}
extern "win64" fn crt_strcpy(dst: *mut u8, src: *const u8) -> *mut u8 {
    let n = c_strlen(src) + 1;
    // SAFETY: caller's destination buffer.
    unsafe { core::ptr::copy(src, dst, n) };
    dst
}
extern "win64" fn crt_strcpy_s(dst: *mut u8, dstsz: usize, src: *const u8) -> i32 {
    if dst.is_null() || dstsz == 0 || src.is_null() {
        return 22;
    }
    let n = c_strlen(src);
    if n + 1 > dstsz {
        // SAFETY: write NUL terminator on error.
        unsafe { dst.write(0) };
        return 34;
    }
    // SAFETY: fits in `dstsz`.
    unsafe { core::ptr::copy(src, dst, n + 1) };
    0
}
extern "win64" fn crt_strncpy(dst: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    let mut i = 0;
    while i < n {
        // SAFETY: bounded by `n`.
        let c = unsafe { src.add(i).read() };
        // SAFETY: bounded by `n`.
        unsafe { dst.add(i).write(c) };
        i += 1;
        if c == 0 {
            break;
        }
    }
    while i < n {
        // SAFETY: bounded by `n`.
        unsafe { dst.add(i).write(0) };
        i += 1;
    }
    dst
}
extern "win64" fn crt_strcat_s(dst: *mut u8, dstsz: usize, src: *const u8) -> i32 {
    if dst.is_null() || dstsz == 0 || src.is_null() {
        return 22;
    }
    let dlen = crt_strnlen(dst, dstsz);
    let slen = c_strlen(src);
    if dlen + slen + 1 > dstsz {
        // SAFETY: clear dst on error.
        unsafe { dst.write(0) };
        return 34;
    }
    // SAFETY: fits in `dstsz`.
    unsafe { core::ptr::copy(src, dst.add(dlen), slen + 1) };
    0
}
extern "win64" fn crt_strchr(s: *const u8, c: i32) -> *const u8 {
    if s.is_null() {
        return core::ptr::null();
    }
    let want = c as u8;
    let mut i = 0;
    loop {
        // SAFETY: NUL-terminated string.
        let ch = unsafe { s.add(i).read() };
        if ch == want {
            // SAFETY: inside string.
            return unsafe { s.add(i) };
        }
        if ch == 0 {
            return core::ptr::null();
        }
        i += 1;
    }
}
extern "win64" fn crt_strrchr(s: *const u8, c: i32) -> *const u8 {
    if s.is_null() {
        return core::ptr::null();
    }
    let want = c as u8;
    let mut last = core::ptr::null();
    let mut i = 0;
    loop {
        // SAFETY: NUL-terminated string.
        let ch = unsafe { s.add(i).read() };
        if ch == want {
            // SAFETY: inside string.
            last = unsafe { s.add(i) };
        }
        if ch == 0 {
            return last;
        }
        i += 1;
    }
}
extern "win64" fn crt_strstr(hay: *const u8, needle: *const u8) -> *const u8 {
    if hay.is_null() || needle.is_null() {
        return core::ptr::null();
    }
    let h = read_cstr(hay);
    let n = read_cstr(needle);
    if n.is_empty() {
        return hay;
    }
    if n.len() > h.len() {
        return core::ptr::null();
    }
    for i in 0..=h.len() - n.len() {
        if &h[i..i + n.len()] == n.as_slice() {
            // SAFETY: within `hay`.
            return unsafe { hay.add(i) };
        }
    }
    core::ptr::null()
}
extern "win64" fn crt_wcslen(s: *const u16) -> usize {
    if s.is_null() {
        return 0;
    }
    let mut n = 0;
    // SAFETY: NUL-terminated UTF-16 string.
    while unsafe { s.add(n).read_unaligned() } != 0 {
        n += 1;
    }
    n
}
extern "win64" fn crt_wcscmp(a: *const u16, b: *const u16) -> i32 {
    let mut i = 0;
    loop {
        // SAFETY: NUL-terminated UTF-16 strings.
        let (x, y) = unsafe { (a.add(i).read_unaligned(), b.add(i).read_unaligned()) };
        if x != y || x == 0 {
            return i32::from(x) - i32::from(y);
        }
        i += 1;
    }
}

// ---- argv, environment, runtime startup & onexit -----------------------------------------------

struct NarrowArgs {
    ready: bool,
    argc: i32,
    argv_ptrs: Vec<*mut u8>,
    _storage: Vec<Vec<u8>>,
}

// SAFETY: accessed only under `ARGS` mutex; raw pointers point into stable heap allocations inside
// `_storage` that live for the lifetime of the process.
unsafe impl Send for NarrowArgs {}

static ARGS: Mutex<NarrowArgs> = Mutex::new(NarrowArgs { ready: false, argc: 0, argv_ptrs: Vec::new(), _storage: Vec::new() });
static ARGC_SLOT: AtomicI32 = AtomicI32::new(0);
static ARGV_SLOT: AtomicU64 = AtomicU64::new(0);
static COMMODE_SLOT: AtomicI32 = AtomicI32::new(0);
static FMODE_SLOT: AtomicI32 = AtomicI32::new(0x4000); // _O_TEXT
static ENV_PTR_SLOT: AtomicU64 = AtomicU64::new(0);
static APP_TYPE: AtomicI32 = AtomicI32::new(1); // _crt_console_app

/// Split Windows command line into MSVC argv tokens.
fn split_win_cmdline(cmd: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < cmd.len() {
        while i < cmd.len() && (cmd[i] == b' ' || cmd[i] == b'\t') {
            i += 1;
        }
        if i >= cmd.len() {
            break;
        }
        let mut arg = Vec::new();
        let mut in_quotes = false;
        while i < cmd.len() {
            let c = cmd[i];
            if c == b'"' {
                in_quotes = !in_quotes;
                i += 1;
            } else if !in_quotes && (c == b' ' || c == b'\t') {
                break;
            } else {
                arg.push(c);
                i += 1;
            }
        }
        arg.push(0);
        out.push(arg);
    }
    if out.is_empty() {
        out.push(b"app.exe\0".to_vec());
    }
    out
}

fn ensure_narrow_argv() {
    let mut a = ARGS.lock();
    if a.ready {
        return;
    }
    let parts = split_win_cmdline(&k32::cmdline_a());
    let argc = parts.len() as i32;
    let mut ptrs = Vec::with_capacity(parts.len() + 1);
    for p in &parts {
        let m = crt_malloc(p.len());
        if !m.is_null() {
            // SAFETY: freshly allocated buffer of `p.len()` bytes.
            unsafe { core::ptr::copy_nonoverlapping(p.as_ptr(), m, p.len()) };
            ptrs.push(m);
        }
    }
    ptrs.push(core::ptr::null_mut());
    // Allocate stable pointer array on CRT heap.
    let arr = crt_malloc(ptrs.len() * 8) as *mut *mut u8;
    if !arr.is_null() {
        for (idx, &ptr) in ptrs.iter().enumerate() {
            // SAFETY: within `arr`.
            unsafe { arr.add(idx).write(ptr) };
        }
    }
    a.argc = argc;
    a.argv_ptrs = ptrs;
    a._storage = parts;
    a.ready = true;
    ARGC_SLOT.store(argc, Ordering::Release);
    ARGV_SLOT.store(arr as u64, Ordering::Release);
}

extern "win64" fn crt_configure_narrow_argv(_mode: i32) -> i32 {
    ensure_narrow_argv();
    0
}
extern "win64" fn crt_configure_wide_argv(_mode: i32) -> i32 {
    0
}
extern "win64" fn crt_p_argc() -> *mut i32 {
    ensure_narrow_argv();
    ARGC_SLOT.as_ptr()
}
extern "win64" fn crt_p_argv() -> *mut *mut *mut u8 {
    ensure_narrow_argv();
    ARGV_SLOT.as_ptr().cast()
}
extern "win64" fn crt_initialize_narrow_environment() -> i32 {
    if ENV_PTR_SLOT.load(Ordering::Acquire) == 0 {
        let arr = crt_calloc(1, 8);
        ENV_PTR_SLOT.store(arr as u64, Ordering::Release);
    }
    0
}
extern "win64" fn crt_get_initial_narrow_environment() -> *mut *mut u8 {
    crt_initialize_narrow_environment();
    ENV_PTR_SLOT.load(Ordering::Acquire) as *mut *mut u8
}
extern "win64" fn crt_p_environ() -> *mut *mut *mut u8 {
    crt_initialize_narrow_environment();
    ENV_PTR_SLOT.as_ptr().cast()
}
extern "win64" fn crt_set_app_type(ty: i32) {
    APP_TYPE.store(ty, Ordering::Relaxed);
}
extern "win64" fn crt_p_commode() -> *mut i32 {
    COMMODE_SLOT.as_ptr()
}
extern "win64" fn crt_set_fmode(mode: i32) -> i32 {
    FMODE_SLOT.store(mode, Ordering::Relaxed);
    0
}
extern "win64" fn crt_get_fmode(out_mode: *mut i32) -> i32 {
    if !out_mode.is_null() {
        // SAFETY: caller's out pointer.
        unsafe { out_mode.write(FMODE_SLOT.load(Ordering::Relaxed)) };
    }
    0
}
extern "win64" fn crt_initterm(first: *const u64, last: *const u64) {
    if first.is_null() || last.is_null() {
        return;
    }
    let mut p = first;
    while p < last {
        // SAFETY: function pointer table emitted by MSVC linker.
        let fp = unsafe { p.read() };
        if fp != 0 {
            type InitFn = extern "win64" fn();
            // SAFETY: initializer function in loaded PE image.
            let f: InitFn = unsafe { core::mem::transmute::<u64, InitFn>(fp) };
            f();
        }
        // SAFETY: advance within `[first, last)`.
        p = unsafe { p.add(1) };
    }
}
extern "win64" fn crt_initterm_e(first: *const u64, last: *const u64) -> i32 {
    if first.is_null() || last.is_null() {
        return 0;
    }
    let mut p = first;
    while p < last {
        // SAFETY: function pointer table emitted by MSVC linker.
        let fp = unsafe { p.read() };
        if fp != 0 {
            type InitFnE = extern "win64" fn() -> i32;
            // SAFETY: initializer function in loaded PE image.
            let f: InitFnE = unsafe { core::mem::transmute::<u64, InitFnE>(fp) };
            let r = f();
            if r != 0 {
                return r;
            }
        }
        // SAFETY: advance within `[first, last)`.
        p = unsafe { p.add(1) };
    }
    0
}

#[repr(C)]
struct OnexitTable {
    first: *mut u64,
    last: *mut u64,
    end: *mut u64,
}

static ATEXIT_LIST: Mutex<Vec<u64>> = Mutex::new(Vec::new());

extern "win64" fn crt_initialize_onexit_table(table: *mut OnexitTable) -> i32 {
    if table.is_null() {
        return -1;
    }
    let cap = 32usize;
    let buf = crt_calloc(cap, 8) as *mut u64;
    if buf.is_null() {
        return -1;
    }
    // SAFETY: caller's `_onexit_table_t`.
    unsafe {
        (*table).first = buf;
        (*table).last = buf;
        (*table).end = buf.add(cap);
    }
    0
}
extern "win64" fn crt_register_onexit_function(table: *mut OnexitTable, func: u64) -> i32 {
    if table.is_null() || func == 0 {
        return 0;
    }
    // SAFETY: valid initialized `_onexit_table_t`.
    unsafe {
        let t = &mut *table;
        if t.first.is_null() && crt_initialize_onexit_table(table) != 0 {
            return -1;
        }
        if t.last >= t.end {
            let len = t.last.offset_from(t.first) as usize;
            let new_cap = (len * 2).max(32);
            let nb = crt_realloc(t.first.cast::<u8>(), new_cap * 8) as *mut u64;
            if nb.is_null() {
                return -1;
            }
            t.first = nb;
            t.last = nb.add(len);
            t.end = nb.add(new_cap);
        }
        t.last.write(func);
        t.last = t.last.add(1);
    }
    0
}
extern "win64" fn crt_execute_onexit_table(table: *mut OnexitTable) -> i32 {
    if table.is_null() {
        return 0;
    }
    // SAFETY: valid `_onexit_table_t`.
    let fns: Vec<u64> = unsafe {
        let t = &mut *table;
        if t.first.is_null() || t.last <= t.first {
            return 0;
        }
        let n = t.last.offset_from(t.first) as usize;
        let mut v = Vec::with_capacity(n);
        for i in 0..n {
            v.push(t.first.add(i).read());
        }
        t.last = t.first;
        v
    };
    for fp in fns.into_iter().rev() {
        if fp != 0 {
            type OnExitFn = extern "win64" fn() -> i32;
            // SAFETY: registered exit handler.
            let f: OnExitFn = unsafe { core::mem::transmute::<u64, OnExitFn>(fp) };
            let _ = f();
        }
    }
    0
}
extern "win64" fn crt_atexit(func: u64) -> i32 {
    if func != 0 {
        ATEXIT_LIST.lock().push(func);
    }
    0
}
extern "win64" fn crt_register_tls_atexit(_cb: u64) {}

fn run_process_atexit() {
    let fns = core::mem::take(&mut *ATEXIT_LIST.lock());
    for fp in fns.into_iter().rev() {
        type AtExitFn = extern "win64" fn();
        // SAFETY: registered atexit callback.
        let f: AtExitFn = unsafe { core::mem::transmute::<u64, AtExitFn>(fp) };
        f();
    }
}

extern "win64" fn crt_cexit() {
    run_process_atexit();
    out::flush_all();
}
extern "win64" fn crt_c_exit() {
    out::flush_all();
}
extern "win64" fn crt_exit(code: i32) -> ! {
    run_process_atexit();
    k32::exit_process(code as u32)
}
extern "win64" fn crt_quick_exit(code: i32) -> ! {
    k32::exit_process(code as u32)
}
extern "win64" fn crt_abort() -> ! {
    out::flush_all();
    sys::process_exit(3)
}
extern "win64" fn crt_seh_filter_exe(_code: u32, _ptrs: u64) -> i32 {
    0 // EXCEPTION_CONTINUE_SEARCH
}
extern "win64" fn crt_seh_filter_dll(_code: u32, _ptrs: u64) -> i32 {
    0
}
extern "win64" fn crt_beginthreadex(sec: u64, stack: u32, start: u64, arg: u64, flags: u32, tid: *mut u32) -> u64 {
    k32::create_thread_pub(sec, stack as usize, start, arg, flags, tid)
}
extern "win64" fn crt_endthreadex(code: u32) -> ! {
    super::finish_thread(code)
}

static FALLBACK_ERRNO: AtomicI32 = AtomicI32::new(0);
extern "win64" fn crt_errno() -> *mut i32 {
    match current_thread() {
        Some(t) => &raw mut t.crt_errno,
        None => FALLBACK_ERRNO.as_ptr(),
    }
}
extern "win64" fn crt_set_errno(v: i32) -> i32 {
    set_errno(v);
    0
}
extern "win64" fn crt_get_errno(out_v: *mut i32) -> i32 {
    if !out_v.is_null() {
        let v = current_thread().map_or(0, |t| t.crt_errno);
        // SAFETY: caller's out pointer.
        unsafe { out_v.write(v) };
    }
    0
}
extern "win64" fn crt_invalid_param() {}
extern "win64" fn crt_invalid_param_noreturn() -> ! {
    crt_abort()
}

// ---- vcruntime140 C++ exception helpers --------------------------------------------------------

#[repr(C)]
struct StdExceptionData {
    what: *const u8,
    dofree: u8,
}

extern "win64" fn std_exception_copy(from: *const StdExceptionData, to: *mut StdExceptionData) {
    if from.is_null() || to.is_null() {
        return;
    }
    // SAFETY: valid MSVC `__std_exception_data` pointers.
    unsafe {
        let f = &*from;
        let t = &mut *to;
        if f.dofree != 0 && !f.what.is_null() {
            let dup = crt_strdup(f.what);
            t.what = dup;
            t.dofree = u8::from(!dup.is_null());
        } else {
            t.what = f.what;
            t.dofree = 0;
        }
    }
}
extern "win64" fn std_exception_destroy(data: *mut StdExceptionData) {
    if data.is_null() {
        return;
    }
    // SAFETY: valid MSVC `__std_exception_data` pointer.
    unsafe {
        let d = &mut *data;
        if d.dofree != 0 && !d.what.is_null() {
            crt_free(d.what.cast_mut());
        }
        d.what = core::ptr::null();
        d.dofree = 0;
    }
}

static FALLBACK_CUR_EXC: AtomicU64 = AtomicU64::new(0);
extern "win64" fn crt_current_exception() -> *mut u64 {
    match current_thread() {
        Some(t) => &raw mut t.cur_exc_rec,
        None => FALLBACK_CUR_EXC.as_ptr(),
    }
}
extern "win64" fn crt_current_exception_context() -> *mut u64 {
    match current_thread() {
        Some(t) => &raw mut t.cur_exc_ctx,
        None => FALLBACK_CUR_EXC.as_ptr(),
    }
}
extern "win64" fn crt_uncaught_exceptions() -> i32 {
    0
}
extern "win64" fn std_type_info_destroy_list(root: *mut u64) {
    if root.is_null() {
        return;
    }
    // SAFETY: MSVC `__type_info_node` singly-linked list head `{ void *_MemPtr; _Next; }`.
    unsafe { root.write(0) };
}
extern "win64" fn std_type_info_compare(a: *const u8, b: *const u8) -> i32 {
    if a == b {
        return 0;
    }
    if a.is_null() || b.is_null() {
        return if a.is_null() { -1 } else { 1 };
    }
    // SAFETY: MSVC `__std_type_info_data` has undecorated/decorated name at offset +8.
    unsafe { crt_strcmp(a.add(8), b.add(8)) }
}
extern "win64" fn std_type_info_name(data: *const u8, _root: *mut u64) -> *const u8 {
    if data.is_null() {
        return core::ptr::null();
    }
    // SAFETY: MSVC `__std_type_info_data` name starts at offset +8.
    unsafe { data.add(8) }
}

// ---- environment -------------------------------------------------------------------------------

static GETENV_CACHE: Mutex<Vec<Vec<u8>>> = Mutex::new(Vec::new());

extern "win64" fn crt_getenv(name: *const u8) -> *const u8 {
    if name.is_null() {
        return core::ptr::null();
    }
    let Some(mut v) = k32::env_value(&read_cstr(name)) else {
        return core::ptr::null();
    };
    v.push(0);
    let mut cache = GETENV_CACHE.lock();
    let ptr = v.as_ptr();
    cache.push(v);
    if cache.len() > 64 {
        cache.remove(0);
    }
    ptr
}
extern "win64" fn crt_getenv_s(req: *mut usize, buf: *mut u8, bufsz: usize, name: *const u8) -> i32 {
    if name.is_null() {
        return 22;
    }
    let Some(v) = k32::env_value(&read_cstr(name)) else {
        if !req.is_null() {
            // SAFETY: caller out pointer.
            unsafe { req.write(0) };
        }
        return 0;
    };
    if !req.is_null() {
        // SAFETY: caller out pointer.
        unsafe { req.write(v.len() + 1) };
    }
    if buf.is_null() || bufsz < v.len() + 1 {
        return 34;
    }
    // SAFETY: fits in `bufsz`.
    unsafe {
        core::ptr::copy_nonoverlapping(v.as_ptr(), buf, v.len());
        buf.add(v.len()).write(0);
    }
    0
}
extern "win64" fn crt_putenv_s(name: *const u8, val: *const u8) -> i32 {
    if name.is_null() || val.is_null() {
        return 22;
    }
    let n = read_cstr(name);
    let v = read_cstr(val);
    let ok = k32::env_set_pub(n, if v.is_empty() { None } else { Some(v) });
    if ok { 0 } else { 22 }
}
extern "win64" fn crt_putenv(spec: *const u8) -> i32 {
    let s = read_cstr(spec);
    let Some(eq) = s.iter().position(|&c| c == b'=') else { return -1 };
    let n = s[..eq].to_vec();
    let v = s[eq + 1..].to_vec();
    if k32::env_set_pub(n, if v.is_empty() { None } else { Some(v) }) { 0 } else { -1 }
}

// ---- stdio streams & printf formatting ---------------------------------------------------------

enum StreamKind {
    Stdin,
    Stdout,
    Stderr,
    File { node: Node, pos: u64, write: bool, read: bool, append: bool, eof: bool, err: bool },
}

struct CrtStream {
    inner: Mutex<StreamKind>,
}

static STREAM_STDIN: CrtStream = CrtStream { inner: Mutex::new(StreamKind::Stdin) };
static STREAM_STDOUT: CrtStream = CrtStream { inner: Mutex::new(StreamKind::Stdout) };
static STREAM_STDERR: CrtStream = CrtStream { inner: Mutex::new(StreamKind::Stderr) };

fn stream_ptr(s: &CrtStream) -> *mut CrtStream {
    core::ptr::from_ref(s).cast_mut()
}

extern "win64" fn crt_acrt_iob_func(idx: u32) -> *mut CrtStream {
    match idx {
        0 => stream_ptr(&STREAM_STDIN),
        1 => stream_ptr(&STREAM_STDOUT),
        2 => stream_ptr(&STREAM_STDERR),
        _ => core::ptr::null_mut(),
    }
}

fn open_stream(file: &[u8], mode: &[u8]) -> Result<*mut CrtStream, i32> {
    if file.is_empty() || mode.is_empty() {
        return Err(22);
    }
    let first = mode[0];
    let plus = mode.contains(&b'+');
    let (read, write, create, trunc, append) = match first {
        b'r' => (true, plus, false, false, false),
        b'w' => (plus, true, true, true, false),
        b'a' => (plus, true, true, false, true),
        _ => return Err(22),
    };
    let abs = k32::win_path_pub(file);
    let mut flags = 0u64;
    if create {
        flags |= fp::O_CREATE;
    }
    if trunc {
        flags |= fp::O_TRUNCATE;
    }
    let rights = fp::R_READ | if write { fp::R_WRITE } else { 0 };
    let (node, kind, _) = path::open(&abs, flags, rights).map_err(fs_to_errno)?;
    if kind == fp::KIND_DIR {
        return Err(21);
    }
    let pos = if append { node.stat().map(|st| st.size).unwrap_or(0) } else { 0 };
    let s = Box::new(CrtStream {
        inner: Mutex::new(StreamKind::File { node, pos, write, read, append, eof: false, err: false }),
    });
    Ok(Box::into_raw(s))
}

extern "win64" fn crt_fopen(file: *const u8, mode: *const u8) -> *mut CrtStream {
    match open_stream(&read_cstr(file), &read_cstr(mode)) {
        Ok(s) => s,
        Err(e) => {
            set_errno(e);
            core::ptr::null_mut()
        }
    }
}
extern "win64" fn crt_fopen_s(out_f: *mut *mut CrtStream, file: *const u8, mode: *const u8) -> i32 {
    if out_f.is_null() {
        return 22;
    }
    match open_stream(&read_cstr(file), &read_cstr(mode)) {
        Ok(s) => {
            // SAFETY: caller's `FILE**` out pointer.
            unsafe { out_f.write(s) };
            0
        }
        Err(e) => {
            // SAFETY: set `*out_f = NULL` on error.
            unsafe { out_f.write(core::ptr::null_mut()) };
            set_errno(e);
            e
        }
    }
}
extern "win64" fn crt_fclose(s: *mut CrtStream) -> i32 {
    if s.is_null() {
        return -1;
    }
    if s == stream_ptr(&STREAM_STDIN) || s == stream_ptr(&STREAM_STDOUT) || s == stream_ptr(&STREAM_STDERR) {
        out::flush_all();
        return 0;
    }
    // SAFETY: allocated by `open_stream` via `Box::into_raw`.
    let b = unsafe { Box::from_raw(s) };
    drop(b);
    0
}
extern "win64" fn crt_fflush(s: *mut CrtStream) -> i32 {
    if s.is_null() || s == stream_ptr(&STREAM_STDOUT) || s == stream_ptr(&STREAM_STDERR) {
        out::flush_all();
        return 0;
    }
    // SAFETY: valid `CrtStream`.
    let g = unsafe { &*s }.inner.lock();
    if let StreamKind::File { node, write: true, .. } = &*g {
        let _ = node.sync();
    }
    0
}

fn stream_write_bytes(s: *mut CrtStream, bytes: &[u8]) -> usize {
    if s.is_null() {
        return 0;
    }
    // SAFETY: valid `CrtStream`.
    let mut g = unsafe { &*s }.inner.lock();
    match &mut *g {
        StreamKind::Stdout | StreamKind::Stderr => {
            out::write(bytes);
            bytes.len()
        }
        StreamKind::Stdin => 0,
        StreamKind::File { node, pos, write, append, err, .. } => {
            if !*write {
                *err = true;
                return 0;
            }
            if *append {
                *pos = node.stat().map(|st| st.size).unwrap_or(*pos);
            }
            match node.write(*pos, bytes) {
                Ok(w) => {
                    *pos += w as u64;
                    w
                }
                Err(_) => {
                    *err = true;
                    0
                }
            }
        }
    }
}

fn stream_read_bytes(s: *mut CrtStream, buf: &mut [u8]) -> usize {
    if s.is_null() {
        return 0;
    }
    // SAFETY: valid `CrtStream`.
    let mut g = unsafe { &*s }.inner.lock();
    match &mut *g {
        StreamKind::Stdin | StreamKind::Stdout | StreamKind::Stderr => 0,
        StreamKind::File { node, pos, read, eof, err, .. } => {
            if !*read {
                *err = true;
                return 0;
            }
            match node.read(*pos, buf) {
                Ok(0) => {
                    *eof = true;
                    0
                }
                Ok(n) => {
                    *pos += n as u64;
                    n
                }
                Err(_) => {
                    *err = true;
                    0
                }
            }
        }
    }
}

extern "win64" fn crt_fwrite(ptr: *const u8, size: usize, nmemb: usize, s: *mut CrtStream) -> usize {
    if ptr.is_null() || size == 0 || nmemb == 0 {
        return 0;
    }
    let Some(total) = size.checked_mul(nmemb) else { return 0 };
    // SAFETY: caller's buffer of `total` bytes.
    let bytes = unsafe { core::slice::from_raw_parts(ptr, total) };
    stream_write_bytes(s, bytes) / size
}
extern "win64" fn crt_fread(ptr: *mut u8, size: usize, nmemb: usize, s: *mut CrtStream) -> usize {
    if ptr.is_null() || size == 0 || nmemb == 0 {
        return 0;
    }
    let Some(total) = size.checked_mul(nmemb) else { return 0 };
    // SAFETY: caller's buffer of `total` bytes.
    let buf = unsafe { core::slice::from_raw_parts_mut(ptr, total) };
    stream_read_bytes(s, buf) / size
}
extern "win64" fn crt_fgets(buf: *mut u8, n: i32, s: *mut CrtStream) -> *mut u8 {
    if buf.is_null() || n <= 0 || s.is_null() {
        return core::ptr::null_mut();
    }
    if n == 1 {
        // SAFETY: 1-byte buffer holds NUL.
        unsafe { buf.write(0) };
        return buf;
    }
    let max = (n - 1) as usize;
    let mut got = 0usize;
    // Read chunk and rewind excess bytes past `\n`.
    let mut tmp = alloc::vec![0u8; max.min(512)];
    while got < max {
        let want = (max - got).min(tmp.len());
        let r = stream_read_bytes(s, &mut tmp[..want]);
        if r == 0 {
            break;
        }
        if let Some(nl) = tmp[..r].iter().position(|&c| c == b'\n') {
            let take = nl + 1;
            // SAFETY: `got + take <= max`.
            unsafe { core::ptr::copy_nonoverlapping(tmp.as_ptr(), buf.add(got), take) };
            got += take;
            let back = (r - take) as u64;
            if back > 0 {
                // SAFETY: valid `CrtStream`.
                let mut g = unsafe { &*s }.inner.lock();
                if let StreamKind::File { pos, .. } = &mut *g {
                    *pos = pos.saturating_sub(back);
                }
            }
            break;
        }
        // SAFETY: `got + r <= max`.
        unsafe { core::ptr::copy_nonoverlapping(tmp.as_ptr(), buf.add(got), r) };
        got += r;
    }
    if got == 0 {
        return core::ptr::null_mut();
    }
    // SAFETY: `got < n`.
    unsafe { buf.add(got).write(0) };
    buf
}
extern "win64" fn crt_fputs(str_p: *const u8, s: *mut CrtStream) -> i32 {
    let b = read_cstr(str_p);
    if stream_write_bytes(s, &b) == b.len() { 0 } else { -1 }
}
extern "win64" fn crt_puts(str_p: *const u8) -> i32 {
    let mut b = read_cstr(str_p);
    b.push(b'\n');
    out::write(&b);
    0
}
extern "win64" fn crt_putchar(c: i32) -> i32 {
    out::write(&[c as u8]);
    c & 0xFF
}
extern "win64" fn crt_fputc(c: i32, s: *mut CrtStream) -> i32 {
    if stream_write_bytes(s, &[c as u8]) == 1 { c & 0xFF } else { -1 }
}
extern "win64" fn crt_fgetc(s: *mut CrtStream) -> i32 {
    let mut b = [0u8; 1];
    if stream_read_bytes(s, &mut b) == 1 { i32::from(b[0]) } else { -1 }
}
extern "win64" fn crt_fseek(s: *mut CrtStream, off: i64, whence: i32) -> i32 {
    if s.is_null() {
        return -1;
    }
    // SAFETY: valid `CrtStream`.
    let mut g = unsafe { &*s }.inner.lock();
    let StreamKind::File { node, pos, eof, .. } = &mut *g else { return -1 };
    let base = match whence {
        0 => 0i64,
        1 => *pos as i64,
        2 => node.stat().map(|st| st.size as i64).unwrap_or(0),
        _ => return -1,
    };
    match base.checked_add(off) {
        Some(n) if n >= 0 => {
            *pos = n as u64;
            *eof = false;
            0
        }
        _ => -1,
    }
}
extern "win64" fn crt_ftell(s: *mut CrtStream) -> i64 {
    if s.is_null() {
        return -1;
    }
    // SAFETY: valid `CrtStream`.
    let g = unsafe { &*s }.inner.lock();
    match &*g {
        StreamKind::File { pos, .. } => *pos as i64,
        _ => -1,
    }
}
extern "win64" fn crt_feof(s: *mut CrtStream) -> i32 {
    if s.is_null() {
        return 0;
    }
    // SAFETY: valid `CrtStream`.
    match &*unsafe { &*s }.inner.lock() {
        StreamKind::File { eof, .. } => i32::from(*eof),
        _ => 0,
    }
}
extern "win64" fn crt_ferror(s: *mut CrtStream) -> i32 {
    if s.is_null() {
        return 0;
    }
    // SAFETY: valid `CrtStream`.
    match &*unsafe { &*s }.inner.lock() {
        StreamKind::File { err, .. } => i32::from(*err),
        _ => 0,
    }
}
extern "win64" fn crt_clearerr(s: *mut CrtStream) {
    if !s.is_null() {
        // SAFETY: valid `CrtStream`.
        if let StreamKind::File { eof, err, .. } = &mut *unsafe { &*s }.inner.lock() {
            *eof = false;
            *err = false;
        }
    }
}

/// Format a C `printf` format string against a Windows x64 `va_list` (`*const u64` slots).
fn format_printf(fmt: &[u8], va: *const u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(fmt.len() + 32);
    let mut i = 0usize;
    let mut arg_idx = 0usize;
    let mut next_arg = || -> u64 {
        if va.is_null() {
            return 0;
        }
        // SAFETY: Windows x64 `va_list` is a contiguous array of 8-byte argument slots.
        let v = unsafe { va.add(arg_idx).read_unaligned() };
        arg_idx += 1;
        v
    };

    while i < fmt.len() {
        if fmt[i] != b'%' {
            out.push(fmt[i]);
            i += 1;
            continue;
        }
        i += 1;
        if i >= fmt.len() {
            break;
        }
        if fmt[i] == b'%' {
            out.push(b'%');
            i += 1;
            continue;
        }
        // Flags
        let (mut left, mut plus, mut space, mut alt, mut zero) = (false, false, false, false, false);
        while i < fmt.len() {
            match fmt[i] {
                b'-' => left = true,
                b'+' => plus = true,
                b' ' => space = true,
                b'#' => alt = true,
                b'0' => zero = true,
                _ => break,
            }
            i += 1;
        }
        // Width
        let mut width = 0usize;
        if i < fmt.len() && fmt[i] == b'*' {
            let w = next_arg() as i32;
            if w < 0 {
                left = true;
                width = w.unsigned_abs() as usize;
            } else {
                width = w as usize;
            }
            i += 1;
        } else {
            while i < fmt.len() && fmt[i].is_ascii_digit() {
                width = width.saturating_mul(10).saturating_add(usize::from(fmt[i] - b'0'));
                i += 1;
            }
        }
        // Precision
        let mut prec: Option<usize> = None;
        if i < fmt.len() && fmt[i] == b'.' {
            i += 1;
            if i < fmt.len() && fmt[i] == b'*' {
                let p = next_arg() as i32;
                prec = if p >= 0 { Some(p as usize) } else { None };
                i += 1;
            } else {
                let mut p = 0usize;
                while i < fmt.len() && fmt[i].is_ascii_digit() {
                    p = p.saturating_mul(10).saturating_add(usize::from(fmt[i] - b'0'));
                    i += 1;
                }
                prec = Some(p);
            }
        }
        // Length modifier
        let mut is64 = false;
        let mut is_short = false;
        let mut is_char = false;
        while i < fmt.len() {
            match fmt[i] {
                b'l' => {
                    if i + 1 < fmt.len() && fmt[i + 1] == b'l' {
                        is64 = true;
                        i += 2;
                    } else {
                        i += 1; // Windows `long` is 32-bit!
                    }
                }
                b'z' | b't' | b'j' => {
                    is64 = true;
                    i += 1;
                }
                b'I' => {
                    if i + 2 < fmt.len() && &fmt[i + 1..i + 3] == b"64" {
                        is64 = true;
                        i += 3;
                    } else if i + 2 < fmt.len() && &fmt[i + 1..i + 3] == b"32" {
                        i += 3;
                    } else {
                        is64 = true;
                        i += 1;
                    }
                }
                b'h' => {
                    if i + 1 < fmt.len() && fmt[i + 1] == b'h' {
                        is_char = true;
                        i += 2;
                    } else {
                        is_short = true;
                        i += 1;
                    }
                }
                _ => break,
            }
        }
        if i >= fmt.len() {
            break;
        }
        let spec = fmt[i];
        i += 1;

        let mut prefix: &[u8] = b"";
        let mut body = Vec::new();
        let mut is_num = true;
        match spec {
            b'd' | b'i' => {
                let raw = next_arg();
                let v: i64 = if is64 {
                    raw as i64
                } else if is_char {
                    i64::from(raw as i8)
                } else if is_short {
                    i64::from(raw as i16)
                } else {
                    i64::from(raw as i32)
                };
                if v < 0 {
                    prefix = b"-";
                } else if plus {
                    prefix = b"+";
                } else if space {
                    prefix = b" ";
                }
                push_uint(&mut body, v.unsigned_abs(), 10, false);
            }
            b'u' | b'x' | b'X' | b'o' => {
                let raw = next_arg();
                let v: u64 = if is64 {
                    raw
                } else if is_char {
                    u64::from(raw as u8)
                } else if is_short {
                    u64::from(raw as u16)
                } else {
                    u64::from(raw as u32)
                };
                let (base, upper) = match spec {
                    b'u' => (10, false),
                    b'o' => (8, false),
                    b'X' => (16, true),
                    _ => (16, false),
                };
                if alt && v != 0 {
                    prefix = match spec {
                        b'x' => b"0x",
                        b'X' => b"0X",
                        b'o' => b"0",
                        _ => b"",
                    };
                }
                push_uint(&mut body, v, base, upper);
            }
            b'p' => {
                let v = next_arg();
                prefix = b"0x";
                push_uint(&mut body, v, 16, false);
            }
            b'c' => {
                is_num = false;
                body.push(next_arg() as u8);
            }
            b's' => {
                is_num = false;
                let p = next_arg() as *const u8;
                let s = if p.is_null() { b"(null)".to_vec() } else { read_cstr(p) };
                let take = prec.map_or(s.len(), |pr| s.len().min(pr));
                body.extend_from_slice(&s[..take]);
            }
            _ => {
                is_num = false;
                body.push(b'%');
                body.push(spec);
            }
        }

        let mut min_digits = 0usize;
        if is_num && let Some(pr) = prec {
            if pr == 0 && body == b"0" {
                body.clear();
            } else if pr > body.len() {
                min_digits = pr - body.len();
            }
        }
        let content_len = prefix.len() + min_digits + body.len();
        let pad = width.saturating_sub(content_len);
        if left {
            out.extend_from_slice(prefix);
            out.extend(core::iter::repeat_n(b'0', min_digits));
            out.extend_from_slice(&body);
            out.extend(core::iter::repeat_n(b' ', pad));
        } else if zero && is_num && prec.is_none() {
            out.extend_from_slice(prefix);
            out.extend(core::iter::repeat_n(b'0', pad));
            out.extend_from_slice(&body);
        } else {
            out.extend(core::iter::repeat_n(b' ', pad));
            out.extend_from_slice(prefix);
            out.extend(core::iter::repeat_n(b'0', min_digits));
            out.extend_from_slice(&body);
        }
    }
    out
}

fn push_uint(out: &mut Vec<u8>, mut v: u64, base: u64, upper: bool) {
    let digits = if upper { b"0123456789ABCDEF" } else { b"0123456789abcdef" };
    let mut tmp = [0u8; 24];
    let mut n = 0;
    loop {
        tmp[n] = digits[(v % base) as usize];
        n += 1;
        v /= base;
        if v == 0 {
            break;
        }
    }
    for k in (0..n).rev() {
        out.push(tmp[k]);
    }
}

extern "win64" fn crt_stdio_vfprintf(_opts: u64, s: *mut CrtStream, fmt: *const u8, _loc: u64, va: *const u64) -> i32 {
    if fmt.is_null() {
        return -1;
    }
    let formatted = format_printf(&read_cstr(fmt), va);
    let n = stream_write_bytes(s, &formatted);
    if n == formatted.len() { n as i32 } else { -1 }
}
extern "win64" fn crt_stdio_vsprintf(_opts: u64, buf: *mut u8, bufsz: usize, fmt: *const u8, _loc: u64, va: *const u64) -> i32 {
    if fmt.is_null() {
        return -1;
    }
    let formatted = format_printf(&read_cstr(fmt), va);
    if buf.is_null() || bufsz == 0 {
        return formatted.len() as i32;
    }
    let copy = formatted.len().min(bufsz - 1);
    // SAFETY: fits in `bufsz`.
    unsafe {
        core::ptr::copy_nonoverlapping(formatted.as_ptr(), buf, copy);
        buf.add(copy).write(0);
    }
    formatted.len() as i32
}
extern "win64" fn crt_stdio_vsprintf_s(_opts: u64, buf: *mut u8, bufsz: usize, fmt: *const u8, _loc: u64, va: *const u64) -> i32 {
    if buf.is_null() || bufsz == 0 || fmt.is_null() {
        return -1;
    }
    let formatted = format_printf(&read_cstr(fmt), va);
    if formatted.len() + 1 > bufsz {
        // SAFETY: zero first byte on truncation per `_s` contract.
        unsafe { buf.write(0) };
        return -1;
    }
    // SAFETY: fits in `bufsz`.
    unsafe {
        core::ptr::copy_nonoverlapping(formatted.as_ptr(), buf, formatted.len());
        buf.add(formatted.len()).write(0);
    }
    formatted.len() as i32
}
extern "win64" fn crt_stdio_vsnprintf_s(
    _opts: u64,
    buf: *mut u8,
    bufsz: usize,
    maxcount: usize,
    fmt: *const u8,
    _loc: u64,
    va: *const u64,
) -> i32 {
    if fmt.is_null() {
        return -1;
    }
    let formatted = format_printf(&read_cstr(fmt), va);
    if buf.is_null() || bufsz == 0 {
        return formatted.len() as i32;
    }
    let limit = if maxcount == usize::MAX { bufsz - 1 } else { maxcount.min(bufsz - 1) };
    let copy = formatted.len().min(limit);
    // SAFETY: fits in `bufsz`.
    unsafe {
        core::ptr::copy_nonoverlapping(formatted.as_ptr(), buf, copy);
        buf.add(copy).write(0);
    }
    copy as i32
}

// ---- filesystem, conversion, sorting, locale, time, math ---------------------------------------

extern "win64" fn crt_remove(p: *const u8) -> i32 {
    let abs = k32::win_path_pub(&read_cstr(p));
    match path::parent(&abs, fp::R_READ | fp::R_WRITE).and_then(|(d, leaf)| d.unlink(&leaf)) {
        Ok(()) => 0,
        Err(e) => {
            set_errno(fs_to_errno(e));
            -1
        }
    }
}
extern "win64" fn crt_rename(old_p: *const u8, new_p: *const u8) -> i32 {
    let a = k32::win_path_pub(&read_cstr(old_p));
    let b = k32::win_path_pub(&read_cstr(new_p));
    match path::rename(&a, &b, true) {
        Ok(()) => 0,
        Err(e) => {
            set_errno(fs_to_errno(e));
            -1
        }
    }
}
extern "win64" fn crt_access(p: *const u8, _mode: i32) -> i32 {
    let abs = k32::win_path_pub(&read_cstr(p));
    match path::open(&abs, 0, fp::R_READ) {
        Ok(_) => 0,
        Err(e) => {
            set_errno(fs_to_errno(e));
            -1
        }
    }
}
extern "win64" fn crt_atoi(s: *const u8) -> i32 {
    crt_strtoll(s, core::ptr::null_mut(), 10) as i32
}
extern "win64" fn crt_strtoll(s: *const u8, endp: *mut *const u8, base: i32) -> i64 {
    if s.is_null() {
        return 0;
    }
    let bytes = read_cstr(s);
    let mut i = 0;
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    let mut neg = false;
    if i < bytes.len() && (bytes[i] == b'-' || bytes[i] == b'+') {
        neg = bytes[i] == b'-';
        i += 1;
    }
    let radix = if base == 0 {
        if bytes[i..].starts_with(b"0x") || bytes[i..].starts_with(b"0X") {
            i += 2;
            16
        } else if bytes[i..].starts_with(b"0") {
            8
        } else {
            10
        }
    } else {
        if base == 16 && (bytes[i..].starts_with(b"0x") || bytes[i..].starts_with(b"0X")) {
            i += 2;
        }
        base.clamp(2, 36) as u64
    };
    let mut val = 0u64;
    while i < bytes.len() {
        let d = match bytes[i] {
            b'0'..=b'9' => u64::from(bytes[i] - b'0'),
            b'a'..=b'z' => u64::from(bytes[i] - b'a' + 10),
            b'A'..=b'Z' => u64::from(bytes[i] - b'A' + 10),
            _ => break,
        };
        if d >= radix {
            break;
        }
        val = val.wrapping_mul(radix).wrapping_add(d);
        i += 1;
    }
    if !endp.is_null() {
        // SAFETY: within `s`.
        unsafe { endp.write(s.add(i)) };
    }
    if neg { -(val as i64) } else { val as i64 }
}
extern "win64" fn crt_strtoull(s: *const u8, endp: *mut *const u8, base: i32) -> u64 {
    crt_strtoll(s, endp, base) as u64
}
extern "win64" fn crt_qsort(base: *mut u8, nmemb: usize, size: usize, cmp: extern "win64" fn(*const u8, *const u8) -> i32) {
    if base.is_null() || nmemb <= 1 || size == 0 {
        return;
    }
    // Simple in-place shell/insertion sort (deterministic, zero recursion overflow risk).
    let mut tmp = alloc::vec![0u8; size];
    let mut gap = nmemb / 2;
    while gap > 0 {
        for i in gap..nmemb {
            // SAFETY: element `i < nmemb`.
            unsafe { core::ptr::copy_nonoverlapping(base.add(i * size), tmp.as_mut_ptr(), size) };
            let mut j = i;
            while j >= gap {
                // SAFETY: `j - gap < nmemb`.
                let prev = unsafe { base.add((j - gap) * size) };
                if cmp(prev, tmp.as_ptr()) <= 0 {
                    break;
                }
                // SAFETY: non-overlapping slots `j - gap` and `j`.
                unsafe { core::ptr::copy_nonoverlapping(prev, base.add(j * size), size) };
                j -= gap;
            }
            // SAFETY: slot `j < nmemb`.
            unsafe { core::ptr::copy_nonoverlapping(tmp.as_ptr(), base.add(j * size), size) };
        }
        gap /= 2;
    }
}
extern "win64" fn crt_setusermatherr(_cb: u64) {}
extern "win64" fn crt_configthreadlocale(_flag: i32) -> i32 {
    2 // _DISABLE_PER_THREAD_LOCALE
}
static C_LOCALE: &[u8] = b"C\0";
extern "win64" fn crt_setlocale(_cat: i32, _loc: *const u8) -> *const u8 {
    C_LOCALE.as_ptr()
}
extern "win64" fn crt_time64(out_t: *mut i64) -> i64 {
    const UNIX_2000: i64 = 946_684_800;
    let s = crate::wall_ns().div_euclid(1_000_000_000) + UNIX_2000;
    if !out_t.is_null() {
        // SAFETY: caller out pointer.
        unsafe { out_t.write(s) };
    }
    s
}
extern "win64" fn crt_clock() -> i32 {
    (sys::clock_ns() / 1_000_000) as i32
}
extern "win64" fn crt_tolower(c: i32) -> i32 {
    if (0..=255).contains(&c) { i32::from((c as u8).to_ascii_lowercase()) } else { c }
}
extern "win64" fn crt_toupper(c: i32) -> i32 {
    if (0..=255).contains(&c) { i32::from((c as u8).to_ascii_uppercase()) } else { c }
}
extern "win64" fn crt_isdigit(c: i32) -> i32 {
    i32::from((0..=255).contains(&c) && (c as u8).is_ascii_digit())
}
extern "win64" fn crt_isalpha(c: i32) -> i32 {
    i32::from((0..=255).contains(&c) && (c as u8).is_ascii_alphabetic())
}
extern "win64" fn crt_isspace(c: i32) -> i32 {
    i32::from((0..=255).contains(&c) && (c as u8).is_ascii_whitespace())
}

// ---- kernelbase & ntdll additions (SRW locks, InitOnce, Rtl helpers) ---------------------------

extern "win64" fn init_srw_lock(lock: *mut AtomicU32) {
    if !lock.is_null() {
        // SAFETY: caller's SRWLOCK (8 bytes, using low 32 bits as spin/futex word).
        unsafe { (*lock).store(0, Ordering::Relaxed) };
    }
}
extern "win64" fn acquire_srw_lock(lock: *mut AtomicU32) {
    if lock.is_null() {
        return;
    }
    // SAFETY: caller's SRWLOCK.
    let l = unsafe { &*lock };
    while l.compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed).is_err() {
        sys::yield_now();
    }
}
extern "win64" fn release_srw_lock(lock: *mut AtomicU32) {
    if !lock.is_null() {
        // SAFETY: caller's SRWLOCK.
        unsafe { (*lock).store(0, Ordering::Release) };
    }
}
extern "win64" fn init_once_execute_once(
    once: *mut AtomicU32,
    cb: extern "win64" fn(*mut AtomicU32, u64, *mut u64) -> i32,
    param: u64,
    ctx: *mut u64,
) -> i32 {
    if once.is_null() {
        return 0;
    }
    // SAFETY: caller's INIT_ONCE.
    let o = unsafe { &*once };
    loop {
        match o.load(Ordering::Acquire) {
            2 => return 1,
            0 => {
                if o.compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire).is_ok() {
                    let ok = cb(once, param, ctx);
                    o.store(if ok != 0 { 2 } else { 0 }, Ordering::Release);
                    return ok;
                }
            }
            _ => sys::yield_now(),
        }
    }
}
extern "win64" fn rtl_zero_memory(dst: *mut u8, n: usize) {
    crt_memset(dst, 0, n);
}
extern "win64" fn rtl_fill_memory(dst: *mut u8, n: usize, fill: u8) {
    crt_memset(dst, i32::from(fill), n);
}
extern "win64" fn rtl_move_memory(dst: *mut u8, src: *const u8, n: usize) {
    crt_memcpy(dst, src, n);
}
extern "win64" fn rtl_get_version(ver: *mut u8) -> i32 {
    if !ver.is_null() {
        // SAFETY: RTL_OSVERSIONINFOW (minimum 20 bytes header: size, major, minor, build, platform).
        unsafe {
            (ver.add(4) as *mut u32).write_unaligned(10);
            (ver.add(8) as *mut u32).write_unaligned(0);
            (ver.add(12) as *mut u32).write_unaligned(19041);
            (ver.add(16) as *mut u32).write_unaligned(2);
        }
    }
    0 // STATUS_SUCCESS
}
extern "win64" fn rtl_ntstatus_to_dos_error(st: u32) -> u32 {
    match st {
        0 => 0,
        0xC000_0022 => 5, // ACCESS_DENIED
        0xC000_000F => 2, // FILE_NOT_FOUND
        _ => 31,          // GEN_FAILURE
    }
}

// ---- export lookup tables ----------------------------------------------------------------------

pub fn lookup_kernelbase(func: &[u8]) -> Option<u64> {
    Some(match func {
        b"InitializeSRWLock" => init_srw_lock as *const () as u64,
        b"AcquireSRWLockExclusive" | b"AcquireSRWLockShared" => acquire_srw_lock as *const () as u64,
        b"ReleaseSRWLockExclusive" | b"ReleaseSRWLockShared" => release_srw_lock as *const () as u64,
        b"InitOnceExecuteOnce" => init_once_execute_once as *const () as u64,
        _ => return None,
    })
}

pub fn lookup_ntdll(func: &[u8]) -> Option<u64> {
    Some(match func {
        b"RtlZeroMemory" => rtl_zero_memory as *const () as u64,
        b"RtlFillMemory" => rtl_fill_memory as *const () as u64,
        b"RtlMoveMemory" | b"RtlCopyMemory" => rtl_move_memory as *const () as u64,
        b"RtlGetVersion" => rtl_get_version as *const () as u64,
        b"RtlNtStatusToDosError" => rtl_ntstatus_to_dos_error as *const () as u64,
        b"__C_specific_handler" => seh::c_specific_handler as *const () as u64,
        b"RtlCaptureContext" => seh::dcmpl_capture_context as *const () as u64,
        b"RtlLookupFunctionEntry" => seh::rtl_lookup_function_entry as *const () as u64,
        b"RtlPcToFileHeader" => seh::rtl_pc_to_file_header as *const () as u64,
        b"RtlRestoreContext" => seh::dcmpl_restore_context as *const () as u64,
        b"RtlUnwindEx" => seh::dcmpl_unwind_ex as *const () as u64,
        b"RtlVirtualUnwind" => seh::rtl_virtual_unwind as *const () as u64,
        b"RtlAcquireSRWLockExclusive" | b"RtlAcquireSRWLockShared" => acquire_srw_lock as *const () as u64,
        b"RtlReleaseSRWLockExclusive" | b"RtlReleaseSRWLockShared" => release_srw_lock as *const () as u64,
        b"RtlInitializeSRWLock" => init_srw_lock as *const () as u64,
        _ => return None,
    })
}

pub fn lookup_vcruntime(func: &[u8]) -> Option<u64> {
    Some(match func {
        b"__C_specific_handler" => seh::c_specific_handler as *const () as u64,
        b"_CxxThrowException" => seh::dcmpl_cxx_throw_exception as *const () as u64,
        b"__CxxFrameHandler3" => seh::cxx_frame_handler3 as *const () as u64,
        b"__CxxFrameHandler4" => seh::cxx_frame_handler4 as *const () as u64,
        b"__std_exception_copy" => std_exception_copy as *const () as u64,
        b"__std_exception_destroy" => std_exception_destroy as *const () as u64,
        b"__std_type_info_destroy_list" => std_type_info_destroy_list as *const () as u64,
        b"__std_type_info_compare" => std_type_info_compare as *const () as u64,
        b"__std_type_info_name" => std_type_info_name as *const () as u64,
        b"__current_exception" => crt_current_exception as *const () as u64,
        b"__current_exception_context" => crt_current_exception_context as *const () as u64,
        b"__uncaught_exceptions" => crt_uncaught_exceptions as *const () as u64,
        b"_purecall" => crt_abort as *const () as u64,
        b"memcpy" | b"memmove" => crt_memcpy as *const () as u64,
        b"memset" => crt_memset as *const () as u64,
        b"memcmp" => crt_memcmp as *const () as u64,
        b"memchr" => crt_memchr as *const () as u64,
        b"strchr" => crt_strchr as *const () as u64,
        b"strrchr" => crt_strrchr as *const () as u64,
        b"strstr" => crt_strstr as *const () as u64,
        _ => return None,
    })
}

pub fn lookup_vcruntime_1(func: &[u8]) -> Option<u64> {
    Some(match func {
        b"__CxxFrameHandler4" => seh::cxx_frame_handler4 as *const () as u64,
        b"__CxxFrameHandler3" => seh::cxx_frame_handler3 as *const () as u64,
        _ => return None,
    })
}

pub fn lookup_ucrt(func: &[u8]) -> Option<u64> {
    Some(match func {
        // Heap
        b"malloc" => crt_malloc as *const () as u64,
        b"calloc" => crt_calloc as *const () as u64,
        b"realloc" => crt_realloc as *const () as u64,
        b"free" => crt_free as *const () as u64,
        b"_msize" => crt_msize as *const () as u64,
        b"_set_new_mode" => crt_set_new_mode as *const () as u64,
        b"_query_new_mode" => crt_query_new_mode as *const () as u64,
        b"_strdup" | b"strdup" => crt_strdup as *const () as u64,
        // Runtime / Startup / Exit / Threads
        b"_set_app_type" => crt_set_app_type as *const () as u64,
        b"_configure_narrow_argv" => crt_configure_narrow_argv as *const () as u64,
        b"_configure_wide_argv" => crt_configure_wide_argv as *const () as u64,
        b"__p___argc" => crt_p_argc as *const () as u64,
        b"__p___argv" => crt_p_argv as *const () as u64,
        b"__p__environ" => crt_p_environ as *const () as u64,
        b"_initialize_narrow_environment" => crt_initialize_narrow_environment as *const () as u64,
        b"_get_initial_narrow_environment" => crt_get_initial_narrow_environment as *const () as u64,
        b"_initterm" => crt_initterm as *const () as u64,
        b"_initterm_e" => crt_initterm_e as *const () as u64,
        b"_initialize_onexit_table" => crt_initialize_onexit_table as *const () as u64,
        b"_register_onexit_function" => crt_register_onexit_function as *const () as u64,
        b"_execute_onexit_table" => crt_execute_onexit_table as *const () as u64,
        b"_crt_atexit" | b"atexit" | b"_crt_at_quick_exit" => crt_atexit as *const () as u64,
        b"_register_thread_local_exe_atexit_callback" => crt_register_tls_atexit as *const () as u64,
        b"_cexit" => crt_cexit as *const () as u64,
        b"_c_exit" => crt_c_exit as *const () as u64,
        b"exit" => crt_exit as *const () as u64,
        b"_exit" | b"quick_exit" => crt_quick_exit as *const () as u64,
        b"abort" | b"terminate" => crt_abort as *const () as u64,
        b"_seh_filter_exe" => crt_seh_filter_exe as *const () as u64,
        b"_seh_filter_dll" => crt_seh_filter_dll as *const () as u64,
        b"_beginthreadex" => crt_beginthreadex as *const () as u64,
        b"_endthreadex" => crt_endthreadex as *const () as u64,
        b"_errno" => crt_errno as *const () as u64,
        b"_set_errno" => crt_set_errno as *const () as u64,
        b"_get_errno" => crt_get_errno as *const () as u64,
        b"_invalid_parameter_noinfo" => crt_invalid_param as *const () as u64,
        b"_invalid_parameter_noinfo_noreturn" => crt_invalid_param_noreturn as *const () as u64,
        // Stdio
        b"__acrt_iob_func" => crt_acrt_iob_func as *const () as u64,
        b"__p__commode" => crt_p_commode as *const () as u64,
        b"_set_fmode" => crt_set_fmode as *const () as u64,
        b"_get_fmode" => crt_get_fmode as *const () as u64,
        b"__stdio_common_vfprintf" => crt_stdio_vfprintf as *const () as u64,
        b"__stdio_common_vsprintf" => crt_stdio_vsprintf as *const () as u64,
        b"__stdio_common_vsprintf_s" => crt_stdio_vsprintf_s as *const () as u64,
        b"__stdio_common_vsnprintf_s" => crt_stdio_vsnprintf_s as *const () as u64,
        b"fopen" => crt_fopen as *const () as u64,
        b"fopen_s" => crt_fopen_s as *const () as u64,
        b"fclose" => crt_fclose as *const () as u64,
        b"fflush" => crt_fflush as *const () as u64,
        b"fwrite" => crt_fwrite as *const () as u64,
        b"fread" => crt_fread as *const () as u64,
        b"fgets" => crt_fgets as *const () as u64,
        b"fputs" => crt_fputs as *const () as u64,
        b"puts" => crt_puts as *const () as u64,
        b"putchar" => crt_putchar as *const () as u64,
        b"fputc" | b"putc" => crt_fputc as *const () as u64,
        b"fgetc" | b"getc" => crt_fgetc as *const () as u64,
        b"fseek" | b"_fseeki64" => crt_fseek as *const () as u64,
        b"ftell" | b"_ftelli64" => crt_ftell as *const () as u64,
        b"feof" => crt_feof as *const () as u64,
        b"ferror" => crt_ferror as *const () as u64,
        b"clearerr" => crt_clearerr as *const () as u64,
        // Environment
        b"getenv" => crt_getenv as *const () as u64,
        b"getenv_s" => crt_getenv_s as *const () as u64,
        b"_putenv_s" => crt_putenv_s as *const () as u64,
        b"_putenv" => crt_putenv as *const () as u64,
        // Filesystem
        b"remove" | b"_unlink" => crt_remove as *const () as u64,
        b"rename" => crt_rename as *const () as u64,
        b"_access" => crt_access as *const () as u64,
        // Strings / Memory / Convert / Sort
        b"memcpy" | b"memmove" => crt_memcpy as *const () as u64,
        b"memcpy_s" | b"memmove_s" => crt_memcpy_s as *const () as u64,
        b"memset" => crt_memset as *const () as u64,
        b"memcmp" => crt_memcmp as *const () as u64,
        b"memchr" => crt_memchr as *const () as u64,
        b"strlen" => crt_strlen as *const () as u64,
        b"strnlen" => crt_strnlen as *const () as u64,
        b"strcmp" => crt_strcmp as *const () as u64,
        b"strncmp" => crt_strncmp as *const () as u64,
        b"_stricmp" => crt_stricmp as *const () as u64,
        b"_strnicmp" => crt_strnicmp as *const () as u64,
        b"strcpy" => crt_strcpy as *const () as u64,
        b"strcpy_s" => crt_strcpy_s as *const () as u64,
        b"strncpy" => crt_strncpy as *const () as u64,
        b"strcat_s" => crt_strcat_s as *const () as u64,
        b"strchr" => crt_strchr as *const () as u64,
        b"strrchr" => crt_strrchr as *const () as u64,
        b"strstr" => crt_strstr as *const () as u64,
        b"wcslen" => crt_wcslen as *const () as u64,
        b"wcscmp" => crt_wcscmp as *const () as u64,
        b"atoi" | b"atol" => crt_atoi as *const () as u64,
        b"atoll" | b"strtol" | b"strtoll" | b"_strtoi64" => crt_strtoll as *const () as u64,
        b"strtoul" | b"strtoull" | b"_strtoui64" => crt_strtoull as *const () as u64,
        b"qsort" => crt_qsort as *const () as u64,
        b"tolower" => crt_tolower as *const () as u64,
        b"toupper" => crt_toupper as *const () as u64,
        b"isdigit" => crt_isdigit as *const () as u64,
        b"isalpha" => crt_isalpha as *const () as u64,
        b"isspace" => crt_isspace as *const () as u64,
        // Math / Locale / Time
        b"__setusermatherr" => crt_setusermatherr as *const () as u64,
        b"_configthreadlocale" => crt_configthreadlocale as *const () as u64,
        b"setlocale" => crt_setlocale as *const () as u64,
        b"_time64" => crt_time64 as *const () as u64,
        b"clock" => crt_clock as *const () as u64,
        _ => return None,
    })
}
