//! D-CMPL proofs (design: docs/compat.md): real foreign binaries on the IPC
//! kernel mechanisms. A ring-3 program, embedded in the image like init, with no runtime beyond
//! this crate (no libd yet).
//!
//! Arguments (from the spawner, e.g. `init run dcmpl win w1.exe` or utest):
//!   win <exe>             load the PE32+ program <exe> (an embedded PROGRAM VMO) into this process
//!                         and run it on the minimal kernel32 (`win.rs`); exit with its exit code
//!   linux <elf> [args]    spawn <elf> as a FORWARD process and serve its Linux syscalls
//!                         (`linux.rs`); exit with its exit code
//!   pefuzz <rounds>       mutate every embedded `.exe` <rounds> times through the PE parser,
//!                         layout, relocation and import binding (`fuzz.rs`)
//!
//! Startup handles used: LOG, PROC_SELF, VMAR_ROOT, the PROGRAM VMOs, and VMEX (win: code is
//! sealed before it is mapped executable, so W^X holds for loaded foreign code too).
//!
//! Exit codes of D-CMPL itself: 2 = the program was refused (bad image, unsupported import,
//! unsupported feature), 3 = bad arguments or missing program, 127 = internal panic.

#![no_std]

pub mod fuzz;
pub mod linux;
pub mod out;
pub mod pe;
pub mod sys;
pub mod win;

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

pub const EXIT_REFUSED: i32 = 2;
pub const EXIT_USAGE: i32 = 3;

static STARTUP: AtomicU64 = AtomicU64::new(0);
static ROOT_VMAR: AtomicU32 = AtomicU32::new(0);

// Entry point: RDI = startup block; a 16-byte aligned stack for Rust, no frame to return to.
core::arch::global_asm!(
    ".globl _start",
    "_start:",
    "  xor ebp, ebp",
    "  and rsp, -16",
    "  call {entry}",
    "  ud2",
    entry = sym dcmpl_entry,
);

#[repr(C)]
struct Startup {
    magic: u32,
    abi_version: u32,
    nhandles: u32,
    args_len: u32,
    args: u64,
    image_base: u64,
    stack_base: u64,
    stack_size: u64,
}

fn startup() -> &'static Startup {
    // SAFETY: set once in dcmpl_entry to the kernel's startup block, which lives (read-only for
    // us) at the top of the initial stack for the life of the process.
    unsafe { &*(STARTUP.load(Ordering::Relaxed) as *const Startup) }
}

/// Startup handles as (handle, tag).
pub fn startup_handles() -> impl Iterator<Item = (u32, u32)> {
    let s = startup();
    let base = (s as *const Startup as u64) + core::mem::size_of::<Startup>() as u64;
    (0..u64::from(s.nhandles)).map(move |i| {
        // SAFETY: the kernel writes nhandles (handle, tag) pairs right after the header.
        unsafe { (*((base + 8 * i) as *const u32), *((base + 8 * i + 4) as *const u32)) }
    })
}

pub fn startup_handle(tag: u32) -> sys::Handle {
    startup_handles().find(|&(_, t)| t == tag).map_or(0, |(h, _)| h)
}

pub fn root_vmar() -> sys::Handle {
    ROOT_VMAR.load(Ordering::Relaxed)
}

fn args() -> &'static [u8] {
    let s = startup();
    // SAFETY: args_len bytes at `args` (kernel-written, NUL-terminated copy).
    unsafe { core::slice::from_raw_parts(s.args as *const u8, s.args_len as usize) }
}

/// The `n`-th space-separated word of `s` (empty if there is none).
pub fn word(s: &[u8], n: usize) -> &[u8] {
    s.split(|&c| c == b' ').filter(|w| !w.is_empty()).nth(n).unwrap_or(&[])
}

/// Everything after the first `n` words.
pub fn rest(s: &[u8], n: usize) -> &[u8] {
    let mut i = 0;
    for _ in 0..n {
        while i < s.len() && s[i] == b' ' {
            i += 1;
        }
        while i < s.len() && s[i] != b' ' {
            i += 1;
        }
    }
    while i < s.len() && s[i] == b' ' {
        i += 1;
    }
    &s[i..]
}

pub fn parse_u(s: &[u8]) -> u64 {
    s.iter().take_while(|c| c.is_ascii_digit()).fold(0u64, |v, &c| v.saturating_mul(10).saturating_add(u64::from(c - b'0')))
}

pub fn text(b: &[u8]) -> &str {
    core::str::from_utf8(b).unwrap_or("?")
}

/// The embedded program named `name` (a PROGRAM VMO, found by object name).
pub fn find_program(name: &[u8]) -> Option<sys::Handle> {
    let mut buf = [0u8; 64];
    startup_handles().filter(|&(_, t)| t == sys::TAG_PROGRAM).map(|(h, _)| h).find(|&h| {
        let n = sys::object_name(h, &mut buf);
        n >= 0 && n as usize == name.len() && buf[..name.len()] == *name
    })
}

/// Names of every embedded program (for the fuzzer).
pub fn programs(mut f: impl FnMut(sys::Handle, &[u8])) {
    let mut buf = [0u8; 64];
    for (h, t) in startup_handles() {
        if t == sys::TAG_PROGRAM {
            let n = sys::object_name(h, &mut buf);
            if n > 0 && (n as usize) <= buf.len() {
                f(h, &buf[..n as usize]);
            }
        }
    }
}

/// Read a whole program VMO into a fresh mapping (at most `max` bytes).
pub fn read_program(h: sys::Handle, max: u64) -> Result<(sys::Mapping, usize), i64> {
    let size = sys::vmo_size(h);
    if size < 0 {
        return Err(size);
    }
    let size = size as u64;
    if size == 0 || size > max {
        return Err(-7); // OUT_OF_RANGE
    }
    let mut m = sys::Mapping::new(root_vmar(), size)?;
    let buf = &mut m.bytes()[..size as usize];
    let mut off = 0usize;
    while off < buf.len() {
        let n = (buf.len() - off).min(64 * 1024);
        let r = sys::vmo_read(h, off as u64, &mut buf[off..off + n]);
        if r < 0 {
            return Err(r);
        }
        off += n;
    }
    Ok((m, size as usize))
}

extern "C" fn dcmpl_entry(s: *const Startup) -> ! {
    // SAFETY: the kernel passes its startup block in RDI; checked before any other use.
    let ok = !s.is_null() && unsafe { (*s).magic == sys::STARTUP_MAGIC && (*s).abi_version >= sys::ABI_VERSION };
    if !ok {
        sys::process_exit(-1);
    }
    STARTUP.store(s as u64, Ordering::Relaxed);
    ROOT_VMAR.store(startup_handle(sys::TAG_VMAR_ROOT), Ordering::Relaxed);
    out::set_log(startup_handle(sys::TAG_LOG));
    let a = args();
    let code = match word(a, 0) {
        b"win" => win::run(word(a, 1)),
        b"linux" => linux::run(word(a, 1), rest(a, 1)),
        b"pefuzz" => fuzz::run(parse_u(word(a, 1))),
        _ => {
            println!("dcmpl: usage: win <exe> | linux <elf> [args] | pefuzz <rounds> (got '{}')", text(a));
            EXIT_USAGE
        }
    };
    sys::process_exit(code)
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo<'_>) -> ! {
    println!("dcmpl: PANIC: {}", info);
    sys::process_exit(127)
}
