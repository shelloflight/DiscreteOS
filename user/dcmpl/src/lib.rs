//! D-CMPL (design: docs/compat.md): foreign console programs, unchanged, on libd.
//!
//! Arguments (from the spawner: the shell's `run`, utest, `init run`):
//!   win <exe> [args]      load the PE32+ program <exe> into this process and run it on D-CMPL's
//!                         kernel32 (`win/`); exit with its exit code
//!   linux <elf> [args]    spawn <elf> as a FORWARD process and serve its Linux syscalls
//!                         (`linux/`); exit with its exit code
//!   pefuzz <rounds>       mutate every embedded `.exe` <rounds> times through the PE parser,
//!                         layout, relocation and import binding (`fuzz.rs`)
//!
//! The program image is the `tool::TAG_IMAGE` startup handle (a file the shell read), else the
//! embedded PROGRAM VMO named <exe>/<elf>. Other startup handles used: LOG, PROC_SELF, VMAR_ROOT,
//! VMEX (code is sealed before it is mapped executable, so W^X holds for foreign code too; a
//! Linux image from a file is allowed as unsigned code, a measured decision), `tool::TAG_OUTPUT`
//! (standard output and error as text; else the log), `tool::TAG_TIME_BASE` (the wall clock) and
//! a namespace (`fs::Namespace`): the first entry is the working directory. Nothing else: the
//! foreign program can reach only what this process was given.
//!
//! Exit codes of D-CMPL itself: 2 = the program was refused (bad image, unsupported import,
//! unsupported feature), 3 = bad arguments or missing program, 127 = internal panic.

#![no_std]

extern crate alloc;

pub mod fuzz;
pub mod linux;
pub mod out;
pub mod path;
pub mod pe;
pub mod win;

use alloc::vec::Vec;

use libd::sys::{self, Handle};
use libd::{Startup, println, tool};

pub const EXIT_REFUSED: i32 = 2;
pub const EXIT_USAGE: i32 = 3;

/// The user half of the address space (docs/abi.md, "User memory"); VMAR offsets are relative
/// to its start.
pub const USER_BASE: u64 = 0x20_0000;
pub const USER_TOP: u64 = 0x0000_7FFF_FFFF_0000;
pub const PAGE: u64 = sys::PAGE;

libd::entry!(_start, main);

pub fn text(b: &[u8]) -> &str {
    core::str::from_utf8(b).unwrap_or("?")
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

/// The program to run: the image handed over (`tool::TAG_IMAGE`), else the embedded program
/// named `name`.
pub fn find_image(name: &[u8]) -> Option<Handle> {
    match libd::startup_handle(tool::TAG_IMAGE) {
        0 => libd::find_program(name),
        h => Some(h),
    }
}

/// Was the program handed over as a file (not embedded, so not trusted as a program yet)?
pub fn tool_image() -> bool {
    libd::startup_handle(tool::TAG_IMAGE) != 0
}

/// Names of every embedded program (for the fuzzer).
pub fn programs(mut f: impl FnMut(Handle, &[u8])) {
    let mut buf = [0u8; 64];
    for (h, t) in libd::startup_handles() {
        if t == sys::TAG_PROGRAM {
            let n = sys::object_name(h, &mut buf);
            if n > 0 && (n as usize) <= buf.len() {
                f(h, &buf[..n as usize]);
            }
        }
    }
}

/// Read a whole image VMO (at most `max` bytes).
pub fn read_image(h: Handle, max: u64) -> Result<Vec<u8>, i64> {
    let size = sys::vmo_size(h)?;
    if size == 0 || size > max {
        return Err(sys::ERR_OUT_OF_RANGE);
    }
    let mut buf: Vec<u8> = Vec::new();
    buf.try_reserve_exact(size as usize).map_err(|_| sys::ERR_NO_MEMORY)?;
    buf.resize(size as usize, 0);
    let mut off = 0usize;
    while off < buf.len() {
        let n = (buf.len() - off).min(64 * 1024);
        let r = sys::vmo_read(h, off as u64, &mut buf[off..off + n]);
        if r < 0 {
            return Err(r);
        }
        off += n;
    }
    Ok(buf)
}

/// The wall clock the spawner handed over (`tool::TAG_TIME_BASE`: wall ns since 2000, monotonic ns).
fn set_time_base() {
    let v = libd::startup_handle(tool::TAG_TIME_BASE);
    let mut b = [0u8; 16];
    if v != 0 && sys::vmo_read(v, 0, &mut b) == 0 {
        let wall = i64::from_le_bytes(b[..8].try_into().unwrap_or([0; 8]));
        let mono = u64::from_le_bytes(b[8..].try_into().unwrap_or([0; 8]));
        if wall != 0 {
            libd::time::set_base(&libd::time::Base { wall: libd::time::Time(wall), mono, source: 0 });
        }
    }
}

/// Wall-clock time in ns since 2000-01-01 UTC; without a clock, the time since boot counted from
/// 2000-01-01 (so it still advances).
pub fn wall_ns() -> i64 {
    match libd::time::now() {
        libd::time::Time(0) => sys::clock_ns() as i64,
        t => t.0,
    }
}

fn main(s: *const Startup) -> i32 {
    // SAFETY: `s` is the startup block the kernel passed to the entry point.
    if !unsafe { libd::init(s, "dcmpl") } {
        return EXIT_USAGE;
    }
    set_time_base();
    path::init();
    let mut a = libd::args();
    loop {
        match word(a, 0) {
            b"--prefix" => {
                let p = word(a, 1);
                if p.is_empty() {
                    println!("dcmpl: --prefix requires a directory");
                    return EXIT_USAGE;
                }
                path::set_prefix(p);
                a = rest(a, 2);
            }
            b"--app-dir" => {
                let d = word(a, 1);
                if d.is_empty() {
                    println!("dcmpl: --app-dir requires a directory");
                    return EXIT_USAGE;
                }
                path::set_app_dir(d);
                a = rest(a, 2);
            }
            _ => break,
        }
    }
    let code = match word(a, 0) {
        b"win" => win::run(word(a, 1), rest(a, 2)),
        b"linux" => linux::run(word(a, 1), rest(a, 1)),
        b"pefuzz" => fuzz::run(parse_u(word(a, 1))),
        _ => {
            println!("dcmpl: usage: [--prefix <dir>] win <exe> [args] | linux <elf> [args] | pefuzz <rounds> (got '{}')", text(a));
            EXIT_USAGE
        }
    };
    out::flush_all();
    code
}
