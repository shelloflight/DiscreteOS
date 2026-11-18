//! Linux personality, milestone L1 (docs/compat.md): a minimal **Linux server**.
//!
//! The Linux program runs unchanged in its own process, spawned with the `FORWARD` personality
//! (every `syscall` becomes an exception message to us; the kernel runs none of them) and with
//! `START_EXCEPTION` (ABI addition): before its first instruction we get a START
//! exception and build the initial stack a Linux program expects (argc, argv, envp, auxv) in its
//! memory, then resume it at its entry point.
//!
//! Served: `write` (fd 1 and 2 to the debug log), `exit`/`exit_group`, `arch_prctl`
//! (`ARCH_SET_FS`, `ARCH_GET_FS`), `set_tid_address`, `getpid`/`gettid` (the forwarded-syscall
//! benchmark). Every other syscall is answered `-ENOSYS` and logged. A fault in the program
//! (no signals yet) is reported and kills it with the native fault exit code.
//!
//! The server runs per program (never one system-wide server); it reaches the program only
//! through its process handle (memory access needs MANAGE) and the exception channel.

use crate::sys::{self, ExceptionMsg, Handle, Regs};
use crate::{EXIT_REFUSED, EXIT_USAGE, find_program, println, startup_handle, text, word};

const EBADF: i64 = 9;
const EFAULT: i64 = 14;
const EINVAL: i64 = 22;
const EPERM: i64 = 1;
const ENOSYS: i64 = 38;

const NR_WRITE: u64 = 1;
const NR_GETPID: u64 = 39;
const NR_EXIT: u64 = 60;
const NR_ARCH_PRCTL: u64 = 158;
const NR_GETTID: u64 = 186;
const NR_SET_TID_ADDRESS: u64 = 218;
const NR_EXIT_GROUP: u64 = 231;

const ARCH_SET_FS: u64 = 0x1002;
const ARCH_GET_FS: u64 = 0x1003;

const MAX_ARGS: usize = 32;
const MAX_ENOSYS_LOGS: u32 = 16;

fn syscall_name(n: u64) -> &'static str {
    match n {
        0 => "read",
        2 => "open",
        3 => "close",
        9 => "mmap",
        12 => "brk",
        13 => "rt_sigaction",
        14 => "rt_sigprocmask",
        16 => "ioctl",
        20 => "writev",
        57 => "fork",
        59 => "execve",
        63 => "uname",
        89 => "readlink",
        228 => "clock_gettime",
        257 => "openat",
        302 => "prlimit64",
        318 => "getrandom",
        334 => "rseq",
        _ => "?",
    }
}

/// Where the program headers are mapped (for AT_PHDR), from the ELF header: PT_PHDR, or the
/// PT_LOAD that contains them. 0 if neither (AT_PHDR is then left out).
struct ElfInfo {
    phdr: u64,
    phnum: u64,
}

fn elf_info(image: Handle) -> Option<ElfInfo> {
    let mut h = [0u8; 64];
    if sys::vmo_read(image, 0, &mut h) < 0 || h[0..4] != [0x7F, b'E', b'L', b'F'] || h[4] != 2 {
        return None; // identified by magic, never by name
    }
    let u16_at = |b: &[u8], o: usize| u64::from(u16::from_le_bytes([b[o], b[o + 1]]));
    let u64_at = |b: &[u8], o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap_or([0; 8]));
    let (phoff, phnum) = (u64_at(&h, 32), u16_at(&h, 56).min(64));
    let mut phdr = 0;
    for i in 0..phnum {
        let mut p = [0u8; 56];
        if sys::vmo_read(image, phoff.saturating_add(i * 56), &mut p) < 0 {
            break;
        }
        let ty = u32::from_le_bytes([p[0], p[1], p[2], p[3]]);
        let (off, vaddr, filesz) = (u64_at(&p, 8), u64_at(&p, 16), u64_at(&p, 32));
        if ty == 6 {
            phdr = vaddr; // PT_PHDR
            break;
        }
        if ty == 1 && phdr == 0 && phoff >= off && phoff - off < filesz {
            phdr = vaddr + (phoff - off); // PT_LOAD containing the table
        }
    }
    Some(ElfInfo { phdr, phnum })
}

fn random16() -> [u8; 16] {
    // RDRAND when the CPU has it (CPUID.1:ECX bit 30), else TSC mixing (AT_RANDOM seeds stack
    // canaries and pointer guards; not a key).
    let has_rdrand = core::arch::x86_64::__cpuid(1).ecx & (1 << 30) != 0;
    let mut out = [0u8; 16];
    for half in out.chunks_mut(8) {
        let mut v: u64 = 0;
        let mut ok = false;
        if has_rdrand {
            for _ in 0..10 {
                let c: u8;
                // SAFETY: RDRAND exists (checked above); it only writes the output and CF.
                unsafe { core::arch::asm!("rdrand {}", "setc {}", out(reg) v, out(reg_byte) c, options(nomem, nostack)) };
                if c != 0 {
                    ok = true;
                    break;
                }
            }
        }
        if !ok {
            let t = sys::rdtsc();
            v = t.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ (t >> 29);
        }
        half.copy_from_slice(&v.to_le_bytes());
    }
    out
}

/// Build the Linux initial stack below the startup block and point the registers at it:
/// RSP -> argc, argv[], NULL, envp NULL, auxv pairs, AT_NULL; strings and AT_RANDOM above.
fn initial_stack(proc: Handle, r: &mut Regs, argv: &[&[u8]], elf: &ElfInfo) -> Result<(), &'static str> {
    const AREA: usize = 4096;
    let top = r.rsp & !15; // the kernel's startup block starts here (unused by a Linux program)
    let base = top.checked_sub(AREA as u64).ok_or("stack too small")?;
    let mut buf = [0u8; AREA];
    let mut p = AREA;
    let mut push = |s: &[u8], nul: bool, p: &mut usize| -> Result<u64, &'static str> {
        let n = s.len() + usize::from(nul);
        if n + 512 > *p {
            return Err("arguments too long");
        }
        *p -= n;
        buf[*p..*p + s.len()].copy_from_slice(s);
        if nul {
            buf[*p + s.len()] = 0;
        }
        Ok(base + *p as u64)
    };
    let random = push(&random16(), false, &mut p)?;
    let platform = push(b"x86_64", true, &mut p)?;
    let mut argp = [0u64; MAX_ARGS];
    for (i, a) in argv.iter().enumerate() {
        argp[i] = push(a, true, &mut p)?;
    }
    // Program image bias (0 for ET_EXEC) from the startup block, for AT_PHDR.
    let mut bias = [0u8; 8];
    if sys::process_read_memory(proc, r.rdi.wrapping_add(24), &mut bias) < 0 {
        return Err("cannot read the startup block");
    }
    let bias = u64::from_le_bytes(bias);
    let auxv: [(u64, u64); 17] = [
        (3, if elf.phdr != 0 { bias.wrapping_add(elf.phdr) } else { 0 }), // AT_PHDR
        (4, 56),                                                             // AT_PHENT
        (5, elf.phnum),                                                      // AT_PHNUM
        (6, 4096),                                                           // AT_PAGESZ
        (7, 0),                                                              // AT_BASE (no interpreter)
        (8, 0),                                                              // AT_FLAGS
        (9, r.rip),                                                          // AT_ENTRY
        (11, 0),                                                             // AT_UID
        (12, 0),                                                             // AT_EUID
        (13, 0),                                                             // AT_GID
        (14, 0),                                                             // AT_EGID
        (15, platform),                                                      // AT_PLATFORM
        (16, 0),                                                             // AT_HWCAP
        (17, 100),                                                           // AT_CLKTCK
        (23, 0),                                                             // AT_SECURE
        (25, random),                                                        // AT_RANDOM
        (31, argp[0]),                                                       // AT_EXECFN
    ];
    let nwords = 1 + argv.len() + 1 + 1 + 2 * auxv.len() + 2;
    let sp = (p - 8 * nwords) & !15;
    let mut w = sp;
    let mut put = |v: u64| {
        buf[w..w + 8].copy_from_slice(&v.to_le_bytes());
        w += 8;
    };
    put(argv.len() as u64);
    for a in &argp[..argv.len()] {
        put(*a);
    }
    put(0); // argv end
    put(0); // envp: empty
    for (k, v) in auxv {
        let k = if k == 3 && v == 0 { 1 } else { k }; // AT_PHDR unknown: AT_IGNORE
        put(k);
        put(v);
    }
    put(0); // AT_NULL
    put(0);
    if sys::process_write_memory(proc, base + sp as u64, &buf[sp..]) < 0 {
        return Err("cannot write the initial stack");
    }
    r.rsp = base + sp as u64;
    r.rdi = 0;
    r.rsi = 0;
    r.rdx = 0; // no rtld_fini
    Ok(())
}

enum Next {
    Resume,
    Exit(i32),
}

struct Server<'a> {
    proc: Handle,
    name: &'a [u8],
    enosys_logged: u32,
}

impl Server<'_> {
    fn write(&self, r: &Regs) -> i64 {
        if r.rdi != 1 && r.rdi != 2 {
            return -EBADF;
        }
        let total = r.rdx.min(64 * 1024);
        let mut chunk = [0u8; 4096];
        let mut done = 0u64;
        while done < total {
            let n = (total - done).min(chunk.len() as u64) as usize;
            if sys::process_read_memory(self.proc, r.rsi.wrapping_add(done), &mut chunk[..n]) < 0 {
                return if done > 0 { done as i64 } else { -EFAULT };
            }
            sys::log_write(crate::out::log(), &chunk[..n]);
            done += n as u64;
        }
        done as i64
    }

    fn syscall(&mut self, m: &ExceptionMsg, r: &mut Regs) -> Next {
        let nr = m.error;
        let pid = (m.pid & 0x3FFF_FFFF) as i64;
        let v: i64 = match nr {
            NR_WRITE => self.write(r),
            NR_GETPID | NR_GETTID => pid,
            NR_EXIT | NR_EXIT_GROUP => return Next::Exit((r.rdi & 0xFF) as i32),
            NR_ARCH_PRCTL => match r.rdi {
                ARCH_SET_FS if r.rsi < sys::USER_TOP => {
                    r.fs_base = r.rsi;
                    0
                }
                ARCH_SET_FS => -EPERM,
                ARCH_GET_FS => {
                    if sys::process_write_memory(self.proc, r.rsi, &r.fs_base.to_le_bytes()) < 0 { -EFAULT } else { 0 }
                }
                _ => -EINVAL,
            },
            NR_SET_TID_ADDRESS => pid, // clear_child_tid matters once there are threads (L2)
            _ => {
                if self.enosys_logged < MAX_ENOSYS_LOGS {
                    self.enosys_logged += 1;
                    println!(
                        "dcmpl: {}: unsupported Linux syscall {} ({}) -> ENOSYS",
                        text(self.name),
                        nr,
                        syscall_name(nr)
                    );
                }
                -ENOSYS
            }
        };
        r.rax = v as u64;
        Next::Resume
    }
}

fn signal_of(vector: u32) -> &'static str {
    match vector {
        0 => "SIGFPE",
        3 => "SIGTRAP",
        6 => "SIGILL",
        13 | 14 => "SIGSEGV",
        _ => "SIGBUS",
    }
}

pub fn run(name: &[u8], cmdline: &[u8]) -> i32 {
    if name.is_empty() {
        println!("dcmpl: linux: which program?");
        return EXIT_USAGE;
    }
    let Some(image) = find_program(name) else {
        println!("dcmpl: linux: no program '{}'", text(name));
        return EXIT_USAGE;
    };
    let Some(elf) = elf_info(image) else {
        println!("dcmpl: linux: {} refused: not an ELF64 executable", text(name));
        return EXIT_REFUSED;
    };
    let mut argv: [&[u8]; MAX_ARGS] = [&[]; MAX_ARGS];
    let mut argc = 0;
    while argc < MAX_ARGS && !word(cmdline, argc).is_empty() {
        argv[argc] = word(cmdline, argc);
        argc += 1;
    }

    let mut ch: Handle = 0;
    let s = sys::Spawn {
        parent: startup_handle(sys::TAG_PROC_SELF),
        image,
        name: name.as_ptr() as u64,
        name_len: name.len() as u64,
        args: 0,
        args_len: 0,
        handles: 0,
        nhandles: 0,
        flags: sys::SPAWN_EXCEPTION_CHANNEL | sys::SPAWN_FORWARD | sys::SPAWN_START_EXCEPTION,
        limits: 0,
        exception_channel: (&raw mut ch) as u64,
    };
    let p = sys::spawn(&s);
    if p < 0 {
        println!("dcmpl: linux: {} refused by spawn: {}", text(name), sys::status(p));
        return EXIT_REFUSED;
    }
    let proc = p as Handle;
    let mut srv = Server { proc, name, enosys_logged: 0 };
    let mut m = ExceptionMsg::default();
    loop {
        // SAFETY: ExceptionMsg is repr(C) plain data; any bytes are a valid value.
        let bytes = unsafe {
            core::slice::from_raw_parts_mut((&raw mut m).cast::<u8>(), core::mem::size_of::<ExceptionMsg>())
        };
        let Ok((n, exc)) = sys::channel_read(ch, bytes, sys::WAIT_FOREVER) else {
            break; // PEER_CLOSED: the program has ended
        };
        if n as usize != core::mem::size_of::<ExceptionMsg>() || exc == 0 {
            println!("dcmpl: linux: bad exception message");
            if exc != 0 {
                sys::handle_close(exc); // unresolved: the kernel kills the program
            }
            continue;
        }
        let mut r = m.regs;
        let next = match m.kind {
            sys::EXC_START => match initial_stack(proc, &mut r, &argv[..argc.max(1)], &elf) {
                Ok(()) => Next::Resume,
                Err(e) => {
                    println!("dcmpl: {}: cannot start: {}", text(name), e);
                    Next::Exit(EXIT_REFUSED)
                }
            },
            sys::EXC_SYSCALL => srv.syscall(&m, &mut r),
            _ => {
                println!(
                    "dcmpl: {}: {} (vector {}, error {:#x}, address {:#x}) at rip {:#x}; no signal handlers yet, killed",
                    text(name),
                    signal_of(m.vector),
                    m.vector,
                    m.error,
                    m.cr2,
                    r.rip
                );
                Next::Exit(sys::EXIT_FAULT)
            }
        };
        match next {
            Next::Resume => {
                if sys::exception_set_regs(exc, &r) < 0 || sys::exception_resume(exc, sys::EXC_RESUME, 0) < 0 {
                    println!("dcmpl: {}: invalid registers, killed", text(name));
                    sys::exception_resume(exc, sys::EXC_KILL, sys::EXIT_FAULT);
                }
            }
            Next::Exit(code) => {
                sys::exception_resume(exc, sys::EXC_KILL, code);
            }
        }
        sys::handle_close(exc);
    }
    sys::handle_close(ch);
    sys::object_wait(proc, sys::TERMINATED, sys::WAIT_FOREVER);
    let code = sys::process_exit_code(proc);
    sys::handle_close(proc);
    code as i32
}
