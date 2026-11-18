//! Linux personality (docs/compat.md): a **Linux server** per program.
//!
//! The Linux program runs unchanged in its own process, spawned with the `FORWARD` personality
//! (every `syscall` becomes an exception message to this server; the kernel runs none of them)
//! and with `START_EXCEPTION`: before its first instruction the server builds the initial stack a
//! Linux program expects (argc, argv, envp, auxv) in its memory, then resumes it at its entry.
//!
//! The server is one loop over the program's exception channel. A syscall is answered at once,
//! or parked (its exception kept unresolved, the thread stays stopped) while it waits: `futex`
//! waits and sleeps, with deadlines (the channel read's timeout). Served:
//! - files through the namespace (`fs.rs`), standard output and error as text (`out.rs`);
//! - memory (`mem.rs`): `mmap` (anonymous, private file copies; code only through VMEX, never
//!   writable and executable), `munmap`, `mprotect` (see there), `brk`;
//! - threads: `clone` with `CLONE_VM | CLONE_THREAD` (a thread made stopped,
//!   `thread_create_stopped`, started with the parent's registers), `set_tid_address`, the
//!   child-tid clear and wake on `exit`, `exit` (that thread only), `exit_group`; `futex`
//!   (wait, wake, bitsets, requeue) with timeouts;
//! - signals: `rt_sigaction`, `rt_sigprocmask`, `sigaltstack`, `rt_sigreturn`, `kill`, `tkill`,
//!   `tgkill`; faults become SIGSEGV/SIGBUS/SIGFPE/SIGILL/SIGTRAP for a handler; a signal for
//!   another thread interrupts its wait (EINTR) or is delivered at its next syscall; no FPU
//!   state in the signal frame;
//! - time (`clock_gettime`, `gettimeofday`, `time`, `nanosleep`, `clock_nanosleep`), ids,
//!   `arch_prctl`, `getrandom`, limits.
//!
//! Every other syscall (fork, exec, sockets, pipes, ...) is answered `-ENOSYS` and logged.
//!
//! The server reaches the program only through its process handle (memory access and thread
//! creation need MANAGE), its root VMAR (`process_vmar`, for mmap) and the exception channel. A
//! Linux image read from a file is allowed as unsigned code with the VMEX resource (a measured
//! decision, like any `vmo_allow_unsigned`).

mod fs;
mod mem;

use alloc::vec::Vec;

use libd::handle::Owned;
use libd::println;
use libd::sys::{self, ExceptionMsg, Handle, Regs};

use crate::{EXIT_REFUSED, EXIT_USAGE, USER_TOP, find_image, text, tool_image, word};

pub const EPERM: i64 = 1;
pub const ENOENT: i64 = 2;
pub const ESRCH: i64 = 3;
pub const EINTR: i64 = 4;
pub const EIO: i64 = 5;
pub const EBADF: i64 = 9;
pub const EAGAIN: i64 = 11;
pub const ENOMEM: i64 = 12;
pub const EACCES: i64 = 13;
pub const EFAULT: i64 = 14;
pub const EEXIST: i64 = 17;
pub const ENOTDIR: i64 = 20;
pub const EISDIR: i64 = 21;
pub const EINVAL: i64 = 22;
pub const EMFILE: i64 = 24;
pub const ENOTTY: i64 = 25;
pub const ENOSPC: i64 = 28;
pub const ESPIPE: i64 = 29;
pub const EROFS: i64 = 30;
pub const ERANGE: i64 = 34;
pub const ENOSYS: i64 = 38;
pub const ENOTEMPTY: i64 = 39;
pub const ENAMETOOLONG: i64 = 36;
pub const ETIMEDOUT: i64 = 110;
pub const EXDEV: i64 = 18;

const MAX_ARGS: usize = 32;
const MAX_ENOSYS_LOGS: u32 = 16;
const UNIX_2000: i64 = 946_684_800;

fn syscall_name(n: u64) -> &'static str {
    match n {
        7 => "poll",
        22 => "pipe",
        23 => "select",
        41 => "socket",
        57 => "fork",
        58 => "vfork",
        59 => "execve",
        61 => "wait4",
        63 => "uname",
        101 => "ptrace",
        232 => "epoll_wait",
        293 => "pipe2",
        332 => "statx",
        334 => "rseq",
        435 => "clone3",
        _ => "?",
    }
}

// ---- the program's memory ---------------------------------------------------------------------

/// Reads and writes of the program's memory (through the kernel: a bad address is an error).
#[derive(Clone, Copy)]
pub struct Mem {
    pub proc: Handle,
}

impl Mem {
    pub fn read(&self, addr: u64, buf: &mut [u8]) -> bool {
        let mut done = 0;
        while done < buf.len() {
            let n = (buf.len() - done).min(64 * 1024);
            if sys::process_read_memory(self.proc, addr.wrapping_add(done as u64), &mut buf[done..done + n]) < 0 {
                return false;
            }
            done += n;
        }
        true
    }
    pub fn write(&self, addr: u64, data: &[u8]) -> bool {
        let mut done = 0;
        while done < data.len() {
            let n = (data.len() - done).min(64 * 1024);
            if sys::process_write_memory(self.proc, addr.wrapping_add(done as u64), &data[done..done + n]) < 0 {
                return false;
            }
            done += n;
        }
        true
    }
    pub fn u64(&self, addr: u64) -> Option<u64> {
        let mut b = [0u8; 8];
        self.read(addr, &mut b).then(|| u64::from_le_bytes(b))
    }
    pub fn u32(&self, addr: u64) -> Option<u32> {
        let mut b = [0u8; 4];
        self.read(addr, &mut b).then(|| u32::from_le_bytes(b))
    }
    pub fn put_u64(&self, addr: u64, v: u64) -> bool {
        self.write(addr, &v.to_le_bytes())
    }
    pub fn put_u32(&self, addr: u64, v: u32) -> bool {
        self.write(addr, &v.to_le_bytes())
    }
    /// A NUL-terminated string (at most `max` bytes), read page by page.
    pub fn cstr(&self, addr: u64, max: usize) -> Option<Vec<u8>> {
        let mut v = Vec::new();
        let mut at = addr;
        loop {
            let n = (4096 - (at % 4096) as usize).min(256);
            let mut b = [0u8; 256];
            if !self.read(at, &mut b[..n]) {
                return None;
            }
            if let Some(z) = b[..n].iter().position(|&c| c == 0) {
                v.extend_from_slice(&b[..z]);
                return Some(v);
            }
            v.extend_from_slice(&b[..n]);
            if v.len() > max {
                return None;
            }
            at += n as u64;
        }
    }
}

// ---- the initial stack ------------------------------------------------------------------------

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

/// 16 random bytes: RDRAND when the CPU has it (CPUID.1:ECX bit 30), else TSC mixing.
pub fn random_bytes(out: &mut [u8]) {
    let has_rdrand = core::arch::x86_64::__cpuid(1).ecx & (1 << 30) != 0;
    for chunk in out.chunks_mut(8) {
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
            let t = sys::clock_ns() ^ v;
            v = t.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ (t >> 29);
        }
        chunk.copy_from_slice(&v.to_le_bytes()[..chunk.len()]);
    }
}

/// Build the Linux initial stack below the startup block and point the registers at it:
/// RSP -> argc, argv[], NULL, envp[], NULL, auxv pairs, AT_NULL; strings and AT_RANDOM above.
fn initial_stack(m: Mem, r: &mut Regs, argv: &[&[u8]], env: &[&[u8]], elf: &ElfInfo) -> Result<(), &'static str> {
    const AREA: usize = 8192;
    let top = r.rsp & !15; // the kernel's startup block starts here (unused by a Linux program)
    let base = top.checked_sub(AREA as u64).ok_or("stack too small")?;
    let mut buf = [0u8; AREA];
    let mut p = AREA;
    let mut push = |s: &[u8], nul: bool, p: &mut usize| -> Result<u64, &'static str> {
        let n = s.len() + usize::from(nul);
        if n + 1024 > *p {
            return Err("arguments too long");
        }
        *p -= n;
        buf[*p..*p + s.len()].copy_from_slice(s);
        if nul {
            buf[*p + s.len()] = 0;
        }
        Ok(base + *p as u64)
    };
    let mut rnd = [0u8; 16];
    random_bytes(&mut rnd);
    let random = push(&rnd, false, &mut p)?;
    let platform = push(b"x86_64", true, &mut p)?;
    let mut argp = [0u64; MAX_ARGS];
    for (i, a) in argv.iter().enumerate() {
        argp[i] = push(a, true, &mut p)?;
    }
    let mut envp = [0u64; 8];
    for (i, e) in env.iter().take(8).enumerate() {
        envp[i] = push(e, true, &mut p)?;
    }
    // Program image bias (0 for ET_EXEC) from the startup block, for AT_PHDR.
    let bias = m.u64(r.rdi.wrapping_add(24)).ok_or("cannot read the startup block")?;
    let auxv: [(u64, u64); 17] = [
        (3, if elf.phdr != 0 { bias.wrapping_add(elf.phdr) } else { 0 }), // AT_PHDR
        (4, 56),                                                             // AT_PHENT
        (5, elf.phnum),                                                      // AT_PHNUM
        (6, 4096),                                                           // AT_PAGESZ
        (7, 0),                                                              // AT_BASE (no interpreter)
        (8, 0),                                                              // AT_FLAGS
        (9, r.rip),                                                          // AT_ENTRY
        (11, 1000),                                                          // AT_UID
        (12, 1000),                                                          // AT_EUID
        (13, 1000),                                                          // AT_GID
        (14, 1000),                                                          // AT_EGID
        (15, platform),                                                      // AT_PLATFORM
        (16, 0),                                                             // AT_HWCAP
        (17, 100),                                                           // AT_CLKTCK
        (23, 0),                                                             // AT_SECURE
        (25, random),                                                        // AT_RANDOM
        (31, argp[0]),                                                       // AT_EXECFN
    ];
    let nenv = env.len().min(8);
    let nwords = 1 + argv.len() + 1 + nenv + 1 + 2 * auxv.len() + 2;
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
    for e in &envp[..nenv] {
        put(*e);
    }
    put(0); // envp end
    for (k, v) in auxv {
        let k = if k == 3 && v == 0 { 1 } else { k }; // AT_PHDR unknown: AT_IGNORE
        put(k);
        put(v);
    }
    put(0); // AT_NULL
    put(0);
    if !m.write(base + sp as u64, &buf[sp..]) {
        return Err("cannot write the initial stack");
    }
    r.rsp = base + sp as u64;
    r.rdi = 0;
    r.rsi = 0;
    r.rdx = 0; // no rtld_fini
    Ok(())
}

// ---- threads, waits, signals -------------------------------------------------------------------

#[derive(Clone, Copy, Default)]
struct SigAction {
    handler: u64,
    flags: u64,
    restorer: u64,
    mask: u64,
}

const SIG_DFL: u64 = 0;
const SIG_IGN: u64 = 1;
const SA_ONSTACK: u64 = 0x0800_0000;
const SA_RESTORER: u64 = 0x0400_0000;
const SA_NODEFER: u64 = 0x4000_0000;
const SA_RESETHAND: u64 = 0x8000_0000;
const SIGKILL: u32 = 9;
const SIGSTOP: u32 = 19;
const UNBLOCKABLE: u64 = 1 << (SIGKILL - 1) | 1 << (SIGSTOP - 1);

#[derive(Clone, Copy)]
enum Wait {
    Futex { addr: u64, bitset: u32 },
    Sleep { rem: u64 },
}

struct Parked {
    exc: Owned,
    regs: Regs,
    wait: Wait,
    deadline: u64,
}

struct Thread {
    koid: u64,
    tid: i64,
    _handle: Option<Owned>,
    clear_tid: u64,
    mask: u64,
    pending: u64,
    /// sigaltstack: (sp, flags, size)
    alt: (u64, u32, u64),
    parked: Option<Parked>,
}

/// Siginfo for a signal being delivered.
#[derive(Clone, Copy)]
struct SigInfo {
    signo: u32,
    code: i32,
    addr: u64,
    pid: i64,
}

enum Next {
    Resume(Regs),
    Park(Wait, u64),
    ExitThread(i32),
    ExitGroup(i32),
}

pub struct Server<'a> {
    pub mem: Mem,
    name: &'a [u8],
    pid: i64,
    threads: Vec<Thread>,
    next_tid: i64,
    pending_clones: Vec<(u64, Regs)>,
    actions: [SigAction; 64],
    enosys_logged: u32,
    pub vmar: Handle,
    pub vmex: Handle,
    pub fds: fs::Fds,
    pub mm: mem::Mm,
}

fn signal_of(vector: u32) -> (u32, i32) {
    match vector {
        0 => (8, 1),  // SIGFPE, FPE_INTDIV
        16 | 19 => (8, 0),
        3 | 1 => (5, 1), // SIGTRAP, TRAP_BRKPT
        6 => (4, 2),  // SIGILL, ILL_ILLOPN
        17 => (7, 1), // SIGBUS, BUS_ADRALN
        _ => (11, 1), // SIGSEGV, SEGV_MAPERR
    }
}

fn signal_name(sig: u32) -> &'static str {
    match sig {
        4 => "SIGILL",
        5 => "SIGTRAP",
        7 => "SIGBUS",
        8 => "SIGFPE",
        11 => "SIGSEGV",
        _ => "signal",
    }
}

fn unix_ns() -> i64 {
    crate::wall_ns() + UNIX_2000 * 1_000_000_000
}

impl Server<'_> {
    fn ti(&self, koid: u64) -> Option<usize> {
        self.threads.iter().position(|t| t.koid == koid)
    }
    fn by_tid(&self, tid: i64) -> Option<usize> {
        self.threads.iter().position(|t| t.tid == tid)
    }

    fn timespec(&self, addr: u64) -> Result<u64, i64> {
        let (Some(s), Some(n)) = (self.mem.u64(addr), self.mem.u64(addr + 8)) else { return Err(-EFAULT) };
        let (s, n) = (s as i64, n as i64);
        if s < 0 || !(0..1_000_000_000).contains(&n) {
            return Err(-EINVAL);
        }
        Ok((s as u64).saturating_mul(1_000_000_000).saturating_add(n as u64))
    }
    fn put_timespec(&self, addr: u64, ns: i64) -> bool {
        let mut b = [0u8; 16];
        b[..8].copy_from_slice(&ns.div_euclid(1_000_000_000).to_le_bytes());
        b[8..].copy_from_slice(&ns.rem_euclid(1_000_000_000).to_le_bytes());
        self.mem.write(addr, &b)
    }

    /// FUTEX_WAKE: resume up to `n` waiters on `addr` (matching `bitset`).
    fn futex_wake(&mut self, addr: u64, n: u64, bitset: u32) -> i64 {
        let mut woken = 0;
        for i in 0..self.threads.len() {
            if woken >= n {
                break;
            }
            let hit = matches!(self.threads[i].parked, Some(Parked { wait: Wait::Futex { addr: a, bitset: b }, .. }) if a == addr && b & bitset != 0);
            if hit {
                self.wake(i, 0);
                woken += 1;
            }
        }
        woken as i64
    }

    /// Resume a parked thread with `result` (and any signal it has now).
    fn wake(&mut self, i: usize, result: i64) {
        let Some(p) = self.threads[i].parked.take() else { return };
        let mut r = p.regs;
        r.rax = result as u64;
        if let Wait::Sleep { rem } = p.wait
            && result == -EINTR
            && rem != 0
        {
            let left = p.deadline.saturating_sub(sys::clock_ns());
            self.put_timespec(rem, left as i64);
        }
        self.finish(i, p.exc, Next::Resume(r));
    }

    /// Hand the outcome of a syscall (or fault) of thread `i` back to the kernel.
    fn finish(&mut self, i: usize, exc: Owned, next: Next) {
        match next {
            Next::Resume(mut r) => {
                if let Err(code) = self.deliver_pending(i, &mut r) {
                    println!("dcmpl: {}: ended by a signal (exit code {})", text(self.name), code);
                    return self.finish(i, exc, Next::ExitGroup(code));
                }
                if sys::exception_set_regs(exc.raw(), &r) < 0 || sys::exception_resume(exc.raw(), sys::EXC_RESUME, 0) < 0 {
                    println!("dcmpl: {}: invalid registers, killed", text(self.name));
                    sys::exception_resume(exc.raw(), sys::EXC_KILL, sys::EXIT_FAULT);
                }
            }
            Next::Park(..) => unreachable!("parked outside handle"),
            Next::ExitThread(code) => {
                let t = self.threads.remove(i);
                if t.clear_tid != 0 {
                    self.mem.put_u32(t.clear_tid, 0);
                    self.futex_wake(t.clear_tid, 1, u32::MAX);
                }
                sys::exception_resume(exc.raw(), sys::EXC_EXIT_THREAD, code);
            }
            Next::ExitGroup(code) => {
                sys::exception_resume(exc.raw(), sys::EXC_KILL, code);
                for t in &mut self.threads {
                    t.parked = None; // their exceptions close unresolved: the process is ending anyway
                }
            }
        }
    }

    /// Deliver every pending, unblocked signal of thread `i` on `r` (frames nest). Err(code):
    /// one whose default action ends the program (exit code 128 + the signal).
    fn deliver_pending(&mut self, i: usize, r: &mut Regs) -> Result<(), i32> {
        for _ in 0..8 {
            let t = &self.threads[i];
            let ready = t.pending & !t.mask;
            if ready == 0 {
                break;
            }
            let sig = ready.trailing_zeros() + 1;
            self.threads[i].pending &= !(1 << (sig - 1));
            let info = SigInfo { signo: sig, code: -6, addr: 0, pid: self.pid };
            self.deliver(i, info, r)?;
        }
        Ok(())
    }

    /// Build a signal frame on thread `i`'s stack and point `r` at the handler. Err(code): the
    /// signal's default action ends the program.
    fn deliver(&mut self, i: usize, info: SigInfo, r: &mut Regs) -> Result<(), i32> {
        let sig = info.signo;
        let act = self.actions[(sig - 1) as usize];
        match act.handler {
            SIG_DFL => {
                return if matches!(sig, 17 | 18 | 23 | 28) { Ok(()) } else { Err(128 + sig as i32) };
            }
            SIG_IGN => return Ok(()),
            _ => {}
        }
        if act.flags & SA_RESTORER == 0 {
            return Err(128 + sig as i32); // x86-64 handlers return through the restorer only
        }
        let t = &self.threads[i];
        let mut sp = r.rsp;
        let (alt_sp, alt_flags, alt_size) = t.alt;
        let on_alt = alt_size != 0 && sp > alt_sp && sp <= alt_sp + alt_size;
        if act.flags & SA_ONSTACK != 0 && alt_size != 0 && alt_flags & 2 == 0 && !on_alt {
            sp = alt_sp + alt_size;
        }
        sp = sp.wrapping_sub(128); // the red zone
        let frame = (sp.wrapping_sub(8 + 304 + 128) & !15).wrapping_sub(8);
        let mut f = [0u8; 8 + 304 + 128];
        let mut put = |off: usize, v: u64| f[off..off + 8].copy_from_slice(&v.to_le_bytes());
        put(0, act.restorer);
        // ucontext at 8: flags, link, stack (sp, flags, size), mcontext at 48, sigmask at 304.
        put(24, alt_sp);
        put(32, u64::from(alt_flags));
        put(40, alt_size);
        let mc = 48;
        for (k, v) in [r.r8, r.r9, r.r10, r.r11, r.r12, r.r13, r.r14, r.r15, r.rdi, r.rsi, r.rbp, r.rbx, r.rdx, r.rax, r.rcx, r.rsp, r.rip, r.rflags]
            .into_iter()
            .enumerate()
        {
            put(mc + 8 * k, v);
        }
        put(mc + 144, 0x002B_0000_0000_0033); // cs, gs, fs, ss
        put(mc + 168, u64::from(t.mask as u32)); // oldmask
        put(mc + 176, info.addr); // cr2
        put(8 + 296, t.mask); // uc_sigmask (at ucontext + 296)
        // siginfo at 8 + 304
        let si = 8 + 304;
        f[si..si + 4].copy_from_slice(&(info.signo as i32).to_le_bytes());
        f[si + 8..si + 12].copy_from_slice(&info.code.to_le_bytes());
        if info.code > 0 {
            f[si + 16..si + 24].copy_from_slice(&info.addr.to_le_bytes()); // si_addr
        } else {
            f[si + 16..si + 20].copy_from_slice(&(info.pid as i32).to_le_bytes()); // si_pid
            f[si + 20..si + 24].copy_from_slice(&1000u32.to_le_bytes()); // si_uid
        }
        if !self.mem.write(frame, &f) {
            return Err(128 + 11); // no room for the frame: as Linux, SIGSEGV
        }
        r.rsp = frame;
        r.rip = act.handler;
        r.rdi = u64::from(sig);
        r.rsi = frame + si as u64;
        r.rdx = frame + 8;
        r.rax = 0;
        r.rflags &= !(1 << 10); // DF clear
        let t = &mut self.threads[i];
        t.mask |= act.mask & !UNBLOCKABLE;
        if act.flags & SA_NODEFER == 0 {
            t.mask |= 1 << (sig - 1);
        }
        if act.flags & SA_RESETHAND != 0 {
            self.actions[(sig - 1) as usize].handler = SIG_DFL;
        }
        Ok(())
    }

    fn sigreturn(&mut self, i: usize, r: &Regs) -> Next {
        let uc = r.rsp; // the restorer was entered by `ret` from the frame's pretcode
        let mut b = [0u8; 304];
        if !self.mem.read(uc, &mut b) {
            return Next::ExitGroup(128 + 11);
        }
        let g = |k: usize| u64::from_le_bytes(b[40 + 8 * k..48 + 8 * k].try_into().unwrap_or([0; 8]));
        let mut n = *r;
        n.r8 = g(0);
        n.r9 = g(1);
        n.r10 = g(2);
        n.r11 = g(3);
        n.r12 = g(4);
        n.r13 = g(5);
        n.r14 = g(6);
        n.r15 = g(7);
        n.rdi = g(8);
        n.rsi = g(9);
        n.rbp = g(10);
        n.rbx = g(11);
        n.rdx = g(12);
        n.rax = g(13);
        n.rcx = g(14);
        n.rsp = g(15);
        n.rip = g(16);
        n.rflags = (r.rflags & !0xCD5) | (g(17) & 0xCD5); // arithmetic flags and DF only
        let mask = u64::from_le_bytes(b[296..304].try_into().unwrap_or([0; 8]));
        self.threads[i].mask = mask & !UNBLOCKABLE;
        Next::Resume(n)
    }

    /// Raise `sig` for thread `i` (from kill/tgkill): pending, and a parked thread is woken.
    fn raise(&mut self, i: usize, sig: u32) {
        self.threads[i].pending |= 1 << (sig - 1);
        if self.threads[i].mask & (1 << (sig - 1)) == 0 && self.threads[i].parked.is_some() {
            self.wake(i, -EINTR);
        }
    }

    fn kill(&mut self, caller: usize, pid: i64, sig: u64) -> i64 {
        if pid != self.pid && pid != 0 && pid != -1 {
            return -ESRCH;
        }
        if sig == 0 {
            return 0;
        }
        if sig > 64 {
            return -EINVAL;
        }
        let sig = sig as u32;
        let bit = 1u64 << (sig - 1);
        let target = if self.threads[caller].mask & bit == 0 { caller } else { self.threads.iter().position(|t| t.mask & bit == 0).unwrap_or(caller) };
        self.raise(target, sig);
        0
    }

    fn rt_sigaction(&mut self, sig: u64, act: u64, old: u64) -> i64 {
        if sig == 0 || sig > 64 {
            return -EINVAL;
        }
        let k = (sig - 1) as usize;
        if old != 0 {
            let a = self.actions[k];
            let mut b = [0u8; 32];
            b[0..8].copy_from_slice(&a.handler.to_le_bytes());
            b[8..16].copy_from_slice(&a.flags.to_le_bytes());
            b[16..24].copy_from_slice(&a.restorer.to_le_bytes());
            b[24..32].copy_from_slice(&a.mask.to_le_bytes());
            if !self.mem.write(old, &b) {
                return -EFAULT;
            }
        }
        if act != 0 {
            if sig as u32 == SIGKILL || sig as u32 == SIGSTOP {
                return -EINVAL;
            }
            let mut b = [0u8; 32];
            if !self.mem.read(act, &mut b) {
                return -EFAULT;
            }
            let g = |o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap_or([0; 8]));
            self.actions[k] = SigAction { handler: g(0), flags: g(8), restorer: g(16), mask: g(24) };
        }
        0
    }

    fn rt_sigprocmask(&mut self, i: usize, how: u64, set: u64, old: u64) -> i64 {
        let cur = self.threads[i].mask;
        if old != 0 && !self.mem.put_u64(old, cur) {
            return -EFAULT;
        }
        if set != 0 {
            let Some(s) = self.mem.u64(set) else { return -EFAULT };
            let new = match how {
                0 => cur | s,
                1 => cur & !s,
                2 => s,
                _ => return -EINVAL,
            };
            self.threads[i].mask = new & !UNBLOCKABLE;
        }
        0
    }

    fn sigaltstack(&mut self, i: usize, ss: u64, old: u64) -> i64 {
        let (sp, fl, size) = self.threads[i].alt;
        if old != 0 {
            let mut b = [0u8; 24];
            b[0..8].copy_from_slice(&sp.to_le_bytes());
            b[8..12].copy_from_slice(&(if size == 0 { 2 } else { fl }).to_le_bytes()); // SS_DISABLE
            b[16..24].copy_from_slice(&size.to_le_bytes());
            if !self.mem.write(old, &b) {
                return -EFAULT;
            }
        }
        if ss != 0 {
            let mut b = [0u8; 24];
            if !self.mem.read(ss, &mut b) {
                return -EFAULT;
            }
            let g = |o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap_or([0; 8]));
            let flags = u32::from_le_bytes(b[8..12].try_into().unwrap_or([0; 4]));
            self.threads[i].alt = if flags & 2 != 0 { (0, 2, 0) } else { (g(0), flags, g(16)) };
        }
        0
    }

    fn clone(&mut self, i: usize, r: &Regs) -> i64 {
        const VM: u64 = 0x100;
        const THREAD: u64 = 0x1_0000;
        const SIGHAND: u64 = 0x800;
        const SETTLS: u64 = 0x8_0000;
        const PARENT_SETTID: u64 = 0x10_0000;
        const CHILD_CLEARTID: u64 = 0x20_0000;
        const CHILD_SETTID: u64 = 0x100_0000;
        let (flags, newsp, ptid, ctid, tls) = (r.rdi, r.rsi, r.rdx, r.r10, r.r8);
        if flags & (VM | THREAD | SIGHAND) != VM | THREAD | SIGHAND {
            self.unsupported(56, "clone without CLONE_VM|CLONE_THREAD (fork)");
            return -ENOSYS;
        }
        let sp = if newsp != 0 { newsp } else { r.rsp };
        if flags & SETTLS != 0 && tls >= USER_TOP {
            return -EPERM;
        }
        let h = match sys::thread_create_stopped(self.mem.proc, r.rip, sp, 0) {
            Ok(h) => Owned::from_raw(h),
            Err(e) if e == sys::ERR_NO_RESOURCES => return -EAGAIN,
            Err(_) => return -ENOMEM,
        };
        let Ok(info) = sys::object_info(h.raw()) else { return -ENOMEM };
        let mut c = *r;
        c.rax = 0;
        c.rsp = sp;
        if flags & SETTLS != 0 {
            c.fs_base = tls;
        }
        let tid = self.next_tid;
        self.next_tid += 1;
        self.pending_clones.push((info.koid, c));
        let mask = self.threads[i].mask;
        self.threads.push(Thread {
            koid: info.koid,
            tid,
            _handle: Some(h),
            clear_tid: if flags & CHILD_CLEARTID != 0 { ctid } else { 0 },
            mask,
            pending: 0,
            alt: (0, 2, 0),
            parked: None,
        });
        if flags & PARENT_SETTID != 0 {
            self.mem.put_u32(ptid, tid as u32);
        }
        if flags & CHILD_SETTID != 0 {
            self.mem.put_u32(ctid, tid as u32);
        }
        tid
    }

    fn futex(&mut self, i: usize, r: &Regs) -> Result<i64, (Wait, u64)> {
        const PRIVATE: u64 = 128;
        const REALTIME: u64 = 256;
        let (addr, op, val, ts, addr2, val3) = (r.rdi, r.rsi, r.rdx as u32, r.r10, r.r8, r.r9 as u32);
        let cmd = op & !(PRIVATE | REALTIME);
        let _ = i;
        match cmd {
            0 | 9 => {
                // WAIT, WAIT_BITSET
                let bitset = if cmd == 9 { val3 } else { u32::MAX };
                if bitset == 0 {
                    return Ok(-EINVAL);
                }
                let Some(cur) = self.mem.u32(addr) else { return Ok(-EFAULT) };
                if cur != val {
                    return Ok(-EAGAIN);
                }
                let deadline = if ts == 0 {
                    sys::WAIT_FOREVER
                } else {
                    let ns = match self.timespec(ts) {
                        Ok(ns) => ns,
                        Err(e) => return Ok(e),
                    };
                    if cmd == 9 {
                        // absolute: CLOCK_MONOTONIC, or CLOCK_REALTIME with the flag
                        if op & REALTIME != 0 {
                            let now = unix_ns();
                            sys::clock_ns().saturating_add((ns as i64 - now).max(0) as u64)
                        } else {
                            ns
                        }
                    } else {
                        sys::clock_ns().saturating_add(ns)
                    }
                };
                Err((Wait::Futex { addr, bitset }, deadline))
            }
            1 => Ok(self.futex_wake(addr, u64::from(val), u32::MAX)),
            10 => Ok(self.futex_wake(addr, u64::from(val), if val3 == 0 { return Ok(-EINVAL) } else { val3 })),
            3 | 4 => {
                // REQUEUE, CMP_REQUEUE: wake `val`, move up to `ts` (val2) others to addr2
                if cmd == 4 {
                    match self.mem.u32(addr) {
                        Some(v) if v == val3 => {}
                        Some(_) => return Ok(-EAGAIN),
                        None => return Ok(-EFAULT),
                    }
                }
                let woken = self.futex_wake(addr, u64::from(val), u32::MAX);
                let mut moved = 0u64;
                for t in &mut self.threads {
                    if moved >= ts {
                        break;
                    }
                    if let Some(Parked { wait: Wait::Futex { addr: a, .. }, .. }) = &mut t.parked
                        && *a == addr
                    {
                        *a = addr2;
                        moved += 1;
                    }
                }
                Ok(woken + moved as i64)
            }
            _ => {
                self.unsupported(202, "this futex operation");
                Ok(-ENOSYS)
            }
        }
    }

    fn unsupported(&mut self, nr: u64, what: &str) {
        if self.enosys_logged < MAX_ENOSYS_LOGS {
            self.enosys_logged += 1;
            println!("dcmpl: {}: unsupported Linux syscall {} ({}) -> ENOSYS", text(self.name), nr, what);
        }
    }

    fn clock(&self, clk: u64) -> Option<i64> {
        match clk {
            0 | 5 | 8 | 11 => Some(unix_ns()),                // REALTIME (+COARSE, ALARM, TAI)
            1 | 4 | 6 | 7 | 9 => Some(sys::clock_ns() as i64), // MONOTONIC, RAW, COARSE, BOOTTIME
            2 | 3 => Some(sys::clock_ns() as i64),            // process / thread CPU time (approx.)
            _ => None,
        }
    }

    fn syscall(&mut self, i: usize, r: &mut Regs) -> Next {
        let nr = r.rax;
        let (a0, a1, a2, a3) = (r.rdi, r.rsi, r.rdx, r.r10);
        let v: i64 = match nr {
            0 | 1 | 2 | 3 | 4 | 5 | 6 | 8 | 16 | 17 | 18 | 19 | 20 | 21 | 32 | 33 | 72 | 74 | 75 | 76 | 77 | 79 | 80 | 81 | 82
            | 83 | 84 | 87 | 89 | 217 | 257 | 258 | 262 | 263 | 264 | 267 | 269 | 292 | 316 | 439 => {
                fs::syscall(self, nr, r)
            }
            9 => mem::mmap(self, a0, a1, a2, a3, r.r8 as i64, r.r9),
            10 => mem::mprotect(self, a0, a1, a2),
            11 => mem::munmap(self, a0, a1),
            12 => mem::brk(self, a0) as i64,
            25 => -ENOMEM, // mremap: callers fall back to a new mapping and a copy
            28 => 0,       // madvise: advice only
            13 => self.rt_sigaction(a0, a1, a2),
            14 => self.rt_sigprocmask(i, a0, a1, a2),
            15 => return self.sigreturn(i, r),
            24 => 0, // sched_yield
            35 => match self.timespec(a0) {
                Ok(ns) => return Next::Park(Wait::Sleep { rem: a1 }, sys::clock_ns().saturating_add(ns)),
                Err(e) => e,
            },
            230 => {
                // clock_nanosleep(clock, flags, req, rem)
                match self.timespec(a2) {
                    Ok(ns) => {
                        let d = if a1 & 1 != 0 {
                            let now = self.clock(a0).unwrap_or(0);
                            sys::clock_ns().saturating_add((ns as i64 - now).max(0) as u64)
                        } else {
                            sys::clock_ns().saturating_add(ns)
                        };
                        return Next::Park(Wait::Sleep { rem: if a1 & 1 != 0 { 0 } else { a3 } }, d);
                    }
                    Err(e) => e,
                }
            }
            39 => self.pid,                       // getpid
            186 => self.threads[i].tid,           // gettid
            110 => 1,                             // getppid
            102 | 104 | 107 | 108 => 1000,        // getuid, getgid, geteuid, getegid
            95 => 0o022,                          // umask
            56 => self.clone(i, r),
            60 => return Next::ExitThread((a0 & 0xFF) as i32),
            231 => return Next::ExitGroup((a0 & 0xFF) as i32),
            62 => self.kill(i, a0 as i64, a1),
            200 => match self.by_tid(a0 as i64) {
                // tkill
                Some(t) if a1 > 0 && a1 <= 64 => {
                    self.raise(t, a1 as u32);
                    0
                }
                Some(_) => -EINVAL,
                None => -ESRCH,
            },
            234 => match self.by_tid(a1 as i64) {
                // tgkill
                Some(t) if a0 as i64 == self.pid && a2 > 0 && a2 <= 64 => {
                    self.raise(t, a2 as u32);
                    0
                }
                Some(_) if a2 == 0 => 0,
                Some(_) => -EINVAL,
                None => -ESRCH,
            },
            131 => self.sigaltstack(i, a0, a1),
            158 => match a0 {
                0x1002 if a1 < USER_TOP => {
                    r.fs_base = a1; // ARCH_SET_FS
                    0
                }
                0x1002 => -EPERM,
                0x1003 => {
                    if self.mem.put_u64(a1, r.fs_base) { 0 } else { -EFAULT } // ARCH_GET_FS
                }
                _ => -EINVAL,
            },
            202 => match self.futex(i, r) {
                Ok(v) => v,
                Err((w, d)) => return Next::Park(w, d),
            },
            218 => {
                self.threads[i].clear_tid = a0; // set_tid_address
                self.threads[i].tid
            }
            273 => 0, // set_robust_list: robust futexes are not cleaned up
            228 => match self.clock(a0) {
                Some(ns) => {
                    if self.put_timespec(a1, ns) { 0 } else { -EFAULT }
                }
                None => -EINVAL,
            },
            229 => {
                // clock_getres
                if a1 != 0 && !self.put_timespec(a1, 1) { -EFAULT } else { 0 }
            }
            96 => {
                // gettimeofday
                let ns = unix_ns();
                let mut b = [0u8; 16];
                b[..8].copy_from_slice(&ns.div_euclid(1_000_000_000).to_le_bytes());
                b[8..].copy_from_slice(&(ns.rem_euclid(1_000_000_000) / 1000).to_le_bytes());
                if a0 != 0 && !self.mem.write(a0, &b) { -EFAULT } else { 0 }
            }
            201 => {
                let s = unix_ns().div_euclid(1_000_000_000);
                if a0 != 0 && !self.mem.put_u64(a0, s as u64) { -EFAULT } else { s }
            }
            318 => {
                // getrandom
                let n = (a1 as usize).min(64 * 1024);
                let mut b = alloc::vec![0u8; n];
                random_bytes(&mut b);
                if self.mem.write(a0, &b) { n as i64 } else { -EFAULT }
            }
            204 => {
                // sched_getaffinity: one CPU
                if a1 < 8 {
                    -EINVAL
                } else if self.mem.put_u64(a2, 1) {
                    8
                } else {
                    -EFAULT
                }
            }
            97 | 302 => {
                // getrlimit(res, old) / prlimit64(pid, res, new, old)
                let (res, old) = if nr == 97 { (a0, a1) } else { (a1, a3) };
                let (cur, max) = match res {
                    3 => (8 << 20, u64::MAX), // STACK
                    7 => (1024, 1024),        // NOFILE
                    _ => (u64::MAX, u64::MAX),
                };
                if old != 0 && !(self.mem.put_u64(old, cur) && self.mem.put_u64(old + 8, max)) { -EFAULT } else { 0 }
            }
            _ => {
                self.unsupported(nr, syscall_name(nr));
                -ENOSYS
            }
        };
        r.rax = v as u64;
        Next::Resume(*r)
    }

    /// One exception message.
    fn handle(&mut self, m: &ExceptionMsg, exc: Owned, argv: &[&[u8]], env: &[&[u8]], elf: &ElfInfo) {
        let mut r = m.regs;
        match m.kind {
            sys::EXC_START => {
                if let Some(k) = self.pending_clones.iter().position(|&(koid, _)| koid == m.tid) {
                    let (_, c) = self.pending_clones.swap_remove(k);
                    if let Some(i) = self.ti(m.tid) {
                        self.finish(i, exc, Next::Resume(c));
                    }
                    return;
                }
                if !self.threads.is_empty() {
                    sys::exception_resume(exc.raw(), sys::EXC_KILL, sys::EXIT_FAULT);
                    return;
                }
                self.pid = (m.pid & 0x3FFF_FFFF) as i64;
                self.next_tid = self.pid + 1;
                self.threads.push(Thread {
                    koid: m.tid,
                    tid: self.pid,
                    _handle: None,
                    clear_tid: 0,
                    mask: 0,
                    pending: 0,
                    alt: (0, 2, 0),
                    parked: None,
                });
                match initial_stack(self.mem, &mut r, argv, env, elf) {
                    Ok(()) => self.finish(0, exc, Next::Resume(r)),
                    Err(e) => {
                        println!("dcmpl: {}: cannot start: {}", text(self.name), e);
                        sys::exception_resume(exc.raw(), sys::EXC_KILL, EXIT_REFUSED);
                    }
                }
            }
            sys::EXC_SYSCALL => {
                let Some(i) = self.ti(m.tid) else {
                    sys::exception_resume(exc.raw(), sys::EXC_KILL, sys::EXIT_FAULT);
                    return;
                };
                match self.syscall(i, &mut r) {
                    Next::Park(wait, deadline) => {
                        self.threads[i].parked = Some(Parked { exc, regs: r, wait, deadline });
                        // A signal already pending interrupts the wait at once.
                        if self.threads[i].pending & !self.threads[i].mask != 0 {
                            self.wake(i, -EINTR);
                        }
                    }
                    next => self.finish(i, exc, next),
                }
            }
            _ => {
                let (sig, code) = signal_of(m.vector);
                let code = if sig == 11 && m.vector == 14 && m.error & 1 != 0 { 2 } else { code }; // SEGV_ACCERR
                let addr = if m.vector == 14 { m.cr2 } else { r.rip };
                let i = self.ti(m.tid);
                let handled = i.is_some_and(|i| {
                    let bit = 1u64 << (sig - 1);
                    let a = self.actions[(sig - 1) as usize];
                    a.handler > SIG_IGN && self.threads[i].mask & bit == 0
                });
                if let (true, Some(i)) = (handled, i)
                    && self.deliver(i, SigInfo { signo: sig, code, addr, pid: 0 }, &mut r).is_ok()
                {
                    self.finish(i, exc, Next::Resume(r));
                    return;
                }
                println!(
                    "dcmpl: {}: {} (vector {}, error {:#x}, address {:#x}) at rip {:#x}; no handler for it, killed",
                    text(self.name),
                    signal_name(sig),
                    m.vector,
                    m.error,
                    m.cr2,
                    r.rip
                );
                sys::exception_resume(exc.raw(), sys::EXC_KILL, sys::EXIT_FAULT);
            }
        }
    }

    /// Time out every wait whose deadline has passed; the next deadline.
    fn expire(&mut self) -> u64 {
        let now = sys::clock_ns();
        let mut next = sys::WAIT_FOREVER;
        for i in 0..self.threads.len() {
            let Some(p) = &self.threads[i].parked else { continue };
            if p.deadline <= now {
                let res = match p.wait {
                    Wait::Futex { .. } => -ETIMEDOUT,
                    Wait::Sleep { .. } => 0,
                };
                self.wake(i, res);
            } else {
                next = next.min(p.deadline);
            }
        }
        next
    }
}

pub fn run(name: &[u8], cmdline: &[u8]) -> i32 {
    if name.is_empty() {
        println!("dcmpl: linux: which program?");
        return EXIT_USAGE;
    }
    let Some(image) = find_image(name) else {
        println!("dcmpl: linux: no program '{}'", text(name));
        return EXIT_USAGE;
    };
    let Some(elf) = elf_info(image) else {
        println!("dcmpl: linux: {} refused: not an ELF64 executable", text(name));
        return EXIT_REFUSED;
    };
    let vmex = libd::startup_handle(sys::TAG_VMEX);
    if tool_image() && sys::vmo_allow_unsigned(image, vmex) < 0 {
        println!("dcmpl: linux: {} refused: cannot allow it as unsigned code (no VMEX resource)", text(name));
        return EXIT_REFUSED;
    }
    let mut argv: [&[u8]; MAX_ARGS] = [&[]; MAX_ARGS];
    let mut argc = 0;
    while argc < MAX_ARGS && !word(cmdline, argc).is_empty() {
        argv[argc] = word(cmdline, argc);
        argc += 1;
    }
    let mut pwd = Vec::from(&b"PWD="[..]);
    pwd.extend_from_slice(crate::path::cwd().as_bytes());
    let env: [&[u8]; 2] = [&pwd, b"LANG=C.UTF-8"];

    let mut ch: Handle = 0;
    let s = sys::Spawn {
        parent: libd::startup_handle(sys::TAG_PROC_SELF),
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
    let proc = match sys::spawn_raw(&s) {
        Ok(p) => Owned::from_raw(p),
        Err(e) => {
            println!("dcmpl: linux: {} refused by spawn: {}", text(name), sys::status(e));
            return EXIT_REFUSED;
        }
    };
    let ch = Owned::from_raw(ch);
    let vmar = match sys::process_vmar(proc.raw()) {
        Ok(v) => Owned::from_raw(v),
        Err(e) => {
            println!("dcmpl: linux: {}: no access to its memory: {}", text(name), sys::status(e));
            sys::process_kill(proc.raw());
            return EXIT_REFUSED;
        }
    };
    let mut srv = Server {
        mem: Mem { proc: proc.raw() },
        name,
        pid: 0,
        threads: Vec::new(),
        next_tid: 0,
        pending_clones: Vec::new(),
        actions: [SigAction::default(); 64],
        enosys_logged: 0,
        vmar: vmar.raw(),
        vmex,
        fds: fs::Fds::new(),
        mm: mem::Mm::default(),
    };
    let mut m = ExceptionMsg::default();
    let mut deadline = sys::WAIT_FOREVER;
    loop {
        // SAFETY: ExceptionMsg is repr(C) plain data; any bytes are a valid value.
        let bytes = unsafe {
            core::slice::from_raw_parts_mut((&raw mut m).cast::<u8>(), core::mem::size_of::<ExceptionMsg>())
        };
        let timeout = if deadline == sys::WAIT_FOREVER { deadline } else { deadline.saturating_sub(sys::clock_ns()) };
        let mut hs = [0 as Handle; 1];
        match sys::channel_read_h(ch.raw(), bytes, &mut hs, timeout) {
            Ok((n, nh)) => {
                let exc = Owned::from_raw(if nh > 0 { hs[0] } else { 0 });
                if n != core::mem::size_of::<ExceptionMsg>() || nh == 0 {
                    println!("dcmpl: linux: bad exception message");
                    continue; // dropping `exc` leaves it unresolved: the kernel kills the program
                }
                srv.handle(&m, exc, &argv[..argc.max(1)], &env, &elf);
            }
            Err(sys::ERR_TIMED_OUT) => {}
            Err(_) => break, // PEER_CLOSED: the program has ended
        }
        deadline = srv.expire();
    }
    drop(srv);
    let _ = sys::object_wait(proc.raw(), sys::TERMINATED, sys::WAIT_FOREVER);
    sys::process_exit_code(proc.raw()) as i32
}
