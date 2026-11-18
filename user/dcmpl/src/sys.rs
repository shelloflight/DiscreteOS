//! D-OS user ABI v2 (docs/abi.md): raw syscalls and the structures D-CMPL uses. Mirrors
//! user/include/dos.h; numbers and layouts never change meaning.

use core::arch::asm;

pub type Handle = u32;

pub const OK: i64 = 0;

pub const RIGHT_READ: u32 = 1 << 2;
pub const RIGHT_WRITE: u32 = 1 << 3;
pub const RIGHT_EXECUTE: u32 = 1 << 4;
pub const RIGHTS_SAME: u32 = 1 << 31;

pub const TERMINATED: u32 = 1 << 1;
pub const WAIT_FOREVER: u64 = u64::MAX;
pub const ANY: u64 = u64::MAX;

pub const EXIT_FAULT: i32 = 0x8000_0002_u32 as i32;

pub const TAG_PROC_SELF: u32 = 1;
pub const TAG_VMAR_ROOT: u32 = 3;
pub const TAG_LOG: u32 = 4;
pub const TAG_PROGRAM: u32 = 5;
pub const TAG_VMEX: u32 = 6;
pub const STARTUP_MAGIC: u32 = 0x5353_4F44;
pub const ABI_VERSION: u32 = 2;

pub const USER_BASE: u64 = 0x20_0000;
pub const USER_TOP: u64 = 0x0000_7FFF_FFFF_0000;
pub const PAGE: u64 = 4096;

pub const SPAWN_EXCEPTION_CHANNEL: u32 = 1 << 0;
pub const SPAWN_FORWARD: u32 = 1 << 1;
pub const SPAWN_START_EXCEPTION: u32 = 1 << 2;

pub const EXC_FAULT: u32 = 1;
pub const EXC_SYSCALL: u32 = 2;
pub const EXC_START: u32 = 3;
pub const EXC_RESUME: u32 = 0;
pub const EXC_KILL: u32 = 1;

pub const BASE_GS: u32 = 1;

mod nr {
    pub const LOG_WRITE: u64 = 1;
    pub const HANDLE_CLOSE: u64 = 2;
    pub const OBJECT_NAME: u64 = 7;
    pub const OBJECT_WAIT: u64 = 8;
    pub const VMO_CREATE: u64 = 14;
    pub const VMO_READ: u64 = 15;
    pub const VMO_WRITE: u64 = 16;
    pub const VMO_SIZE: u64 = 17;
    pub const VMAR_MAP: u64 = 18;
    pub const VMAR_UNMAP: u64 = 19;
    pub const VMAR_ALLOCATE: u64 = 20;
    pub const PROCESS_EXIT: u64 = 23;
    pub const PROCESS_EXIT_CODE: u64 = 25;
    pub const SPAWN: u64 = 29;
    pub const CLOCK_NS: u64 = 30;
    pub const CHANNEL_READ: u64 = 34;
    pub const EXCEPTION_SET_REGS: u64 = 42;
    pub const EXCEPTION_RESUME: u64 = 43;
    pub const THREAD_SET_BASE: u64 = 46;
    pub const VMO_MAKE_EXECUTABLE: u64 = 48;
    pub const PROCESS_READ_MEMORY: u64 = 49;
    pub const PROCESS_WRITE_MEMORY: u64 = 50;
}

#[inline(always)]
fn sc(n: u64, a: u64, b: u64, c: u64, d: u64, e: u64, f: u64) -> i64 {
    let r: i64;
    // SAFETY: the syscall instruction only clobbers RCX and R11 (ABI); every pointer argument is
    // checked by the kernel, so a bad one is an error code, never memory corruption here.
    unsafe {
        asm!("syscall", inlateout("rax") n as i64 => r, in("rdi") a, in("rsi") b, in("rdx") c,
             in("r10") d, in("r8") e, in("r9") f, lateout("rcx") _, lateout("r11") _, options(nostack));
    }
    r
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Regs {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub rsp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub rflags: u64,
    pub fs_base: u64,
    pub gs_base: u64,
}

/// Exception channel message (`struct dos_exception_msg`).
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct ExceptionMsg {
    pub txid: u32,
    pub kind: u32,
    pub vector: u32,
    pub reserved: u32,
    pub error: u64,
    pub cr2: u64,
    pub pid: u64,
    pub tid: u64,
    pub regs: Regs,
}
const _: () = assert!(core::mem::size_of::<ExceptionMsg>() == 208);

#[repr(C)]
pub struct Spawn {
    pub parent: Handle,
    pub image: Handle,
    pub name: u64,
    pub name_len: u64,
    pub args: u64,
    pub args_len: u64,
    pub handles: u64,
    pub nhandles: u32,
    pub flags: u32,
    pub limits: u64,
    pub exception_channel: u64,
}

#[repr(C)]
struct Msg {
    data: u64,
    len: u32,
    nhandles: u32,
    handles: u64,
}

pub fn log_write(log: Handle, s: &[u8]) -> i64 {
    sc(nr::LOG_WRITE, log.into(), s.as_ptr() as u64, s.len() as u64, 0, 0, 0)
}
/// log_write of a range known only by address (a foreign program's buffer): the kernel checks it.
pub fn log_write_raw(log: Handle, ptr: u64, len: u64) -> i64 {
    sc(nr::LOG_WRITE, log.into(), ptr, len, 0, 0, 0)
}
pub fn handle_close(h: Handle) -> i64 {
    sc(nr::HANDLE_CLOSE, h.into(), 0, 0, 0, 0, 0)
}
pub fn object_name(h: Handle, buf: &mut [u8]) -> i64 {
    sc(nr::OBJECT_NAME, h.into(), buf.as_mut_ptr() as u64, buf.len() as u64, 0, 0, 0)
}
pub fn object_wait(h: Handle, mask: u32, timeout: u64) -> i64 {
    sc(nr::OBJECT_WAIT, h.into(), mask.into(), timeout, 0, 0, 0)
}
pub fn vmo_create(size: u64) -> i64 {
    sc(nr::VMO_CREATE, size, 0, 0, 0, 0, 0)
}
pub fn vmo_read(h: Handle, off: u64, buf: &mut [u8]) -> i64 {
    sc(nr::VMO_READ, h.into(), off, buf.as_mut_ptr() as u64, buf.len() as u64, 0, 0)
}
pub fn vmo_write(h: Handle, off: u64, buf: &[u8]) -> i64 {
    sc(nr::VMO_WRITE, h.into(), off, buf.as_ptr() as u64, buf.len() as u64, 0, 0)
}
pub fn vmo_size(h: Handle) -> i64 {
    sc(nr::VMO_SIZE, h.into(), 0, 0, 0, 0, 0)
}
pub fn vmar_map(vmar: Handle, offset: u64, vmo: Handle, vmo_off: u64, len: u64, perms: u32) -> i64 {
    sc(nr::VMAR_MAP, vmar.into(), offset, vmo.into(), vmo_off, len, perms.into())
}
pub fn vmar_unmap(vmar: Handle, addr: u64, len: u64) -> i64 {
    sc(nr::VMAR_UNMAP, vmar.into(), addr, len, 0, 0, 0)
}
/// A sub-region at `offset` (relative to `vmar`, or ANY): (handle, base address).
pub fn vmar_allocate(vmar: Handle, offset: u64, len: u64) -> Result<(Handle, u64), i64> {
    let mut base = 0u64;
    let r = sc(nr::VMAR_ALLOCATE, vmar.into(), offset, len, RIGHTS_SAME.into(), (&raw mut base) as u64, 0);
    if r < 0 { Err(r) } else { Ok((r as Handle, base)) }
}
pub fn process_exit(code: i32) -> ! {
    sc(nr::PROCESS_EXIT, code as i64 as u64, 0, 0, 0, 0, 0);
    // SAFETY: process_exit does not return.
    unsafe { core::hint::unreachable_unchecked() }
}
pub fn process_exit_code(h: Handle) -> i64 {
    sc(nr::PROCESS_EXIT_CODE, h.into(), 0, 0, 0, 0, 0)
}
pub fn spawn(s: &Spawn) -> i64 {
    sc(nr::SPAWN, s as *const Spawn as u64, 0, 0, 0, 0, 0)
}
pub fn clock_ns() -> u64 {
    sc(nr::CLOCK_NS, 0, 0, 0, 0, 0, 0) as u64
}
/// Read one message carrying at most one handle: (bytes, handle or 0).
pub fn channel_read(ch: Handle, buf: &mut [u8], timeout: u64) -> Result<(u32, Handle), i64> {
    let mut h: Handle = 0;
    let mut m = Msg { data: buf.as_mut_ptr() as u64, len: buf.len() as u32, nhandles: 1, handles: (&raw mut h) as u64 };
    let r = sc(nr::CHANNEL_READ, ch.into(), (&raw mut m) as u64, 0, timeout, 0, 0);
    if r < 0 { Err(r) } else { Ok((m.len, if m.nhandles > 0 { h } else { 0 })) }
}
pub fn exception_set_regs(e: Handle, r: &Regs) -> i64 {
    sc(nr::EXCEPTION_SET_REGS, e.into(), r as *const Regs as u64, 0, 0, 0, 0)
}
pub fn exception_resume(e: Handle, action: u32, code: i32) -> i64 {
    sc(nr::EXCEPTION_RESUME, e.into(), action.into(), code as i64 as u64, 0, 0, 0)
}
pub fn thread_set_base(which: u32, v: u64) -> i64 {
    sc(nr::THREAD_SET_BASE, which.into(), v, 0, 0, 0, 0)
}
pub fn vmo_make_executable(vmo: Handle, vmex: Handle) -> i64 {
    sc(nr::VMO_MAKE_EXECUTABLE, vmo.into(), vmex.into(), 0, 0, 0, 0)
}
pub fn process_read_memory(p: Handle, addr: u64, buf: &mut [u8]) -> i64 {
    sc(nr::PROCESS_READ_MEMORY, p.into(), addr, buf.as_mut_ptr() as u64, buf.len() as u64, 0, 0)
}
pub fn process_write_memory(p: Handle, addr: u64, buf: &[u8]) -> i64 {
    sc(nr::PROCESS_WRITE_MEMORY, p.into(), addr, buf.as_ptr() as u64, buf.len() as u64, 0, 0)
}

pub fn rdtsc() -> u64 {
    let (lo, hi): (u32, u32);
    // SAFETY: rdtsc is allowed in ring 3 (docs/abi.md); it only writes EAX and EDX.
    unsafe { asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack)) };
    (u64::from(hi) << 32) | u64::from(lo)
}

/// Status name (docs/abi.md), for messages.
pub fn status(r: i64) -> &'static str {
    const NAMES: [&str; 16] = [
        "OK", "NO_MEMORY", "INVALID_ARGS", "BAD_HANDLE", "WRONG_TYPE", "ACCESS_DENIED", "NO_RESOURCES",
        "OUT_OF_RANGE", "TIMED_OUT", "BAD_STATE", "NO_SPACE", "BAD_ADDRESS", "NOT_SUPPORTED", "SHOULD_WAIT",
        "BUFFER_TOO_SMALL", "PEER_CLOSED",
    ];
    if r > 0 {
        return "OK (value)";
    }
    r.checked_neg().and_then(|v| usize::try_from(v).ok()).and_then(|i| NAMES.get(i).copied()).unwrap_or("?")
}

/// A VMO mapped read-write in this process (unmapped on drop; the mapping keeps the VMO alive).
pub struct Mapping {
    vmar: Handle,
    pub addr: u64,
    pub len: u64,
}

impl Mapping {
    pub fn new(vmar: Handle, len: u64) -> Result<Mapping, i64> {
        let len = len.max(1).div_ceil(PAGE) * PAGE;
        let v = vmo_create(len);
        if v < 0 {
            return Err(v);
        }
        let a = vmar_map(vmar, ANY, v as Handle, 0, len, RIGHT_READ | RIGHT_WRITE);
        handle_close(v as Handle);
        if a < 0 {
            return Err(a);
        }
        Ok(Mapping { vmar, addr: a as u64, len })
    }
    pub fn bytes(&mut self) -> &mut [u8] {
        // SAFETY: a private RW mapping of `len` bytes that lives as long as `self`.
        unsafe { core::slice::from_raw_parts_mut(self.addr as *mut u8, self.len as usize) }
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        vmar_unmap(self.vmar, self.addr, self.len);
    }
}
