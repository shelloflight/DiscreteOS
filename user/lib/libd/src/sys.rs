//! D-OS user ABI v7 (docs/abi.md): every raw syscall and structure. Mirrors user/include/dos.h;
//! numbers and layouts never change meaning. Results: `Ok(value)` or `Err(status)` (< 0).
//! Programs built on libd need a kernel of at least `ABI_VERSION` (checked by `init`).

use core::arch::asm;

pub type Handle = u32;
pub type R = Result<u64, i64>;

pub const ERR_NO_MEMORY: i64 = -1;
pub const ERR_INVALID_ARGS: i64 = -2;
pub const ERR_NO_RESOURCES: i64 = -6;
pub const ERR_BAD_HANDLE: i64 = -3;
pub const ERR_WRONG_TYPE: i64 = -4;
pub const ERR_ACCESS_DENIED: i64 = -5;
pub const ERR_OUT_OF_RANGE: i64 = -7;
pub const ERR_TIMED_OUT: i64 = -8;
pub const ERR_BAD_STATE: i64 = -9;
pub const ERR_NO_SPACE: i64 = -10;
pub const ERR_BAD_ADDRESS: i64 = -11;
pub const ERR_NOT_SUPPORTED: i64 = -12;
pub const ERR_SHOULD_WAIT: i64 = -13;
pub const ERR_BUFFER_TOO_SMALL: i64 = -14;
pub const ERR_PEER_CLOSED: i64 = -15;
pub const ERR_BAD_SIGNATURE: i64 = -16;
pub const ERR_NOT_SIGNED: i64 = -17;

pub const RIGHT_DUPLICATE: u32 = 1 << 0;
pub const RIGHT_TRANSFER: u32 = 1 << 1;
pub const RIGHT_READ: u32 = 1 << 2;
pub const RIGHT_WRITE: u32 = 1 << 3;
pub const RIGHT_EXECUTE: u32 = 1 << 4;
pub const RIGHT_MAP: u32 = 1 << 5;
pub const RIGHT_SIGNAL: u32 = 1 << 6;
pub const RIGHT_WAIT: u32 = 1 << 7;
pub const RIGHT_INSPECT: u32 = 1 << 8;
pub const RIGHT_MANAGE: u32 = 1 << 9;
pub const RIGHTS_SAME: u32 = 1 << 31;

pub const OBJ_PROCESS: u32 = 1;
pub const OBJ_THREAD: u32 = 2;
pub const OBJ_VMO: u32 = 3;
pub const OBJ_VMAR: u32 = 4;
pub const OBJ_EVENT: u32 = 5;
pub const OBJ_TIMER: u32 = 6;
pub const OBJ_LOG: u32 = 7;
pub const OBJ_CHANNEL: u32 = 8;
pub const OBJ_PORT: u32 = 9;
pub const OBJ_EXCEPTION: u32 = 10;
pub const OBJ_RESOURCE: u32 = 11;
pub const OBJ_DEVICE: u32 = 12;
pub const OBJ_INTERRUPT: u32 = 13;
pub const OBJ_PIN: u32 = 14;

pub const SIGNALED: u32 = 1 << 0;
pub const TERMINATED: u32 = 1 << 1;
pub const READABLE: u32 = 1 << 2;
pub const WRITABLE: u32 = 1 << 3;
pub const PEER_CLOSED: u32 = 1 << 4;
pub const WAIT_FOREVER: u64 = u64::MAX;
pub const ANY: u64 = u64::MAX;

pub const EXIT_KILLED: i32 = 0x8000_0001_u32 as i32;
pub const EXIT_FAULT: i32 = 0x8000_0002_u32 as i32;

pub const TAG_PROC_SELF: u32 = 1;
pub const TAG_THREAD_SELF: u32 = 2;
pub const TAG_VMAR_ROOT: u32 = 3;
pub const TAG_LOG: u32 = 4;
pub const TAG_PROGRAM: u32 = 5;
pub const TAG_VMEX: u32 = 6;
pub const TAG_DEVICE: u32 = 7;
pub const TAG_POWER: u32 = 8;
pub const TAG_MEASURE: u32 = 9;
pub const TAG_MANIFEST: u32 = 10;
/// The KLOG resource (ABI v8): read the kernel log (init; the log service).
pub const TAG_KLOG: u32 = 11;
/// The boot-time record (ABI v8): a 32-byte VMO, `BootTime` (UEFI only).
pub const TAG_BOOT_TIME: u32 = 12;
/// The power-button event (ABI v11): signaled on each press; init clears it.
pub const TAG_POWER_BUTTON: u32 = 13;
pub const TAG_USER: u32 = 0x1_0000;
pub const STARTUP_MAGIC: u32 = 0x5353_4F44;
pub const ABI_VERSION: u32 = 14;
pub const PAGE: u64 = 4096;

pub const DEV_KIND_PCI: u32 = 1;
pub const DEV_KIND_PLATFORM: u32 = 2;
pub const DEV_FLAG_IOMMU: u32 = 1 << 0;
pub const DMA_DEVICE_READ: u32 = 1 << 0;
pub const DMA_DEVICE_WRITE: u32 = 1 << 1;

pub const SPAWN_EXCEPTION_CHANNEL: u32 = 1 << 0;
pub const SPAWN_FORWARD: u32 = 1 << 1;
pub const SPAWN_START_EXCEPTION: u32 = 1 << 2;

pub const EXC_FAULT: u32 = 1;
pub const EXC_SYSCALL: u32 = 2;
pub const EXC_START: u32 = 3;
pub const EXC_RESUME: u32 = 0;
pub const EXC_KILL: u32 = 1;
/// ABI v10: end only the stopped thread.
pub const EXC_EXIT_THREAD: u32 = 2;

pub const BASE_FS: u32 = 0;
pub const BASE_GS: u32 = 1;

pub const POWER_OFF: u64 = 1;
pub const POWER_REBOOT: u64 = 2;
pub const POWER_SUSPEND: u64 = 3;

pub mod nr {
    pub const ABI_VERSION: u64 = 0;
    pub const LOG_WRITE: u64 = 1;
    pub const HANDLE_CLOSE: u64 = 2;
    pub const HANDLE_DUPLICATE: u64 = 3;
    pub const HANDLE_REPLACE: u64 = 4;
    pub const HANDLE_GRANT: u64 = 5;
    pub const OBJECT_INFO: u64 = 6;
    pub const OBJECT_NAME: u64 = 7;
    pub const OBJECT_WAIT: u64 = 8;
    pub const EVENT_CREATE: u64 = 9;
    pub const EVENT_SIGNAL: u64 = 10;
    pub const TIMER_CREATE: u64 = 11;
    pub const TIMER_SET: u64 = 12;
    pub const TIMER_CANCEL: u64 = 13;
    pub const VMO_CREATE: u64 = 14;
    pub const VMO_READ: u64 = 15;
    pub const VMO_WRITE: u64 = 16;
    pub const VMO_SIZE: u64 = 17;
    pub const VMAR_MAP: u64 = 18;
    pub const VMAR_UNMAP: u64 = 19;
    pub const VMAR_ALLOCATE: u64 = 20;
    pub const PROCESS_CREATE: u64 = 21;
    pub const PROCESS_KILL: u64 = 22;
    pub const PROCESS_EXIT: u64 = 23;
    pub const PROCESS_QUOTA: u64 = 24;
    pub const PROCESS_EXIT_CODE: u64 = 25;
    pub const THREAD_CREATE: u64 = 26;
    pub const THREAD_EXIT: u64 = 27;
    pub const THREAD_EXIT_CODE: u64 = 28;
    pub const SPAWN: u64 = 29;
    pub const CLOCK_NS: u64 = 30;
    pub const YIELD: u64 = 31;
    pub const CHANNEL_CREATE: u64 = 32;
    pub const CHANNEL_WRITE: u64 = 33;
    pub const CHANNEL_READ: u64 = 34;
    pub const CHANNEL_CALL: u64 = 35;
    pub const PORT_CREATE: u64 = 36;
    pub const PORT_ENTER: u64 = 37;
    pub const OBJECT_WAIT_ASYNC: u64 = 38;
    pub const PORT_CANCEL: u64 = 39;
    pub const PROCESS_EXCEPTION_CHANNEL: u64 = 40;
    pub const EXCEPTION_GET_REGS: u64 = 41;
    pub const EXCEPTION_SET_REGS: u64 = 42;
    pub const EXCEPTION_RESUME: u64 = 43;
    pub const THREAD_SET_EXCEPTION_HANDLER: u64 = 44;
    pub const EXCEPTION_RETURN: u64 = 45;
    pub const THREAD_SET_BASE: u64 = 46;
    pub const THREAD_GET_BASE: u64 = 47;
    pub const VMO_MAKE_EXECUTABLE: u64 = 48;
    pub const PROCESS_READ_MEMORY: u64 = 49;
    pub const PROCESS_WRITE_MEMORY: u64 = 50;
    pub const DEVICE_INFO: u64 = 51;
    pub const DEVICE_CONFIG_READ: u64 = 52;
    pub const DEVICE_CONFIG_WRITE: u64 = 53;
    pub const DEVICE_MAP_BAR: u64 = 54;
    pub const DEVICE_IO_READ: u64 = 55;
    pub const DEVICE_IO_WRITE: u64 = 56;
    pub const DEVICE_INTERRUPT: u64 = 57;
    pub const INTERRUPT_ACK: u64 = 58;
    pub const DEVICE_DMA_MAP: u64 = 59;
    pub const VMO_VERIFY: u64 = 60;
    pub const VMO_ALLOW_UNSIGNED: u64 = 61;
    pub const ATTEST: u64 = 62;
    pub const SYSTEM_POWER: u64 = 63;
    pub const MEASURE: u64 = 64;
    pub const KLOG_READ: u64 = 65;
    pub const LOG_RECORD: u64 = 66;
    pub const DISPLAY_INFO: u64 = 67;
    pub const PROCESS_HANDLES: u64 = 68;
    pub const PROCESS_VMAR: u64 = 69;
    pub const THREAD_CREATE_STOPPED: u64 = 70;
    pub const ATTEST_ACTIVATE: u64 = 71;
    pub const VMAR_DESTROY: u64 = 72;
    pub const GET_RANDOM: u64 = 73;
    /// Syscalls this ABI version defines (numbers below it).
    pub const COUNT: u64 = 74;
}

/// One raw syscall. Prefer the typed wrappers; this is for port submissions and tests.
#[inline(always)]
pub fn sc(n: u64, a: u64, b: u64, c: u64, d: u64, e: u64, f: u64) -> i64 {
    let r: i64;
    // SAFETY: the syscall instruction only clobbers RCX and R11 (ABI); every pointer argument is
    // checked by the kernel, so a bad one is an error code, never memory corruption here.
    unsafe {
        asm!("syscall", inlateout("rax") n as i64 => r, in("rdi") a, in("rsi") b, in("rdx") c,
             in("r10") d, in("r8") e, in("r9") f, lateout("rcx") _, lateout("r11") _, options(nostack));
    }
    r
}

fn res(r: i64) -> R {
    if r < 0 { Err(r) } else { Ok(r as u64) }
}

fn hres(r: i64) -> Result<Handle, i64> {
    res(r).map(|v| v as Handle)
}

pub fn log_write(log: Handle, s: &[u8]) -> i64 {
    sc(nr::LOG_WRITE, u64::from(log), s.as_ptr() as u64, s.len() as u64, 0, 0, 0)
}
pub fn handle_close(h: Handle) -> i64 {
    sc(nr::HANDLE_CLOSE, u64::from(h), 0, 0, 0, 0, 0)
}
pub fn handle_duplicate(h: Handle, rights: u32) -> Result<Handle, i64> {
    hres(sc(nr::HANDLE_DUPLICATE, u64::from(h), u64::from(rights), 0, 0, 0, 0))
}
pub fn handle_replace(h: Handle, rights: u32) -> Result<Handle, i64> {
    hres(sc(nr::HANDLE_REPLACE, u64::from(h), u64::from(rights), 0, 0, 0, 0))
}
pub fn object_name(h: Handle, buf: &mut [u8]) -> i64 {
    sc(nr::OBJECT_NAME, u64::from(h), buf.as_mut_ptr() as u64, buf.len() as u64, 0, 0, 0)
}
/// Signals seen, `Err(TIMED_OUT)` if none of `mask` came in time.
pub fn object_wait(h: Handle, mask: u32, timeout: u64) -> Result<u32, i64> {
    res(sc(nr::OBJECT_WAIT, u64::from(h), u64::from(mask), timeout, 0, 0, 0)).map(|v| v as u32)
}
pub fn vmo_create(size: u64) -> Result<Handle, i64> {
    hres(sc(nr::VMO_CREATE, size, 0, 0, 0, 0, 0))
}
pub fn vmo_read(h: Handle, off: u64, buf: &mut [u8]) -> i64 {
    sc(nr::VMO_READ, u64::from(h), off, buf.as_mut_ptr() as u64, buf.len() as u64, 0, 0)
}
pub fn vmo_write(h: Handle, off: u64, data: &[u8]) -> i64 {
    sc(nr::VMO_WRITE, u64::from(h), off, data.as_ptr() as u64, data.len() as u64, 0, 0)
}
/// ABI v4: check the `.dsig` in `dsig` for the program in `vmo` (seals it); spawn needs this (or
/// `vmo_allow_unsigned` with the VMEX resource).
pub fn vmo_verify(vmo: Handle, dsig: Handle) -> i64 {
    sc(nr::VMO_VERIFY, u64::from(vmo), u64::from(dsig), 0, 0, 0, 0)
}
pub fn vmo_allow_unsigned(vmo: Handle, vmex: Handle) -> i64 {
    sc(nr::VMO_ALLOW_UNSIGNED, u64::from(vmo), u64::from(vmex), 0, 0, 0, 0)
}
pub fn vmo_size(h: Handle) -> R {
    res(sc(nr::VMO_SIZE, u64::from(h), 0, 0, 0, 0, 0))
}
pub fn vmar_unmap(vmar: Handle, addr: u64, len: u64) -> i64 {
    sc(nr::VMAR_UNMAP, u64::from(vmar), addr, len, 0, 0, 0)
}
pub fn vmar_destroy(vmar: Handle) -> i64 {
    sc(nr::VMAR_DESTROY, u64::from(vmar), 0, 0, 0, 0, 0)
}
pub fn vmar_map(vmar: Handle, offset: u64, vmo: Handle, vmo_off: u64, len: u64, perms: u32) -> R {
    res(sc(nr::VMAR_MAP, u64::from(vmar), offset, u64::from(vmo), vmo_off, len, u64::from(perms)))
}
pub fn process_kill(h: Handle) -> i64 {
    sc(nr::PROCESS_KILL, u64::from(h), 0, 0, 0, 0, 0)
}
pub fn process_exit(code: i32) -> ! {
    sc(nr::PROCESS_EXIT, code as i64 as u64, 0, 0, 0, 0, 0);
    loop {
        core::hint::spin_loop();
    }
}
/// The exit code of an ended process (exit codes may be negative: `EXIT_FAULT`, ...); BAD_STATE
/// while it runs, which only a running process gives.
pub fn process_exit_code(h: Handle) -> i64 {
    sc(nr::PROCESS_EXIT_CODE, u64::from(h), 0, 0, 0, 0, 0)
}
pub fn yield_now() {
    sc(nr::YIELD, 0, 0, 0, 0, 0, 0);
}
pub fn clock_ns() -> u64 {
    sc(nr::CLOCK_NS, 0, 0, 0, 0, 0, 0) as u64
}

// ---- spawn ----------------------------------------------------------------------------------

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SpawnHandle {
    pub handle: Handle,
    pub rights: u32,
    pub tag: u32,
    pub reserved: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Limits {
    pub memory: u64,
    pub handles: u64,
    pub threads: u64,
}

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

/// Spawn `image` as `name` with `args`, moving `handles` into it. Returns the process handle.
pub fn spawn(parent: Handle, image: Handle, name: &[u8], args: &[u8], handles: &[SpawnHandle], limits: &Limits) -> Result<Handle, i64> {
    let s = Spawn {
        parent,
        image,
        name: name.as_ptr() as u64,
        name_len: name.len() as u64,
        args: args.as_ptr() as u64,
        args_len: args.len() as u64,
        handles: handles.as_ptr() as u64,
        nhandles: handles.len() as u32,
        flags: 0,
        limits: limits as *const Limits as u64,
        exception_channel: 0,
    };
    hres(sc(nr::SPAWN, &s as *const Spawn as u64, 0, 0, 0, 0, 0))
}

// ---- channels -------------------------------------------------------------------------------

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct MsgHandle {
    pub handle: Handle,
    pub rights: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Msg {
    pub data: u64,
    pub len: u32,
    pub nhandles: u32,
    pub handles: u64,
}

/// Both ends of a new channel.
pub fn channel_pair() -> Result<(Handle, Handle), i64> {
    let mut other: Handle = 0;
    let a = hres(sc(nr::CHANNEL_CREATE, &mut other as *mut Handle as u64, 0, 0, 0, 0, 0))?;
    Ok((a, other))
}

pub fn channel_write(ch: Handle, data: &[u8]) -> i64 {
    let m = Msg { data: data.as_ptr() as u64, len: data.len() as u32, nhandles: 0, handles: 0 };
    sc(nr::CHANNEL_WRITE, u64::from(ch), &m as *const Msg as u64, 0, 0, 0, 0)
}

/// Read one message (data only: one carrying handles is BUFFER_TOO_SMALL). Bytes read.
pub fn channel_read(ch: Handle, buf: &mut [u8], timeout: u64) -> R {
    let mut m = Msg { data: buf.as_mut_ptr() as u64, len: buf.len() as u32, nhandles: 0, handles: 0 };
    res(sc(nr::CHANNEL_READ, u64::from(ch), &mut m as *mut Msg as u64, 0, timeout, 0, 0))?;
    Ok(u64::from(m.len)) // the kernel writes the size received back into the message
}

/// A call: `req` (its first 4 bytes are the kernel's transaction id) and the reply into `buf`.
pub fn channel_call(ch: Handle, req: &[u8], buf: &mut [u8], timeout: u64) -> R {
    let w = Msg { data: req.as_ptr() as u64, len: req.len() as u32, nhandles: 0, handles: 0 };
    let mut r = Msg { data: buf.as_mut_ptr() as u64, len: buf.len() as u32, nhandles: 0, handles: 0 };
    res(sc(nr::CHANNEL_CALL, u64::from(ch), &w as *const Msg as u64, &mut r as *mut Msg as u64, timeout, 0, 0))?;
    Ok(u64::from(r.len))
}

/// Write a message carrying `handles` (moved out of this process, even on error).
pub fn channel_write_h(ch: Handle, data: &[u8], handles: &[MsgHandle]) -> i64 {
    let m = Msg { data: data.as_ptr() as u64, len: data.len() as u32, nhandles: handles.len() as u32, handles: handles.as_ptr() as u64 };
    sc(nr::CHANNEL_WRITE, u64::from(ch), &m as *const Msg as u64, 0, 0, 0, 0)
}

/// Read one message with up to `hbuf.len()` handles: (bytes, handles received).
pub fn channel_read_h(ch: Handle, buf: &mut [u8], hbuf: &mut [Handle], timeout: u64) -> Result<(usize, usize), i64> {
    let mut m = Msg { data: buf.as_mut_ptr() as u64, len: buf.len() as u32, nhandles: hbuf.len() as u32, handles: hbuf.as_mut_ptr() as u64 };
    res(sc(nr::CHANNEL_READ, u64::from(ch), &mut m as *mut Msg as u64, 0, timeout, 0, 0))?;
    Ok((m.len as usize, m.nhandles as usize))
}

/// A call whose request carries `handles` and whose reply may carry up to `hbuf.len()` handles.
pub fn channel_call_h(ch: Handle, req: &[u8], handles: &[MsgHandle], buf: &mut [u8], hbuf: &mut [Handle], timeout: u64) -> Result<(usize, usize), i64> {
    let w = Msg { data: req.as_ptr() as u64, len: req.len() as u32, nhandles: handles.len() as u32, handles: handles.as_ptr() as u64 };
    let mut r = Msg { data: buf.as_mut_ptr() as u64, len: buf.len() as u32, nhandles: hbuf.len() as u32, handles: hbuf.as_mut_ptr() as u64 };
    res(sc(nr::CHANNEL_CALL, u64::from(ch), &w as *const Msg as u64, &mut r as *mut Msg as u64, timeout, 0, 0))?;
    Ok((r.len as usize, r.nhandles as usize))
}

// ---- ports ------------------------------------------------------------------------------------

pub fn port_create(entries: u32) -> Result<(Handle, Handle), i64> {
    let mut vmo: Handle = 0;
    let p = hres(sc(nr::PORT_CREATE, u64::from(entries), &mut vmo as *mut Handle as u64, 0, 0, 0, 0))?;
    Ok((p, vmo))
}
pub fn port_enter(port: Handle, submit: u32, min_complete: u32, timeout: u64) -> R {
    res(sc(nr::PORT_ENTER, u64::from(port), u64::from(submit), u64::from(min_complete), timeout, 0, 0))
}
pub fn object_wait_async(h: Handle, mask: u32, port: Handle, key: u64) -> i64 {
    sc(nr::OBJECT_WAIT_ASYNC, u64::from(h), u64::from(mask), u64::from(port), key, 0, 0)
}

// ---- devices (ABI v3) -------------------------------------------------------------------------

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct DeviceInfo {
    pub kind: u32,
    pub flags: u32,
    pub vendor: u16,
    pub device: u16,
    pub class: u8,
    pub subclass: u8,
    pub progif: u8,
    pub revision: u8,
    pub bus: u8,
    pub dev: u8,
    pub func: u8,
    pub reserved0: u8,
    pub irqs: u16,
    pub config_size: u16,
    pub dma_faults: u64,
    pub bar_size: [u64; 6],
    pub bar_kind: [u8; 6],
    pub reserved1: [u8; 2],
    pub name: [u8; 16],
}

impl DeviceInfo {
    pub fn name(&self) -> &str {
        let n = self.name.iter().position(|&c| c == 0).unwrap_or(16);
        core::str::from_utf8(&self.name[..n]).unwrap_or("?")
    }
}

pub fn device_info(dev: Handle) -> Result<DeviceInfo, i64> {
    let mut i = DeviceInfo::default();
    res(sc(nr::DEVICE_INFO, u64::from(dev), &mut i as *mut DeviceInfo as u64, 0, 0, 0, 0))?;
    Ok(i)
}
/// The display device's layout (ABI v9, `struct dos_display_info`).
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct DisplayInfo {
    pub kind: u32,
    pub width: u32,
    pub height: u32,
    pub pitch: u32,
    pub size: u64,
    pub red_shift: u8,
    pub green_shift: u8,
    pub blue_shift: u8,
    pub reserved: [u8; 5],
}
const _: () = assert!(core::mem::size_of::<DisplayInfo>() == 32);
pub const DISPLAY_RGB32: u32 = 1;
pub const DISPLAY_VGA_TEXT: u32 = 2;

/// ABI v9: the layout of the display device (`WRONG_TYPE` for other devices).
pub fn display_info(dev: Handle) -> Result<DisplayInfo, i64> {
    let mut i = DisplayInfo::default();
    res(sc(nr::DISPLAY_INFO, u64::from(dev), &mut i as *mut DisplayInfo as u64, 0, 0, 0, 0))?;
    Ok(i)
}

/// One handle a process holds (ABI v9, `struct dos_handle_entry`); never the handle's value.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct HandleEntry {
    pub ty: u32,
    pub rights: u32,
    pub koid: u64,
    pub name: [u8; 32],
}
const _: () = assert!(core::mem::size_of::<HandleEntry>() == 48);

impl HandleEntry {
    pub fn name(&self) -> &str {
        let n = self.name.iter().position(|&c| c == 0).unwrap_or(32);
        core::str::from_utf8(&self.name[..n]).unwrap_or("?")
    }
}

/// ABI v9, INSPECT on `process`: its handles into `buf` (at most 256); returns how many it holds.
pub fn process_handles(process: Handle, buf: &mut [HandleEntry]) -> R {
    res(sc(nr::PROCESS_HANDLES, u64::from(process), buf.as_mut_ptr() as u64, buf.len() as u64, 0, 0, 0))
}

pub fn config_read(dev: Handle, off: u64, size: u64) -> R {
    res(sc(nr::DEVICE_CONFIG_READ, u64::from(dev), off, size, 0, 0, 0))
}
pub fn config_write(dev: Handle, off: u64, size: u64, val: u64) -> R {
    res(sc(nr::DEVICE_CONFIG_WRITE, u64::from(dev), off, size, val, 0, 0))
}
pub fn device_map_bar(dev: Handle, bar: u64) -> Result<Handle, i64> {
    hres(sc(nr::DEVICE_MAP_BAR, u64::from(dev), bar, 0, 0, 0, 0))
}
pub fn io_read(dev: Handle, bar: u64, off: u64, size: u64) -> R {
    res(sc(nr::DEVICE_IO_READ, u64::from(dev), bar, off, size, 0, 0))
}
pub fn io_write(dev: Handle, bar: u64, off: u64, size: u64, val: u64) -> R {
    res(sc(nr::DEVICE_IO_WRITE, u64::from(dev), bar, off, size, val, 0))
}
pub fn device_interrupt(dev: Handle, index: u64) -> Result<Handle, i64> {
    hres(sc(nr::DEVICE_INTERRUPT, u64::from(dev), index, 0, 0, 0, 0))
}
/// Clear SIGNALED; how often the interrupt fired so far.
pub fn interrupt_ack(irq: Handle) -> R {
    res(sc(nr::INTERRUPT_ACK, u64::from(irq), 0, 0, 0, 0, 0))
}
/// Pin `len` bytes of `vmo` from `off` for the device; device address of each page into `addrs`.
pub fn dma_map(dev: Handle, vmo: Handle, off: u64, len: u64, flags: u32, addrs: &mut [u64]) -> Result<Handle, i64> {
    if (addrs.len() as u64) < len / PAGE {
        return Err(ERR_INVALID_ARGS);
    }
    hres(sc(nr::DEVICE_DMA_MAP, u64::from(dev), u64::from(vmo), off, len, u64::from(flags), addrs.as_mut_ptr() as u64))
}

/// The name of a status code (`OK`, `NO_MEMORY`, ...), or "?" for one this ABI does not define.
pub fn status(r: i64) -> &'static str {
    const N: [&str; 18] = [
        "OK", "NO_MEMORY", "INVALID_ARGS", "BAD_HANDLE", "WRONG_TYPE", "ACCESS_DENIED", "NO_RESOURCES", "OUT_OF_RANGE",
        "TIMED_OUT", "BAD_STATE", "NO_SPACE", "BAD_ADDRESS", "NOT_SUPPORTED", "SHOULD_WAIT", "BUFFER_TOO_SMALL", "PEER_CLOSED",
        "BAD_SIGNATURE", "NOT_SIGNED",
    ];
    if r <= 0 && r > -(N.len() as i64) { N[(-r) as usize] } else { "?" }
}

// ---- the rest of the ABI (v1-v6) ----------------------------------------------------------------

#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct Info {
    pub obj_type: u32,
    pub rights: u32,
    pub koid: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Quota {
    pub limits: Limits,
    pub used: Limits,
}

#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
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

/// In-process exception handler argument (`struct dos_exception_record`).
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct ExceptionRecord {
    pub kind: u32,
    pub vector: u32,
    pub error: u64,
    pub cr2: u64,
    pub regs: Regs,
    pub reserved: u64,
}

/// Exception channel message (`struct dos_exception_msg`); carries the exception handle.
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

/// Port ring header (`struct dos_port_header`), at offset 0 of the port VMO.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct PortHeader {
    pub sq_head: u32,
    pub sq_tail: u32,
    pub sq_mask: u32,
    pub cq_head: u32,
    pub cq_tail: u32,
    pub cq_mask: u32,
    pub overflow: u32,
    pub flags: u32,
    pub sq_off: u64,
    pub cq_off: u64,
}

/// Port submission (`struct dos_sqe`): `op` is a syscall number.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Sqe {
    pub op: u32,
    pub flags: u32,
    pub user_data: u64,
    pub args: [u64; 6],
}

/// Port completion (`struct dos_cqe`).
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Cqe {
    pub user_data: u64,
    pub result: i64,
}

const _: () = {
    assert!(core::mem::size_of::<Info>() == 16);
    assert!(core::mem::size_of::<Quota>() == 48);
    assert!(core::mem::size_of::<Regs>() == 160);
    assert!(core::mem::size_of::<ExceptionRecord>() == 192);
    assert!(core::mem::size_of::<ExceptionMsg>() == 208);
    assert!(core::mem::size_of::<PortHeader>() == 48);
    assert!(core::mem::size_of::<Sqe>() == 64);
    assert!(core::mem::size_of::<Cqe>() == 16);
    assert!(core::mem::size_of::<Spawn>() == 72);
    assert!(core::mem::size_of::<DeviceInfo>() == 104);
};

pub fn abi_version() -> i64 {
    sc(nr::ABI_VERSION, 0, 0, 0, 0, 0, 0)
}
/// Move `h` into `proc` (narrowed to `rights`): the handle value there. `h` is gone, even on error.
pub fn handle_grant(h: Handle, rights: u32, proc: Handle) -> Result<Handle, i64> {
    hres(sc(nr::HANDLE_GRANT, u64::from(h), u64::from(rights), u64::from(proc), 0, 0, 0))
}
pub fn object_info(h: Handle) -> Result<Info, i64> {
    let mut i = Info::default();
    res(sc(nr::OBJECT_INFO, u64::from(h), &mut i as *mut Info as u64, 0, 0, 0, 0))?;
    Ok(i)
}
pub fn event_create() -> Result<Handle, i64> {
    hres(sc(nr::EVENT_CREATE, 0, 0, 0, 0, 0, 0))
}
/// Clear, then set, signals on an event (only `SIGNALED`).
pub fn event_signal(h: Handle, clear: u32, set: u32) -> i64 {
    sc(nr::EVENT_SIGNAL, u64::from(h), u64::from(clear), u64::from(set), 0, 0, 0)
}
pub fn timer_create() -> Result<Handle, i64> {
    hres(sc(nr::TIMER_CREATE, 0, 0, 0, 0, 0, 0))
}
pub fn timer_set(h: Handle, delay_ns: u64) -> i64 {
    sc(nr::TIMER_SET, u64::from(h), delay_ns, 0, 0, 0, 0)
}
pub fn timer_cancel(h: Handle) -> i64 {
    sc(nr::TIMER_CANCEL, u64::from(h), 0, 0, 0, 0, 0)
}
/// Reserve `len` bytes of `vmar` (at `offset` or `ANY`): (region handle, base address).
pub fn vmar_allocate(vmar: Handle, offset: u64, len: u64, rights: u32) -> Result<(Handle, u64), i64> {
    let mut base = 0u64;
    let h = hres(sc(nr::VMAR_ALLOCATE, u64::from(vmar), offset, len, u64::from(rights), &mut base as *mut u64 as u64, 0))?;
    Ok((h, base))
}
/// An empty process under `parent`: (process, its root VMAR).
pub fn process_create(parent: Handle, name: &[u8], limits: Option<&Limits>) -> Result<(Handle, Handle), i64> {
    let mut vmar: Handle = 0;
    let l = limits.map_or(0, |l| l as *const Limits as u64);
    let p = hres(sc(nr::PROCESS_CREATE, u64::from(parent), name.as_ptr() as u64, name.len() as u64, l, &mut vmar as *mut Handle as u64, 0))?;
    Ok((p, vmar))
}
pub fn process_quota(h: Handle) -> Result<Quota, i64> {
    let mut q = Quota::default();
    res(sc(nr::PROCESS_QUOTA, u64::from(h), &mut q as *mut Quota as u64, 0, 0, 0, 0))?;
    Ok(q)
}
/// A thread in `proc` starting at `entry` with RSP = `stack_top`, RDI = `arg`.
pub fn thread_create(proc: Handle, entry: u64, stack_top: u64, arg: u64) -> Result<Handle, i64> {
    hres(sc(nr::THREAD_CREATE, u64::from(proc), entry, stack_top, arg, 0, 0))
}
pub fn thread_exit(code: i32) -> ! {
    sc(nr::THREAD_EXIT, code as i64 as u64, 0, 0, 0, 0, 0);
    loop {
        core::hint::spin_loop();
    }
}
pub fn thread_exit_code(h: Handle) -> i64 {
    sc(nr::THREAD_EXIT_CODE, u64::from(h), 0, 0, 0, 0, 0)
}
/// `spawn` with every field of `struct dos_spawn` (flags, exception channel out-pointer).
pub fn spawn_raw(s: &Spawn) -> Result<Handle, i64> {
    hres(sc(nr::SPAWN, s as *const Spawn as u64, 0, 0, 0, 0, 0))
}
pub fn port_cancel(port: Handle, h: Handle, key: u64) -> i64 {
    sc(nr::PORT_CANCEL, u64::from(port), u64::from(h), key, 0, 0, 0)
}
/// ABI v10: the root VMAR of `proc` (MANAGE).
pub fn process_vmar(proc: Handle) -> Result<Handle, i64> {
    hres(sc(nr::PROCESS_VMAR, u64::from(proc), 0, 0, 0, 0, 0))
}
/// ABI v10: a thread in `proc` that stops with a START exception before its first instruction.
pub fn thread_create_stopped(proc: Handle, entry: u64, stack_top: u64, arg: u64) -> Result<Handle, i64> {
    hres(sc(nr::THREAD_CREATE_STOPPED, u64::from(proc), entry, stack_top, arg, 0, 0))
}
pub fn process_exception_channel(proc: Handle) -> Result<Handle, i64> {
    hres(sc(nr::PROCESS_EXCEPTION_CHANNEL, u64::from(proc), 0, 0, 0, 0, 0))
}
pub fn exception_get_regs(e: Handle) -> Result<Regs, i64> {
    let mut r = Regs::default();
    res(sc(nr::EXCEPTION_GET_REGS, u64::from(e), &mut r as *mut Regs as u64, 0, 0, 0, 0))?;
    Ok(r)
}
pub fn exception_set_regs(e: Handle, r: &Regs) -> i64 {
    sc(nr::EXCEPTION_SET_REGS, u64::from(e), r as *const Regs as u64, 0, 0, 0, 0)
}
/// `EXC_RESUME`, or `EXC_KILL` (the process) / `EXC_EXIT_THREAD` (this thread) with exit `code`.
pub fn exception_resume(e: Handle, action: u32, code: i32) -> i64 {
    sc(nr::EXCEPTION_RESUME, u64::from(e), u64::from(action), code as i64 as u64, 0, 0, 0)
}
/// This thread's in-process exception handler (`entry(record)` on `stack_top`); (0, 0) removes it.
pub fn thread_set_exception_handler(entry: u64, stack_top: u64) -> i64 {
    sc(nr::THREAD_SET_EXCEPTION_HANDLER, entry, stack_top, 0, 0, 0, 0)
}
/// Resume from an in-process handler with the (validated) registers in `r`.
pub fn exception_return(r: &ExceptionRecord) -> ! {
    sc(nr::EXCEPTION_RETURN, r as *const ExceptionRecord as u64, 0, 0, 0, 0, 0);
    // Only reached if the kernel refused the record: end the process rather than run on.
    process_exit(EXIT_FAULT)
}
pub fn thread_set_base(which: u32, v: u64) -> i64 {
    sc(nr::THREAD_SET_BASE, u64::from(which), v, 0, 0, 0, 0)
}
pub fn thread_get_base(which: u32) -> R {
    res(sc(nr::THREAD_GET_BASE, u64::from(which), 0, 0, 0, 0, 0))
}
/// A sealed, executable (never writable) handle to `vmo`, with the VMEX resource.
pub fn vmo_make_executable(vmo: Handle, vmex: Handle) -> Result<Handle, i64> {
    hres(sc(nr::VMO_MAKE_EXECUTABLE, u64::from(vmo), u64::from(vmex), 0, 0, 0, 0))
}
pub fn process_read_memory(proc: Handle, addr: u64, buf: &mut [u8]) -> i64 {
    sc(nr::PROCESS_READ_MEMORY, u64::from(proc), addr, buf.as_mut_ptr() as u64, buf.len() as u64, 0, 0)
}
pub fn process_write_memory(proc: Handle, addr: u64, data: &[u8]) -> i64 {
    sc(nr::PROCESS_WRITE_MEMORY, u64::from(proc), addr, data.as_ptr() as u64, data.len() as u64, 0, 0)
}
/// A signed attestation report for `nonce` into `buf` (docs/attestation.md): its length.
pub fn attest(nonce: &[u8; 32], buf: &mut [u8]) -> R {
    res(sc(nr::ATTEST, nonce.as_ptr() as u64, buf.as_mut_ptr() as u64, buf.len() as u64, 0, 0, 0))
}
/// A TPM credential challenge's size (blob, then secret).
pub const ATTEST_CHALLENGE: usize = 328;
/// ABI v12: answer a verifier's TPM credential challenge (docs/attestation.md).
pub fn attest_activate(challenge: &[u8; ATTEST_CHALLENGE], out: &mut [u8; 32]) -> R {
    res(sc(nr::ATTEST_ACTIVATE, challenge.as_ptr() as u64, out.as_mut_ptr() as u64, 0, 0, 0, 0))
}
/// ABI v7, with the MEASURE resource: extend PCR 10 with `digest`, logged as `svc <text>`
/// (printable ASCII, at most `MEASURE_TEXT` bytes).
pub fn measure(res: Handle, digest: &[u8; 32], text: &[u8]) -> i64 {
    sc(nr::MEASURE, u64::from(res), digest.as_ptr() as u64, text.as_ptr() as u64, text.len() as u64, 0, 0)
}
pub const MEASURE_TEXT: usize = 52;

/// Log levels (ABI v8): `log_record`; `log_write` is `LOG_INFO`.
pub const LOG_ERROR: u32 = 0;
pub const LOG_WARN: u32 = 1;
pub const LOG_INFO: u32 = 2;
pub const LOG_DEBUG: u32 = 3;

/// ABI v8: `log_write` with a level.
pub fn log_record(log: Handle, level: u32, s: &[u8]) -> i64 {
    sc(nr::LOG_RECORD, u64::from(log), u64::from(level), s.as_ptr() as u64, s.len() as u64, 0, 0)
}

pub const KLOG_TEXT: usize = 120;
pub const KLOG_SOURCE: usize = 24;
pub const KLOG_ORIGIN_KERNEL: u8 = 0;
pub const KLOG_ORIGIN_PROGRAM: u8 = 1;
/// `KlogEntry::flags`: the text did not end with a newline.
pub const KLOG_CONTINUES: u8 = 1;

/// A kernel log record (`struct dos_klog_entry`).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct KlogEntry {
    pub seq: u64,
    /// Monotonic, since kernel entry.
    pub time_us: u64,
    pub level: u8,
    pub len: u8,
    pub origin: u8,
    pub flags: u8,
    /// Program records: the writing process.
    pub koid: u32,
    /// Program records: its name, set by the kernel.
    pub source: [u8; KLOG_SOURCE],
    pub text: [u8; KLOG_TEXT],
    pub reserved: [u8; 8],
}
const _: () = assert!(core::mem::size_of::<KlogEntry>() == 176);

impl Default for KlogEntry {
    fn default() -> Self {
        KlogEntry { seq: 0, time_us: 0, level: 0, len: 0, origin: 0, flags: 0, koid: 0, source: [0; KLOG_SOURCE], text: [0; KLOG_TEXT], reserved: [0; 8] }
    }
}

impl KlogEntry {
    pub fn text(&self) -> &[u8] {
        &self.text[..usize::from(self.len).min(KLOG_TEXT)]
    }
    pub fn source(&self) -> &[u8] {
        let n = self.source.iter().position(|&c| c == 0).unwrap_or(KLOG_SOURCE);
        &self.source[..n]
    }
}

/// ABI v8, with the KLOG resource: records with sequence >= `seq` (at most `out.len()`, at
/// most 64). Kernel addresses in the text read `[kaddr]`.
pub fn klog_read(res: Handle, seq: u64, out: &mut [KlogEntry]) -> Result<usize, i64> {
    let r = sc(nr::KLOG_READ, u64::from(res), seq, out.as_mut_ptr() as u64, core::mem::size_of_val(out) as u64, 0, 0);
    if r < 0 { Err(r) } else { Ok(r as usize) }
}

/// The boot-time record (`TAG_BOOT_TIME`, `struct dos_boot_time`).
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct BootTime {
    pub magic: u32,
    /// 1: UEFI GetTime.
    pub source: u32,
    pub year: u16,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
    pub pad: u8,
    pub nanosecond: u32,
    /// Minutes from UTC; 2047: unspecified.
    pub time_zone: i16,
    pub pad2: u16,
    /// The monotonic clock at that moment (negative: before the kernel started).
    pub mono_ns: i64,
}
const _: () = assert!(core::mem::size_of::<BootTime>() == 32);
pub const BOOT_TIME_MAGIC: u32 = 0x4D49_5444;
/// `POWER_OFF`, `POWER_REBOOT`, or `POWER_SUSPEND` with the POWER resource.
pub fn system_power(power: Handle, action: u64) -> i64 {
    sc(nr::SYSTEM_POWER, u64::from(power), action, 0, 0, 0, 0)
}

/// `get_random` flag: refuse unless hardware entropy (RDSEED, RDRAND, or TPM) seeded the kernel CSPRNG.
pub const RANDOM_STRICT: u64 = 1 << 0;

/// ABI v14: fill `out` from the kernel's Fast-Key-Erasure ChaCha20 CSPRNG.
pub fn get_random(out: &mut [u8], flags: u64) -> Result<(), i64> {
    for chunk in out.chunks_mut(4096) {
        let r = sc(nr::GET_RANDOM, chunk.as_mut_ptr() as u64, chunk.len() as u64, flags, 0, 0, 0);
        if r < 0 {
            return Err(r);
        }
        if r as usize != chunk.len() {
            return Err(ERR_BAD_STATE);
        }
    }
    Ok(())
}
