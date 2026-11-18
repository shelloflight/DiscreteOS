//! The syscall ABI (version `ABI_VERSION`, documented in docs/abi.md; C binding in
//! user/include/dos.h).
//!
//! `syscall` with the number in RAX and up to six arguments in RDI, RSI, RDX, R10, R8, R9. The
//! result comes back in RAX: >= 0 is a value (a handle, a size, an address, ...), < 0 a `Status`.
//! RCX and R11 are clobbered (by the instruction), everything else is preserved.
//!
//! Every object is named by a handle of the calling process and checked for type and rights
//! (Process methods, object/process.rs). Every pointer is a user pointer, copied through
//! `uaccess` (a bad one is `BAD_ADDRESS`). Numbers are never reused: a removed syscall stays
//! `NOT_SUPPORTED`.

use alloc::vec::Vec;
use core::ffi::c_int;

use super::exception;
use super::ipc;
use super::loader::{self, MAX_ARGS, MAX_HANDLES};
use super::thread::{UserThread, current};
use super::uaccess::{self, Pod};
use crate::ffi;
use crate::object::exception::{Action, Regs};
use crate::object::quota::Limits;
use crate::object::resource::{KIND_KLOG, KIND_MEASURE, KIND_POWER, KIND_VMEX};
use crate::object::{Handle, KResult, ObjType, Object, Rights, Status, default_rights, log::MAX_WRITE};

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
    // ABI v2
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
    // ABI v3: devices for user-space drivers
    pub const DEVICE_INFO: u64 = 51;
    pub const DEVICE_CONFIG_READ: u64 = 52;
    pub const DEVICE_CONFIG_WRITE: u64 = 53;
    pub const DEVICE_MAP_BAR: u64 = 54;
    pub const DEVICE_IO_READ: u64 = 55;
    pub const DEVICE_IO_WRITE: u64 = 56;
    pub const DEVICE_INTERRUPT: u64 = 57;
    pub const INTERRUPT_ACK: u64 = 58;
    pub const DEVICE_DMA_MAP: u64 = 59;
    // ABI v4: code signing
    pub const VMO_VERIFY: u64 = 60;
    pub const VMO_ALLOW_UNSIGNED: u64 = 61;
    // ABI v5: remote attestation
    pub const ATTEST: u64 = 62;
    // ABI v6: power control
    pub const SYSTEM_POWER: u64 = 63;
    // ABI v7: service manager decisions in the measurement log
    pub const MEASURE: u64 = 64;
    // ABI v8: the log service
    pub const KLOG_READ: u64 = 65;
    pub const LOG_RECORD: u64 = 66;
    // ABI v9: the terminal and the shell
    pub const DISPLAY_INFO: u64 = 67;
    pub const PROCESS_HANDLES: u64 = 68;
    // ABI v10: D-CMPL's Linux server (mmap, clone)
    pub const PROCESS_VMAR: u64 = 69;
    pub const THREAD_CREATE_STOPPED: u64 = 70;
    pub const COUNT: u64 = 71;
    /// Test builds only: make the kernel touch / execute user memory without permission.
    pub const KTEST_SMAP: u64 = 0xF000;
    pub const KTEST_SMEP: u64 = 0xF001;
}

/// "Any address" for vmar_map / vmar_allocate offsets.
pub const ANY: u64 = u64::MAX;

/// Register frame (struct interrupt_frame, arch.h).
#[repr(C)]
pub struct Frame {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rbp: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rdx: u64,
    pub rcx: u64,
    pub rbx: u64,
    pub rax: u64,
    pub vector: u64,
    pub error: u64,
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Info {
    ty: u32,
    rights: u32,
    koid: u64,
}
// SAFETY: repr(C), integers only, no padding.
unsafe impl Pod for Info {}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct RawLimits {
    memory: u64,
    handles: u64,
    threads: u64,
}
// SAFETY: as above.
unsafe impl Pod for RawLimits {}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Quota {
    limits: RawLimits,
    used: RawLimits,
}
// SAFETY: as above.
unsafe impl Pod for Quota {}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct SpawnArgs {
    parent: u32,
    image: u32,
    name: u64,
    name_len: u64,
    args: u64,
    args_len: u64,
    handles: u64,
    nhandles: u32,
    flags: u32,
    limits: u64,
}
// SAFETY: as above (4 + 4 + 8 * 5 + 4 + 4 + 8 = 64 bytes, no padding).
unsafe impl Pod for SpawnArgs {}
const _: () = assert!(core::mem::size_of::<SpawnArgs>() == 64);

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct SpawnHandle {
    handle: u32,
    rights: u32,
    tag: u32,
    reserved: u32,
}
// SAFETY: as above.
unsafe impl Pod for SpawnHandle {}

/// `struct dos_device_info` (docs/abi.md).
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct DeviceInfo {
    kind: u32,
    flags: u32,
    vendor: u16,
    device: u16,
    class: u8,
    subclass: u8,
    progif: u8,
    revision: u8,
    bus: u8,
    dev: u8,
    func: u8,
    reserved0: u8,
    irqs: u16,
    config_size: u16,
    dma_faults: u64,
    bar_size: [u64; 6],
    bar_kind: [u8; 6],
    reserved1: [u8; 2],
    name: [u8; 16],
}
// SAFETY: repr(C), integers only, no padding (asserted).
unsafe impl Pod for DeviceInfo {}
const _: () = assert!(core::mem::size_of::<DeviceInfo>() == 104);

const DEV_KIND_PCI: u32 = 1;
const DEV_KIND_PLATFORM: u32 = 2;
const DEV_FLAG_IOMMU: u32 = 1 << 0;
const DEV_FLAG_MSI: u32 = 1 << 1;
const DEV_FLAG_MSIX: u32 = 1 << 2;
/// device_dma_map flags: what the device may do with the pages.
const DMA_DEVICE_READ: u64 = 1 << 0;
const DMA_DEVICE_WRITE: u64 = 1 << 1;

fn device_info(u: &UserThread, dh: u64, out: u64) -> KResult<i64> {
    use crate::object::device::Kind;
    let (d, _) = u.proc.get_device(h(dh), Rights::INSPECT)?;
    let mut i = DeviceInfo { irqs: d.irq_count(), ..Default::default() };
    let n = d.name().as_bytes();
    let k = n.len().min(15);
    i.name[..k].copy_from_slice(&n[..k]);
    match &d.kind {
        Kind::Pci(f) => {
            i.kind = DEV_KIND_PCI;
            i.flags = if crate::dev::iommu::enabled() { DEV_FLAG_IOMMU } else { 0 }
                | if f.msi.is_some() { DEV_FLAG_MSI } else { 0 }
                | if f.msix.is_some() { DEV_FLAG_MSIX } else { 0 };
            (i.vendor, i.device, i.class, i.subclass, i.progif, i.revision) =
                (f.vendor, f.device, f.class, f.subclass, f.progif, f.revision);
            (i.bus, i.dev, i.func) = (f.bdf.bus(), f.bdf.dev(), f.bdf.func());
            i.config_size = crate::dev::pci::config_size();
            i.dma_faults = crate::dev::iommu::faults_of(f.bdf);
            for (k, b) in f.bars.iter().enumerate() {
                i.bar_size[k] = b.size;
                i.bar_kind[k] = match b.kind {
                    crate::dev::pci::BarKind::None => 0,
                    crate::dev::pci::BarKind::Memory => 1,
                    crate::dev::pci::BarKind::Io => 2,
                };
            }
        }
        Kind::Platform(p) => {
            i.kind = DEV_KIND_PLATFORM;
            for (k, &(_, len)) in p.io.iter().enumerate() {
                i.bar_size[k] = u64::from(len);
                i.bar_kind[k] = if len != 0 { 2 } else { 0 };
            }
            if p.mem.1 != 0 {
                (i.bar_size[0], i.bar_kind[0]) = (p.mem.1, 1); // the memory window is BAR 0
            }
        }
    }
    drop(d);
    uaccess::write(out, &i)?;
    Ok(0)
}

/// `struct dos_display_info` (docs/abi.md).
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct DisplayInfo {
    kind: u32,
    width: u32,
    height: u32,
    pitch: u32,
    size: u64,
    red_shift: u8,
    green_shift: u8,
    blue_shift: u8,
    reserved: [u8; 5],
}
// SAFETY: repr(C), integers only, no padding (asserted).
unsafe impl Pod for DisplayInfo {}
const _: () = assert!(core::mem::size_of::<DisplayInfo>() == 32);

/// display_info(device, struct dos_display_info *): the layout of the display device's memory
/// window (BAR 0). `WRONG_TYPE` for any other device.
fn display_info(u: &UserThread, dh: u64, out: u64) -> KResult<i64> {
    use crate::object::device::Kind;
    let (d, _) = u.proc.get_device(h(dh), Rights::INSPECT)?;
    let Kind::Platform(p) = &d.kind else { return Err(Status::WrongType) };
    let disp = p.display.ok_or(Status::WrongType)?;
    let i = DisplayInfo {
        kind: disp.kind,
        width: disp.width,
        height: disp.height,
        pitch: disp.pitch,
        size: p.mem.1,
        red_shift: disp.shifts[0],
        green_shift: disp.shifts[1],
        blue_shift: disp.shifts[2],
        reserved: [0; 5],
    };
    drop(d);
    uaccess::write(out, &i)?;
    Ok(0)
}

/// `struct dos_handle_entry` (docs/abi.md).
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct HandleEntry {
    ty: u32,
    rights: u32,
    koid: u64,
    name: [u8; 32],
}
// SAFETY: repr(C), integers only, no padding (asserted).
unsafe impl Pod for HandleEntry {}
const _: () = assert!(core::mem::size_of::<HandleEntry>() == 48);
/// Entries one process_handles call returns at most.
const HANDLES_MAX: usize = 256;

/// process_handles(process, buf, cap) -> handles the process holds. Copies at most `cap` (and at
/// most 256) entries: type, rights, koid and name; never the handle values (they mean nothing
/// outside that process). Needs INSPECT.
fn process_handles(u: &UserThread, ph: u64, buf: u64, cap: u64) -> KResult<i64> {
    let (target, _) = u.proc.get_process(h(ph), Rights::INSPECT)?;
    let max = usize::try_from(cap).unwrap_or(usize::MAX).min(HANDLES_MAX);
    let mut v: alloc::vec::Vec<HandleEntry> = alloc::vec::Vec::new();
    v.try_reserve_exact(max).map_err(|_| Status::NoMemory)?;
    let total = target.handle_list(max, |o, r| {
        let mut e = HandleEntry { ty: o.obj_type() as u32, rights: r.0, koid: o.koid(), name: [0; 32] };
        let n = o.name().as_bytes();
        let k = n.len().min(31);
        e.name[..k].copy_from_slice(&n[..k]);
        v.push(e); // capacity reserved: never allocates under the lock
    });
    drop(target);
    for (k, e) in v.iter().enumerate() {
        uaccess::write(buf + (k * core::mem::size_of::<HandleEntry>()) as u64, e)?;
    }
    Ok(i64::from(total))
}

fn device_map_bar(u: &UserThread, dh: u64, bar: u64) -> KResult<i64> {
    let (d, _) = u.proc.get_device(h(dh), Rights::MAP)?;
    let v = d.bar_vmo(bar, u.proc.account())?;
    let rights = Rights::DUPLICATE | Rights::TRANSFER | Rights::READ | Rights::WRITE | Rights::MAP | Rights::INSPECT;
    u.proc.add(Object::Vmo(v), rights).map(|x| i64::from(x.0))
}

fn device_interrupt(u: &UserThread, dh: u64, index: u64, flags: u64) -> KResult<i64> {
    let (d, _) = u.proc.get_device(h(dh), Rights::MANAGE)?;
    if flags != 0 {
        return Err(Status::InvalidArgs);
    }
    let irq = crate::object::DeviceObj::interrupt(&d, index)?;
    u.proc.add(Object::Interrupt(irq), default_rights(ObjType::Interrupt)).map(|x| i64::from(x.0))
}

/// device_dma_map(dev, vmo, offset, len, flags, uint64_t addrs[len / 4096]) -> pin handle.
fn device_dma_map(u: &UserThread, a: [u64; 6]) -> KResult<i64> {
    let flags = a[4];
    if flags & !(DMA_DEVICE_READ | DMA_DEVICE_WRITE) != 0 || flags == 0 {
        return Err(Status::InvalidArgs);
    }
    let (d, _) = u.proc.get_device(h(a[0]), Rights::MANAGE)?;
    // The device gets at most the access the driver has: reading needs READ, writing WRITE.
    let need = if flags & DMA_DEVICE_READ != 0 { Rights::READ } else { Rights::NONE }
        | if flags & DMA_DEVICE_WRITE != 0 { Rights::WRITE } else { Rights::NONE };
    let (v, _) = u.proc.get_vmo(h(a[1]), need)?;
    if a[3] == 0 || !a[3].is_multiple_of(4096) || a[3] / 4096 > crate::object::device::MAX_PIN_PAGES {
        return Err(Status::InvalidArgs);
    }
    uaccess::check(a[5], a[3] / 4096 * 8)?;
    let mut addrs = Vec::new();
    let pin = crate::object::DeviceObj::dma_map(
        &d,
        v,
        a[2],
        a[3],
        flags & DMA_DEVICE_READ != 0,
        flags & DMA_DEVICE_WRITE != 0,
        &mut addrs,
    )?;
    drop(d);
    for (i, ad) in addrs.iter().enumerate() {
        uaccess::write(a[5] + 8 * i as u64, ad)?; // on failure `pin` drops: unmapped again
    }
    u.proc.add(Object::Pin(pin), default_rights(ObjType::Pin)).map(|x| i64::from(x.0))
}

enum Next {
    Return(i64),
    /// Return to user mode with every register from the frame (IRETQ): the registers were
    /// replaced (exception return, a forwarded syscall).
    Restore,
    ExitThread(i32),
}

/// spawn flags (docs/abi.md).
pub const SPAWN_EXCEPTION_CHANNEL: u32 = 1 << 0;
pub const SPAWN_FORWARD: u32 = 1 << 1;
/// ABI v2: the first thread stops with a START exception before its first instruction.
pub const SPAWN_START_EXCEPTION: u32 = 1 << 2;
const SPAWN_FLAGS: u32 = SPAWN_EXCEPTION_CHANNEL | SPAWN_FORWARD | SPAWN_START_EXCEPTION;
const SPAWN_NEEDS_SUPERVISOR: u32 = SPAWN_FORWARD | SPAWN_START_EXCEPTION;

/// exception_resume actions.
const RESUME: u64 = 0;
const KILL: u64 = 1;
const EXIT_THREAD: u64 = 2;

fn ok(v: u64) -> KResult<i64> {
    Ok(v as i64)
}

fn h(v: u64) -> Handle {
    Handle(v as u32)
}

fn rights(v: u64) -> KResult<Rights> {
    u32::try_from(v).map(Rights).map_err(|_| Status::InvalidArgs)
}

fn offset(v: u64) -> Option<u64> {
    (v != ANY).then_some(v)
}

fn read_limits(ptr: u64) -> KResult<Limits> {
    if ptr == 0 {
        return Ok(Limits::DEFAULT);
    }
    let l: RawLimits = uaccess::read(ptr)?;
    Ok(Limits { memory: l.memory, handles: l.handles, threads: l.threads })
}

/// Copy a name (at most 31 bytes are kept, like every object name).
fn read_name(ptr: u64, len: u64) -> KResult<([u8; 64], usize)> {
    let mut buf = [0u8; 64];
    let n = usize::try_from(len).map_err(|_| Status::InvalidArgs)?;
    if n > buf.len() {
        return Err(Status::InvalidArgs);
    }
    uaccess::copy_from_user(&mut buf[..n], ptr)?;
    Ok((buf, n))
}

fn name_str(b: &[u8]) -> &str {
    match core::str::from_utf8(b) {
        Ok(s) => s,
        Err(e) => core::str::from_utf8(&b[..e.valid_up_to()]).unwrap_or(""),
    }
}

fn log_write(u: &UserThread, lh: u64, ptr: u64, len: u64) -> KResult<i64> {
    log_record(u, lh, crate::ffi::KLOG_INFO as u64, ptr, len)
}

/// log_record (ABI v8): `log_write` with a level (0 error .. 3 debug). Every record is attributed
/// to the calling process by the kernel (its koid and name).
fn log_record(u: &UserThread, lh: u64, level: u64, ptr: u64, len: u64) -> KResult<i64> {
    let (log, _) = u.proc.get_log(h(lh), Rights::WRITE)?;
    if len > 64 * 1024 || level > crate::ffi::KLOG_DEBUG as u64 {
        return Err(Status::InvalidArgs);
    }
    uaccess::check(ptr, len)?;
    let koid = u.proc.header.koid as u32;
    let name = u.proc.name().as_bytes();
    let mut buf = [0u8; MAX_WRITE];
    let mut done = 0;
    while done < len {
        let n = (len - done).min(MAX_WRITE as u64) as usize;
        uaccess::copy_from_user(&mut buf[..n], ptr + done)?;
        log.write(level as core::ffi::c_int, koid, name, &mut buf[..n]);
        done += n as u64;
    }
    ok(len)
}

/// Records one `klog_read` returns at most.
const KLOG_READ_MAX: usize = 64;

/// klog_read (ABI v8): with the KLOG authority (the log service), copy kernel log records with
/// sequence >= `seq` into `buf` (`struct dos_klog_entry`, 176 bytes each; at most `cap`
/// bytes, at most 64 records). Returns how many. Kernel addresses in the text are replaced by
/// `[kaddr]` before anything leaves the kernel. A reader that fell behind gets the oldest record
/// still kept: the gap in sequence numbers is what it missed.
fn klog_read(u: &UserThread, rh: u64, seq: u64, buf: u64, cap: u64) -> KResult<i64> {
    use crate::klog::{self, KlogEntry};
    let (res, _) = u.proc.get_resource(Handle(rh as u32), Rights::MANAGE)?;
    if res.kind != KIND_KLOG {
        return Err(Status::AccessDenied);
    }
    const SZ: usize = core::mem::size_of::<KlogEntry>();
    let max = ((cap as usize) / SZ).min(KLOG_READ_MAX);
    if max == 0 {
        return Err(Status::BufferTooSmall);
    }
    uaccess::check(buf, (max * SZ) as u64)?;
    let mut at = seq;
    let mut n = 0;
    while n < max {
        let Some(mut e) = klog::read(at) else { break };
        at = e.seq + 1;
        e.len = klog::filter_kernel_addresses(&mut e.text, usize::from(e.len)) as u8;
        e.text[usize::from(e.len)..].fill(0);
        e.reserved = [0; 8];
        // SAFETY: KlogEntry is repr(C) plain data without padding (asserted size, all fields bytes
        // or naturally aligned integers): viewing it as bytes is sound.
        let bytes = unsafe { core::slice::from_raw_parts((&raw const e).cast::<u8>(), SZ) };
        uaccess::copy_to_user(buf + (n * SZ) as u64, bytes)?;
        n += 1;
    }
    ok(n as u64)
}

fn object_name(u: &UserThread, hv: u64, ptr: u64, len: u64) -> KResult<i64> {
    let (obj, _) = u.proc.get(h(hv), Rights::NONE)?;
    let mut tmp = [0u8; 32];
    let n = {
        let s = obj.name();
        tmp[..s.len()].copy_from_slice(s.as_bytes());
        s.len()
    };
    drop(obj);
    let copy = n.min(usize::try_from(len).unwrap_or(usize::MAX));
    uaccess::copy_to_user(ptr, &tmp[..copy])?;
    ok(n as u64)
}

fn spawn(u: &UserThread, ptr: u64) -> KResult<i64> {
    let a: SpawnArgs = uaccess::read(ptr)?;
    if a.flags & !SPAWN_FLAGS != 0 || (a.flags & SPAWN_NEEDS_SUPERVISOR != 0 && a.flags & SPAWN_EXCEPTION_CHANNEL == 0) {
        // FORWARD without a supervisor could never run a syscall; START would have nobody to stop for
        return Err(Status::InvalidArgs);
    }
    // The structure grows at the end, guarded by the flag: exception_channel_out (u32 *).
    let exc_out: u64 = if a.flags & SPAWN_EXCEPTION_CHANNEL != 0 {
        let p: u64 = uaccess::read(ptr + 64)?;
        uaccess::write(p, &0u32)?;
        p
    } else {
        0
    };
    let (name, nlen) = read_name(a.name, a.name_len)?;
    let alen = usize::try_from(a.args_len).map_err(|_| Status::InvalidArgs)?;
    let nh = a.nhandles as usize;
    if alen > MAX_ARGS || nh > MAX_HANDLES {
        return Err(Status::InvalidArgs);
    }
    let mut args = Vec::new();
    args.try_reserve_exact(alen).map_err(|_| Status::NoMemory)?;
    args.resize(alen, 0u8);
    uaccess::copy_from_user(&mut args, a.args)?;
    let mut list: Vec<SpawnHandle> = Vec::new();
    list.try_reserve_exact(nh).map_err(|_| Status::NoMemory)?;
    for i in 0..nh {
        list.push(uaccess::read(a.handles + 16 * i as u64)?);
    }
    let limits = read_limits(a.limits)?;
    let (parent, _) = u.proc.get_process(Handle(a.parent), Rights::MANAGE)?;
    let (image, _) = u.proc.get_vmo(Handle(a.image), Rights::READ)?;

    // Validate every handle before moving any: TRANSFER, rights a subset, no duplicates.
    for (i, e) in list.iter().enumerate() {
        if list[..i].iter().any(|o| o.handle == e.handle) {
            return Err(Status::InvalidArgs);
        }
        let (_, have) = u.proc.get(Handle(e.handle), Rights::TRANSFER)?;
        let want = Rights(e.rights);
        if want != Rights::SAME && (want.0 & !Rights::ALL.0 != 0 || !have.contains(want)) {
            return Err(Status::AccessDenied);
        }
    }
    let mut moved = Vec::new();
    moved.try_reserve_exact(nh).map_err(|_| Status::NoMemory)?;
    for e in &list {
        let (obj, have) = u.proc.take(Handle(e.handle))?; // consumed from here on
        let r = if Rights(e.rights) == Rights::SAME { have } else { Rights(e.rights) };
        moved.push((obj, r, e.tag));
    }
    let (child, exc) = loader::spawn(loader::Spawn {
        parent,
        image,
        name: name_str(&name[..nlen]),
        args: &args,
        handles: moved,
        limits,
        exception_channel: a.flags & SPAWN_EXCEPTION_CHANNEL != 0,
        forward: a.flags & SPAWN_FORWARD != 0,
        start_exception: a.flags & SPAWN_START_EXCEPTION != 0,
    })
    .map_err(|e| {
        if let loader::SpawnError::Elf(err) = &e {
            crate::kprintln!("spawn: '{}' refused: {}", name_str(&name[..nlen]), err.text());
        }
        e.status()
    })?;
    let hp = u.proc.add(
        crate::object::Object::Process(child.clone()),
        crate::object::default_rights(crate::object::ObjType::Process),
    );
    if hp.is_err() {
        child.kill(); // nobody could ever reach it
    }
    let hp = hp?;
    if let Some(ch) = exc {
        let hc = u.proc.add(Object::Channel(ch), default_rights(ObjType::Channel));
        let r = hc.and_then(|hc| uaccess::write(exc_out, &hc.0).inspect_err(|_| {
            let _ = u.proc.handle_close(hc);
        }));
        if let Err(e) = r {
            child.kill(); // a FORWARD child without its supervisor could never run anyway
            let _ = u.proc.handle_close(hp);
            return Err(e);
        }
    }
    ok(u64::from(hp.0))
}

/// Ops a port may run from its submission queue: everything that cannot block or end the
/// thread. Waits are polls there (timeout forced to 0).
fn port_op(op: u64, args: &mut [u64; 6]) -> bool {
    match op {
        nr::OBJECT_WAIT => {
            args[2] = 0;
            true
        }
        nr::CHANNEL_READ => {
            args[3] = 0;
            true
        }
        nr::THREAD_EXIT | nr::PROCESS_EXIT | nr::PORT_ENTER | nr::CHANNEL_CALL | nr::EXCEPTION_RETURN | nr::YIELD
        | nr::SYSTEM_POWER => false,
        _ => op < nr::COUNT,
    }
}

fn port_enter(u: &UserThread, h: u64, to_submit: u64, min_complete: u64, timeout: u64) -> KResult<i64> {
    let port = ipc::port_of(u, h)?;
    let core = &port.core;
    let min = u32::try_from(min_complete).map_err(|_| Status::InvalidArgs)?;
    if min > core.cq_entries() {
        return Err(Status::InvalidArgs);
    }
    let deadline = crate::object::signals::deadline(timeout);
    core.sync();
    // Batches: claim up to BATCH entries in one lock hold, run them, post all results at once.
    const BATCH: usize = 16;
    let mut sqes = [crate::object::port::Sqe::default(); BATCH];
    let mut res = [(0u64, 0i64); BATCH];
    let mut done = 0u64;
    'outer: while done < to_submit {
        let want = (to_submit - done).min(BATCH as u64) as usize;
        let n = core.claim(&mut sqes[..want])?;
        if n == 0 {
            break;
        }
        for i in 0..n {
            let sqe = &mut sqes[i];
            let op = u64::from(sqe.op);
            let r = if sqe.flags != 0 {
                Status::InvalidArgs as i32 as i64
            } else if !port_op(op, &mut sqe.args) {
                Status::NotSupported as i32 as i64
            } else {
                match sys(u, op, sqe.args) {
                    Ok(Next::Return(v)) => v,
                    Ok(_) => Status::NotSupported as i32 as i64, // unreachable: excluded above
                    Err(e) => e as i32 as i64,
                }
            };
            res[i] = (sqe.user_data, r);
            // SAFETY: plain read of the current thread's kill flag.
            if unsafe { ffi::thread_kill_pending() } {
                // Claimed entries still get their (reserved) completion slots.
                for (j, s) in sqes.iter().enumerate().take(n).skip(i + 1) {
                    res[j] = (s.user_data, Status::BadState as i32 as i64);
                }
                core.complete(&res[..n]);
                done += n as u64;
                break 'outer;
            }
        }
        core.complete(&res[..n]);
        done += n as u64;
    }
    if min > 0 && timeout != 0 {
        match core.wait_completions(min, deadline) {
            Ok(()) | Err(Status::TimedOut) => {}
            Err(e) => return Err(e),
        }
    }
    ok(done)
}

fn exception_resume(u: &UserThread, h: u64, action: u64, code: u64) -> KResult<i64> {
    let (e, _) = u.proc.get_exception(Handle(h as u32), Rights::WRITE)?;
    let a = match action {
        RESUME => Action::Resume,
        KILL => Action::Kill(code as i32),
        EXIT_THREAD => Action::ExitThread(code as i32),
        _ => return Err(Status::InvalidArgs),
    };
    e.core.resolve(a)?;
    Ok(0)
}

fn vmo_make_executable(u: &UserThread, vh: u64, rh: u64) -> KResult<i64> {
    let (res, _) = u.proc.get_resource(Handle(rh as u32), Rights::MANAGE)?;
    if res.kind != KIND_VMEX {
        return Err(Status::AccessDenied);
    }
    let (v, have) = u.proc.get_vmo(Handle(vh as u32), Rights::READ)?;
    v.make_executable()?; // BadState while it is mapped writable or being written
    // The old handle goes; the new one can map executable but never write.
    let rights = Rights((have.0 & !Rights::WRITE.0) | Rights::EXECUTE.0);
    let (obj, _) = u.proc.take(Handle(vh as u32))?;
    drop(v);
    u.proc.add(obj, rights).map(|x| i64::from(x.0))
}

/// vmo_verify (ABI v4): check a `.dsig` (in `sh`, its first 256 bytes) for the program in `vh` against
/// the D-OS key. Seals the VMO; on success the kernel trusts it as a program image (spawn).
fn vmo_verify(u: &UserThread, vh: u64, sh: u64) -> KResult<i64> {
    let (v, _) = u.proc.get_vmo(Handle(vh as u32), Rights::READ)?;
    let (s, _) = u.proc.get_vmo(Handle(sh as u32), Rights::READ)?;
    if s.size() < doscrypt::dsig::SIZE as u64 {
        return Err(Status::InvalidArgs);
    }
    let mut d = [0u8; doscrypt::dsig::SIZE];
    s.read(0, &mut d)?;
    crate::security::verify_vmo(&v, &d).map(|_| 0)
}

/// system_power (ABI v6): with the POWER authority, switch the machine off (1) or reset it (2).
/// Power-off returns NOT_SUPPORTED when the machine has no usable ACPI S5 (or it did not work);
/// a reset does not return. Nothing is flushed here: services sync their volumes first.
fn system_power(u: &UserThread, rh: u64, action: u64) -> KResult<i64> {
    let (res, _) = u.proc.get_resource(Handle(rh as u32), Rights::MANAGE)?;
    if res.kind != KIND_POWER {
        return Err(Status::AccessDenied);
    }
    match action {
        1 => {
            // SAFETY: plain calls into the power code (it returns only if S5 did not happen).
            if !unsafe { ffi::power_off_supported() } {
                return Err(Status::NotSupported);
            }
            crate::kprintln!("Power: switch-off requested by process {}", u.proc.name());
            // SAFETY: as above; returns only if the machine is still on.
            unsafe { ffi::power_off() };
            Err(Status::NotSupported)
        }
        2 => {
            crate::kprintln!("Power: reset requested by process {}", u.proc.name());
            // SAFETY: as above; never returns.
            unsafe { ffi::power_reboot() }
        }
        _ => Err(Status::InvalidArgs),
    }
}

/// measure (ABI v7): with the MEASURE authority, extend PCR 10 with a 32-byte digest and record it
/// in the measurement log as `svc <text>` (printable ASCII; at most `TEXT_MAX - 4` bytes). The
/// service manager records every manifest it accepts or refuses, so an attestation shows it.
fn measure(u: &UserThread, rh: u64, digest: u64, text: u64, len: u64) -> KResult<i64> {
    use crate::security::measure as m;
    let (res, _) = u.proc.get_resource(Handle(rh as u32), Rights::MANAGE)?;
    if res.kind != KIND_MEASURE {
        return Err(Status::AccessDenied);
    }
    if len > (m::TEXT_MAX - 4) as u64 {
        return Err(Status::InvalidArgs);
    }
    let n = len as usize;
    let mut d = [0u8; 32];
    uaccess::copy_from_user(&mut d, digest)?;
    let mut t = [0u8; m::TEXT_MAX];
    t[..4].copy_from_slice(b"svc ");
    uaccess::copy_from_user(&mut t[4..4 + n], text)?;
    // Printable ASCII only: the log is shown by kdb and parsed by verifiers.
    if t[4..4 + n].iter().any(|c| !(b' '..=b'~').contains(c)) {
        return Err(Status::InvalidArgs);
    }
    m::measure(m::PCR_CODE, &d, core::str::from_utf8(&t[..4 + n]).unwrap_or("svc ?"), false);
    Ok(0)
}

/// vmo_allow_unsigned (ABI v4): with the VMEX authority, let an unsigned image run (sealed, measured).
fn vmo_allow_unsigned(u: &UserThread, vh: u64, rh: u64) -> KResult<i64> {
    let (res, _) = u.proc.get_resource(Handle(rh as u32), Rights::MANAGE)?;
    if res.kind != KIND_VMEX {
        return Err(Status::AccessDenied);
    }
    let (v, _) = u.proc.get_vmo(Handle(vh as u32), Rights::READ)?;
    crate::security::allow_unsigned(&v).map(|_| 0)
}

/// attest(nonce, buf, cap): a signed attestation report for the caller's 32-byte nonce
/// (security/attest.rs, docs/attestation.md). Returns its length; `BUFFER_TOO_SMALL` (nothing
/// written) when `cap` is less (`doscrypt::attest::MAX_SIZE` always suffices). No handle or right:
/// a report holds only public facts (what ran), signed by a key that never leaves the kernel.
fn attest(nonce: u64, buf: u64, cap: u64) -> KResult<i64> {
    let mut n = [0u8; 32];
    uaccess::copy_from_user(&mut n, nonce)?;
    uaccess::check(buf, cap)?;
    let r = crate::security::attest::report(&n).ok_or(Status::NoMemory)?;
    if (r.len() as u64) > cap {
        return Err(Status::BufferTooSmall);
    }
    uaccess::copy_to_user(buf, &r)?;
    Ok(r.len() as i64)
}

/// process_read_memory / process_write_memory: copy between the caller's memory and another
/// process's (a supervisor serving a forwarded syscall, a debugger). Needs `MANAGE`. Only what is
/// mapped there with the matching permission (read / write) can be reached, through the VMO
/// behind the mapping: a sealed (code) VMO can never be written this way.
fn process_memory(u: &UserThread, ph: u64, addr: u64, buf: u64, len: u64, write: bool) -> KResult<i64> {
    const MAX: u64 = 64 * 1024;
    if len > MAX {
        return Err(Status::InvalidArgs);
    }
    uaccess::check(buf, len)?;
    let (target, _) = u.proc.get_process(h(ph), Rights::MANAGE)?;
    if target.is_dead() {
        return Err(Status::BadState);
    }
    let mut tmp = [0u8; 512];
    let mut done = 0u64;
    while done < len {
        let at = addr.checked_add(done).ok_or(Status::BadAddress)?;
        let (vmo, off, perms, left) = target.root_vmar().lookup(at).ok_or(Status::BadAddress)?;
        let need = if write { Rights::WRITE } else { Rights::READ };
        if !perms.contains(need) {
            return Err(Status::AccessDenied);
        }
        let n = (len - done).min(left).min(tmp.len() as u64) as usize;
        if write {
            uaccess::copy_from_user(&mut tmp[..n], buf + done)?;
            vmo.write(off, &tmp[..n])?;
        } else {
            vmo.read(off, &mut tmp[..n])?;
            uaccess::copy_to_user(buf + done, &tmp[..n])?;
        }
        done += n as u64;
    }
    ok(done)
}

/// thread_set_base / get: 0 = FS, 1 = GS (the calling thread's own).
fn which_base(w: u64) -> KResult<u32> {
    match w {
        0 | 1 => Ok(w as u32),
        _ => Err(Status::InvalidArgs),
    }
}

fn sys(u: &UserThread, n: u64, a: [u64; 6]) -> KResult<Next> {
    sys_frame(u, n, a, None)
}

fn sys_frame(u: &UserThread, n: u64, a: [u64; 6], f: Option<&mut Frame>) -> KResult<Next> {
    let p = &u.proc;
    // Spectre v1: the number selects a handler; a mispredicted range check must not reach past
    // the table with a user-chosen number (test-only numbers above COUNT keep their value).
    let n = if n < nr::COUNT { crate::nospec::index(n as usize, nr::COUNT as usize) as u64 } else { n };
    let r = match n {
        nr::ABI_VERSION => ok(u64::from(loader::ABI_VERSION)),
        nr::LOG_WRITE => log_write(u, a[0], a[1], a[2]),
        nr::HANDLE_CLOSE => p.handle_close(h(a[0])).map(|_| 0),
        nr::HANDLE_DUPLICATE => p.handle_duplicate(h(a[0]), rights(a[1])?).map(|x| i64::from(x.0)),
        nr::HANDLE_REPLACE => p.handle_replace(h(a[0]), rights(a[1])?).map(|x| i64::from(x.0)),
        nr::HANDLE_GRANT => p.handle_grant(h(a[0]), rights(a[1])?, h(a[2])).map(|x| i64::from(x.0)),
        nr::OBJECT_INFO => {
            let (ty, koid, r) = p.object_info(h(a[0]))?;
            uaccess::write(a[1], &Info { ty: ty as u32, rights: r.0, koid })?;
            Ok(0)
        }
        nr::OBJECT_NAME => object_name(u, a[0], a[1], a[2]),
        nr::OBJECT_WAIT => {
            let mask = u32::try_from(a[1]).map_err(|_| Status::InvalidArgs)?;
            p.object_wait(h(a[0]), mask, a[2]).map(i64::from)
        }
        nr::EVENT_CREATE => p.event_create().map(|x| i64::from(x.0)),
        nr::EVENT_SIGNAL => {
            let (c, s) = (u32::try_from(a[1]), u32::try_from(a[2]));
            let (Ok(c), Ok(s)) = (c, s) else { return Err(Status::InvalidArgs) };
            p.event_signal(h(a[0]), c, s).map(|_| 0)
        }
        nr::TIMER_CREATE => p.timer_create().map(|x| i64::from(x.0)),
        nr::TIMER_SET => p.timer_set(h(a[0]), a[1]).map(|_| 0),
        nr::TIMER_CANCEL => p.timer_cancel(h(a[0])).map(i64::from),
        nr::VMO_CREATE => p.vmo_create(a[0]).map(|x| i64::from(x.0)),
        nr::VMO_READ => p.get_vmo(h(a[0]), Rights::READ)?.0.read_to_user(a[1], a[2], a[3]).map(|_| 0),
        nr::VMO_WRITE => p.get_vmo(h(a[0]), Rights::WRITE)?.0.write_from_user(a[1], a[2], a[3]).map(|_| 0),
        nr::VMO_SIZE => p.vmo_size(h(a[0])).map(|s| s as i64),
        nr::VMAR_MAP => p
            .vmar_map(h(a[0]), offset(a[1]), h(a[2]), a[3], a[4], rights(a[5])?)
            .map(|x| x as i64),
        nr::VMAR_UNMAP => p.vmar_unmap(h(a[0]), a[1], a[2]).map(i64::from),
        nr::VMAR_ALLOCATE => {
            uaccess::write(a[4], &0u64)?; // the result pointer must be writable before anything happens
            let (hv, base) = p.vmar_allocate(h(a[0]), offset(a[1]), a[2], rights(a[3])?)?;
            if let Err(e) = uaccess::write(a[4], &base) {
                let _ = p.handle_close(hv);
                return Err(e);
            }
            Ok(i64::from(hv.0))
        }
        nr::PROCESS_CREATE => {
            let (name, n) = read_name(a[1], a[2])?;
            let limits = read_limits(a[3])?;
            uaccess::write(a[4], &0u32)?;
            let (hp, hv) = p.process_create(h(a[0]), name_str(&name[..n]), limits)?;
            if let Err(e) = uaccess::write(a[4], &hv.0) {
                let _ = p.handle_close(hv);
                if let Ok((c, _)) = p.get_process(hp, Rights::NONE) {
                    c.kill();
                }
                let _ = p.handle_close(hp);
                return Err(e);
            }
            Ok(i64::from(hp.0))
        }
        nr::PROCESS_KILL => p.process_kill(h(a[0])).map(|_| 0),
        nr::PROCESS_EXIT => {
            p.kill_with(a[0] as i32); // this thread too: it ends on the way out
            Ok(0)
        }
        nr::PROCESS_QUOTA => {
            let (l, us) = p.process_quota(h(a[0]))?;
            let q = Quota {
                limits: RawLimits { memory: l.memory, handles: l.handles, threads: l.threads },
                used: RawLimits { memory: us.memory, handles: us.handles, threads: us.threads },
            };
            uaccess::write(a[1], &q)?;
            Ok(0)
        }
        nr::PROCESS_EXIT_CODE => {
            let (c, _) = p.get_process(h(a[0]), Rights::INSPECT)?;
            c.exit_code().map(i64::from).ok_or(Status::BadState)
        }
        nr::THREAD_CREATE => {
            let (target, _) = p.get_process(h(a[0]), Rights::MANAGE)?;
            if p.is_dead() {
                return Err(Status::BadState);
            }
            let t = super::thread::start(&target, a[1], a[2], a[3], 0, false)?;
            let ht = p.add(
                crate::object::Object::Thread(t),
                crate::object::default_rights(crate::object::ObjType::Thread),
            )?;
            Ok(i64::from(ht.0))
        }
        nr::THREAD_CREATE_STOPPED => {
            // As thread_create, but the thread stops with a START exception before its first
            // instruction: its supervisor sets every register (a Linux clone child).
            let (target, _) = p.get_process(h(a[0]), Rights::MANAGE)?;
            if p.is_dead() {
                return Err(Status::BadState);
            }
            if target.exception_channel().is_none() {
                return Err(Status::BadState); // nobody would start it
            }
            let t = super::thread::start(&target, a[1], a[2], a[3], 0, true)?;
            p.add(Object::Thread(t), default_rights(ObjType::Thread)).map(|x| i64::from(x.0))
        }
        nr::PROCESS_VMAR => {
            // The root region of a process: what a supervisor needs to map memory into it (a
            // Linux mmap). MANAGE already allows reading and writing all of its memory.
            let (target, _) = p.get_process(h(a[0]), Rights::MANAGE)?;
            let v = target.root_vmar().clone();
            p.add(Object::Vmar(v), default_rights(ObjType::Vmar)).map(|x| i64::from(x.0))
        }
        nr::THREAD_EXIT => return Ok(Next::ExitThread(a[0] as i32)),
        nr::THREAD_EXIT_CODE => p.thread_exit_code(h(a[0])).map(i64::from),
        nr::SPAWN => spawn(u, a[0]),
        nr::CLOCK_NS => ok(ffi::now_ns()),
        nr::YIELD => {
            crate::thread::yield_now();
            Ok(0)
        }
        nr::CHANNEL_CREATE => ipc::channel_create(u, a[0]),
        nr::CHANNEL_WRITE => ipc::channel_write(u, a[0], a[1], a[2]),
        nr::CHANNEL_READ => ipc::channel_read(u, a[0], a[1], a[2], a[3]),
        nr::CHANNEL_CALL => ipc::channel_call(u, a[0], a[1], a[2], a[3]),
        nr::PORT_CREATE => ipc::port_create(u, a[0], a[1]),
        nr::PORT_ENTER => port_enter(u, a[0], a[1], a[2], a[3]),
        nr::OBJECT_WAIT_ASYNC => ipc::object_wait_async(u, a[0], a[1], a[2], a[3], a[4]),
        nr::PORT_CANCEL => ipc::port_cancel(u, a[0], a[1], a[2]),
        nr::PROCESS_EXCEPTION_CHANNEL => {
            let (target, _) = p.get_process(h(a[0]), Rights::MANAGE)?;
            let ch = target.create_exception_channel()?;
            p.add(Object::Channel(ch), default_rights(ObjType::Channel)).map(|x| i64::from(x.0))
        }
        nr::EXCEPTION_GET_REGS => {
            let (e, _) = p.get_exception(h(a[0]), Rights::READ)?;
            let r = e.core.regs()?;
            uaccess::write(a[1], &r)?;
            Ok(0)
        }
        nr::EXCEPTION_SET_REGS => {
            let (e, _) = p.get_exception(h(a[0]), Rights::WRITE)?;
            let r: Regs = uaccess::read(a[1])?;
            e.core.set_regs(r)?;
            Ok(0)
        }
        nr::EXCEPTION_RESUME => exception_resume(u, a[0], a[1], a[2]),
        nr::THREAD_SET_EXCEPTION_HANDLER => {
            if a[0] != 0 && (a[0] >= ffi::USER_TOP || a[1] >= ffi::USER_TOP || a[1] < ffi::USER_BASE) {
                return Err(Status::InvalidArgs);
            }
            u.handler_entry.store(a[0], core::sync::atomic::Ordering::Relaxed);
            u.handler_stack.store(if a[0] != 0 { a[1] } else { 0 }, core::sync::atomic::Ordering::Relaxed);
            Ok(0)
        }
        nr::EXCEPTION_RETURN => {
            let Some(f) = f else { return Err(Status::NotSupported) };
            exception::handler_return(u, f, a[0])?;
            return Ok(Next::Restore);
        }
        nr::THREAD_SET_BASE => {
            let w = which_base(a[0])?;
            if a[1] >= ffi::USER_TOP {
                return Err(Status::InvalidArgs); // a non-canonical base would fault in WRMSR
            }
            // SAFETY: a validated user address, the calling thread's own base.
            unsafe { ffi::uthread_set_base(w, a[1]) };
            Ok(0)
        }
        nr::THREAD_GET_BASE => {
            let w = which_base(a[0])?;
            // SAFETY: plain read of the calling thread's base.
            Ok(unsafe { ffi::uthread_get_base(w) } as i64)
        }
        nr::VMO_MAKE_EXECUTABLE => vmo_make_executable(u, a[0], a[1]),
        nr::PROCESS_READ_MEMORY => process_memory(u, a[0], a[1], a[2], a[3], false),
        nr::PROCESS_WRITE_MEMORY => process_memory(u, a[0], a[1], a[2], a[3], true),
        nr::DEVICE_INFO => device_info(u, a[0], a[1]),
        nr::DEVICE_CONFIG_READ => p.get_device(h(a[0]), Rights::READ)?.0.config_read(a[1], a[2]).map(i64::from),
        nr::DEVICE_CONFIG_WRITE => p.get_device(h(a[0]), Rights::WRITE)?.0.config_write(a[1], a[2], a[3]).map(|_| 0),
        nr::DEVICE_MAP_BAR => device_map_bar(u, a[0], a[1]),
        nr::DEVICE_IO_READ => p.get_device(h(a[0]), Rights::READ)?.0.io_read(a[1], a[2], a[3]).map(i64::from),
        nr::DEVICE_IO_WRITE => p.get_device(h(a[0]), Rights::WRITE)?.0.io_write(a[1], a[2], a[3], a[4]).map(|_| 0),
        nr::DEVICE_INTERRUPT => device_interrupt(u, a[0], a[1], a[2]),
        nr::INTERRUPT_ACK => p.get_interrupt(h(a[0]), Rights::WRITE)?.0.ack().try_into().map_err(|_| Status::BadState),
        nr::DEVICE_DMA_MAP => device_dma_map(u, a),
        nr::VMO_VERIFY => vmo_verify(u, a[0], a[1]),
        nr::VMO_ALLOW_UNSIGNED => vmo_allow_unsigned(u, a[0], a[1]),
        nr::ATTEST => attest(a[0], a[1], a[2]),
        nr::SYSTEM_POWER => system_power(u, a[0], a[1]),
        nr::MEASURE => measure(u, a[0], a[1], a[2], a[3]),
        nr::KLOG_READ => klog_read(u, a[0], a[1], a[2], a[3]),
        nr::LOG_RECORD => log_record(u, a[0], a[1], a[2], a[3]),
        nr::DISPLAY_INFO => display_info(u, a[0], a[1]),
        nr::PROCESS_HANDLES => process_handles(u, a[0], a[1], a[2]),
        #[cfg(ktest)]
        nr::KTEST_SMAP => {
            // SAFETY: test builds only: makes the kernel fault on purpose (SMAP).
            unsafe { ffi::ktest_user_smap(a[0]) };
            Ok(0)
        }
        #[cfg(ktest)]
        nr::KTEST_SMEP => {
            // SAFETY: as above (SMEP).
            unsafe { ffi::ktest_user_smep(a[0]) };
            Ok(0)
        }
        _ => Err(Status::NotSupported),
    };
    r.map(Next::Return)
}

/// Called by syscall_entry (syscall.asm) with interrupts on, on the thread's kernel stack.
/// Nothing that needs dropping is alive here when the thread exits. Returns 0 to go back with
/// SYSRET (RAX = result), 1 to go back with IRETQ (every register from the frame).
///
/// # Safety
/// Only called by syscall_entry, with the frame it built.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn syscall_dispatch(f: *mut Frame) -> u64 {
    // SAFETY: syscall_entry passes the frame it built on this thread's stack.
    let f = unsafe { &mut *f };
    let t0 = if ffi::profiling() { ffi::now_ns() } else { 0 };
    let mut restore = 0;
    match current() {
        Some(u) if u.proc.forwards_syscalls() => {
            exception::forward_syscall(u, f);
            restore = 1;
        }
        Some(u) => {
            let args = [f.rdi, f.rsi, f.rdx, f.r10, f.r8, f.r9];
            let n = f.rax;
            match sys_frame(u, n, args, Some(&mut *f)).unwrap_or_else(|e| Next::Return(e as i32 as i64)) {
                Next::Return(v) => f.rax = v as u64,
                Next::Restore => restore = 1,
                // SAFETY: the thread's own exit; no Rust state is alive in this frame.
                Next::ExitThread(code) => unsafe { ffi::uthread_exit(code as c_int) },
            }
        }
        None => f.rax = Status::BadState as i32 as i64 as u64,
    }
    if t0 != 0 {
        // SAFETY: a static histogram, updated with atomics on the C side.
        unsafe { ffi::lat_record(&raw mut ffi::lat_syscall, ffi::now_ns().saturating_sub(t0)) };
    }
    // SAFETY: plain read of the current thread's kill flag.
    if unsafe { ffi::thread_kill_pending() } {
        // SAFETY: as above.
        unsafe { ffi::uthread_exit(ffi::UTHREAD_EXIT_KILLED) }
    }
    restore
}
