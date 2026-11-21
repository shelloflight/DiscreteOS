//! Program loader and `spawn`: a new process from an ELF image in a VMO, with an explicit set of
//! handles and nothing else.
//!
//! Layout of a new process (all placements randomized, see `Vmar`):
//! - the image: one region for the whole span; a VMO per PT_LOAD (copied from the image, so the
//!   image VMO can be reused or changed without affecting the process); ET_DYN images at a random
//!   base with their RELATIVE relocations applied before anything is mapped; code mapped R-X
//!   (its VMO is the only kind marked executable), data RW-, the RELRO part read-only;
//! - a stack (`STACK_SIZE`, RW, never executable) with an unmapped guard page on each side;
//! - with CET, for an image that asks for it (ELF property SHSTK): a shadow stack per thread
//!   (user/thread.rs);
//! - the startup block at the top of the stack (`Startup`, docs/abi.md): ABI version, the
//!   arguments and the startup handles (own process, own thread, root VMAR, then the ones the
//!   spawner passed, each with its tag). RDI points at it.
//!
//! The process gets no handle to its image or stack regions, so it cannot remap its own code.
//! Everything is charged to the new process's quota (and so to its parent's).

use alloc::vec::Vec;

use super::elf::{self, ElfError, PF_W, PF_X, Source};
use crate::ffi::{USER_BASE, USER_TOP};
use crate::object::quota::Limits;
use crate::object::vmar::Placement;
use crate::object::{ChannelObj, KRef, KResult, ObjType, Object, Process, Rights, Status, ThreadObj, Vmo, default_rights};

const PAGE: u64 = 4096;
pub const STACK_SIZE: u64 = 256 * 1024;
pub const MAX_ARGS: usize = 4096;
/// Handles a spawner may pass (on top of the child's own three). 256: init alone gets one per
/// device, and a real PC has 50+ PCI functions (the first real-hardware boot had 50).
/// The startup block holds them in 8 bytes each on the 256 KiB stack.
pub const MAX_HANDLES: usize = 256;

/// ABI version (docs/abi.md): 2 added IPC, ports and exceptions; 3 added devices for user-space
/// drivers. A program built for version N runs on any kernel whose
/// version is at least N.
pub const ABI_VERSION: u32 = 15;
pub const STARTUP_MAGIC: u32 = 0x5353_4F44; // "DOSS"

/// Startup handle tags (docs/abi.md).
pub mod tag {
    pub const PROC_SELF: u32 = 1;
    pub const THREAD_SELF: u32 = 2;
    pub const VMAR_ROOT: u32 = 3;
    pub const LOG: u32 = 4;
    pub const PROGRAM: u32 = 5;
    pub const VMEX: u32 = 6;
    /// A device: init gets every one, the device manager what init passes on.
    pub const DEVICE: u32 = 7;
    /// The POWER resource (ABI v6): init only.
    pub const POWER: u32 = 8;
    /// The MEASURE resource (ABI v7): init only.
    pub const MEASURE: u32 = 9;
    /// A service manifest embedded in the kernel image (ABI v7, `<name>.dman`, read-only): init only.
    pub const MANIFEST: u32 = 10;
    /// The KLOG resource (ABI v8): init only (it grants it to the log service).
    pub const KLOG: u32 = 11;
    /// The boot-time record (ABI v8, a 32-byte read-only VMO): init only, if the loader left one.
    pub const BOOT_TIME: u32 = 12;
    /// The power-button event (ABI v11): signaled on each press of the machine's power button
    /// (ACPI fixed event or a PNP0C0C device's Notify). init only.
    pub const POWER_BUTTON: u32 = 13;
}

struct VmoSource<'a>(&'a Vmo);

impl Source for VmoSource<'_> {
    fn size(&self) -> u64 {
        self.0.size()
    }
    fn read(&self, off: u64, buf: &mut [u8]) -> bool {
        self.0.read(off, buf).is_ok()
    }
}

pub struct Spawn<'a> {
    pub parent: KRef<Process>,
    pub image: KRef<Vmo>,
    pub name: &'a str,
    pub args: &'a [u8],
    /// (object, rights, tag), moved into the new process.
    pub handles: Vec<(Object, Rights, u32)>,
    pub limits: Limits,
    /// Create an exception channel (its supervisor end is returned).
    pub exception_channel: bool,
    /// FORWARD syscall personality (needs `exception_channel`).
    pub forward: bool,
    /// The first thread stops with a START exception before its first instruction (needs
    /// `exception_channel`).
    pub start_exception: bool,
}

#[derive(Debug)]
pub enum SpawnError {
    Elf(ElfError),
    Status(Status),
}

impl From<Status> for SpawnError {
    fn from(s: Status) -> Self {
        SpawnError::Status(s)
    }
}

impl SpawnError {
    pub fn status(&self) -> Status {
        match self {
            SpawnError::Elf(_) => Status::InvalidArgs,
            SpawnError::Status(s) => *s,
        }
    }
}

/// Create, load and start a process from a trusted image (see `security::Trust`). On failure nothing is left behind (the handles passed in
/// are closed). Returns the process and, if asked for, the supervisor end of its exception
/// channel (made before the first thread runs, so no exception can miss it).
pub fn spawn(req: Spawn<'_>) -> Result<(KRef<Process>, Option<KRef<ChannelObj>>), SpawnError> {
    if req.args.len() > MAX_ARGS || req.handles.len() > MAX_HANDLES || ((req.forward || req.start_exception) && !req.exception_channel) {
        return Err(Status::InvalidArgs.into());
    }
    // Code signing: only images the kernel trusts run: signed, part of the kernel, or
    // allowed unsigned by a VMEX holder. Checked before the image is even parsed.
    if req.image.trust() == crate::security::Trust::None {
        return Err(Status::NotSigned.into());
    }
    let src = VmoSource(&req.image);
    let img = elf::parse(&src, USER_BASE, USER_TOP).map_err(SpawnError::Elf)?;
    let child = Process::new(Some(&req.parent), req.name, req.limits)?;
    let exc = if req.exception_channel {
        match child.create_exception_channel() {
            Ok(c) => Some(c),
            Err(e) => {
                child.kill();
                return Err(e.into());
            }
        }
    } else {
        None
    };
    if req.forward {
        child.set_forward();
    }
    // Shadow stacks when the image asks for them (`-z shstk`) and the CPU has them. Not for a
    // process whose supervisor runs a foreign personality (FORWARD, or a START stop that sets
    // the first registers): those programs move between frames in ways the kernel cannot
    // follow on a shadow stack.
    // SAFETY: plain read of a flag set once at boot.
    let cet = unsafe { crate::ffi::cet_ss };
    if cet && img.x86_features & elf::FEATURE_1_SHSTK != 0 && !req.forward && !req.start_exception {
        child.set_shadow_stacks();
    }
    match load(&child, &img, &src, req.args, req.handles, req.start_exception) {
        Ok(()) => Ok((child, exc)),
        Err(e) => {
            child.kill();
            Err(e)
        }
    }
}

fn copy_vmo(dst: &Vmo, dst_off: u64, src: &Vmo, src_off: u64, len: u64, buf: &mut [u8]) -> KResult<()> {
    let mut done = 0;
    while done < len {
        let n = (len - done).min(buf.len() as u64) as usize;
        src.read(src_off + done, &mut buf[..n])?;
        dst.write(dst_off + done, &buf[..n])?;
        done += n as u64;
    }
    Ok(())
}

fn load(
    child: &KRef<Process>,
    img: &elf::Image,
    src: &VmoSource<'_>,
    args: &[u8],
    handles: Vec<(Object, Rights, u32)>,
    start_exception: bool,
) -> Result<(), SpawnError> {
    let root = child.root_vmar();
    let span = img.hi - img.lo;
    let fixed = (!img.dynamic).then(|| img.lo - USER_BASE);
    let region = match fixed {
        Some(off) => root.allocate(Some(off), span)?,
        None => root.allocate_at(Placement::Random, span)?,
    };
    let bias = region.base().wrapping_sub(img.lo);

    // Segments: copy, relocate, then map.
    let mut buf = Vec::new();
    buf.try_reserve_exact(PAGE as usize).map_err(|_| Status::NoMemory)?;
    buf.resize(PAGE as usize, 0u8);
    let mut vmos: Vec<KRef<Vmo>> = Vec::new();
    vmos.try_reserve_exact(img.nseg).map_err(|_| Status::NoMemory)?;
    for s in &img.segs[..img.nseg] {
        let v = Vmo::create_named(child.account(), s.page_end() - s.page_start(), child.name())?;
        copy_vmo(&v, s.vaddr - s.page_start(), src.0, s.offset, s.filesz, &mut buf)?;
        vmos.push(v);
    }
    img.relocations(src, bias, |seg, off, value| vmos[seg].write(off, &value.to_le_bytes()).is_ok())
        .map_err(SpawnError::Elf)?;
    for (s, v) in img.segs[..img.nseg].iter().zip(&vmos) {
        let mut perms = Rights::READ;
        if s.flags & PF_W != 0 {
            perms = perms | Rights::WRITE;
        }
        if s.flags & PF_X != 0 {
            perms = perms | Rights::EXECUTE;
            v.make_executable()?; // sealed: final contents, never writable again
        }
        let (ps, pe) = (s.page_start(), s.page_end());
        // Pieces: [ps, rs) segment perms, [rs, re) read-only (RELRO), [re, pe) segment perms.
        let (rs, re) = match img.relro {
            Some((a, b)) if a >= ps && b <= pe => (a, b),
            _ => (pe, pe),
        };
        for (a, b, p) in [(ps, rs, perms), (rs, re, Rights::READ), (re, pe, perms)] {
            if a < b {
                region.map(Some(a - img.lo), v.clone(), a - ps, b - a, p)?;
            }
        }
    }
    drop(vmos);

    // Stack with a guard page below and above.
    let stack_region = root.allocate_at(Placement::Random, STACK_SIZE + 2 * PAGE)?;
    let stack = Vmo::create_named(child.account(), STACK_SIZE, child.name())?;
    let stack_base = stack_region.map(Some(PAGE), stack.clone(), 0, STACK_SIZE, Rights::READ | Rights::WRITE)?;
    let stack_top = stack_base + STACK_SIZE;

    // Startup handles: the kernel's three, then the spawner's.
    let thread = ThreadObj::new(child.name())?;
    let mut entries: Vec<(u32, u32)> = Vec::new();
    entries
        .try_reserve_exact(3 + handles.len())
        .map_err(|_| Status::NoMemory)?;
    let hp = child.add(Object::Process(child.clone()), default_rights(ObjType::Process))?;
    entries.push((hp.0, tag::PROC_SELF));
    let ht = child.add(Object::Thread(thread.clone()), default_rights(ObjType::Thread))?;
    entries.push((ht.0, tag::THREAD_SELF));
    let hv = child.add(Object::Vmar(root.clone()), default_rights(ObjType::Vmar))?;
    entries.push((hv.0, tag::VMAR_ROOT));
    for (obj, rights, t) in handles {
        let h = child.add(obj, rights)?;
        entries.push((h.0, t));
    }

    // Startup block (layout: docs/abi.md, struct dos_startup in user/include/dos.h).
    let head = 48 + 8 * entries.len();
    let total = (head + args.len() + 1).div_ceil(16) * 16;
    let block = stack_top - total as u64;
    let mut b = Vec::new();
    b.try_reserve_exact(total).map_err(|_| Status::NoMemory)?;
    b.resize(total, 0u8);
    let put32 = |b: &mut Vec<u8>, at: usize, v: u32| b[at..at + 4].copy_from_slice(&v.to_le_bytes());
    let put64 = |b: &mut Vec<u8>, at: usize, v: u64| b[at..at + 8].copy_from_slice(&v.to_le_bytes());
    put32(&mut b, 0, STARTUP_MAGIC);
    put32(&mut b, 4, ABI_VERSION);
    put32(&mut b, 8, entries.len() as u32);
    put32(&mut b, 12, args.len() as u32);
    put64(&mut b, 16, block + head as u64);
    put64(&mut b, 24, bias);
    put64(&mut b, 32, stack_base);
    put64(&mut b, 40, STACK_SIZE);
    for (i, (h, t)) in entries.iter().enumerate() {
        put32(&mut b, 48 + 8 * i, *h);
        put32(&mut b, 52 + 8 * i, *t);
    }
    b[head..head + args.len()].copy_from_slice(args);
    stack.write(STACK_SIZE - total as u64, &b)?;

    super::thread::start_with(child, thread, img.entry.wrapping_add(bias), block, block, 0, start_exception)?;
    Ok(())
}
