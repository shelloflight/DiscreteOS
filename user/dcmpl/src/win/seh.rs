//! Structured exception handling for Windows programs (x64 SEH), in this process.
//!
//! Windows x64 has no exception frames on the stack: every non-leaf function has a
//! `RUNTIME_FUNCTION` entry in the image's exception table (`.pdata`) pointing at unwind codes
//! that describe its prologue, and optionally at a language handler (`__C_specific_handler` for
//! `__try`, `__CxxFrameHandler4` for C++). This module is the part of `ntdll` that walks them:
//!
//! - `virtual_unwind` (`RtlVirtualUnwind`): undo one frame's prologue on a `CONTEXT` (pushes,
//!   allocations, frame register, saved registers, machine frames; chained entries; a PC inside
//!   an epilogue is unwound by decoding the epilogue's instructions instead);
//! - `dispatch` (`RtlDispatchException`): first pass, frame by frame from the exception, asking
//!   each language handler (filters run here) until one handles it;
//! - `unwind` (`RtlUnwindEx`): second pass, running termination handlers (`__finally`,
//!   destructors) up to the target frame, then resuming there; `STATUS_UNWIND_CONSOLIDATE`
//!   (C++ `catch`) calls the consolidation callback first, which runs the catch block.
//!
//! Sources of an exception: a CPU fault (the kernel calls this thread's in-process handler,
//! `fault_entry`, on its own stack: `thread_set_exception_handler`) or `RaiseException`. Resuming
//! after a fault goes through `exception_return` (the kernel ends the handler), after a raised
//! exception through `restore` (registers loaded directly).
//!
//! Every read of unwind data is checked against the image, every read of a stack slot against the
//! thread's stack: bad data stops the walk (the exception is then unhandled), it never makes
//! D-CMPL read outside them. Not supported: collided unwinds, rethrowing from inside a C++ catch
//! block that was entered from a fault, vectored handlers.

use core::arch::global_asm;

use libd::sys;

use super::{current_thread, image, println_unhandled};

pub const CONTEXT_SIZE: usize = 0x4D0;

/// `CONTEXT` (x64): 0x4D0 bytes, 16-byte aligned. Integer registers at 0x78 + 8 * n in the
/// unwind codes' order (RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI, R8..R15), RIP at 0xF8, the
/// FXSAVE area at 0x100 (XMM n at 0x1A0 + 16 * n).
#[repr(C, align(16))]
#[derive(Clone, Copy)]
pub struct Context(pub [u64; CONTEXT_SIZE / 8]);

const C_RAX: usize = 0x78 / 8;
pub const C_RSP: usize = 4;
const C_RIP: usize = 0xF8 / 8;
const C_FLAGS_OFF: usize = 0x30;
const C_EFLAGS_OFF: usize = 0x44;
const C_FX: usize = 0x100;
const C_XMM: usize = 0x1A0;
pub const CONTEXT_FULL: u32 = 0x10_000F;

impl Context {
    pub const fn zero() -> Context {
        Context([0; CONTEXT_SIZE / 8])
    }
    pub fn gpr(&self, n: usize) -> u64 {
        self.0[C_RAX + (n & 15)]
    }
    pub fn set_gpr(&mut self, n: usize, v: u64) {
        self.0[C_RAX + (n & 15)] = v;
    }
    pub fn rsp(&self) -> u64 {
        self.gpr(C_RSP)
    }
    pub fn set_rsp(&mut self, v: u64) {
        self.set_gpr(C_RSP, v);
    }
    pub fn rip(&self) -> u64 {
        self.0[C_RIP]
    }
    pub fn set_rip(&mut self, v: u64) {
        self.0[C_RIP] = v;
    }
    pub fn eflags(&self) -> u32 {
        u32::from_le_bytes(self.bytes()[C_EFLAGS_OFF..C_EFLAGS_OFF + 4].try_into().unwrap_or([0; 4]))
    }
    pub fn bytes(&self) -> &[u8] {
        // SAFETY: plain data, CONTEXT_SIZE bytes.
        unsafe { core::slice::from_raw_parts(self.0.as_ptr().cast::<u8>(), CONTEXT_SIZE) }
    }
    pub fn bytes_mut(&mut self) -> &mut [u8] {
        // SAFETY: as above.
        unsafe { core::slice::from_raw_parts_mut(self.0.as_mut_ptr().cast::<u8>(), CONTEXT_SIZE) }
    }
    fn set_xmm(&mut self, n: usize, v: [u8; 16]) {
        let at = C_XMM + 16 * (n & 15);
        self.bytes_mut()[at..at + 16].copy_from_slice(&v);
    }
    /// Fill the fixed fields: flags, segment selectors, EFlags.
    pub fn set_header(&mut self, eflags: u32) {
        let b = self.bytes_mut();
        b[C_FLAGS_OFF..C_FLAGS_OFF + 4].copy_from_slice(&CONTEXT_FULL.to_le_bytes());
        for (off, sel) in [(0x38, 0x33u16), (0x3A, 0x2B), (0x3C, 0x2B), (0x3E, 0x53), (0x40, 0x2B), (0x42, 0x2B)] {
            b[off..off + 2].copy_from_slice(&sel.to_le_bytes());
        }
        b[C_EFLAGS_OFF..C_EFLAGS_OFF + 4].copy_from_slice(&eflags.to_le_bytes());
    }
}

/// `EXCEPTION_RECORD` (0x98 bytes).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExcRecord {
    pub code: u32,
    pub flags: u32,
    pub record: u64,
    pub address: u64,
    pub nparams: u32,
    pub pad: u32,
    pub info: [u64; 15],
}
const _: () = assert!(core::mem::size_of::<ExcRecord>() == 0x98);

impl ExcRecord {
    pub const fn new(code: u32, flags: u32, address: u64) -> ExcRecord {
        ExcRecord { code, flags, record: 0, address, nparams: 0, pad: 0, info: [0; 15] }
    }
}

/// `DISPATCHER_CONTEXT` (x64).
#[repr(C)]
struct DispatcherContext {
    control_pc: u64,
    image_base: u64,
    function_entry: u64,
    establisher_frame: u64,
    target_ip: u64,
    context: *mut Context,
    language_handler: u64,
    handler_data: u64,
    history_table: u64,
    scope_index: u32,
    fill0: u32,
}

pub const EXCEPTION_NONCONTINUABLE: u32 = 0x1;
const EH_UNWINDING: u32 = 0x2;
const EH_EXIT_UNWIND: u32 = 0x4;
const EH_TARGET_UNWIND: u32 = 0x20;
const EH_COLLIDED_UNWIND: u32 = 0x40;
const UNW_FLAG_EHANDLER: u32 = 1;
const UNW_FLAG_UHANDLER: u32 = 2;
const UNW_FLAG_CHAININFO: u32 = 4;

pub const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
pub const STATUS_BREAKPOINT: u32 = 0x8000_0003;
pub const STATUS_UNWIND: u32 = 0xC000_0027;
pub const STATUS_UNWIND_CONSOLIDATE: u32 = 0x8000_0029;
pub const STATUS_NONCONTINUABLE_EXCEPTION: u32 = 0xC000_0025;

const DISPOSITION_CONTINUE_EXECUTION: u32 = 0;

/// `RUNTIME_FUNCTION`.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct RtFn {
    pub begin: u32,
    pub end: u32,
    pub unwind: u32,
}

// ---- checked reads ----------------------------------------------------------------------------

/// Bytes of the loaded image at `rva` (inside the image), or None.
fn img_bytes<const N: usize>(rva: u64) -> Option<[u8; N]> {
    let im = image();
    if rva.checked_add(N as u64)? > im.size {
        return None;
    }
    let mut b = [0u8; N];
    // SAFETY: inside the mapped image (every page of it is mapped readable by the loader).
    unsafe { core::ptr::copy_nonoverlapping((im.base + rva) as *const u8, b.as_mut_ptr(), N) };
    Some(b)
}
fn img_u8(rva: u64) -> Option<u8> {
    img_bytes::<1>(rva).map(|b| b[0])
}
fn img_u16(rva: u64) -> Option<u16> {
    img_bytes::<2>(rva).map(u16::from_le_bytes)
}
fn img_u32(rva: u64) -> Option<u32> {
    img_bytes::<4>(rva).map(u32::from_le_bytes)
}
fn img_rtfn(rva: u64) -> Option<RtFn> {
    Some(RtFn { begin: img_u32(rva)?, end: img_u32(rva + 4)?, unwind: img_u32(rva + 8)? })
}

/// A word of the current thread's stack at `addr`, or None outside it.
fn stack_u64(addr: u64) -> Option<u64> {
    let t = current_thread()?;
    if addr < t.stack_lo || addr.checked_add(8)? > t.stack_hi || !addr.is_multiple_of(8) {
        return None;
    }
    // SAFETY: inside the thread's own stack mapping (checked).
    Some(unsafe { (addr as *const u64).read() })
}
fn stack_16(addr: u64) -> Option<[u8; 16]> {
    let lo = stack_u64(addr)?;
    let hi = stack_u64(addr + 8)?;
    let mut b = [0u8; 16];
    b[..8].copy_from_slice(&lo.to_le_bytes());
    b[8..].copy_from_slice(&hi.to_le_bytes());
    Some(b)
}
fn in_stack(addr: u64) -> bool {
    current_thread().is_some_and(|t| addr >= t.stack_lo && addr <= t.stack_hi)
}

// ---- lookup -------------------------------------------------------------------------------------

/// The function-table entry covering `pc` (binary search of the image's `.pdata`): its RVA.
pub fn lookup(pc: u64) -> Option<u64> {
    let im = image();
    if pc < im.base || pc >= im.base + im.size || im.pdata_count == 0 {
        return None;
    }
    let rva = (pc - im.base) as u32;
    let (mut lo, mut hi) = (0u64, im.pdata_count);
    while lo < hi {
        let mid = (lo + hi) / 2;
        let at = u64::from(im.pdata_rva) + 12 * mid;
        let e = img_rtfn(at)?;
        if rva < e.begin {
            hi = mid;
        } else if rva >= e.end {
            lo = mid + 1;
        } else {
            return Some(at);
        }
    }
    None
}

// ---- virtual unwind -----------------------------------------------------------------------------

/// Where each non-volatile register was restored from (`KNONVOLATILE_CONTEXT_POINTERS`: 16 XMM
/// pointers, then 16 integer pointers), if the caller wants them.
pub type Ptrs = [u64; 32];

pub struct Unwound {
    pub handler: u64,
    pub data: u64,
    pub frame: u64,
}

/// Undo the prologue of the function `fe` (entry RVA) at `pc` on `ctx`: afterwards `ctx` is the
/// caller's context. Returns the language handler of type `ty` (0: none), its data and the
/// establisher frame. None: the unwind data is bad or leaves the stack.
pub fn virtual_unwind(ty: u32, pc: u64, fe_rva: u64, ctx: &mut Context, mut ptrs: Option<&mut Ptrs>) -> Option<Unwound> {
    let base = image().base;
    let mut fe = img_rtfn(fe_rva)?;
    if fe.unwind & 1 != 0 {
        fe = img_rtfn(u64::from(fe.unwind & !1))?; // an indirect entry
    }
    let pc_off = (pc - base).checked_sub(u64::from(fe.begin))?;
    let hdr = img_bytes::<4>(u64::from(fe.unwind))?;
    let (prolog, count) = (u64::from(hdr[1]), u64::from(hdr[2]));
    let (freg, foff) = (usize::from(hdr[3] & 15), u64::from(hdr[3] >> 4));
    let in_prolog = pc_off < prolog;
    let codes = u64::from(fe.unwind) + 4;
    // The establisher frame: the frame register's value (minus its offset) once the prologue
    // has set it, else RSP.
    let fp_set = freg != 0
        && (!in_prolog || (0..count).any(|i| img_u8(codes + 2 * i + 1).is_some_and(|op| op & 15 == 3) && img_u8(codes + 2 * i).is_some_and(|o| u64::from(o) <= pc_off)));
    let frame = if fp_set { ctx.gpr(freg).wrapping_sub(foff * 16) } else { ctx.rsp() };

    if !in_prolog && is_inside_epilog(pc, &fe) {
        interpret_epilog(pc, ctx, ptrs)?;
        return Some(Unwound { handler: 0, data: 0, frame });
    }

    let mut info_rva = u64::from(fe.unwind);
    let mut primary = true;
    let mut machframe = false;
    let flags;
    loop {
        let h = img_bytes::<4>(info_rva)?;
        let (ver, fl, count) = (h[0] & 7, u32::from(h[0] >> 3), u64::from(h[2]));
        let (freg, foff) = (usize::from(h[3] & 15), u64::from(h[3] >> 4));
        if ver != 1 && ver != 2 {
            return None;
        }
        let codes = info_rva + 4;
        let mut i = 0u64;
        while i < count {
            let off = u64::from(img_u8(codes + 2 * i)?);
            let opb = img_u8(codes + 2 * i + 1)?;
            let (op, info) = (opb & 15, usize::from(opb >> 4));
            let slot16 = |k: u64| img_u16(codes + 2 * (i + k));
            let slots = match op {
                1 if info == 0 => 2,
                1 => 3,
                4 | 8 => 2,
                5 | 9 => 3,
                6 if ver == 1 => 2,
                6 => 1,
                7 if ver == 1 => 3,
                7 => return None,
                _ => 1,
            };
            if primary && in_prolog && pc_off < off {
                i += slots; // this prologue instruction has not run yet
                continue;
            }
            match op {
                0 => {
                    // PUSH_NONVOL
                    let at = ctx.rsp();
                    ctx.set_gpr(info, stack_u64(at)?);
                    if let Some(p) = ptrs.as_deref_mut() {
                        p[16 + info] = at;
                    }
                    ctx.set_rsp(at + 8);
                }
                1 => {
                    // ALLOC_LARGE
                    let size = if info == 0 {
                        u64::from(slot16(1)?) * 8
                    } else {
                        u64::from(slot16(1)?) | u64::from(slot16(2)?) << 16
                    };
                    ctx.set_rsp(ctx.rsp().checked_add(size)?);
                }
                2 => ctx.set_rsp(ctx.rsp() + info as u64 * 8 + 8), // ALLOC_SMALL
                3 => ctx.set_rsp(ctx.gpr(freg).wrapping_sub(foff * 16)), // SET_FPREG
                4 | 5 => {
                    // SAVE_NONVOL(_FAR)
                    let off = if op == 4 { u64::from(slot16(1)?) * 8 } else { u64::from(slot16(1)?) | u64::from(slot16(2)?) << 16 };
                    let at = frame.checked_add(off)?;
                    ctx.set_gpr(info, stack_u64(at)?);
                    if let Some(p) = ptrs.as_deref_mut() {
                        p[16 + info] = at;
                    }
                }
                8 | 9 => {
                    // SAVE_XMM128(_FAR)
                    let off = if op == 8 { u64::from(slot16(1)?) * 16 } else { u64::from(slot16(1)?) | u64::from(slot16(2)?) << 16 };
                    let at = frame.checked_add(off)?;
                    ctx.set_xmm(info, stack_16(at)?);
                    if let Some(p) = ptrs.as_deref_mut() {
                        p[info] = at;
                    }
                }
                10 => {
                    // PUSH_MACHFRAME: RIP, CS, EFLAGS, RSP, SS (after an error code if info = 1)
                    let at = ctx.rsp() + if info == 1 { 8 } else { 0 };
                    let rip = stack_u64(at)?;
                    let rsp = stack_u64(at + 24)?;
                    ctx.set_rip(rip);
                    ctx.set_rsp(rsp);
                    machframe = true;
                }
                _ => {} // version 1 SAVE_XMM(_FAR), version 2 EPILOG markers
            }
            i += slots;
        }
        if fl & UNW_FLAG_CHAININFO == 0 {
            flags = fl;
            break;
        }
        let chained = img_rtfn(codes + 2 * ((count + 1) & !1))?;
        info_rva = u64::from(chained.unwind & !1);
        primary = false;
    }
    if !machframe {
        let at = ctx.rsp();
        ctx.set_rip(stack_u64(at)?);
        ctx.set_rsp(at + 8);
    }
    let codes_end = info_rva + 4 + 2 * ((u64::from(img_u8(info_rva + 2)?) + 1) & !1);
    if flags & ty == 0 || in_prolog {
        return Some(Unwound { handler: 0, data: 0, frame });
    }
    let h = img_u32(codes_end)?;
    Some(Unwound { handler: base + u64::from(h), data: base + codes_end + 4, frame })
}

/// Is `pc` inside an epilogue of `fe` (an optional `add rsp`/`lea rsp`, pops, then `ret` or a
/// jump out of the function)?
fn is_inside_epilog(pc: u64, fe: &RtFn) -> bool {
    let base = image().base;
    let Some(mut at) = pc.checked_sub(base) else { return false };
    let b = |a: u64| img_u8(a);
    let (Some(b0), Some(b1)) = (b(at), b(at + 1)) else { return false };
    if b0 & 0xF8 == 0x48 {
        match b1 {
            0x81 if b0 == 0x48 && b(at + 2) == Some(0xC4) => at += 7,
            0x83 if b0 == 0x48 && b(at + 2) == Some(0xC4) => at += 4,
            0x8D => {
                let Some(m) = b(at + 2) else { return false };
                if b0 & 0x06 != 0 || (m >> 3) & 7 != 4 || m & 7 == 4 {
                    return false;
                }
                match m >> 6 {
                    1 => at += 4,
                    2 => at += 7,
                    _ => return false,
                }
            }
            0x81 | 0x83 => return false,
            _ => {}
        }
    }
    for _ in 0..32 {
        let Some(mut c) = b(at) else { return false };
        if c & 0xF0 == 0x40 {
            at += 1;
            let Some(n) = b(at) else { return false };
            c = n;
        }
        match c {
            0x58..=0x5F => {
                at += 1;
                continue;
            }
            0xC2 | 0xC3 => return true,
            0xE9 => {
                let Some(d) = img_u32(at + 1) else { return false };
                let t = (at + 5).wrapping_add(i64::from(d as i32) as u64);
                return !(t >= u64::from(fe.begin) && t < u64::from(fe.end));
            }
            0xEB => {
                let Some(d) = b(at + 1) else { return false };
                let t = (at + 2).wrapping_add(i64::from(d as i8) as u64);
                return !(t >= u64::from(fe.begin) && t < u64::from(fe.end));
            }
            0xF3 => return b(at + 1) == Some(0xC3),
            0xFF => return b(at + 1).is_some_and(|m| (m >> 3) & 7 == 4), // jmp [mem]: a tail call
            _ => return false,
        }
    }
    false
}

/// Unwind through the epilogue at `pc` by doing what its instructions do.
fn interpret_epilog(pc: u64, ctx: &mut Context, mut ptrs: Option<&mut Ptrs>) -> Option<()> {
    let base = image().base;
    let mut at = pc - base;
    for _ in 0..40 {
        let mut c = img_u8(at)?;
        let mut rex = 0u8;
        if c & 0xF0 == 0x40 {
            rex = c & 15;
            at += 1;
            c = img_u8(at)?;
        }
        match c {
            0x58..=0x5F => {
                let reg = usize::from(c - 0x58) + usize::from(rex & 1) * 8;
                let sp = ctx.rsp();
                ctx.set_gpr(reg, stack_u64(sp)?);
                if let Some(p) = ptrs.as_deref_mut() {
                    p[16 + reg] = sp;
                }
                ctx.set_rsp(sp + 8);
                at += 1;
            }
            0x81 => {
                ctx.set_rsp(ctx.rsp().wrapping_add(i64::from(img_u32(at + 2)? as i32) as u64));
                at += 6;
            }
            0x83 => {
                ctx.set_rsp(ctx.rsp().wrapping_add(i64::from(img_u8(at + 2)? as i8) as u64));
                at += 3;
            }
            0x8D => {
                let m = img_u8(at + 1)?;
                let reg = usize::from(m & 7) + usize::from(rex & 1) * 8;
                if m >> 6 == 1 {
                    ctx.set_rsp(ctx.gpr(reg).wrapping_add(i64::from(img_u8(at + 2)? as i8) as u64));
                    at += 3;
                } else {
                    ctx.set_rsp(ctx.gpr(reg).wrapping_add(i64::from(img_u32(at + 2)? as i32) as u64));
                    at += 6;
                }
            }
            0xC2 => {
                let sp = ctx.rsp();
                ctx.set_rip(stack_u64(sp)?);
                ctx.set_rsp(sp + 8 + u64::from(img_u16(at + 1)?));
                return Some(());
            }
            0xC3 | 0xE9 | 0xEB | 0xF3 | 0xFF => {
                let sp = ctx.rsp();
                ctx.set_rip(stack_u64(sp)?);
                ctx.set_rsp(sp + 8);
                return Some(());
            }
            _ => return None,
        }
    }
    None
}

/// One frame up from `ctx` (also leaf functions, which have no entry): (entry RVA, unwound).
fn step(ty: u32, ctx: &mut Context, ptrs: Option<&mut Ptrs>) -> Option<(u64, Unwound)> {
    let pc = ctx.rip();
    let im = image();
    if pc < im.base || pc >= im.base + im.size {
        return None; // outside the program (D-CMPL's own code, or the thread's start): the end
    }
    match lookup(pc) {
        Some(fe) => {
            let u = virtual_unwind(ty, pc, fe, ctx, ptrs)?;
            Some((fe, u))
        }
        None => {
            // A leaf function: only the return address is on the stack.
            let sp = ctx.rsp();
            ctx.set_rip(stack_u64(sp)?);
            ctx.set_rsp(sp + 8);
            Some((0, Unwound { handler: 0, data: 0, frame: sp }))
        }
    }
}

type Handler = extern "win64" fn(*mut ExcRecord, u64, *mut Context, *mut DispatcherContext) -> u32;

fn call_handler(h: u64, rec: *mut ExcRecord, frame: u64, ctx: *mut Context, dc: *mut DispatcherContext) -> u32 {
    // SAFETY: a language handler named by the image's own unwind data (inside the image).
    let f: Handler = unsafe { core::mem::transmute::<u64, Handler>(h) };
    f(rec, frame, ctx, dc)
}

/// First pass: true if a handler said "continue execution" (with `orig` possibly changed).
fn dispatch(rec: &mut ExcRecord, orig: &mut Context) -> bool {
    let mut ctx = *orig;
    for _ in 0..4096 {
        let pc = ctx.rip();
        let mut next = ctx;
        let Some((fe, u)) = step(UNW_FLAG_EHANDLER, &mut next, None) else { return false };
        if !u.frame.is_multiple_of(8) || !in_stack(u.frame) {
            return false;
        }
        if u.handler != 0 {
            let mut dc = DispatcherContext {
                control_pc: pc,
                image_base: image().base,
                function_entry: image().base + fe,
                establisher_frame: u.frame,
                target_ip: 0,
                context: &raw mut ctx,
                language_handler: u.handler,
                handler_data: u.data,
                history_table: 0,
                scope_index: 0,
                fill0: 0,
            };
            if call_handler(u.handler, rec, u.frame, orig, &raw mut dc) == DISPOSITION_CONTINUE_EXECUTION {
                if rec.flags & EXCEPTION_NONCONTINUABLE != 0 {
                    return false;
                }
                return true;
            }
        }
        ctx = next;
    }
    false
}

/// Second pass (`RtlUnwindEx`) from `start`: termination handlers up to `target_frame`, then
/// resume at `target_ip` with RAX = `retval`. Never returns.
fn unwind(start: Context, target_frame: u64, target_ip: u64, rec: Option<&mut ExcRecord>, retval: u64) -> ! {
    let mut own = ExcRecord::new(STATUS_UNWIND, 0, start.rip());
    let rec: &mut ExcRecord = match rec {
        Some(r) => r,
        None => &mut own,
    };
    rec.flags |= EH_UNWINDING;
    if target_frame == 0 {
        rec.flags |= EH_EXIT_UNWIND;
    }
    let mut ctx = start;
    let mut ptrs: Ptrs = [0; 32];
    for _ in 0..4096 {
        let pc = ctx.rip();
        let mut next = ctx;
        let Some((fe, u)) = step(UNW_FLAG_UHANDLER, &mut next, Some(&mut ptrs)) else {
            fatal("the unwind target was not found on the stack")
        };
        if !u.frame.is_multiple_of(8) || !in_stack(u.frame) || (target_frame != 0 && u.frame > target_frame) {
            fatal("invalid unwind target");
        }
        if u.frame == target_frame {
            rec.flags |= EH_TARGET_UNWIND;
        }
        if u.handler != 0 {
            let mut dc = DispatcherContext {
                control_pc: pc,
                image_base: image().base,
                function_entry: image().base + fe,
                establisher_frame: u.frame,
                target_ip,
                context: &raw mut ctx,
                language_handler: u.handler,
                handler_data: u.data,
                history_table: 0,
                scope_index: 0,
                fill0: 0,
            };
            call_handler(u.handler, rec, u.frame, &raw mut ctx, &raw mut dc);
            rec.flags &= !EH_COLLIDED_UNWIND;
        }
        if u.frame == target_frame {
            break;
        }
        ctx = next;
    }
    ctx.set_gpr(0, retval);
    if target_ip != 0 {
        ctx.set_rip(target_ip);
    }
    restore(&mut ctx, Some(rec), &mut ptrs)
}

/// Resume `ctx` (after a consolidation callback, if `rec` asks for one). Never returns.
fn restore(ctx: &mut Context, rec: Option<&mut ExcRecord>, ptrs: &mut Ptrs) -> ! {
    let fault = match current_thread() {
        Some(t) => {
            t.dispatch_ctx = core::ptr::null_mut();
            t.in_fault
        }
        None => false,
    };
    if let Some(rec) = rec
        && rec.code == STATUS_UNWIND_CONSOLIDATE
        && rec.nparams >= 1
    {
        rec.info[10] = ptrs.as_ptr() as u64;
        type Consolidate = extern "win64" fn(*mut ExcRecord) -> u64;
        // SAFETY: the callback the program's own frame handler put into the record.
        let cb: Consolidate = unsafe { core::mem::transmute::<u64, Consolidate>(rec.info[0]) };
        let ip = cb(rec);
        ctx.set_rip(ip);
    }
    if fault {
        fault_return(ctx)
    }
    // SAFETY: a context made from the program's own state (its stack, its code).
    unsafe { dcmpl_restore(ctx) }
}

fn fatal(what: &str) -> ! {
    println_unhandled(format_args!("SEH: {}; the program is ended", what));
    crate::out::flush_all();
    sys::process_exit(sys::EXIT_FAULT)
}

// ---- entry points ---------------------------------------------------------------------------------

unsafe extern "C" {
    fn dcmpl_restore(ctx: *const Context) -> !;
    fn dcmpl_fault_return(rec: *const sys::ExceptionRecord, fx: *const u8) -> !;
    pub fn dcmpl_fault_entry();
    pub fn dcmpl_capture_context(ctx: *mut Context);
    pub fn dcmpl_raise_exception(code: u32, flags: u32, n: u32, params: *const u64);
    pub fn dcmpl_unwind_ex(frame: u64, ip: u64, rec: *mut ExcRecord, retval: u64, ctx: *mut Context, history: u64);
    pub fn dcmpl_restore_context(ctx: *mut Context, rec: *mut ExcRecord);
}

/// Store the caller's registers into a CONTEXT at RCX (Windows x64 ABI: the stubs below and
/// RtlCaptureContext). Clobbers nothing but flags.
macro_rules! capture {
    ($ctx:literal, $caller_rsp:literal, $ret:literal) => {
        concat!(
            "mov [", $ctx, "+0x78], rax\n",
            "mov [", $ctx, "+0x80], rcx\n",
            "mov [", $ctx, "+0x88], rdx\n",
            "mov [", $ctx, "+0x90], rbx\n",
            "mov [", $ctx, "+0xA0], rbp\n",
            "mov [", $ctx, "+0xA8], rsi\n",
            "mov [", $ctx, "+0xB0], rdi\n",
            "mov [", $ctx, "+0xB8], r8\n",
            "mov [", $ctx, "+0xC0], r9\n",
            "mov [", $ctx, "+0xC8], r10\n",
            "mov [", $ctx, "+0xD0], r11\n",
            "mov [", $ctx, "+0xD8], r12\n",
            "mov [", $ctx, "+0xE0], r13\n",
            "mov [", $ctx, "+0xE8], r14\n",
            "mov [", $ctx, "+0xF0], r15\n",
            "lea rax, [", $caller_rsp, "]\n",
            "mov [", $ctx, "+0x98], rax\n",
            "mov rax, [", $ret, "]\n",
            "mov [", $ctx, "+0xF8], rax\n",
            "fxsave64 [", $ctx, "+0x100]\n",
            "stmxcsr [", $ctx, "+0x34]\n",
            "pushfq\n",
            "pop rax\n",
            "mov [", $ctx, "+0x44], eax\n",
            "mov dword ptr [", $ctx, "+0x30], 0x10000F\n",
            "mov dword ptr [", $ctx, "+0x38], 0x002B0033\n",
            "mov dword ptr [", $ctx, "+0x3C], 0x0053002B\n",
            "mov dword ptr [", $ctx, "+0x40], 0x002B002B\n",
            "mov rax, [", $ctx, "+0x78]\n",
        )
    };
}

global_asm!(
    // RtlCaptureContext(CONTEXT *rcx): the caller's state (RIP = return address).
    ".globl dcmpl_capture_context",
    "dcmpl_capture_context:",
    capture!("rcx", "rsp+8", "rsp"),
    "ret",
    // RaiseException(code, flags, n, params): capture the caller, then dispatch (never returns
    // here: resuming the caller goes through dcmpl_restore).
    ".globl dcmpl_raise_exception",
    "dcmpl_raise_exception:",
    "sub rsp, 0x4D8",
    capture!("rsp", "rsp+0x4E0", "rsp+0x4D8"),
    "mov rdi, rcx",
    "mov rsi, rdx",
    "mov rdx, r8",
    "mov rcx, r9",
    "mov r8, rsp",
    "call {raise}",
    "ud2",
    // RtlUnwindEx(frame, ip, rec, retval, ctx, history)
    ".globl dcmpl_unwind_ex",
    "dcmpl_unwind_ex:",
    "sub rsp, 0x4D8",
    capture!("rsp", "rsp+0x4E0", "rsp+0x4D8"),
    "mov rdi, rcx",
    "mov rsi, rdx",
    "mov rdx, r8",
    "mov rcx, r9",
    "mov r8, rsp",
    "call {unwind}",
    "ud2",
    // RtlRestoreContext(ctx, rec)
    ".globl dcmpl_restore_context",
    "dcmpl_restore_context:",
    "and rsp, -16",
    "mov rdi, rcx",
    "mov rsi, rdx",
    "call {restore_ctx}",
    "ud2",
    // Load a CONTEXT (RDI) and jump to its RIP on its stack.
    ".globl dcmpl_restore",
    "dcmpl_restore:",
    "mov rcx, rdi",
    "fxrstor64 [rcx+0x100]",
    "mov rax, [rcx+0x98]",
    "sub rax, 16",
    "mov rdx, [rcx+0xF8]",
    "mov [rax+8], rdx",
    "mov rdx, [rcx+0x80]",
    "mov [rax], rdx",
    "mov rdx, [rcx+0x88]",
    "mov rbx, [rcx+0x90]",
    "mov rbp, [rcx+0xA0]",
    "mov rsi, [rcx+0xA8]",
    "mov rdi, [rcx+0xB0]",
    "mov r8, [rcx+0xB8]",
    "mov r9, [rcx+0xC0]",
    "mov r10, [rcx+0xC8]",
    "mov r11, [rcx+0xD0]",
    "mov r12, [rcx+0xD8]",
    "mov r13, [rcx+0xE0]",
    "mov r14, [rcx+0xE8]",
    "mov r15, [rcx+0xF0]",
    "mov rsp, rax",
    "mov rax, [rcx+0x78]",
    "pop rcx",
    "ret",
    // The thread's in-process exception handler: RDI = the kernel's record, RSP + 8 aligned.
    // The FPU/SSE state is still the program's: saved first, for the CONTEXT.
    ".globl dcmpl_fault_entry",
    "dcmpl_fault_entry:",
    "sub rsp, 0x208",
    "fxsave64 [rsp]",
    "mov rsi, rsp",
    "call {fault}",
    "ud2",
    // Leave the handler: the FPU/SSE state from the CONTEXT, then exception_return(record).
    ".globl dcmpl_fault_return",
    "dcmpl_fault_return:",
    "fxrstor64 [rsi]",
    "mov eax, 45",
    "syscall",
    "ud2",
    raise = sym raise_entry,
    unwind = sym unwind_entry,
    restore_ctx = sym restore_context_entry,
    fault = sym fault_entry,
);

/// The exception for a CPU fault (`vector`, error code, CR2) at `rip`, like Windows reports it.
fn fault_record(vector: u32, error: u64, cr2: u64, rip: u64) -> ExcRecord {
    let mut r = ExcRecord::new(STATUS_ACCESS_VIOLATION, 0, rip);
    match vector {
        0 => r.code = 0xC000_0094,  // INT_DIVIDE_BY_ZERO
        1 => r.code = 0x8000_0004,  // SINGLE_STEP
        3 => r.code = STATUS_BREAKPOINT,
        4 => r.code = 0xC000_0095,  // INTEGER_OVERFLOW
        5 => r.code = 0xC000_008C,  // ARRAY_BOUNDS_EXCEEDED
        6 => r.code = 0xC000_001D,  // ILLEGAL_INSTRUCTION
        16 => r.code = 0xC000_0090, // FLOAT_INVALID_OPERATION
        17 => r.code = 0x8000_0002, // DATATYPE_MISALIGNMENT
        19 => r.code = 0xC000_02B5, // FLOAT_MULTIPLE_TRAPS
        14 => {
            r.nparams = 2;
            r.info[0] = if error & 0x10 != 0 { 8 } else if error & 2 != 0 { 1 } else { 0 };
            r.info[1] = cr2;
        }
        _ => {
            r.nparams = 2;
            r.info[1] = u64::MAX;
        }
    }
    r
}

/// A CPU fault in the program (on the handler stack). Dispatch; resume, or end the program the
/// native way (the handler is removed and the instruction runs again: the kernel reports the
/// fault and ends the process with `EXIT_FAULT`).
extern "C" fn fault_entry(krec: *mut sys::ExceptionRecord, fx: *const u8) -> ! {
    // SAFETY: the kernel's record on this handler stack, valid until exception_return.
    let k = unsafe { &mut *krec };
    let r = &k.regs;
    let mut ctx = Context::zero();
    for (i, v) in [r.rax, r.rcx, r.rdx, r.rbx, r.rsp, r.rbp, r.rsi, r.rdi, r.r8, r.r9, r.r10, r.r11, r.r12, r.r13, r.r14, r.r15]
        .into_iter()
        .enumerate()
    {
        ctx.set_gpr(i, v);
    }
    let mut rip = r.rip;
    if k.vector == 3 {
        rip -= 1; // int3: Windows reports the breakpoint itself
    }
    ctx.set_rip(rip);
    ctx.set_header(r.rflags as u32);
    // SAFETY: the 512-byte FXSAVE image the entry stub made.
    unsafe { core::ptr::copy_nonoverlapping(fx, ctx.bytes_mut()[C_FX..].as_mut_ptr(), 512) };
    if k.vector == 13 && k.error == (0x29 << 3) | 2 {
        // `int 0x29`: __fastfail(code in RCX). Not an exception: the program ends at once with
        // STATUS_STACK_BUFFER_OVERRUN, as on Windows.
        println_unhandled(format_args!("__fastfail({}) at {:#x}", r.rcx, rip));
        crate::out::flush_all();
        sys::process_exit(0xC000_0409_u32 as i32);
    }
    let mut rec = fault_record(k.vector, k.error, k.cr2, rip);
    let Some(t) = current_thread() else { refault(k) };
    if t.in_fault || !t.dispatch_ctx.is_null() {
        refault(k); // a fault while dispatching another: not handled (as Windows ends a nested fault)
    }
    t.in_fault = true;
    t.fault_rec = krec;
    t.dispatch_ctx = &raw mut ctx;
    let handled = dispatch(&mut rec, &mut ctx) || top_level_filter(&mut rec, &mut ctx);
    t.dispatch_ctx = core::ptr::null_mut();
    if !handled {
        println_unhandled(format_args!("unhandled exception {:#010x} at {:#x}", rec.code, rec.address));
        crate::out::flush_all();
        refault(k);
    }
    fault_return(&ctx)
}

/// Remove the handler and run the faulting instruction again: the kernel's own fault path.
fn refault(k: &sys::ExceptionRecord) -> ! {
    sys::thread_set_exception_handler(0, 0);
    if let Some(t) = current_thread() {
        t.in_fault = false;
    }
    sys::exception_return(k)
}

/// Leave the fault handler with `ctx` (registers, FPU/SSE state).
fn fault_return(ctx: &Context) -> ! {
    let t = current_thread();
    let Some(t) = t else { sys::process_exit(sys::EXIT_FAULT) };
    // SAFETY: the record the kernel gave this handler (still on the handler stack).
    let k = unsafe { &mut *t.fault_rec };
    let g = |n: usize| ctx.gpr(n);
    k.regs.rax = g(0);
    k.regs.rcx = g(1);
    k.regs.rdx = g(2);
    k.regs.rbx = g(3);
    k.regs.rsp = g(4);
    k.regs.rbp = g(5);
    k.regs.rsi = g(6);
    k.regs.rdi = g(7);
    k.regs.r8 = g(8);
    k.regs.r9 = g(9);
    k.regs.r10 = g(10);
    k.regs.r11 = g(11);
    k.regs.r12 = g(12);
    k.regs.r13 = g(13);
    k.regs.r14 = g(14);
    k.regs.r15 = g(15);
    k.regs.rip = ctx.rip();
    k.regs.rflags = u64::from(ctx.eflags());
    t.in_fault = false;
    let fx = ctx.bytes()[C_FX..].as_ptr();
    // SAFETY: the kernel validates the registers; `fx` is a 16-byte aligned FXSAVE image (the
    // CONTEXT is 16-byte aligned and the area is at 0x100).
    unsafe { dcmpl_fault_return(k, fx) }
}

/// The filter of `SetUnhandledExceptionFilter`, if any: true if it says continue execution.
fn top_level_filter(rec: &mut ExcRecord, ctx: &mut Context) -> bool {
    let f = super::k32::unhandled_filter();
    if f == 0 {
        return false;
    }
    let mut ptrs = [rec as *mut ExcRecord as u64, ctx as *mut Context as u64];
    type Filter = extern "win64" fn(*mut [u64; 2]) -> i32;
    // SAFETY: the program's own filter function (it registered it).
    let f: Filter = unsafe { core::mem::transmute::<u64, Filter>(f) };
    f(&mut ptrs) == -1
}

/// `RaiseException`, after the stub captured the caller into `ctx`.
extern "sysv64" fn raise_entry(code: u32, flags: u32, n: u32, params: *const u64, ctx: *mut Context) -> ! {
    // SAFETY: the stub's CONTEXT, in its frame above this one.
    let ctx = unsafe { &mut *ctx };
    let mut rec = ExcRecord::new(code, flags & EXCEPTION_NONCONTINUABLE, ctx.rip());
    let n = n.min(15);
    if !params.is_null() {
        for (i, slot) in rec.info.iter_mut().take(n as usize).enumerate() {
            // SAFETY: the caller's array of `n` parameters.
            *slot = unsafe { params.add(i).read() };
        }
        rec.nparams = n;
    }
    let Some(t) = current_thread() else { sys::process_exit(code as i32) };
    let saved = (t.dispatch_ctx, t.in_fault);
    t.dispatch_ctx = ctx;
    t.in_fault = false;
    let handled = dispatch(&mut rec, ctx) || top_level_filter(&mut rec, ctx);
    t.dispatch_ctx = saved.0;
    t.in_fault = saved.1;
    if !handled || rec.flags & EXCEPTION_NONCONTINUABLE != 0 {
        println_unhandled(format_args!("unhandled exception {:#010x} (raised at {:#x})", code, rec.address));
        crate::out::flush_all();
        sys::process_exit(code as i32);
    }
    let mut ptrs = [0; 32];
    // SAFETY: as in `restore`.
    restore(ctx, None, &mut ptrs)
}

/// `RtlUnwindEx`: from the exception being dispatched on this thread, else from its caller.
extern "sysv64" fn unwind_entry(frame: u64, ip: u64, rec: *mut ExcRecord, retval: u64, caller: *mut Context) -> ! {
    let t = current_thread();
    let start = match t {
        // SAFETY: the dispatch's CONTEXT (live while its handlers run, which is now).
        Some(t) if !t.dispatch_ctx.is_null() => unsafe { *t.dispatch_ctx },
        // SAFETY: the stub's capture of the caller.
        _ => unsafe { *caller },
    };
    // SAFETY: the caller's exception record, if it passed one.
    let rec = unsafe { rec.as_mut() };
    unwind(start, frame, ip, rec, retval)
}

extern "sysv64" fn restore_context_entry(ctx: *mut Context, rec: *mut ExcRecord) -> ! {
    // SAFETY: the caller's CONTEXT and optional record.
    let (ctx, rec) = unsafe { (&mut *ctx, rec.as_mut()) };
    let mut c = *ctx;
    let mut ptrs = [0; 32];
    restore(&mut c, rec, &mut ptrs)
}

// ---- the Rtl exports ---------------------------------------------------------------------------

pub(super) extern "win64" fn rtl_lookup_function_entry(pc: u64, base: *mut u64, _history: u64) -> u64 {
    match lookup(pc) {
        Some(fe) => {
            if !base.is_null() {
                // SAFETY: the caller's out-pointer.
                unsafe { base.write(image().base) };
            }
            image().base + fe
        }
        None => 0,
    }
}

#[allow(clippy::too_many_arguments)] // RtlVirtualUnwind's own signature
pub(super) extern "win64" fn rtl_virtual_unwind(
    ty: u32,
    _base: u64,
    pc: u64,
    fe: u64,
    ctx: *mut Context,
    data: *mut u64,
    frame: *mut u64,
    ptrs: *mut Ptrs,
) -> u64 {
    let im = image();
    // SAFETY: the caller's CONTEXT.
    let Some(ctx) = (unsafe { ctx.as_mut() }) else { return 0 };
    let fe_rva = fe.wrapping_sub(im.base);
    // SAFETY: the caller's optional KNONVOLATILE_CONTEXT_POINTERS.
    let p = unsafe { ptrs.as_mut() };
    let u = if fe == 0 || fe_rva >= im.size {
        // a leaf function
        let sp = ctx.rsp();
        let Some(ret) = stack_u64(sp) else { return 0 };
        ctx.set_rip(ret);
        ctx.set_rsp(sp + 8);
        Unwound { handler: 0, data: 0, frame: sp }
    } else {
        match virtual_unwind(ty, pc, fe_rva, ctx, p) {
            Some(u) => u,
            None => return 0,
        }
    };
    // SAFETY: the caller's out-pointers.
    unsafe {
        if !data.is_null() {
            data.write(u.data);
        }
        if !frame.is_null() {
            frame.write(u.frame);
        }
    }
    u.handler
}

pub(super) extern "win64" fn rtl_pc_to_file_header(pc: u64, base: *mut u64) -> u64 {
    let im = image();
    let b = if pc >= im.base && pc < im.base + im.size { im.base } else { 0 };
    if !base.is_null() {
        // SAFETY: the caller's out-pointer.
        unsafe { base.write(b) };
    }
    b
}
