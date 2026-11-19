//! Processor power from the AML namespace: the first present processor's `_CST`, `_CPC` and
//! `_PSS`/`_PCT` (read by `aml::processor`), handed to the C side (`cpupm.h`), which uses what this
//! kernel can reach: MSRs ("functional fixed hardware"), I/O ports and constants. Run once on the
//! ACPI thread, after the namespace is initialised. Every processor of a machine has the same
//! description in practice; per-core values (the highest performance of each core) are read on
//! each CPU from the registers named here.

use aml::processor::{CEntry, CpcValue, Gas, SPACE_FFH, SPACE_IO};
use aml::{Handler, Interpreter};

use crate::ffi;
use crate::kprintln;

const MAX_C: usize = 6;
const MAX_P: usize = 16;

const ENTRY_HLT: u32 = 0;
const ENTRY_MWAIT: u32 = 1;
const ENTRY_IO: u32 = 2;

const REG_NONE: u32 = 0;
const REG_INT: u32 = 1;
const REG_MSR: u32 = 2;
const REG_IO: u32 = 3;

/// `struct cpupm_cstate` (cpupm.h).
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct CState {
    entry: u32,
    kind: u32,
    arg: u32,
    latency_us: u32,
}

/// `struct cpupm_reg` (cpupm.h).
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Reg {
    kind: u32,
    bit_offset: u8,
    bit_width: u8,
    reserved: u16,
    value: u64,
}
const _: () = assert!(core::mem::size_of::<Reg>() == 16);

/// `struct cpupm_desc` (cpupm.h).
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Desc {
    ncstates: u32,
    npstates: u32,
    cst: [CState; MAX_C],
    cpc: u32,
    cpc_lowest_mhz: u32,
    cpc_nominal_mhz: u32,
    reserved: u32,
    highest: Reg,
    nominal: Reg,
    lowest_nonlinear: Reg,
    lowest: Reg,
    desired: Reg,
    min: Reg,
    max: Reg,
    enable: Reg,
    autonomous: Reg,
    epp: Reg,
    pct_control: Reg,
    pss_mhz: [u32; MAX_P],
    pss_control: [u64; MAX_P],
}
const _: () = assert!(core::mem::size_of::<Desc>() == 488);

/// A register the kernel reaches: an MSR field or an I/O port. None for memory, PCC and others.
fn reg(g: &Gas) -> Option<Reg> {
    let kind = match g.space {
        SPACE_FFH => REG_MSR,
        SPACE_IO if g.address <= 0xFFFF => REG_IO,
        _ => return None,
    };
    Some(Reg { kind, bit_offset: g.bit_offset, bit_width: g.bit_width, reserved: 0, value: g.address })
}

fn cpc_reg(v: CpcValue, unreachable: &mut u32) -> Reg {
    match v {
        CpcValue::None => Reg::default(),
        CpcValue::Int(x) => Reg { kind: REG_INT, value: x, ..Reg::default() },
        CpcValue::Reg(g) => reg(&g).unwrap_or_else(|| {
            *unreachable += 1;
            Reg { kind: REG_NONE, ..Reg::default() }
        }),
    }
}

fn space_name(g: &Gas) -> &'static str {
    match g.space {
        0x00 => "memory",
        0x01 => "I/O",
        0x0A => "PCC",
        0x7F => "MSR",
        _ => "other",
    }
}

/// Read the first present processor's power objects and configure every CPU.
pub fn configure<H: Handler>(aml: &mut Interpreter<H>) {
    let mut d = Desc::default();
    let count = aml.processors().len();
    let Some(cpu) = aml.first_processor() else {
        kprintln!("ACPI: no processor objects; CPU power from the CPU alone");
        // SAFETY: a valid description (empty); the C side copies it.
        unsafe { ffi::cpupm_configure(&raw const d as *const core::ffi::c_void) };
        return;
    };
    if let Some(cst) = aml.cst(cpu) {
        for s in cst.iter().take(MAX_C) {
            let (entry, arg) = match s.entry {
                CEntry::Halt => (ENTRY_HLT, 0),
                CEntry::Mwait { hint, .. } => (ENTRY_MWAIT, hint),
                CEntry::Io { port } => (ENTRY_IO, u32::from(port)),
                CEntry::Other(_) if s.kind <= 1 => (ENTRY_HLT, 0), // C1 is HLT whatever the register says
                CEntry::Other(_) => continue,
            };
            d.cst[d.ncstates as usize] = CState { entry, kind: u32::from(s.kind), arg, latency_us: s.latency_us };
            d.ncstates += 1;
        }
    }
    let mut cpc_note = alloc::string::String::from("none");
    if let Some(c) = aml.cpc(cpu) {
        let mut unreachable = 0;
        d.highest = cpc_reg(c.highest, &mut unreachable);
        d.nominal = cpc_reg(c.nominal, &mut unreachable);
        d.lowest_nonlinear = cpc_reg(c.lowest_nonlinear, &mut unreachable);
        d.lowest = cpc_reg(c.lowest, &mut unreachable);
        d.desired = cpc_reg(c.desired, &mut unreachable);
        d.min = cpc_reg(c.min, &mut unreachable);
        d.max = cpc_reg(c.max, &mut unreachable);
        d.enable = cpc_reg(c.enable, &mut unreachable);
        d.autonomous = cpc_reg(c.autonomous, &mut unreachable);
        d.epp = cpc_reg(c.epp, &mut unreachable);
        d.cpc_lowest_mhz = c.lowest_mhz.min(u64::from(u32::MAX)) as u32;
        d.cpc_nominal_mhz = c.nominal_mhz.min(u64::from(u32::MAX)) as u32;
        let space = match c.highest {
            CpcValue::Reg(g) => space_name(&g),
            CpcValue::Int(_) => "constants",
            CpcValue::None => "nothing",
        };
        d.cpc = 1;
        cpc_note = if unreachable == 0 {
            alloc::format!("revision {}, registers in {}", c.revision, space)
        } else {
            alloc::format!("revision {}, {} register(s) out of reach ({})", c.revision, unreachable, space)
        };
    }
    let mut pss_note = alloc::string::String::from("none");
    if let Some(p) = aml.pss(cpu) {
        if let Some(r) = reg(&p.control) {
            d.pct_control = r;
            for s in p.states.iter().take(MAX_P) {
                d.pss_mhz[d.npstates as usize] = s.mhz;
                d.pss_control[d.npstates as usize] = s.control;
                d.npstates += 1;
            }
        }
        pss_note = alloc::format!("{} state(s), control in {}", p.states.len(), space_name(&p.control));
    }
    kprintln!(
        "ACPI: {} processor(s); {}: _CST {} state(s), _CPC {}, _PSS {}",
        count,
        aml.path(cpu),
        d.ncstates,
        cpc_note,
        pss_note
    );
    // SAFETY: `d` is a complete description; the C side copies it before returning.
    unsafe { ffi::cpupm_configure(&raw const d as *const core::ffi::c_void) };
}

/// No AML namespace: performance control from the CPU alone (Intel HWP).
pub fn configure_without_acpi() {
    // SAFETY: NULL is allowed (no firmware description).
    unsafe { ffi::cpupm_configure(core::ptr::null()) };
}
