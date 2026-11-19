//! Processor power descriptions (ACPI 6.5, section 8.4): idle states (`_CST`), collaborative
//! performance control (`_CPC`) and performance states (`_PSS` with `_PCT`).
//!
//! The objects are evaluated like any other method, then read strictly: a register is a
//! Generic Register Descriptor (`Register()`) or nothing; counts larger than the package are
//! clipped; anything else in a slot reads as absent. The caller decides what it can use (the
//! kernel: functional fixed hardware as MSRs, I/O ports, constants).

use alloc::vec::Vec;

use crate::interp::Interpreter;
use crate::namespace::{NodeId, ROOT};
use crate::object::Object;
use crate::Handler;

/// Address spaces of a register (ACPI 6.5, table 5.25).
pub const SPACE_MEMORY: u8 = 0x00;
pub const SPACE_IO: u8 = 0x01;
pub const SPACE_PCC: u8 = 0x0A;
pub const SPACE_FFH: u8 = 0x7F;

/// A Generic Address Structure as a `Register()` resource template carries it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Gas {
    pub space: u8,
    pub bit_width: u8,
    pub bit_offset: u8,
    pub access: u8,
    pub address: u64,
}

impl Gas {
    /// A Generic Register Descriptor (ACPI 6.5, 6.4.3.7: tag 0x82, length 12, then the GAS).
    pub fn from_template(b: &[u8]) -> Option<Gas> {
        if b.len() < 15 || b[0] != 0x82 || u16::from_le_bytes([b[1], b[2]]) < 12 {
            return None;
        }
        let address = u64::from_le_bytes(b[7..15].try_into().ok()?);
        Some(Gas { space: b[3], bit_width: b[4], bit_offset: b[5], access: b[6], address })
    }

    /// The "null" register (every field zero): this optional register is not implemented.
    pub fn is_null(&self) -> bool {
        *self == Gas::default()
    }
}

/// How an idle state is entered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CEntry {
    /// HLT (functional fixed hardware, class 1: "C1 halt").
    Halt,
    /// MWAIT with this hint in EAX (functional fixed hardware, class 2); `flags`: the
    /// descriptor's access-size byte (bit 0: break on interrupt, bit 1: bus-master avoidance).
    Mwait { hint: u32, flags: u8 },
    /// Read this I/O port.
    Io { port: u16 },
    /// Anything else (memory, an unknown class): not usable.
    Other(Gas),
}

/// One `_CST` entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CState {
    /// ACPI C-state type: 1, 2 or 3.
    pub kind: u8,
    pub entry: CEntry,
    pub latency_us: u32,
    pub power_mw: u32,
}

/// A `_CPC` element: a constant, a register, or absent (a null register, or no such element).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CpcValue {
    None,
    Int(u64),
    Reg(Gas),
}

/// `_CPC` (ACPI 6.5, 8.4.6.1), the elements a kernel needs. Performance values are abstract units.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cpc {
    pub revision: u64,
    pub highest: CpcValue,
    pub nominal: CpcValue,
    pub lowest_nonlinear: CpcValue,
    pub lowest: CpcValue,
    pub desired: CpcValue,
    pub min: CpcValue,
    pub max: CpcValue,
    pub enable: CpcValue,
    pub autonomous: CpcValue,
    pub epp: CpcValue,
    /// Revision 3: the frequencies of the lowest and nominal performance (0: not given).
    pub lowest_mhz: u64,
    pub nominal_mhz: u64,
}

/// One `_PSS` entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PState {
    pub mhz: u32,
    pub power_mw: u32,
    pub latency_us: u32,
    pub control: u64,
    pub status: u64,
}

/// `_PSS` with the control and status registers of `_PCT`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pss {
    pub states: Vec<PState>,
    pub control: Gas,
    pub status: Gas,
}

/// At most this many entries are read from a `_CST` or `_PSS` (real firmware has a handful).
pub const MAX_ENTRIES: usize = 32;

impl<H: Handler> Interpreter<H> {
    /// Processor objects and processor devices (`ACPI0007`), in namespace order.
    pub fn processors(&mut self) -> Vec<NodeId> {
        let devices = self.find_devices(&["ACPI0007"]);
        self.namespace()
            .walk(ROOT)
            .into_iter()
            .filter(|&n| matches!(self.namespace().obj(n), Object::Processor { .. }) || devices.contains(&n))
            .collect()
    }

    /// The first processor that is present (`_STA` bit 0, or no `_STA`).
    pub fn first_processor(&mut self) -> Option<NodeId> {
        for n in self.processors() {
            match self.child_int(n, "_STA") {
                Ok(Some(s)) if s & 1 == 0 => continue,
                Err(_) => continue,
                _ => return Some(n),
            }
        }
        None
    }

    fn package_of(&mut self, node: NodeId, seg: &str) -> Option<Vec<Object>> {
        let c = self.child(node, seg)?;
        let v = self.evaluate_node(c, Vec::new()).ok()?;
        let Object::Package(p) = self.deref_all(v).ok()? else { return None };
        let items = p.borrow().clone();
        let mut out = Vec::new();
        for o in items {
            out.push(self.deref_all(o).unwrap_or(Object::Uninit));
        }
        Some(out)
    }

    /// `_CST` of a processor: its idle states in the firmware's order.
    pub fn cst(&mut self, cpu: NodeId) -> Option<Vec<CState>> {
        let p = self.package_of(cpu, "_CST")?;
        let count = p.first()?.as_integer()? as usize;
        let mut out = Vec::new();
        for e in p.iter().skip(1).take(count.min(MAX_ENTRIES)) {
            let Object::Package(s) = e else { continue };
            let s = s.borrow().clone();
            let s: Vec<Object> = s.into_iter().map(|o| self.deref_all(o).unwrap_or(Object::Uninit)).collect();
            let (Some(Object::Buffer(reg)), Some(kind), Some(lat)) =
                (s.first(), s.get(1).and_then(Object::as_integer), s.get(2).and_then(Object::as_integer))
            else {
                continue;
            };
            let Some(g) = Gas::from_template(&reg.borrow()) else { continue };
            let entry = match g.space {
                SPACE_FFH if g.bit_offset == 1 => CEntry::Halt,
                SPACE_FFH if g.bit_offset == 2 => CEntry::Mwait { hint: g.address as u32, flags: g.access },
                SPACE_IO if g.address <= 0xFFFF => CEntry::Io { port: g.address as u16 },
                _ => CEntry::Other(g),
            };
            let power = s.get(3).and_then(Object::as_integer).unwrap_or(0);
            out.push(CState {
                kind: kind.min(255) as u8,
                entry,
                latency_us: lat.min(u64::from(u32::MAX)) as u32,
                power_mw: power.min(u64::from(u32::MAX)) as u32,
            });
        }
        Some(out)
    }

    /// `_CPC` of a processor (revision 2 or later: at least 21 elements).
    pub fn cpc(&mut self, cpu: NodeId) -> Option<Cpc> {
        let p = self.package_of(cpu, "_CPC")?;
        if p.len() < 21 {
            return None;
        }
        let v = |i: usize| match p.get(i) {
            Some(Object::Integer(x)) => CpcValue::Int(*x),
            Some(Object::Buffer(b)) => match Gas::from_template(&b.borrow()) {
                Some(g) if !g.is_null() => CpcValue::Reg(g),
                _ => CpcValue::None,
            },
            _ => CpcValue::None,
        };
        let int = |i: usize| p.get(i).and_then(Object::as_integer).unwrap_or(0);
        Some(Cpc {
            revision: int(1),
            highest: v(2),
            nominal: v(3),
            lowest_nonlinear: v(4),
            lowest: v(5),
            desired: v(7),
            min: v(8),
            max: v(9),
            enable: v(16),
            autonomous: v(17),
            epp: v(19),
            lowest_mhz: int(21),
            nominal_mhz: int(22),
        })
    }

    /// `_PSS` and `_PCT` of a processor (both needed).
    pub fn pss(&mut self, cpu: NodeId) -> Option<Pss> {
        let pct = self.package_of(cpu, "_PCT")?;
        let reg = |o: Option<&Object>| match o {
            Some(Object::Buffer(b)) => Gas::from_template(&b.borrow()),
            _ => None,
        };
        let (control, status) = (reg(pct.first())?, reg(pct.get(1))?);
        let p = self.package_of(cpu, "_PSS")?;
        let mut states = Vec::new();
        for e in p.iter().take(MAX_ENTRIES) {
            let Object::Package(s) = e else { continue };
            let s = s.borrow().clone();
            let n: Vec<u64> = s.into_iter().filter_map(|o| self.deref_all(o).ok()?.as_integer()).collect();
            if n.len() < 6 {
                continue;
            }
            let u = |x: u64| x.min(u64::from(u32::MAX)) as u32;
            states.push(PState { mhz: u(n[0]), power_mw: u(n[1]), latency_us: u(n[2]), control: n[4], status: n[5] });
        }
        (!states.is_empty()).then_some(Pss { states, control, status })
    }
}
