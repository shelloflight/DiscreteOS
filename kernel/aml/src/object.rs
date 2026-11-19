//! AML objects: what a namespace node holds and what expressions produce.

use alloc::rc::Rc;
use alloc::vec::Vec;
use core::cell::{Cell, RefCell};

use crate::namespace::NodeId;

/// A shared, mutable byte string (Buffer and String objects; buffer fields point into it).
pub type Buf = Rc<RefCell<Vec<u8>>>;
/// A shared, mutable package (Index references point into it).
pub type Pkg = Rc<RefCell<Vec<Object>>>;

pub fn buf(v: Vec<u8>) -> Buf {
    Rc::new(RefCell::new(v))
}

pub fn pkg(v: Vec<Object>) -> Pkg {
    Rc::new(RefCell::new(v))
}

/// A control method: its byte code stays in the table it came from.
pub struct Method {
    pub code: Rc<[u8]>,
    pub start: usize,
    pub end: usize,
    pub args: u8,
    pub serialized: bool,
    /// Integers are 64 bits wide (table revision 2 or later), else 32.
    pub int64: bool,
}

/// Address spaces of operation regions (ACPI 6.5, table 19.31).
pub mod space {
    pub const MEMORY: u8 = 0;
    pub const IO: u8 = 1;
    pub const PCI: u8 = 2;
    pub const EC: u8 = 3;
    pub const CMOS: u8 = 5;
}

pub struct Region {
    pub space: u8,
    pub base: u64,
    pub len: u64,
    /// The scope the region was declared in (its device, for PCI_Config).
    pub scope: NodeId,
    /// PCI_Config: segment, bus, device, function, found on first access.
    pub pci: Cell<Option<(u16, u8, u8, u8)>>,
}

pub enum FieldKind {
    Region(Rc<Region>),
    /// IndexField: the index and data fields (nodes).
    Index {
        index: NodeId,
        data: NodeId,
    },
    /// BankField: the bank selector field is written with `value` before each access.
    Bank {
        region: Rc<Region>,
        bank: NodeId,
        value: u64,
    },
}

pub struct Field {
    pub kind: FieldKind,
    /// Bit offset and length inside the region (IndexField: inside the data window).
    pub bit: u64,
    pub len: u64,
    /// Access width in bytes (1, 2, 4, 8).
    pub access: u8,
    pub lock: bool,
    /// Update rule: 0 preserve, 1 write as ones, 2 write as zeros.
    pub update: u8,
}

/// Built-in methods the interpreter answers itself.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Native {
    Osi,
}

/// What an object reference points at (RefOf, Index, CondRefOf).
#[derive(Clone)]
pub enum Ref {
    Node(NodeId),
    Elem(Pkg, usize),
    Byte(Buf, usize),
}

#[derive(Clone, Default)]
pub enum Object {
    #[default]
    Uninit,
    Integer(u64),
    String(Buf),
    Buffer(Buf),
    Package(Pkg),
    Method(Rc<Method>),
    Native(Native),
    Device,
    Scope,
    Processor {
        id: u8,
        pblk: u32,
        pblk_len: u8,
    },
    PowerRes {
        level: u8,
        order: u16,
    },
    ThermalZone,
    Mutex(Rc<Cell<u32>>),
    Event(Rc<Cell<u32>>),
    Region(Rc<Region>),
    Field(Rc<Field>),
    BufferField {
        buf: Buf,
        bit: usize,
        len: usize,
    },
    Ref(Ref),
    Alias(NodeId),
    Debug,
}

impl Object {
    pub fn int(v: u64) -> Object {
        Object::Integer(v)
    }

    pub fn string(s: &[u8]) -> Object {
        Object::String(buf(s.to_vec()))
    }

    pub fn buffer(b: &[u8]) -> Object {
        Object::Buffer(buf(b.to_vec()))
    }

    pub fn package(v: Vec<Object>) -> Object {
        Object::Package(pkg(v))
    }

    /// ObjectType codes (ACPI 6.5, 19.6.97).
    pub fn type_code(&self) -> u64 {
        match self {
            Object::Uninit => 0,
            Object::Integer(_) => 1,
            Object::String(_) => 2,
            Object::Buffer(_) => 3,
            Object::Package(_) => 4,
            Object::Field(_) => 5,
            Object::Device => 6,
            Object::Event(_) => 7,
            Object::Method(_) | Object::Native(_) => 8,
            Object::Mutex(_) => 9,
            Object::Region(_) => 10,
            Object::PowerRes { .. } => 11,
            Object::Processor { .. } => 12,
            Object::ThermalZone => 13,
            Object::BufferField { .. } => 14,
            Object::Debug => 16,
            Object::Scope | Object::Alias(_) | Object::Ref(_) => 0,
        }
    }

    pub fn type_name(&self) -> &'static str {
        match self {
            Object::Uninit => "uninitialized",
            Object::Integer(_) => "integer",
            Object::String(_) => "string",
            Object::Buffer(_) => "buffer",
            Object::Package(_) => "package",
            Object::Method(_) | Object::Native(_) => "method",
            Object::Device => "device",
            Object::Scope => "scope",
            Object::Processor { .. } => "processor",
            Object::PowerRes { .. } => "power resource",
            Object::ThermalZone => "thermal zone",
            Object::Mutex(_) => "mutex",
            Object::Event(_) => "event",
            Object::Region(_) => "operation region",
            Object::Field(_) => "field",
            Object::BufferField { .. } => "buffer field",
            Object::Ref(_) => "reference",
            Object::Alias(_) => "alias",
            Object::Debug => "debug",
        }
    }

    /// The integer value, for callers outside the interpreter (no conversion).
    pub fn as_integer(&self) -> Option<u64> {
        match self {
            Object::Integer(v) => Some(*v),
            _ => None,
        }
    }

    /// The bytes of a String or Buffer.
    pub fn as_bytes(&self) -> Option<Vec<u8>> {
        match self {
            Object::String(b) | Object::Buffer(b) => Some(b.borrow().clone()),
            _ => None,
        }
    }

    /// The elements of a Package.
    pub fn as_package(&self) -> Option<Vec<Object>> {
        match self {
            Object::Package(p) => Some(p.borrow().clone()),
            _ => None,
        }
    }

    /// Does this object open a scope that can hold children (for device walks)?
    pub fn is_device_like(&self) -> bool {
        matches!(
            self,
            Object::Device
                | Object::Processor { .. }
                | Object::ThermalZone
                | Object::PowerRes { .. }
        )
    }
}

impl core::fmt::Debug for Object {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Object::Integer(v) => write!(f, "Integer({:#x})", v),
            Object::String(s) => write!(
                f,
                "String({:?})",
                alloc::string::String::from_utf8_lossy(&s.borrow())
            ),
            Object::Buffer(b) => write!(f, "Buffer({:02x?})", b.borrow()),
            Object::Package(p) => f.debug_list().entries(p.borrow().iter()).finish(),
            o => write!(f, "{}", o.type_name()),
        }
    }
}
