//! ACPI Machine Language (AML) interpreter for D-OS. Reference: docs/acpi.md.
//!
//! Firmware describes the machine in AML byte code (the DSDT and SSDT tables): devices, how to
//! switch power states, which methods run on events. This crate loads those tables into one
//! namespace and runs their control methods:
//!
//! - `Interpreter::load_table` executes a table's top level (names, scopes, devices, methods,
//!   regions, fields); method bodies are kept as byte ranges and parsed only when called;
//! - `Interpreter::initialize` runs `_REG` for the address spaces it serves and the `_STA`/`_INI`
//!   device walk (ACPI 6.5, 6.5.1);
//! - `Interpreter::evaluate` runs a method or reads a named object.
//!
//! Hardware is reached only through `Handler` (port I/O, physical memory, PCI configuration,
//! delays, notifications), so the same code runs in the kernel and under `cargo test`.
//!
//! **Fail closed.** Every byte is bounds-checked; malformed code, a missing name or a type error
//! ends the method being evaluated with an `Error` (the namespace stays usable). Each evaluation has
//! budgets: steps (terms executed), method call depth, expression depth, buffer and package sizes,
//! namespace size, and a stack check the handler answers (the kernel's stacks are small). A table
//! that fails half-way keeps what it defined before the failure, and a failing scope or device body
//! is skipped with its own length, so one bad definition does not lose the rest of the table.

#![no_std]

extern crate alloc;

mod field;
mod interp;
pub mod namespace;
pub mod object;

pub use interp::{Interpreter, Stats};
pub use namespace::{NodeId, ROOT};
pub use object::Object;

use alloc::string::String;

/// What went wrong; `at` is the byte offset in the table's AML (0 when not from byte code).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error {
    pub kind: ErrorKind,
    pub at: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    /// Byte code that does not decode (truncated, unknown opcode, bad length).
    Malformed,
    /// A name that does not resolve.
    NotFound(String),
    /// A name created twice.
    Exists(String),
    /// An operand of the wrong type (what was expected).
    Type(&'static str),
    /// Division by zero, index out of range, field outside its region.
    Range(&'static str),
    /// A budget ran out (which one).
    Limit(&'static str),
    /// The handler refused or failed a hardware access.
    Hardware,
    /// An operation this interpreter does not do (Load, LoadTable, some address spaces).
    Unsupported(&'static str),
    /// The firmware executed Fatal (type, code, argument).
    Fatal(u8, u32, u64),
}

impl Error {
    pub fn new(kind: ErrorKind, at: usize) -> Error {
        Error { kind, at }
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match &self.kind {
            ErrorKind::Malformed => write!(f, "malformed AML"),
            ErrorKind::NotFound(n) => write!(f, "{} not found", n),
            ErrorKind::Exists(n) => write!(f, "{} already exists", n),
            ErrorKind::Type(t) => write!(f, "{} expected", t),
            ErrorKind::Range(r) => write!(f, "{}", r),
            ErrorKind::Limit(l) => write!(f, "{} limit reached", l),
            ErrorKind::Hardware => write!(f, "hardware access refused"),
            ErrorKind::Unsupported(u) => write!(f, "{} not supported", u),
            ErrorKind::Fatal(t, c, a) => write!(f, "Fatal({:#x}, {:#x}, {:#x})", t, c, a),
        }?;
        if self.at != 0 {
            write!(f, " at AML offset {:#x}", self.at)?;
        }
        Ok(())
    }
}

pub type Result<T> = core::result::Result<T, Error>;

/// A hardware access the handler refused (the method making it fails).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Refused;

/// Hardware access for the interpreter. Widths are in bytes (1, 2, 4, 8). An `Err(Refused)` ends the
/// method that made the access (fail closed); a handler that wants to ignore an access silently
/// (protected ports) returns `Ok` instead.
pub trait Handler {
    fn read_io(&mut self, port: u16, width: u8) -> core::result::Result<u64, Refused>;
    fn write_io(&mut self, port: u16, width: u8, value: u64) -> core::result::Result<(), Refused>;
    fn read_mem(&mut self, addr: u64, width: u8) -> core::result::Result<u64, Refused>;
    fn write_mem(&mut self, addr: u64, width: u8, value: u64) -> core::result::Result<(), Refused>;
    /// PCI configuration space of (segment, bus, device, function).
    fn read_pci(
        &mut self,
        pci: (u16, u8, u8, u8),
        offset: u16,
        width: u8,
    ) -> core::result::Result<u64, Refused>;
    fn write_pci(
        &mut self,
        pci: (u16, u8, u8, u8),
        offset: u16,
        width: u8,
        value: u64,
    ) -> core::result::Result<(), Refused>;
    /// Embedded controller space (one byte at a time); none by default.
    fn read_ec(&mut self, _offset: u8) -> core::result::Result<u8, Refused> {
        Err(Refused)
    }
    fn write_ec(&mut self, _offset: u8, _value: u8) -> core::result::Result<(), Refused> {
        Err(Refused)
    }
    /// Busy-wait (Stall) and sleep (Sleep).
    fn stall_us(&mut self, us: u64);
    fn sleep_ms(&mut self, ms: u64);
    /// A monotonic clock in 100 ns units (Timer).
    fn timer(&mut self) -> u64;
    /// `Notify(path, value)`.
    fn notify(&mut self, _path: &str, _value: u64) {}
    /// A Store to the Debug object.
    fn debug(&mut self, _text: &str) {}
    /// The firmware's global lock (FACS), for fields declared with `Lock`. True when held.
    fn acquire_global_lock(&mut self) -> bool {
        true
    }
    fn release_global_lock(&mut self) {}
    /// Is there room on the stack for another level of nesting? (The kernel answers from its
    /// stack pointer; the host has plenty.)
    fn stack_ok(&mut self) -> bool {
        true
    }
}

/// Per-evaluation budgets (fail closed). The defaults fit real firmware with a wide margin.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Terms executed per top-level evaluation (loops polling hardware end here).
    pub steps: u64,
    /// Nested method calls.
    pub calls: u32,
    /// Nested expressions inside one method.
    pub nesting: u32,
    /// Largest buffer or string, in bytes.
    pub buffer: usize,
    /// Most elements in one package.
    pub package: usize,
    /// Most namespace nodes in total.
    pub nodes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            steps: 2_000_000,
            calls: 48,
            nesting: 48,
            buffer: 1 << 20,
            package: 1 << 16,
            nodes: 1 << 18,
        }
    }
}
