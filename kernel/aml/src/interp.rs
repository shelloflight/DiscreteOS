//! The interpreter: executes AML byte code directly (no intermediate tree). Definitions at a
//! table's top level run once at load; method bodies run when called.

use alloc::rc::Rc;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::cell::Cell;
use core::cmp::Ordering;
use core::fmt::Write;

use crate::namespace::{Name, Namespace, NodeId, ROOT, lead_char, name_char};
use crate::object::{Field, FieldKind, Method, Native, Object, Ref, Region, buf, pkg};
use crate::{Error, ErrorKind as K, Handler, Limits, Result};

/// What `Revision` returns (the interpreter's version, as a date).
const REVISION: u64 = 0x2026_1118;
/// Most errors kept in `Stats::errors`.
const ERRORS_KEPT: usize = 16;

/// The `_OSI` strings answered true. Firmware is written and tested against Windows, and picks
/// its code paths from these (ACPICA and other operating systems answer the same way).
const OSI: &[&[u8]] = &[
    b"Windows 2000",
    b"Windows 2001",
    b"Windows 2001 SP1",
    b"Windows 2001.1",
    b"Windows 2001 SP2",
    b"Windows 2001.1 SP1",
    b"Windows 2006",
    b"Windows 2006.1",
    b"Windows 2006 SP1",
    b"Windows 2006 SP2",
    b"Windows 2009",
    b"Windows 2012",
    b"Windows 2013",
    b"Windows 2015",
    b"Windows 2016",
    b"Windows 2017",
    b"Windows 2017.2",
    b"Windows 2018",
    b"Windows 2018.2",
    b"Windows 2019",
    b"Windows 2020",
    b"Windows 2021",
    b"Windows 2022",
    b"Module Device",
    b"Processor Device",
    b"3.0 Thermal Model",
    b"3.0 _SCP Extensions",
    b"Processor Aggregator Device",
    b"Extended Address Space Descriptor",
];

#[derive(Clone, Default, Debug)]
pub struct Stats {
    /// Tables loaded.
    pub tables: u32,
    /// Definitions skipped while loading (each kept in `errors` up to a limit).
    pub load_errors: u32,
    /// Names defined twice while loading (the first definition wins).
    pub duplicates: u32,
    /// Methods called (including nested calls).
    pub calls: u64,
    /// The first errors: where (a path) and what.
    pub errors: Vec<(String, Error)>,
}

/// Result of the device initialisation walk.
#[derive(Clone, Default, Debug)]
pub struct InitReport {
    pub regs: u32,
    pub devices: u32,
    pub present: u32,
    pub inits: u32,
    pub failures: u32,
}

pub(crate) struct Frame {
    pub code: Rc<[u8]>,
    pub pc: usize,
    pub scope: NodeId,
    pub locals: [Object; 8],
    pub args: [Object; 7],
    pub int64: bool,
    /// Running a method (names created are temporary), not loading a table.
    pub method: bool,
    pub created: Vec<NodeId>,
}

pub(crate) enum Flow {
    Next,
    Return(Object),
    Break,
    Continue,
}

enum Target {
    Null,
    Local(usize),
    Arg(usize),
    Node(NodeId),
    Debug,
    Ref(Ref),
}

impl Frame {
    fn new(code: Rc<[u8]>, pc: usize, scope: NodeId, int64: bool, method: bool) -> Frame {
        Frame {
            code,
            pc,
            scope,
            locals: Default::default(),
            args: Default::default(),
            int64,
            method,
            created: Vec::new(),
        }
    }

    /// Errors carry the offset in the table (the code starts after the 36-byte header).
    pub fn err(&self, kind: K) -> Error {
        Error::new(kind, self.pc + 36)
    }

    fn peek(&self) -> Result<u8> {
        self.code
            .get(self.pc)
            .copied()
            .ok_or_else(|| self.err(K::Malformed))
    }

    fn peek_at(&self, off: usize) -> Option<u8> {
        self.code.get(self.pc + off).copied()
    }

    fn byte(&mut self) -> Result<u8> {
        let b = self.peek()?;
        self.pc += 1;
        Ok(b)
    }

    fn le(&mut self, n: usize) -> Result<u64> {
        if self.pc + n > self.code.len() {
            return Err(self.err(K::Malformed));
        }
        let mut v = 0u64;
        for i in 0..n {
            v |= (self.code[self.pc + i] as u64) << (8 * i);
        }
        self.pc += n;
        Ok(v)
    }

    /// A PkgLength's value.
    fn pkg_raw(&mut self) -> Result<usize> {
        let lead = self.byte()?;
        let extra = (lead >> 6) as usize;
        if extra == 0 {
            return Ok((lead & 0x3F) as usize);
        }
        let mut v = (lead & 0x0F) as usize;
        for i in 0..extra {
            v |= (self.byte()? as usize) << (4 + 8 * i);
        }
        Ok(v)
    }

    /// A PkgLength, as the end offset of the package it measures (it counts its own bytes).
    fn pkg_end(&mut self) -> Result<usize> {
        let start = self.pc;
        let len = self.pkg_raw()?;
        let end = start + len;
        if end < self.pc || end > self.code.len() {
            return Err(Error::new(K::Malformed, start + 36));
        }
        Ok(end)
    }

    fn seg(&mut self) -> Result<[u8; 4]> {
        if self.pc + 4 > self.code.len() {
            return Err(self.err(K::Malformed));
        }
        let s = [
            self.code[self.pc],
            self.code[self.pc + 1],
            self.code[self.pc + 2],
            self.code[self.pc + 3],
        ];
        if !lead_char(s[0]) || !s[1..].iter().all(|&c| name_char(c)) {
            return Err(self.err(K::Malformed));
        }
        self.pc += 4;
        Ok(s)
    }

    fn name(&mut self) -> Result<Name> {
        let mut n = Name::default();
        if self.peek()? == b'\\' {
            n.root = true;
            self.pc += 1;
        }
        while self.peek()? == b'^' {
            n.up = n.up.checked_add(1).ok_or_else(|| self.err(K::Malformed))?;
            self.pc += 1;
        }
        match self.peek()? {
            0x00 => self.pc += 1,
            0x2E => {
                self.pc += 1;
                n.segs.push(self.seg()?);
                n.segs.push(self.seg()?);
            }
            0x2F => {
                self.pc += 1;
                let count = self.byte()?;
                for _ in 0..count {
                    n.segs.push(self.seg()?);
                }
            }
            c if lead_char(c) => n.segs.push(self.seg()?),
            _ => return Err(self.err(K::Malformed)),
        }
        Ok(n)
    }
}

fn name_start(b: u8) -> bool {
    b == b'\\' || b == b'^' || b == 0x2E || b == 0x2F || lead_char(b)
}

pub(crate) fn show(n: &Name) -> String {
    let mut s = String::new();
    if n.root {
        s.push('\\');
    }
    for _ in 0..n.up {
        s.push('^');
    }
    for (i, seg) in n.segs.iter().enumerate() {
        if i > 0 {
            s.push('.');
        }
        for &c in seg {
            s.push(c as char);
        }
    }
    s
}

/// Deepest package nesting stored into a package element.
const MAX_DEPTH: usize = 8;

/// Package nesting of `o`, counted up to `limit`.
fn depth(o: &Object, limit: usize) -> usize {
    match o {
        Object::Package(p) if limit > 0 => {
            1 + p
                .borrow()
                .iter()
                .map(|e| depth(e, limit - 1))
                .max()
                .unwrap_or(0)
        }
        Object::Package(_) => 1,
        _ => 0,
    }
}

/// Copy a value for a Store: strings, buffers and packages are not shared afterwards.
fn copy_value(v: &Object) -> Object {
    match v {
        Object::String(b) => Object::String(buf(b.borrow().clone())),
        Object::Buffer(b) => Object::Buffer(buf(b.borrow().clone())),
        Object::Package(p) => Object::Package(pkg(p.borrow().iter().map(copy_value).collect())),
        o => o.clone(),
    }
}

fn hex_digit(c: u8) -> Option<u64> {
    (c as char).to_digit(16).map(|d| d as u64)
}

/// EISA compressed id (`_HID`/`_CID` integers) as text: 0x030AD041 -> "PNP0A03".
pub fn eisa_id(v: u64) -> String {
    let x = (v as u32).swap_bytes();
    let mut s = String::new();
    for shift in [26u32, 21, 16] {
        s.push((((x >> shift) & 0x1F) as u8 + 0x40) as char);
    }
    let _ = write!(s, "{:04X}", x & 0xFFFF);
    s
}

pub struct Interpreter<H: Handler> {
    pub(crate) ns: Namespace,
    pub(crate) h: H,
    pub limits: Limits,
    pub stats: Stats,
    steps: u64,
    calls: u32,
    nesting: u32,
    gl: NodeId,
    /// An evaluation is running (nested helpers must not reset its budgets).
    active: bool,
}

impl<H: Handler> Interpreter<H> {
    pub fn new(handler: H) -> Interpreter<H> {
        let mut ns = Namespace::new();
        for s in [b"_GPE", b"_PR_", b"_SB_", b"_SI_", b"_TZ_"] {
            ns.add(ROOT, *s, Object::Scope);
        }
        ns.add(ROOT, *b"_OSI", Object::Native(Native::Osi));
        ns.add(ROOT, *b"_OS_", Object::string(b"Microsoft Windows NT"));
        ns.add(ROOT, *b"_REV", Object::Integer(2));
        let gl = ns
            .add(ROOT, *b"_GL_", Object::Mutex(Rc::new(Cell::new(0))))
            .unwrap_or(ROOT);
        Interpreter {
            ns,
            h: handler,
            limits: Limits::default(),
            stats: Stats::default(),
            steps: 0,
            calls: 0,
            nesting: 0,
            gl,
            active: false,
        }
    }

    pub fn handler(&mut self) -> &mut H {
        &mut self.h
    }

    pub fn namespace(&self) -> &Namespace {
        &self.ns
    }

    /// Start a top-level evaluation with fresh budgets, unless one is already running.
    fn enter(&mut self) -> bool {
        let was = self.active;
        if !was {
            self.steps = self.limits.steps;
            self.calls = 0;
            self.nesting = 0;
            self.active = true;
        }
        was
    }

    fn leave(&mut self, was: bool) {
        self.active = was;
    }

    fn record(&mut self, at: NodeId, e: &Error) {
        if self.stats.errors.len() < ERRORS_KEPT {
            let p = self.ns.path(at);
            self.stats.errors.push((p, e.clone()));
        }
    }

    /// Load a DSDT or SSDT (the whole table, header included). Definitions before an error stay.
    pub fn load_table(&mut self, table: &[u8]) -> Result<()> {
        if table.len() < 36 || !(table.starts_with(b"DSDT") || table.starts_with(b"SSDT")) {
            return Err(Error::new(K::Malformed, 0));
        }
        let len = u32::from_le_bytes([table[4], table[5], table[6], table[7]]) as usize;
        if len < 36 || len > table.len() {
            return Err(Error::new(K::Malformed, 4));
        }
        let code: Rc<[u8]> = Rc::from(&table[36..len]);
        let end = code.len();
        let mut f = Frame::new(code, 0, ROOT, table[8] >= 2, false);
        let was = self.enter();
        self.steps = self.limits.steps.saturating_mul(4); // loading a large DSDT is many terms
        self.stats.tables += 1;
        let r = self.exec_list(&mut f, end);
        self.leave(was);
        if let Err(e) = &r {
            self.stats.load_errors += 1;
            self.record(ROOT, e);
        }
        r.map(|_| ())
    }

    /// Evaluate a named object by absolute path (`\_S5`, `\_SB.PCI0._STA`): a method is called
    /// with `args`, a field is read, data is returned as is.
    pub fn evaluate(&mut self, path: &str, args: Vec<Object>) -> Result<Object> {
        let name = Name::parse(path).ok_or(Error::new(K::Malformed, 0))?;
        let node = self
            .ns
            .resolve(ROOT, &name)
            .ok_or_else(|| Error::new(K::NotFound(String::from(path)), 0))?;
        self.evaluate_node(node, args)
    }

    /// Evaluate a node (see `evaluate`).
    pub fn evaluate_node(&mut self, node: NodeId, args: Vec<Object>) -> Result<Object> {
        let was = self.enter();
        let r = self.eval_node(node, args, true);
        self.leave(was);
        if let Err(e) = &r {
            self.record(node, e);
        }
        r
    }

    /// `seg` under `node` (`_STA` of a device), if there is one.
    pub fn child(&self, node: NodeId, seg: &str) -> Option<NodeId> {
        let n = Name::parse(seg)?;
        if n.segs.len() != 1 || n.root || n.up != 0 {
            return None;
        }
        self.ns.child(node, n.segs[0])
    }

    pub fn find(&self, path: &str) -> Option<NodeId> {
        self.ns.resolve(ROOT, &Name::parse(path)?)
    }

    pub fn path(&self, node: NodeId) -> String {
        self.ns.path(node)
    }

    /// Evaluate `seg` under `node` as an integer; None if absent.
    pub fn child_int(&mut self, node: NodeId, seg: &str) -> Result<Option<u64>> {
        let Some(c) = self.child(node, seg) else {
            return Ok(None);
        };
        let was = self.enter();
        let v = self.eval_node(c, Vec::new(), true);
        self.leave(was);
        let v = v?;
        let v = self.deref_all(v)?;
        match v {
            Object::Integer(x) => Ok(Some(x)),
            Object::Buffer(_) | Object::String(_) => Ok(Some(self.conv_int(true, &v)?)),
            _ => Err(Error::new(K::Type("integer"), 0)),
        }
    }

    /// `_HID` and `_CID` of a device as text ids (EISA integers decoded).
    pub fn ids(&mut self, node: NodeId) -> Vec<String> {
        let mut out = Vec::new();
        for seg in ["_HID", "_CID"] {
            let Some(c) = self.child(node, seg) else {
                continue;
            };
            let was = self.enter();
            let v = self.eval_node(c, Vec::new(), true);
            self.leave(was);
            let Ok(v) = v else { continue };
            let list = match &v {
                Object::Package(p) => p.borrow().clone(),
                o => vec![o.clone()],
            };
            for o in list {
                match o {
                    Object::Integer(x) => out.push(eisa_id(x)),
                    Object::String(s) => {
                        let b = s.borrow();
                        let t: String = b
                            .iter()
                            .take_while(|&&c| c != 0)
                            .map(|&c| c as char)
                            .collect();
                        out.push(t);
                    }
                    _ => {}
                }
            }
        }
        out
    }

    /// Devices (anywhere in the namespace) with one of `ids` as `_HID` or `_CID`.
    pub fn find_devices(&mut self, ids: &[&str]) -> Vec<NodeId> {
        let all = self.ns.walk(ROOT);
        let mut out = Vec::new();
        for n in all {
            if !self.ns.exists(n) || !matches!(self.ns.obj(n), Object::Device) {
                continue;
            }
            if self.ids(n).iter().any(|i| ids.contains(&i.as_str())) {
                out.push(n);
            }
        }
        out
    }

    /// `\_Sx` sleep types (SLP_TYPa, SLP_TYPb) for state `s` (0-5), if the firmware has it.
    pub fn sleep_type(&mut self, s: u8) -> Option<(u8, u8)> {
        let path = alloc::format!("\\_S{}_", s.min(9));
        self.find(&path)?;
        let v = self.evaluate(&path, Vec::new()).ok()?;
        let Object::Package(p) = v else { return None };
        let el = p.borrow().clone();
        let a = self.deref_all(el.first()?.clone()).ok()?.as_integer()?;
        let b = match el.get(1) {
            Some(o) => self
                .deref_all(o.clone())
                .ok()
                .and_then(|o| o.as_integer())
                .unwrap_or(a),
            None => a,
        };
        Some(((a & 7) as u8, (b & 7) as u8))
    }

    /// Run `_REG` for the spaces served, then the `_STA`/`_INI` walk (ACPI 6.5, 6.5.1).
    pub fn initialize(&mut self) -> InitReport {
        let mut rep = InitReport::default();
        // _REG(space, 1) for SystemMemory, SystemIO and PCI_Config regions next to each _REG.
        for n in self.ns.walk(ROOT) {
            if !self.ns.exists(n) || self.ns.node(n).name != *b"_REG" {
                continue;
            }
            let parent = self.ns.parent(n);
            let mut spaces: Vec<u8> = Vec::new();
            for c in self.ns.children(parent) {
                if let Object::Region(r) = self.ns.obj(c)
                    && r.space <= 2
                    && !spaces.contains(&r.space)
                {
                    spaces.push(r.space);
                }
            }
            spaces.sort_unstable();
            for s in spaces {
                rep.regs += 1;
                if self
                    .evaluate_node(n, vec![Object::Integer(s as u64), Object::Integer(1)])
                    .is_err()
                {
                    rep.failures += 1;
                }
            }
        }
        let sb = self.find("\\_SB_");
        if let Some(ini) = sb.and_then(|s| self.child(s, "_INI")) {
            rep.inits += 1;
            if self.evaluate_node(ini, Vec::new()).is_err() {
                rep.failures += 1;
            }
        }
        let mut stack = vec![ROOT];
        while let Some(n) = stack.pop() {
            for c in self.ns.children(n).into_iter().rev() {
                if !self.ns.exists(c) {
                    continue;
                }
                let o = self.ns.obj(c);
                let device = matches!(
                    o,
                    Object::Device | Object::Processor { .. } | Object::ThermalZone
                );
                if !device {
                    if matches!(o, Object::Scope) {
                        stack.push(c);
                    }
                    continue;
                }
                rep.devices += 1;
                let sta = match self.child_int(c, "_STA") {
                    Ok(v) => v.unwrap_or(0x0F),
                    Err(e) => {
                        self.record(c, &e);
                        rep.failures += 1;
                        0
                    }
                };
                if sta & 1 != 0 {
                    rep.present += 1;
                    if let Some(ini) = self.child(c, "_INI") {
                        rep.inits += 1;
                        if self.evaluate_node(ini, Vec::new()).is_err() {
                            rep.failures += 1;
                        }
                    }
                    stack.push(c);
                } else if sta & 8 != 0 {
                    stack.push(c);
                }
            }
        }
        rep
    }

    // ---- execution --------------------------------------------------------------------------

    fn step(&mut self, f: &Frame) -> Result<()> {
        if self.steps == 0 {
            return Err(f.err(K::Limit("steps")));
        }
        self.steps -= 1;
        Ok(())
    }

    fn ones(f: &Frame) -> u64 {
        if f.int64 { u64::MAX } else { 0xFFFF_FFFF }
    }

    fn mask(f: &Frame, v: u64) -> u64 {
        v & Self::ones(f)
    }

    fn bool_obj(f: &Frame, b: bool) -> Object {
        Object::Integer(if b { Self::ones(f) } else { 0 })
    }

    pub(crate) fn exec_list(&mut self, f: &mut Frame, end: usize) -> Result<Flow> {
        while f.pc < end {
            match self.exec_term(f, end)? {
                Flow::Next => {}
                other => return Ok(other),
            }
        }
        if f.pc > end {
            return Err(f.err(K::Malformed));
        }
        Ok(Flow::Next)
    }

    /// Run a scope-like body (Scope, Device, ...) with `node` as the scope. While loading, a body
    /// that fails is skipped (recorded); the rest of the table still loads.
    fn body(&mut self, f: &mut Frame, end: usize, node: Option<NodeId>) -> Result<Flow> {
        let Some(node) = node else {
            f.pc = end;
            return Ok(Flow::Next);
        };
        let saved = f.scope;
        f.scope = node;
        let r = self.exec_list(f, end);
        f.scope = saved;
        match r {
            Ok(Flow::Next) => {
                f.pc = end;
                Ok(Flow::Next)
            }
            Ok(other) => Ok(other),
            Err(e) if !f.method => {
                self.stats.load_errors += 1;
                self.record(node, &e);
                f.pc = end;
                Ok(Flow::Next)
            }
            Err(e) => Err(e),
        }
    }

    /// Create a named object. While loading, a missing parent or a duplicate is recorded and the
    /// definition skipped (None); inside a method both are errors.
    fn create(&mut self, f: &mut Frame, name: &Name, obj: Object) -> Result<Option<NodeId>> {
        if self.ns.len() >= self.limits.nodes {
            return Err(f.err(K::Limit("namespace size")));
        }
        let Some((parent, seg)) = self.ns.place(f.scope, name) else {
            let e = f.err(K::NotFound(show(name)));
            if f.method {
                return Err(e);
            }
            self.stats.load_errors += 1;
            self.record(f.scope, &e);
            return Ok(None);
        };
        match self.ns.add(parent, seg, obj) {
            Some(id) => {
                if f.method {
                    f.created.push(id);
                }
                Ok(Some(id))
            }
            None if f.method => Err(f.err(K::Exists(show(name)))),
            None => {
                self.stats.duplicates += 1;
                Ok(None)
            }
        }
    }

    /// A Device-like definition: reuse an existing node of the same kind (a table re-declaring a
    /// device it should have opened with Scope), else create.
    fn create_scope(&mut self, f: &mut Frame, name: &Name, obj: Object) -> Result<Option<NodeId>> {
        if let Some((parent, seg)) = self.ns.place(f.scope, name)
            && let Some(existing) = self.ns.child(parent, seg)
            && core::mem::discriminant(self.ns.obj(existing)) == core::mem::discriminant(&obj)
            && !f.method
        {
            self.stats.duplicates += 1;
            return Ok(Some(existing));
        }
        self.create(f, name, obj)
    }

    /// One term of a term list: a definition, a statement or an expression (`def_*`, `stmt_*`,
    /// `exec_ext`: non-inlined for the same reason as `eval_op`).
    fn exec_term(&mut self, f: &mut Frame, end: usize) -> Result<Flow> {
        self.step(f)?;
        let op = f.peek()?;
        match op {
            0x08 => return self.def_name(f),
            0x10 => return self.def_scope(f),
            0x14 => return self.def_method(f),
            0x15 => return self.def_external(f),
            0x06 => return self.def_alias(f),
            0x8A | 0x8B | 0x8C | 0x8D | 0x8F => return self.def_buffer_field(f, op),
            0xA0 => return self.stmt_if(f, end),
            0xA1 => return self.stmt_else(f),
            0xA2 => return self.stmt_while(f),
            0xA4 => return self.stmt_return(f),
            0xA5 => return self.stmt_break(f),
            0x9F => return self.stmt_continue(f),
            0xA3 | 0xCC => f.pc += 1,
            0x86 => return self.stmt_notify(f),
            0x5B => return self.exec_ext(f),
            _ => {
                self.eval(f)?;
            }
        }
        Ok(Flow::Next)
    }

    #[inline(never)]
    fn def_name(&mut self, f: &mut Frame) -> Result<Flow> {
        f.pc += 1;
        let n = f.name()?;
        let v = self.eval(f)?;
        self.create(f, &n, v)?;
        Ok(Flow::Next)
    }

    #[inline(never)]
    fn def_scope(&mut self, f: &mut Frame) -> Result<Flow> {
        f.pc += 1;
        let pend = f.pkg_end()?;
        let n = f.name()?;
        let node = match self.ns.resolve(f.scope, &n) {
            Some(x) => Some(self.follow_alias(x)),
            None if f.method => return Err(f.err(K::NotFound(show(&n)))),
            None => {
                self.stats.load_errors += 1;
                let e = f.err(K::NotFound(show(&n)));
                self.record(f.scope, &e);
                None
            }
        };
        self.body(f, pend, node)
    }

    #[inline(never)]
    fn def_method(&mut self, f: &mut Frame) -> Result<Flow> {
        f.pc += 1;
        let mend = f.pkg_end()?;
        let n = f.name()?;
        let flags = f.byte()?;
        let m = Method {
            code: f.code.clone(),
            start: f.pc,
            end: mend,
            args: flags & 7,
            serialized: flags & 8 != 0,
            int64: f.int64,
        };
        f.pc = mend;
        self.create(f, &n, Object::Method(Rc::new(m)))?;
        Ok(Flow::Next)
    }

    #[inline(never)]
    fn def_external(&mut self, f: &mut Frame) -> Result<Flow> {
        f.pc += 1;
        f.name()?;
        f.byte()?;
        f.byte()?;
        Ok(Flow::Next)
    }

    #[inline(never)]
    fn def_alias(&mut self, f: &mut Frame) -> Result<Flow> {
        f.pc += 1;
        let src = f.name()?;
        let alias = f.name()?;
        match self.ns.resolve(f.scope, &src) {
            Some(s) => {
                self.create(f, &alias, Object::Alias(s))?;
            }
            None if f.method => return Err(f.err(K::NotFound(show(&src)))),
            None => {
                self.stats.load_errors += 1;
                let e = f.err(K::NotFound(show(&src)));
                self.record(f.scope, &e);
            }
        }
        Ok(Flow::Next)
    }

    #[inline(never)]
    fn def_buffer_field(&mut self, f: &mut Frame, op: u8) -> Result<Flow> {
        f.pc += 1;
        let src = self.eval(f)?;
        let idx = self.int(f)?;
        let n = f.name()?;
        let (bit, len) = match op {
            0x8A => (idx.saturating_mul(8), 32),
            0x8B => (idx.saturating_mul(8), 16),
            0x8C => (idx.saturating_mul(8), 8),
            0x8D => (idx, 1),
            _ => (idx.saturating_mul(8), 64),
        };
        let o = self.buffer_field(f, src, bit, len)?;
        self.create(f, &n, o)?;
        Ok(Flow::Next)
    }

    #[inline(never)]
    fn stmt_if(&mut self, f: &mut Frame, end: usize) -> Result<Flow> {
        f.pc += 1;
        let iend = f.pkg_end()?;
        let p = self.int(f)?;
        if p != 0 {
            let fl = self.exec_list(f, iend)?;
            if let Flow::Next = fl {
                f.pc = iend;
                if f.pc < end && f.peek()? == 0xA1 {
                    f.pc += 1;
                    f.pc = f.pkg_end()?;
                }
            }
            return Ok(fl);
        }
        f.pc = iend;
        if f.pc < end && f.peek()? == 0xA1 {
            f.pc += 1;
            let eend = f.pkg_end()?;
            let fl = self.exec_list(f, eend)?;
            if let Flow::Next = fl {
                f.pc = eend;
            }
            return Ok(fl);
        }
        Ok(Flow::Next)
    }

    #[inline(never)]
    fn stmt_else(&mut self, f: &mut Frame) -> Result<Flow> {
        f.pc += 1;
        f.pc = f.pkg_end()?;
        Ok(Flow::Next)
    }

    #[inline(never)]
    fn stmt_while(&mut self, f: &mut Frame) -> Result<Flow> {
        f.pc += 1;
        let wend = f.pkg_end()?;
        let pred = f.pc;
        loop {
            f.pc = pred;
            self.step(f)?;
            if self.int(f)? == 0 {
                break;
            }
            match self.exec_list(f, wend)? {
                Flow::Next | Flow::Continue => {}
                Flow::Break => break,
                r @ Flow::Return(_) => return Ok(r),
            }
        }
        f.pc = wend;
        Ok(Flow::Next)
    }

    #[inline(never)]
    fn stmt_return(&mut self, f: &mut Frame) -> Result<Flow> {
        f.pc += 1;
        let v = self.eval(f)?;
        Ok(Flow::Return(v))
    }

    #[inline(never)]
    fn stmt_break(&mut self, f: &mut Frame) -> Result<Flow> {
        f.pc += 1;
        Ok(Flow::Break)
    }

    #[inline(never)]
    fn stmt_continue(&mut self, f: &mut Frame) -> Result<Flow> {
        f.pc += 1;
        Ok(Flow::Continue)
    }

    #[inline(never)]
    fn stmt_notify(&mut self, f: &mut Frame) -> Result<Flow> {
        f.pc += 1;
        let t = self.target(f)?;
        let v = self.int(f)?;
        match t {
            Target::Node(n) => {
                let p = self.ns.path(n);
                self.h.notify(&p, v);
            }
            _ => return Err(f.err(K::Type("object to notify"))),
        }
        Ok(Flow::Next)
    }

    #[inline(never)]
    fn exec_ext(&mut self, f: &mut Frame) -> Result<Flow> {
        let ext = f.peek_at(1).ok_or_else(|| f.err(K::Malformed))?;
        match ext {
            0x01 => {
                f.pc += 2;
                let n = f.name()?;
                f.byte()?;
                self.create(f, &n, Object::Mutex(Rc::new(Cell::new(0))))?;
            }
            0x02 => {
                f.pc += 2;
                let n = f.name()?;
                self.create(f, &n, Object::Event(Rc::new(Cell::new(0))))?;
            }
            0x13 => {
                f.pc += 2;
                let src = self.eval(f)?;
                let bit = self.int(f)?;
                let len = self.int(f)?;
                let n = f.name()?;
                let o = self.buffer_field(f, src, bit, len)?;
                self.create(f, &n, o)?;
            }
            0x80 => {
                f.pc += 2;
                let n = f.name()?;
                let space = f.byte()?;
                let base = self.int(f)?;
                let len = self.int(f)?;
                let scope = self.ns.place(f.scope, &n).map_or(f.scope, |p| p.0);
                let r = Region {
                    space,
                    base,
                    len,
                    scope,
                    pci: Cell::new(None),
                };
                self.create(f, &n, Object::Region(Rc::new(r)))?;
            }
            0x88 => {
                f.pc += 2;
                let n = f.name()?;
                self.eval(f)?;
                self.eval(f)?;
                self.eval(f)?;
                let scope = self.ns.place(f.scope, &n).map_or(f.scope, |p| p.0);
                let r = Region {
                    space: 0xFF,
                    base: 0,
                    len: 0,
                    scope,
                    pci: Cell::new(None),
                };
                self.create(f, &n, Object::Region(Rc::new(r)))?;
            }
            0x81 | 0x86 | 0x87 => {
                f.pc += 2;
                let fend = f.pkg_end()?;
                let kind = match ext {
                    0x81 => {
                        let rn = f.name()?;
                        FieldKind::Region(self.region(f, &rn)?)
                    }
                    0x86 => {
                        let i = f.name()?;
                        let d = f.name()?;
                        let index = self.field_node(f, &i)?;
                        let data = self.field_node(f, &d)?;
                        FieldKind::Index { index, data }
                    }
                    _ => {
                        let rn = f.name()?;
                        let bn = f.name()?;
                        let region = self.region(f, &rn)?;
                        let bank = self.field_node(f, &bn)?;
                        let value = self.int(f)?;
                        FieldKind::Bank {
                            region,
                            bank,
                            value,
                        }
                    }
                };
                let flags = f.byte()?;
                self.field_list(f, fend, flags, kind)?;
                f.pc = fend;
            }
            0x82..=0x85 => {
                f.pc += 2;
                let dend = f.pkg_end()?;
                let n = f.name()?;
                let obj = match ext {
                    0x82 => Object::Device,
                    0x83 => {
                        let id = f.byte()?;
                        let pblk = f.le(4)? as u32;
                        let pblk_len = f.byte()?;
                        Object::Processor { id, pblk, pblk_len }
                    }
                    0x84 => {
                        let level = f.byte()?;
                        let order = f.le(2)? as u16;
                        Object::PowerRes { level, order }
                    }
                    _ => Object::ThermalZone,
                };
                let node = self.create_scope(f, &n, obj)?;
                return self.body(f, dend, node);
            }
            0x21 => {
                f.pc += 2;
                let us = self.int(f)?;
                self.h.stall_us(us.min(100_000));
            }
            0x22 => {
                f.pc += 2;
                let ms = self.int(f)?;
                self.h.sleep_ms(ms.min(10_000));
            }
            0x24 | 0x26 => {
                f.pc += 2;
                let t = self.target(f)?;
                match self.target_obj(&t) {
                    Some(Object::Event(c)) => c.set(if ext == 0x24 {
                        c.get().saturating_add(1)
                    } else {
                        0
                    }),
                    _ => return Err(f.err(K::Type("event"))),
                }
            }
            0x27 => {
                f.pc += 2;
                let t = self.target(f)?;
                match self.target_obj(&t) {
                    Some(Object::Mutex(c)) => {
                        if c.get() > 0 {
                            c.set(c.get() - 1);
                            if matches!(t, Target::Node(n) if n == self.gl) && c.get() == 0 {
                                self.h.release_global_lock();
                            }
                        }
                    }
                    _ => return Err(f.err(K::Type("mutex"))),
                }
            }
            0x32 => {
                f.pc += 2;
                let ty = f.byte()?;
                let code = f.le(4)? as u32;
                let arg = self.int(f)?;
                return Err(f.err(K::Fatal(ty, code, arg)));
            }
            0x20 | 0x2A => return Err(f.err(K::Unsupported("Load/Unload"))),
            _ => {
                self.eval(f)?;
            }
        }
        Ok(Flow::Next)
    }

    fn region(&mut self, f: &Frame, n: &Name) -> Result<Rc<Region>> {
        let node = self
            .ns
            .resolve(f.scope, n)
            .ok_or_else(|| f.err(K::NotFound(show(n))))?;
        match self.ns.obj(self.follow_alias(node)) {
            Object::Region(r) => Ok(r.clone()),
            _ => Err(f.err(K::Type("operation region"))),
        }
    }

    fn field_node(&mut self, f: &Frame, n: &Name) -> Result<NodeId> {
        let node = self
            .ns
            .resolve(f.scope, n)
            .ok_or_else(|| f.err(K::NotFound(show(n))))?;
        let node = self.follow_alias(node);
        match self.ns.obj(node) {
            Object::Field(_) => Ok(node),
            _ => Err(f.err(K::Type("field"))),
        }
    }

    fn field_list(&mut self, f: &mut Frame, end: usize, flags: u8, kind: FieldKind) -> Result<()> {
        let kind = Rc::new(kind);
        let mut bit = 0u64;
        let mut access = access_bytes(flags & 0x0F);
        let lock = flags & 0x10 != 0;
        let update = (flags >> 5) & 3;
        while f.pc < end {
            match f.peek()? {
                0x00 => {
                    f.pc += 1;
                    bit = bit.saturating_add(f.pkg_raw()? as u64);
                }
                0x01 => {
                    f.pc += 1;
                    let t = f.byte()?;
                    f.byte()?;
                    access = access_bytes(t & 0x0F);
                }
                0x02 => {
                    f.pc += 1;
                    if f.peek()? == 0x11 {
                        self.eval(f)?;
                    } else {
                        f.name()?;
                    }
                }
                0x03 => {
                    f.pc += 1;
                    let t = f.byte()?;
                    f.byte()?;
                    f.byte()?;
                    access = access_bytes(t & 0x0F);
                }
                _ => {
                    let seg = f.seg()?;
                    let len = f.pkg_raw()? as u64;
                    let fk = match &*kind {
                        FieldKind::Region(r) => FieldKind::Region(r.clone()),
                        FieldKind::Index { index, data } => FieldKind::Index {
                            index: *index,
                            data: *data,
                        },
                        FieldKind::Bank {
                            region,
                            bank,
                            value,
                        } => FieldKind::Bank {
                            region: region.clone(),
                            bank: *bank,
                            value: *value,
                        },
                    };
                    let fl = Field {
                        kind: fk,
                        bit,
                        len,
                        access,
                        lock,
                        update,
                    };
                    let name = Name {
                        root: false,
                        up: 0,
                        segs: vec![seg],
                    };
                    self.create(f, &name, Object::Field(Rc::new(fl)))?;
                    bit = bit.saturating_add(len);
                }
            }
        }
        if f.pc > end {
            return Err(f.err(K::Malformed));
        }
        Ok(())
    }

    fn buffer_field(&mut self, f: &Frame, src: Object, bit: u64, len: u64) -> Result<Object> {
        let src = self.deref_all(src)?;
        let b = match src {
            Object::Buffer(b) => b,
            _ => return Err(f.err(K::Type("buffer"))),
        };
        let size = b.borrow().len() as u64 * 8;
        if len == 0 || bit.checked_add(len).is_none_or(|e| e > size) {
            return Err(f.err(K::Range("buffer field outside its buffer")));
        }
        Ok(Object::BufferField {
            buf: b,
            bit: bit as usize,
            len: len as usize,
        })
    }

    pub(crate) fn follow_alias(&self, mut n: NodeId) -> NodeId {
        for _ in 0..8 {
            match self.ns.obj(n) {
                Object::Alias(t) if self.ns.exists(*t) => n = *t,
                _ => break,
            }
        }
        n
    }

    // ---- expressions --------------------------------------------------------------------------

    fn int(&mut self, f: &mut Frame) -> Result<u64> {
        let v = self.eval(f)?;
        self.conv_int(f.int64, &v)
            .map_err(|e| if e.at == 0 { f.err(e.kind) } else { e })
    }

    pub(crate) fn eval(&mut self, f: &mut Frame) -> Result<Object> {
        if self.nesting >= self.limits.nesting || !self.h.stack_ok() {
            return Err(f.err(K::Limit("nesting")));
        }
        self.nesting += 1;
        let r = self.eval_op(f);
        self.nesting -= 1;
        r
    }

    /// One expression. Each opcode group runs in its own non-inlined function (`op_*`), so
    /// a level of nesting costs only the frame of the operation at that level: real firmware
    /// nests deeply and the kernel runs this on a fixed stack.
    fn eval_op(&mut self, f: &mut Frame) -> Result<Object> {
        let at = f.pc;
        let op = f.byte()?;
        let v = match op {
            0x00 => Object::Integer(0),
            0x01 => Object::Integer(1),
            0xFF => Object::Integer(Self::ones(f)),
            0x0A => Object::Integer(f.le(1)?),
            0x0B => Object::Integer(f.le(2)?),
            0x0C => Object::Integer(f.le(4)?),
            0x0E => return self.op_qword(f),
            0x0D => return self.op_string(f),
            0x11 => return self.op_buffer(f),
            0x12 | 0x13 => return self.op_package(f, op),
            0x60..=0x67 => f.locals[(op - 0x60) as usize].clone(),
            0x68..=0x6E => match f.args[(op - 0x68) as usize].clone() {
                Object::Ref(r) => self.read_ref(&r)?,
                o => o,
            },
            b if name_start(b) => {
                f.pc = at;
                return self.eval_name(f);
            }
            0x70 => return self.op_store(f),
            0x71 => return self.op_refof(f),
            0x72 | 0x74 | 0x77 | 0x79 | 0x7A | 0x7B | 0x7C | 0x7D | 0x7E | 0x7F | 0x85 => {
                return self.op_arith(f, op);
            }
            0x73 => return self.op_concat(f),
            0x84 => return self.op_concat_res(f),
            0x75 | 0x76 => return self.op_incdec(f, op),
            0x78 => return self.op_divide(f),
            0x80..=0x82 => return self.op_unary(f, op),
            0x83 => return self.op_derefof(f),
            0x87 => return self.op_sizeof(f),
            0x88 => return self.op_index(f),
            0x89 => return self.op_match(f),
            0x8E => return self.op_object_type(f),
            0x90 | 0x91 => return self.op_land_lor(f, op),
            0x92 => return self.op_lnot(f),
            0x93..=0x95 => return self.op_compare(f, op),
            0x96 => return self.op_to_buffer(f),
            0x97 | 0x98 => return self.op_to_text(f, op),
            0x99 => return self.op_to_integer(f),
            0x9C => return self.op_to_string(f),
            0x9D => return self.op_copy_object(f),
            0x9E => return self.op_mid(f),
            0x5B => return self.op_ext(f, at),
            _ => return Err(Error::new(K::Malformed, at + 36)),
        };
        Ok(v)
    }

    #[inline(never)]
    fn op_qword(&mut self, f: &mut Frame) -> Result<Object> {
        let v = {
            let v = f.le(8)?;
            Object::Integer(Self::mask(f, v))
        };
        Ok(v)
    }

    #[inline(never)]
    fn op_string(&mut self, f: &mut Frame) -> Result<Object> {
        let v = {
            let start = f.pc;
            let len = f.code[start..]
                .iter()
                .position(|&c| c == 0)
                .ok_or_else(|| f.err(K::Malformed))?;
            f.pc = start + len + 1;
            Object::String(buf(f.code[start..start + len].to_vec()))
        };
        Ok(v)
    }

    #[inline(never)]
    fn op_buffer(&mut self, f: &mut Frame) -> Result<Object> {
        let v = {
            let bend = f.pkg_end()?;
            let size = self.int(f)? as usize;
            if size > self.limits.buffer || f.pc > bend {
                return Err(f.err(K::Limit("buffer size")));
            }
            let init = &f.code[f.pc..bend];
            let mut v = vec![0u8; size.max(init.len())];
            v[..init.len()].copy_from_slice(init);
            f.pc = bend;
            Object::Buffer(buf(v))
        };
        Ok(v)
    }

    #[inline(never)]
    fn op_package(&mut self, f: &mut Frame, op: u8) -> Result<Object> {
        let v = {
            let pend = f.pkg_end()?;
            let count = if op == 0x12 {
                f.byte()? as usize
            } else {
                self.int(f)? as usize
            };
            if count > self.limits.package {
                return Err(f.err(K::Limit("package size")));
            }
            let mut el = Vec::with_capacity(count.min(256));
            while f.pc < pend {
                let b = f.peek()?;
                let o = if name_start(b) {
                    let n = f.name()?;
                    match self.ns.resolve(f.scope, &n) {
                        Some(node) => Object::Ref(Ref::Node(node)),
                        None => Object::string(show(&n).as_bytes()),
                    }
                } else {
                    self.eval(f)?
                };
                if el.len() < count {
                    el.push(o);
                }
            }
            if f.pc != pend {
                return Err(f.err(K::Malformed));
            }
            el.resize(count, Object::Uninit);
            Object::Package(pkg(el))
        };
        Ok(v)
    }

    #[inline(never)]
    fn op_store(&mut self, f: &mut Frame) -> Result<Object> {
        let v = {
            let v = self.eval(f)?;
            let t = self.target(f)?;
            self.store(f, t, &v)?;
            v
        };
        Ok(v)
    }

    #[inline(never)]
    fn op_refof(&mut self, f: &mut Frame) -> Result<Object> {
        let v = {
            let t = self.target(f)?;
            match t {
                Target::Node(n) => Object::Ref(Ref::Node(n)),
                Target::Ref(r) => Object::Ref(r),
                Target::Arg(i) => match &f.args[i] {
                    Object::Ref(r) => Object::Ref(r.clone()),
                    _ => return Err(f.err(K::Unsupported("RefOf an argument"))),
                },
                _ => return Err(f.err(K::Unsupported("RefOf a local"))),
            }
        };
        Ok(v)
    }

    #[inline(never)]
    fn op_arith(&mut self, f: &mut Frame, op: u8) -> Result<Object> {
        let v = {
            let a = self.int(f)?;
            let b = self.int(f)?;
            let r = match op {
                0x72 => a.wrapping_add(b),
                0x74 => a.wrapping_sub(b),
                0x77 => a.wrapping_mul(b),
                0x79 => {
                    if b >= 64 {
                        0
                    } else {
                        a << b
                    }
                }
                0x7A => {
                    if b >= 64 {
                        0
                    } else {
                        a >> b
                    }
                }
                0x7B => a & b,
                0x7C => !(a & b),
                0x7D => a | b,
                0x7E => !(a | b),
                0x7F => a ^ b,
                _ => {
                    if b == 0 {
                        return Err(f.err(K::Range("modulo by zero")));
                    }
                    a % b
                }
            };
            let r = Object::Integer(Self::mask(f, r));
            let t = self.target(f)?;
            self.store(f, t, &r)?;
            r
        };
        Ok(v)
    }

    #[inline(never)]
    fn op_concat(&mut self, f: &mut Frame) -> Result<Object> {
        let v = {
            let a = self.eval(f)?;
            let b = self.eval(f)?;
            let r = self.concat(f, a, b)?;
            let t = self.target(f)?;
            self.store(f, t, &r)?;
            r
        };
        Ok(v)
    }

    #[inline(never)]
    fn op_concat_res(&mut self, f: &mut Frame) -> Result<Object> {
        let v = {
            let a = self.eval(f)?;
            let b = self.eval(f)?;
            let mut x = self.conv_buffer(f, &a)?;
            let y = self.conv_buffer(f, &b)?;
            strip_end_tag(&mut x);
            x.extend_from_slice(&y);
            strip_end_tag(&mut x);
            x.extend_from_slice(&[0x79, 0x00]);
            self.check_len(f, x.len())?;
            let r = Object::Buffer(buf(x));
            let t = self.target(f)?;
            self.store(f, t, &r)?;
            r
        };
        Ok(v)
    }

    #[inline(never)]
    fn op_incdec(&mut self, f: &mut Frame, op: u8) -> Result<Object> {
        let v = {
            let t = self.target(f)?;
            let cur = self.read_target(f, &t)?;
            let v = self.conv_int(f.int64, &cur).map_err(|e| f.err(e.kind))?;
            let r = Object::Integer(Self::mask(
                f,
                if op == 0x75 {
                    v.wrapping_add(1)
                } else {
                    v.wrapping_sub(1)
                },
            ));
            self.store(f, t, &r)?;
            r
        };
        Ok(v)
    }

    #[inline(never)]
    fn op_divide(&mut self, f: &mut Frame) -> Result<Object> {
        let v = {
            let a = self.int(f)?;
            let b = self.int(f)?;
            if b == 0 {
                return Err(f.err(K::Range("division by zero")));
            }
            let rem = Object::Integer(a % b);
            let quo = Object::Integer(a / b);
            let t1 = self.target(f)?;
            self.store(f, t1, &rem)?;
            let t2 = self.target(f)?;
            self.store(f, t2, &quo)?;
            quo
        };
        Ok(v)
    }

    #[inline(never)]
    fn op_unary(&mut self, f: &mut Frame, op: u8) -> Result<Object> {
        let v = {
            let a = self.int(f)?;
            let r = match op {
                0x80 => Self::mask(f, !a),
                0x81 => {
                    if a == 0 {
                        0
                    } else {
                        64 - a.leading_zeros() as u64
                    }
                }
                _ => {
                    if a == 0 {
                        0
                    } else {
                        a.trailing_zeros() as u64 + 1
                    }
                }
            };
            let r = Object::Integer(r);
            let t = self.target(f)?;
            self.store(f, t, &r)?;
            r
        };
        Ok(v)
    }

    #[inline(never)]
    fn op_derefof(&mut self, f: &mut Frame) -> Result<Object> {
        let v = {
            let v = self.eval(f)?;
            match v {
                Object::Ref(r) => self.read_ref(&r)?,
                Object::String(s) => {
                    let text: String = s.borrow().iter().map(|&c| c as char).collect();
                    let n = Name::parse(&text).ok_or_else(|| f.err(K::Malformed))?;
                    let node = self
                        .ns
                        .resolve(f.scope, &n)
                        .ok_or_else(|| f.err(K::NotFound(text.clone())))?;
                    self.value_of(f, node)?
                }
                _ => return Err(f.err(K::Type("reference"))),
            }
        };
        Ok(v)
    }

    #[inline(never)]
    fn op_sizeof(&mut self, f: &mut Frame) -> Result<Object> {
        let v = {
            let t = self.target(f)?;
            let v = self.read_target(f, &t)?;
            let v = self.deref_all(v)?;
            let n = match &v {
                Object::String(b) | Object::Buffer(b) => b.borrow().len(),
                Object::Package(p) => p.borrow().len(),
                _ => return Err(f.err(K::Type("string, buffer or package"))),
            };
            Object::Integer(n as u64)
        };
        Ok(v)
    }

    #[inline(never)]
    fn op_index(&mut self, f: &mut Frame) -> Result<Object> {
        let v = {
            let src = self.eval(f)?;
            let src = self.deref_all(src)?;
            let i = self.int(f)? as usize;
            let r = match src {
                Object::Package(p) => {
                    if i >= p.borrow().len() {
                        return Err(f.err(K::Range("index outside the package")));
                    }
                    Ref::Elem(p, i)
                }
                Object::Buffer(b) | Object::String(b) => {
                    if i >= b.borrow().len() {
                        return Err(f.err(K::Range("index outside the buffer")));
                    }
                    Ref::Byte(b, i)
                }
                _ => return Err(f.err(K::Type("package, buffer or string"))),
            };
            let r = Object::Ref(r);
            let t = self.target(f)?;
            self.store(f, t, &r)?;
            r
        };
        Ok(v)
    }

    #[inline(never)]
    fn op_match(&mut self, f: &mut Frame) -> Result<Object> {
        let v = {
            let p = self.eval(f)?;
            let p = match self.deref_all(p)? {
                Object::Package(p) => p,
                _ => return Err(f.err(K::Type("package"))),
            };
            let op1 = f.byte()?;
            let o1 = self.eval(f)?;
            let op2 = f.byte()?;
            let o2 = self.eval(f)?;
            let start = self.int(f)? as usize;
            let el = p.borrow().clone();
            let mut found = Self::ones(f);
            for (i, e) in el.into_iter().enumerate().skip(start) {
                let e = match self.deref_all(e) {
                    Ok(e) => e,
                    Err(_) => continue,
                };
                if self.match_op(f, op1, &e, &o1) && self.match_op(f, op2, &e, &o2) {
                    found = i as u64;
                    break;
                }
            }
            Object::Integer(found)
        };
        Ok(v)
    }

    #[inline(never)]
    fn op_object_type(&mut self, f: &mut Frame) -> Result<Object> {
        let v = {
            let at = f.pc;
            let code = if name_start(f.peek()?) {
                let n = f.name()?;
                let node = self
                    .ns
                    .resolve(f.scope, &n)
                    .ok_or_else(|| Error::new(K::NotFound(show(&n)), at + 36))?;
                self.ns.obj(self.follow_alias(node)).type_code()
            } else {
                let t = self.target(f)?;
                match t {
                    Target::Debug => 16,
                    _ => {
                        let v = self.read_target(f, &t)?;
                        match v {
                            Object::Ref(Ref::Node(n)) => self.ns.obj(n).type_code(),
                            Object::Ref(r) => self.read_ref(&r)?.type_code(),
                            o => o.type_code(),
                        }
                    }
                }
            };
            Object::Integer(code)
        };
        Ok(v)
    }

    #[inline(never)]
    fn op_land_lor(&mut self, f: &mut Frame, op: u8) -> Result<Object> {
        let v = {
            let a = self.int(f)?;
            let b = self.int(f)?;
            Self::bool_obj(
                f,
                if op == 0x90 {
                    a != 0 && b != 0
                } else {
                    a != 0 || b != 0
                },
            )
        };
        Ok(v)
    }

    #[inline(never)]
    fn op_lnot(&mut self, f: &mut Frame) -> Result<Object> {
        let v = {
            let a = self.int(f)?;
            Self::bool_obj(f, a == 0)
        };
        Ok(v)
    }

    #[inline(never)]
    fn op_compare(&mut self, f: &mut Frame, op: u8) -> Result<Object> {
        let v = {
            let a = self.eval(f)?;
            let b = self.eval(f)?;
            let o = self.compare(f, &a, &b)?;
            Self::bool_obj(
                f,
                match op {
                    0x93 => o == Ordering::Equal,
                    0x94 => o == Ordering::Greater,
                    _ => o == Ordering::Less,
                },
            )
        };
        Ok(v)
    }

    #[inline(never)]
    fn op_to_buffer(&mut self, f: &mut Frame) -> Result<Object> {
        let v = {
            let a = self.eval(f)?;
            let r = Object::Buffer(buf(self.conv_buffer(f, &a)?));
            let t = self.target(f)?;
            self.store(f, t, &r)?;
            r
        };
        Ok(v)
    }

    #[inline(never)]
    fn op_to_text(&mut self, f: &mut Frame, op: u8) -> Result<Object> {
        let v = {
            let a = self.eval(f)?;
            let a = self.deref_all(a)?;
            let s = match (&a, op) {
                (Object::Integer(v), 0x97) => alloc::format!("{}", v),
                (Object::Integer(v), _) => {
                    if f.int64 {
                        alloc::format!("{:016X}", v)
                    } else {
                        alloc::format!("{:08X}", v)
                    }
                }
                (Object::Buffer(b), 0x97) => b
                    .borrow()
                    .iter()
                    .map(|x| alloc::format!("{}", x))
                    .collect::<Vec<_>>()
                    .join(","),
                (Object::Buffer(b), _) => b
                    .borrow()
                    .iter()
                    .map(|x| alloc::format!("0x{:02X}", x))
                    .collect::<Vec<_>>()
                    .join(","),
                (Object::String(s), _) => s.borrow().iter().map(|&c| c as char).collect(),
                _ => return Err(f.err(K::Type("integer, string or buffer"))),
            };
            self.check_len(f, s.len())?;
            let r = Object::string(s.as_bytes());
            let t = self.target(f)?;
            self.store(f, t, &r)?;
            r
        };
        Ok(v)
    }

    #[inline(never)]
    fn op_to_integer(&mut self, f: &mut Frame) -> Result<Object> {
        let v = {
            let a = self.eval(f)?;
            let a = self.deref_all(a)?;
            let v = match &a {
                Object::String(s) => parse_explicit(&s.borrow()),
                o => self.conv_int(f.int64, o).map_err(|e| f.err(e.kind))?,
            };
            let r = Object::Integer(Self::mask(f, v));
            let t = self.target(f)?;
            self.store(f, t, &r)?;
            r
        };
        Ok(v)
    }

    #[inline(never)]
    fn op_to_string(&mut self, f: &mut Frame) -> Result<Object> {
        let v = {
            let a = self.eval(f)?;
            let bytes = self.conv_buffer(f, &a)?;
            let len = self.int(f)?;
            let mut s: Vec<u8> = bytes.into_iter().take_while(|&c| c != 0).collect();
            if (len as usize) < s.len() {
                s.truncate(len as usize);
            }
            let r = Object::String(buf(s));
            let t = self.target(f)?;
            self.store(f, t, &r)?;
            r
        };
        Ok(v)
    }

    #[inline(never)]
    fn op_copy_object(&mut self, f: &mut Frame) -> Result<Object> {
        let v = {
            let v = self.eval(f)?;
            let t = self.target(f)?;
            match t {
                Target::Node(n) => self.ns.set_obj(n, copy_value(&v)),
                Target::Local(i) => f.locals[i] = copy_value(&v),
                Target::Arg(i) => f.args[i] = copy_value(&v),
                other => self.store(f, other, &v)?,
            }
            v
        };
        Ok(v)
    }

    #[inline(never)]
    fn op_mid(&mut self, f: &mut Frame) -> Result<Object> {
        let v = {
            let src = self.eval(f)?;
            let src = self.deref_all(src)?;
            let i = self.int(f)? as usize;
            let n = self.int(f)? as usize;
            let (b, is_str) = match &src {
                Object::String(b) => (b.borrow().clone(), true),
                Object::Buffer(b) => (b.borrow().clone(), false),
                _ => return Err(f.err(K::Type("string or buffer"))),
            };
            let s = i.min(b.len());
            let e = s.saturating_add(n).min(b.len());
            let part = b[s..e].to_vec();
            let r = if is_str {
                Object::String(buf(part))
            } else {
                Object::Buffer(buf(part))
            };
            let t = self.target(f)?;
            self.store(f, t, &r)?;
            r
        };
        Ok(v)
    }

    #[inline(never)]
    fn op_ext(&mut self, f: &mut Frame, at: usize) -> Result<Object> {
        let v = {
            let ext = f.byte()?;
            match ext {
                0x12 => {
                    let found = if name_start(f.peek()?) {
                        let n = f.name()?;
                        self.ns
                            .resolve(f.scope, &n)
                            .map(|x| Object::Ref(Ref::Node(x)))
                    } else {
                        let t = self.target(f)?;
                        let v = self.read_target(f, &t)?;
                        match v {
                            Object::Uninit => None,
                            Object::Ref(r) => Some(Object::Ref(r)),
                            _ => Some(Object::Integer(0)),
                        }
                    };
                    let t = self.target(f)?;
                    match found {
                        Some(r) => {
                            if matches!(r, Object::Ref(_)) {
                                self.store(f, t, &r)?;
                            }
                            Self::bool_obj(f, true)
                        }
                        None => Self::bool_obj(f, false),
                    }
                }
                0x23 => {
                    let t = self.target(f)?;
                    f.le(2)?;
                    match self.target_obj(&t) {
                        Some(Object::Mutex(c)) => {
                            let gl = matches!(t, Target::Node(n) if n == self.gl);
                            if gl && c.get() == 0 && !self.h.acquire_global_lock() {
                                Object::Integer(Self::ones(f))
                            } else {
                                c.set(c.get().saturating_add(1));
                                Object::Integer(0)
                            }
                        }
                        _ => return Err(f.err(K::Type("mutex"))),
                    }
                }
                0x25 => {
                    let t = self.target(f)?;
                    self.int(f)?;
                    match self.target_obj(&t) {
                        Some(Object::Event(c)) => {
                            if c.get() > 0 {
                                c.set(c.get() - 1);
                                Object::Integer(0)
                            } else {
                                Object::Integer(Self::ones(f))
                            }
                        }
                        _ => return Err(f.err(K::Type("event"))),
                    }
                }
                0x28 | 0x29 => {
                    let a = self.int(f)?;
                    let r = if ext == 0x28 { from_bcd(a) } else { to_bcd(a) };
                    let r = Object::Integer(Self::mask(f, r));
                    let t = self.target(f)?;
                    self.store(f, t, &r)?;
                    r
                }
                0x30 => Object::Integer(REVISION),
                0x31 => Object::Debug,
                0x33 => Object::Integer(Self::mask(f, self.h.timer())),
                0x1F => return Err(f.err(K::Unsupported("LoadTable"))),
                _ => return Err(Error::new(K::Malformed, at + 36)),
            }
        };
        Ok(v)
    }

    fn eval_name(&mut self, f: &mut Frame) -> Result<Object> {
        let n = f.name()?;
        if n.segs.is_empty() && !n.root {
            return Ok(Object::Uninit);
        }
        let node = self
            .ns
            .resolve(f.scope, &n)
            .ok_or_else(|| f.err(K::NotFound(show(&n))))?;
        let node = self.follow_alias(node);
        match self.ns.obj(node).clone() {
            Object::Method(m) => {
                let mut args = Vec::with_capacity(m.args as usize);
                for _ in 0..m.args {
                    args.push(self.eval(f)?);
                }
                self.call(node, m, args)
            }
            Object::Native(Native::Osi) => {
                let a = self.eval(f)?;
                let s = self.conv_buffer(f, &a)?;
                let s: Vec<u8> = s.into_iter().take_while(|&c| c != 0).collect();
                Ok(Self::bool_obj(f, OSI.contains(&s.as_slice())))
            }
            _ => self.value_of(f, node),
        }
    }

    /// Evaluate a node from outside byte code (`evaluate`): methods get `args`.
    fn eval_node(&mut self, node: NodeId, args: Vec<Object>, _top: bool) -> Result<Object> {
        let node = self.follow_alias(node);
        match self.ns.obj(node).clone() {
            Object::Method(m) => self.call(node, m, args),
            Object::Native(Native::Osi) => {
                let s = args.first().and_then(|a| a.as_bytes()).unwrap_or_default();
                let s: Vec<u8> = s.into_iter().take_while(|&c| c != 0).collect();
                Ok(Object::Integer(if OSI.contains(&s.as_slice()) {
                    u64::MAX
                } else {
                    0
                }))
            }
            _ => {
                let f = Frame::new(Rc::from(&[][..]), 0, node, true, true);
                self.value_of(&f, node)
            }
        }
    }

    fn call(&mut self, node: NodeId, m: Rc<Method>, args: Vec<Object>) -> Result<Object> {
        if self.calls >= self.limits.calls || !self.h.stack_ok() {
            return Err(Error::new(K::Limit("call depth"), m.start + 36));
        }
        self.calls += 1;
        self.stats.calls += 1;
        let saved = self.nesting;
        self.nesting = 0;
        let mut f = Frame::new(m.code.clone(), m.start, node, m.int64, true);
        for (i, a) in args.into_iter().take(7).enumerate() {
            f.args[i] = a;
        }
        let r = self.exec_list(&mut f, m.end);
        for &n in f.created.iter().rev() {
            self.ns.remove(n);
        }
        self.calls -= 1;
        self.nesting = saved;
        match r? {
            Flow::Return(v) => Ok(v),
            _ => Ok(Object::Integer(0)),
        }
    }

    /// The value of a named object as an operand: fields are read, data is returned (shared).
    fn value_of(&mut self, f: &Frame, node: NodeId) -> Result<Object> {
        let node = self.follow_alias(node);
        match self.ns.obj(node).clone() {
            Object::Field(fl) => self.read_field(&fl, f.int64),
            Object::BufferField { buf, bit, len } => Ok(crate::field::read_bits_obj(
                &buf.borrow(),
                bit,
                len,
                f.int64,
            )),
            o @ (Object::Integer(_)
            | Object::String(_)
            | Object::Buffer(_)
            | Object::Package(_)
            | Object::Ref(_)
            | Object::Uninit) => Ok(o),
            _ => Ok(Object::Ref(Ref::Node(node))),
        }
    }

    // ---- targets ------------------------------------------------------------------------------

    fn target(&mut self, f: &mut Frame) -> Result<Target> {
        let b = f.peek()?;
        Ok(match b {
            0x00 => {
                f.pc += 1;
                Target::Null
            }
            0x60..=0x67 => {
                f.pc += 1;
                Target::Local((b - 0x60) as usize)
            }
            0x68..=0x6E => {
                f.pc += 1;
                Target::Arg((b - 0x68) as usize)
            }
            0x5B if f.peek_at(1) == Some(0x31) => {
                f.pc += 2;
                Target::Debug
            }
            0x71 | 0x83 | 0x88 => {
                let v = self.eval(f)?;
                match v {
                    Object::Ref(r) => Target::Ref(r),
                    Object::String(s) if b == 0x83 => {
                        let text: String = s.borrow().iter().map(|&c| c as char).collect();
                        let n = Name::parse(&text).ok_or_else(|| f.err(K::Malformed))?;
                        Target::Node(
                            self.ns
                                .resolve(f.scope, &n)
                                .ok_or_else(|| f.err(K::NotFound(text.clone())))?,
                        )
                    }
                    _ => return Err(f.err(K::Type("reference"))),
                }
            }
            b if name_start(b) => {
                let n = f.name()?;
                if n.segs.is_empty() && !n.root {
                    return Ok(Target::Null);
                }
                let node = self
                    .ns
                    .resolve(f.scope, &n)
                    .ok_or_else(|| f.err(K::NotFound(show(&n))))?;
                let node = self.follow_alias(node);
                if let Object::Method(m) = self.ns.obj(node).clone() {
                    let mut args = Vec::new();
                    for _ in 0..m.args {
                        args.push(self.eval(f)?);
                    }
                    match self.call(node, m, args)? {
                        Object::Ref(r) => Target::Ref(r),
                        _ => return Err(f.err(K::Type("reference"))),
                    }
                } else {
                    Target::Node(node)
                }
            }
            _ => return Err(f.err(K::Malformed)),
        })
    }

    fn target_obj(&self, t: &Target) -> Option<Object> {
        match t {
            Target::Node(n) => Some(self.ns.obj(*n).clone()),
            Target::Ref(Ref::Node(n)) => Some(self.ns.obj(*n).clone()),
            _ => None,
        }
    }

    fn read_target(&mut self, f: &Frame, t: &Target) -> Result<Object> {
        match t {
            Target::Null => Ok(Object::Uninit),
            Target::Local(i) => Ok(f.locals[*i].clone()),
            Target::Arg(i) => match &f.args[*i] {
                Object::Ref(r) => {
                    let r = r.clone();
                    self.read_ref(&r)
                }
                o => Ok(o.clone()),
            },
            Target::Debug => Ok(Object::Debug),
            Target::Node(n) => self.value_of(f, *n),
            Target::Ref(r) => self.read_ref(r),
        }
    }

    pub(crate) fn read_ref(&mut self, r: &Ref) -> Result<Object> {
        match r {
            Ref::Node(n) => {
                let f = Frame::new(Rc::from(&[][..]), 0, *n, true, true);
                self.value_of(&f, *n)
            }
            Ref::Elem(p, i) => {
                let e = p
                    .borrow()
                    .get(*i)
                    .cloned()
                    .ok_or(Error::new(K::Range("index outside the package"), 0))?;
                match e {
                    Object::Ref(Ref::Node(n))
                        if matches!(
                            self.ns.obj(n),
                            Object::Integer(_)
                                | Object::String(_)
                                | Object::Buffer(_)
                                | Object::Package(_)
                        ) =>
                    {
                        Ok(self.ns.obj(n).clone())
                    }
                    o => Ok(o),
                }
            }
            Ref::Byte(b, i) => b
                .borrow()
                .get(*i)
                .map(|&x| Object::Integer(x as u64))
                .ok_or(Error::new(K::Range("index outside the buffer"), 0)),
        }
    }

    /// Follow references (Index, RefOf) to a value; bounded (a package can hold a reference to
    /// itself).
    pub(crate) fn deref_all(&mut self, mut v: Object) -> Result<Object> {
        for _ in 0..8 {
            match v {
                Object::Ref(r) => v = self.read_ref(&r)?,
                o => return Ok(o),
            }
        }
        Err(Error::new(K::Limit("reference chain"), 0))
    }

    fn store(&mut self, f: &mut Frame, t: Target, v: &Object) -> Result<()> {
        match t {
            Target::Null => Ok(()),
            Target::Local(i) => {
                f.locals[i] = copy_value(v);
                Ok(())
            }
            Target::Arg(i) => {
                if let Object::Ref(r) = &f.args[i] {
                    let r = r.clone();
                    self.store_ref(f, &r, v)
                } else {
                    f.args[i] = copy_value(v);
                    Ok(())
                }
            }
            Target::Debug => {
                let s = self.debug_text(v);
                self.h.debug(&s);
                Ok(())
            }
            Target::Node(n) => self.store_node(f, n, v),
            Target::Ref(r) => self.store_ref(f, &r, v),
        }
    }

    fn store_ref(&mut self, f: &mut Frame, r: &Ref, v: &Object) -> Result<()> {
        match r {
            Ref::Node(n) => self.store_node(f, *n, v),
            Ref::Elem(p, i) => {
                let c = copy_value(v);
                // Packages stored into packages could nest without bound (and dropping or copying
                // one recurses): refuse deep values.
                if depth(&c, MAX_DEPTH) >= MAX_DEPTH {
                    return Err(f.err(K::Limit("package nesting")));
                }
                let mut el = p.borrow_mut();
                let slot = el
                    .get_mut(*i)
                    .ok_or_else(|| f.err(K::Range("index outside the package")))?;
                *slot = c;
                Ok(())
            }
            Ref::Byte(b, i) => {
                let x = self.conv_int(f.int64, v).map_err(|e| f.err(e.kind))?;
                let mut bb = b.borrow_mut();
                let slot = bb
                    .get_mut(*i)
                    .ok_or_else(|| f.err(K::Range("index outside the buffer")))?;
                *slot = x as u8;
                Ok(())
            }
        }
    }

    fn store_node(&mut self, f: &mut Frame, n: NodeId, v: &Object) -> Result<()> {
        let n = self.follow_alias(n);
        let v = match v {
            Object::Ref(Ref::Elem(..) | Ref::Byte(..)) => self.deref_all(v.clone())?,
            o => o.clone(),
        };
        match self.ns.obj(n).clone() {
            Object::Field(fl) => self
                .write_field(&fl, &v, f.int64)
                .map_err(|e| if e.at == 0 { f.err(e.kind) } else { e }),
            Object::BufferField { buf, bit, len } => {
                let bytes = self.value_bytes(f, &v)?;
                crate::field::write_bits(&mut buf.borrow_mut(), bit, len, &bytes);
                Ok(())
            }
            Object::Integer(_) => {
                let x = self.conv_int(f.int64, &v).map_err(|e| f.err(e.kind))?;
                self.ns.set_obj(n, Object::Integer(x));
                Ok(())
            }
            Object::String(_) => {
                let s = self.conv_string(f, &v)?;
                self.ns.set_obj(n, Object::String(buf(s)));
                Ok(())
            }
            Object::Buffer(b) => {
                let src = self.conv_buffer(f, &v)?;
                let mut t = b.borrow_mut();
                for (i, x) in t.iter_mut().enumerate() {
                    *x = src.get(i).copied().unwrap_or(0);
                }
                Ok(())
            }
            Object::Package(_) | Object::Uninit | Object::Ref(_) => {
                self.ns.set_obj(n, copy_value(&v));
                Ok(())
            }
            _ => Err(f.err(K::Type("a data object as the store target"))),
        }
    }

    // ---- conversions ---------------------------------------------------------------------------

    pub(crate) fn conv_int(&mut self, int64: bool, v: &Object) -> Result<u64> {
        let mask = if int64 { u64::MAX } else { 0xFFFF_FFFF };
        let v = self.deref_all(v.clone())?;
        match &v {
            Object::Integer(x) => Ok(x & mask),
            Object::String(s) => {
                let s = s.borrow();
                let mut i = 0;
                while i < s.len() && (s[i] == b' ' || s[i] == b'\t') {
                    i += 1;
                }
                if s.len() >= i + 2 && s[i] == b'0' && (s[i + 1] | 0x20) == b'x' {
                    i += 2;
                }
                let mut r = 0u64;
                for &c in s[i..].iter().take(16) {
                    match hex_digit(c) {
                        Some(d) => r = (r << 4) | d,
                        None => break,
                    }
                }
                Ok(r & mask)
            }
            Object::Buffer(b) => {
                let b = b.borrow();
                let mut r = 0u64;
                for (i, &x) in b.iter().take(if int64 { 8 } else { 4 }).enumerate() {
                    r |= (x as u64) << (8 * i);
                }
                Ok(r)
            }
            _ => Err(Error::new(K::Type("integer"), 0)),
        }
    }

    fn conv_buffer(&mut self, f: &Frame, v: &Object) -> Result<Vec<u8>> {
        let v = self.deref_all(v.clone())?;
        match &v {
            Object::Integer(x) => Ok(x.to_le_bytes()[..if f.int64 { 8 } else { 4 }].to_vec()),
            Object::String(s) => {
                let mut b = s.borrow().clone();
                b.push(0);
                Ok(b)
            }
            Object::Buffer(b) => Ok(b.borrow().clone()),
            _ => Err(f.err(K::Type("integer, string or buffer"))),
        }
    }

    /// Bytes to write to a field: integers as 8 bytes, strings without their terminator.
    fn value_bytes(&mut self, f: &Frame, v: &Object) -> Result<Vec<u8>> {
        let v = self.deref_all(v.clone())?;
        match &v {
            Object::Integer(x) => Ok(x.to_le_bytes().to_vec()),
            Object::String(b) | Object::Buffer(b) => Ok(b.borrow().clone()),
            _ => Err(f.err(K::Type("integer, string or buffer"))),
        }
    }

    fn conv_string(&mut self, f: &Frame, v: &Object) -> Result<Vec<u8>> {
        let v = self.deref_all(v.clone())?;
        match &v {
            Object::Integer(x) => Ok(if f.int64 {
                alloc::format!("{:016X}", x)
            } else {
                alloc::format!("{:08X}", x)
            }
            .into_bytes()),
            Object::String(s) => Ok(s.borrow().clone()),
            Object::Buffer(b) => Ok(b
                .borrow()
                .iter()
                .map(|x| alloc::format!("{:02X}", x))
                .collect::<Vec<_>>()
                .join(" ")
                .into_bytes()),
            _ => Err(f.err(K::Type("integer, string or buffer"))),
        }
    }

    fn check_len(&self, f: &Frame, n: usize) -> Result<()> {
        if n > self.limits.buffer {
            return Err(f.err(K::Limit("buffer size")));
        }
        Ok(())
    }

    fn concat(&mut self, f: &Frame, a: Object, b: Object) -> Result<Object> {
        let a = self.deref_all(a)?;
        let r = match &a {
            Object::Integer(_) => {
                let mut x = self.conv_buffer(f, &a)?;
                let y = self.conv_int(f.int64, &b).map_err(|e| f.err(e.kind))?;
                x.extend_from_slice(&y.to_le_bytes()[..if f.int64 { 8 } else { 4 }]);
                Object::Buffer(buf(x))
            }
            Object::String(s) => {
                let mut x = s.borrow().clone();
                x.extend_from_slice(&self.conv_string(f, &b)?);
                self.check_len(f, x.len())?;
                Object::String(buf(x))
            }
            Object::Buffer(s) => {
                let mut x = s.borrow().clone();
                x.extend_from_slice(&self.conv_buffer(f, &b)?);
                self.check_len(f, x.len())?;
                Object::Buffer(buf(x))
            }
            _ => return Err(f.err(K::Type("integer, string or buffer"))),
        };
        Ok(r)
    }

    fn compare(&mut self, f: &Frame, a: &Object, b: &Object) -> Result<Ordering> {
        let a = self.deref_all(a.clone())?;
        match &a {
            Object::Integer(x) => {
                let y = self.conv_int(f.int64, b).map_err(|e| f.err(e.kind))?;
                Ok((x & Self::ones(f)).cmp(&y))
            }
            Object::String(s) => {
                let t = self.conv_string(f, b)?;
                Ok(s.borrow().as_slice().cmp(t.as_slice()))
            }
            Object::Buffer(s) => {
                let t = self.conv_buffer(f, b)?;
                Ok(s.borrow().as_slice().cmp(t.as_slice()))
            }
            _ => Err(f.err(K::Type("integer, string or buffer"))),
        }
    }

    fn match_op(&mut self, f: &Frame, op: u8, e: &Object, o: &Object) -> bool {
        if op == 0 {
            return true;
        }
        let Ok(c) = self.compare(f, e, o) else {
            return false;
        };
        match op {
            1 => c == Ordering::Equal,
            2 => c != Ordering::Greater,
            3 => c == Ordering::Less,
            4 => c != Ordering::Less,
            5 => c == Ordering::Greater,
            _ => false,
        }
    }

    fn debug_text(&mut self, v: &Object) -> String {
        match v {
            Object::Integer(x) => alloc::format!("{:#x}", x),
            Object::String(s) => s
                .borrow()
                .iter()
                .map(|&c| {
                    if (0x20..0x7F).contains(&c) {
                        c as char
                    } else {
                        '.'
                    }
                })
                .collect(),
            Object::Buffer(b) => b
                .borrow()
                .iter()
                .map(|x| alloc::format!("{:02x}", x))
                .collect::<Vec<_>>()
                .join(" "),
            Object::Package(p) => alloc::format!("package of {}", p.borrow().len()),
            Object::Ref(Ref::Node(n)) => alloc::format!("reference to {}", self.ns.path(*n)),
            o => String::from(o.type_name()),
        }
    }

    // ---- PCI config regions --------------------------------------------------------------------

    fn is_pci_root(&mut self, n: NodeId) -> bool {
        if !matches!(self.ns.obj(n), Object::Device) {
            return false;
        }
        self.ids(n).iter().any(|i| i == "PNP0A03" || i == "PNP0A08")
    }

    /// (segment, bus, device, function) of a PCI_Config region: `_ADR` of its device, `_SEG` and
    /// `_BBN` of the host bridge above it, and the secondary bus of each PCI bridge in between.
    pub(crate) fn pci_addr(&mut self, r: &Region) -> Result<(u16, u8, u8, u8)> {
        if let Some(a) = r.pci.get() {
            return Ok(a);
        }
        let dev = r.scope;
        let adr = self.child_int(dev, "_ADR")?.unwrap_or(0);
        let mut chain = Vec::new();
        let mut n = dev;
        let mut root = None;
        for _ in 0..64 {
            if self.is_pci_root(n) {
                root = Some(n);
                break;
            }
            chain.push(n);
            if n == ROOT {
                break;
            }
            n = self.ns.parent(n);
        }
        let (seg, mut bus) = match root {
            Some(rn) => (
                self.child_int(rn, "_SEG")?.unwrap_or(0) as u16,
                self.child_int(rn, "_BBN")?.unwrap_or(0) as u8,
            ),
            None => (0, 0),
        };
        if root.is_some() {
            // chain = [dev, parent, ..., child of the host bridge]: bridges are all but `dev`.
            for &b in chain.iter().skip(1).rev() {
                let Some(a) = self.child_int(b, "_ADR")? else {
                    continue;
                };
                let bdf = (seg, bus, ((a >> 16) & 0x1F) as u8, (a & 7) as u8);
                let hdr = self
                    .h
                    .read_pci(bdf, 0x0E, 1)
                    .map_err(|_| Error::new(K::Hardware, 0))?
                    & 0x7F;
                if hdr != 1 && hdr != 2 {
                    break;
                }
                bus = self
                    .h
                    .read_pci(bdf, 0x19, 1)
                    .map_err(|_| Error::new(K::Hardware, 0))? as u8;
            }
        }
        let a = (seg, bus, ((adr >> 16) & 0x1F) as u8, (adr & 7) as u8);
        r.pci.set(Some(a));
        Ok(a)
    }
}

fn access_bytes(t: u8) -> u8 {
    match t {
        2 => 2,
        3 => 4,
        4 => 8,
        _ => 1,
    }
}

fn strip_end_tag(b: &mut Vec<u8>) {
    if b.len() >= 2 && b[b.len() - 2] == 0x79 {
        b.truncate(b.len() - 2);
    }
}

/// ToInteger on a string: `0x` hex, else decimal.
fn parse_explicit(s: &[u8]) -> u64 {
    let s: Vec<u8> = s.iter().copied().skip_while(|&c| c == b' ').collect();
    if s.len() >= 2 && s[0] == b'0' && (s[1] | 0x20) == b'x' {
        let mut r = 0u64;
        for &c in &s[2..] {
            match hex_digit(c) {
                Some(d) => r = r.wrapping_shl(4) | d,
                None => break,
            }
        }
        r
    } else {
        let mut r = 0u64;
        for &c in &s {
            if !c.is_ascii_digit() {
                break;
            }
            r = r.wrapping_mul(10).wrapping_add((c - b'0') as u64);
        }
        r
    }
}

fn from_bcd(mut a: u64) -> u64 {
    let mut r = 0u64;
    let mut m = 1u64;
    while a != 0 {
        r = r.wrapping_add((a & 0xF).min(9).wrapping_mul(m));
        m = m.wrapping_mul(10);
        a >>= 4;
    }
    r
}

fn to_bcd(mut a: u64) -> u64 {
    let mut r = 0u64;
    let mut shift = 0;
    while a != 0 && shift < 64 {
        r |= (a % 10) << shift;
        a /= 10;
        shift += 4;
    }
    r
}
