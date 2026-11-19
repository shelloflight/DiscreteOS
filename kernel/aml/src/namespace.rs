//! The ACPI namespace: a tree of 4-character names, each holding one object.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use crate::object::Object;

pub type NodeId = u32;
pub const ROOT: NodeId = 0;

pub struct Node {
    pub name: [u8; 4],
    pub parent: NodeId,
    pub children: BTreeMap<[u8; 4], NodeId>,
    pub obj: Object,
    live: bool,
}

pub struct Namespace {
    nodes: Vec<Node>,
    free: Vec<NodeId>,
    live: usize,
}

/// A parsed NameString: `\` (root), `^` count, then the segments.
#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub struct Name {
    pub root: bool,
    pub up: u8,
    pub segs: Vec<[u8; 4]>,
}

impl Name {
    /// A single segment with no prefix: looked up with the search rules (scope, then parents).
    pub fn searchable(&self) -> bool {
        !self.root && self.up == 0 && self.segs.len() == 1
    }

    /// Parse a text path: `\_SB.PCI0._STA`, `^^FOO`, `_S5`, `\_SB_.PCI0` (short segments padded with `_`).
    pub fn parse(s: &str) -> Option<Name> {
        let b = s.as_bytes();
        let mut i = 0;
        let mut n = Name::default();
        if b.first() == Some(&b'\\') {
            n.root = true;
            i = 1;
        }
        while b.get(i) == Some(&b'^') {
            n.up = n.up.checked_add(1)?;
            i += 1;
        }
        let rest = &s[i..];
        if rest.is_empty() {
            return Some(n);
        }
        for part in rest.split('.') {
            let p = part.as_bytes();
            if p.is_empty()
                || p.len() > 4
                || !lead_char(p[0])
                || !p[1..].iter().all(|&c| name_char(c))
            {
                return None;
            }
            let mut seg = [b'_'; 4];
            seg[..p.len()].copy_from_slice(p);
            n.segs.push(seg);
        }
        Some(n)
    }
}

pub fn lead_char(c: u8) -> bool {
    c.is_ascii_uppercase() || c == b'_'
}

pub fn name_char(c: u8) -> bool {
    lead_char(c) || c.is_ascii_digit()
}

impl Default for Namespace {
    fn default() -> Self {
        Self::new()
    }
}

impl Namespace {
    pub fn new() -> Namespace {
        let root = Node {
            name: *b"\\___",
            parent: ROOT,
            children: BTreeMap::new(),
            obj: Object::Scope,
            live: true,
        };
        Namespace {
            nodes: alloc::vec![root],
            free: Vec::new(),
            live: 1,
        }
    }

    pub fn len(&self) -> usize {
        self.live
    }

    pub fn is_empty(&self) -> bool {
        self.live == 0
    }

    pub fn node(&self, id: NodeId) -> &Node {
        &self.nodes[id as usize]
    }

    pub fn obj(&self, id: NodeId) -> &Object {
        &self.nodes[id as usize].obj
    }

    pub fn set_obj(&mut self, id: NodeId, obj: Object) {
        self.nodes[id as usize].obj = obj;
    }

    pub fn parent(&self, id: NodeId) -> NodeId {
        self.nodes[id as usize].parent
    }

    pub fn exists(&self, id: NodeId) -> bool {
        self.nodes.get(id as usize).is_some_and(|n| n.live)
    }

    pub fn child(&self, id: NodeId, seg: [u8; 4]) -> Option<NodeId> {
        self.nodes[id as usize].children.get(&seg).copied()
    }

    pub fn children(&self, id: NodeId) -> Vec<NodeId> {
        self.nodes[id as usize].children.values().copied().collect()
    }

    /// Add `seg` under `parent`; None if the name is taken.
    pub fn add(&mut self, parent: NodeId, seg: [u8; 4], obj: Object) -> Option<NodeId> {
        if self.nodes[parent as usize].children.contains_key(&seg) {
            return None;
        }
        let node = Node {
            name: seg,
            parent,
            children: BTreeMap::new(),
            obj,
            live: true,
        };
        let id = match self.free.pop() {
            Some(id) => {
                self.nodes[id as usize] = node;
                id
            }
            None => {
                self.nodes.push(node);
                (self.nodes.len() - 1) as NodeId
            }
        };
        self.nodes[parent as usize].children.insert(seg, id);
        self.live += 1;
        Some(id)
    }

    /// Remove a node and everything below it.
    pub fn remove(&mut self, id: NodeId) {
        if id == ROOT || !self.exists(id) {
            return;
        }
        let parent = self.nodes[id as usize].parent;
        let name = self.nodes[id as usize].name;
        if self.nodes[parent as usize].children.get(&name) == Some(&id) {
            self.nodes[parent as usize].children.remove(&name);
        }
        let mut stack = alloc::vec![id];
        while let Some(n) = stack.pop() {
            let node = &mut self.nodes[n as usize];
            stack.extend(node.children.values().copied());
            node.children.clear();
            node.obj = Object::Uninit;
            node.live = false;
            self.free.push(n);
            self.live -= 1;
        }
    }

    /// Resolve a name from `scope`, following the ACPI search rules for single segments.
    pub fn resolve(&self, scope: NodeId, name: &Name) -> Option<NodeId> {
        if name.searchable() {
            let seg = name.segs[0];
            let mut s = scope;
            loop {
                if let Some(c) = self.child(s, seg) {
                    return Some(c);
                }
                if s == ROOT {
                    return None;
                }
                s = self.parent(s);
            }
        }
        let mut s = self.start(scope, name)?;
        for seg in &name.segs {
            s = self.child(s, *seg)?;
        }
        Some(s)
    }

    /// Where a new object named `name` goes: (parent, last segment). The parent must exist.
    pub fn place(&self, scope: NodeId, name: &Name) -> Option<(NodeId, [u8; 4])> {
        let (last, path) = name.segs.split_last()?;
        let mut s = self.start(scope, name)?;
        for seg in path {
            s = self.child(s, *seg)?;
        }
        Some((s, *last))
    }

    fn start(&self, scope: NodeId, name: &Name) -> Option<NodeId> {
        let mut s = if name.root { ROOT } else { scope };
        for _ in 0..name.up {
            if s == ROOT {
                return None;
            }
            s = self.parent(s);
        }
        Some(s)
    }

    /// `\_SB_.PCI0.LPCB` (segments as stored, with their `_` padding).
    pub fn path(&self, id: NodeId) -> String {
        if id == ROOT {
            return String::from("\\");
        }
        let mut segs = Vec::new();
        let mut n = id;
        while n != ROOT {
            segs.push(self.nodes[n as usize].name);
            n = self.parent(n);
        }
        let mut s = String::new();
        for (i, seg) in segs.iter().rev().enumerate() {
            s.push(if i == 0 { '\\' } else { '.' });
            for &c in seg {
                s.push(c as char);
            }
        }
        s
    }

    /// Every live node below `id` (depth first, parents before children).
    pub fn walk(&self, id: NodeId) -> Vec<NodeId> {
        let mut out = Vec::new();
        let mut stack = alloc::vec![id];
        while let Some(n) = stack.pop() {
            out.push(n);
            let mut c: Vec<NodeId> = self.children(n);
            c.reverse();
            stack.extend(c);
        }
        out
    }
}
