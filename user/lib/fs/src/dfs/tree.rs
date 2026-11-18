//! The copy-on-write B+tree DFS keeps everything in (docs/storage.md, "DFS").
//!
//! Nodes are 4 KiB blocks, loaded on demand and checked against the hash in the pointer that
//! led to them (a Merkle tree: the superblock's root hash covers every node and data block). A
//! changed node is never written in place: it is marked dirty (and so is every node above it),
//! and at commit each dirty node gets a new block (`assign`) and is written there (`write`),
//! bottom-up, so parents carry their children's new hashes.
//!
//! Leaf items are (key, value); internal items are (key, child pointer), where the key is a
//! lower bound of the child's keys. Deletion removes empty nodes and merges small neighbours;
//! the root collapses when it has a single child.

use alloc::boxed::Box;
use alloc::vec::Vec;

use super::{BS, Io, Ptr};
use crate::{Error, Result};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Default)]
pub struct Key {
    pub obj: u64,
    pub kind: u8,
    pub off: u64,
}

impl Key {
    pub const fn new(obj: u64, kind: u8, off: u64) -> Key {
        Key { obj, kind, off }
    }
    fn put(&self, b: &mut [u8]) {
        b[0..8].copy_from_slice(&self.obj.to_le_bytes());
        b[8] = self.kind;
        b[9..17].copy_from_slice(&self.off.to_le_bytes());
    }
    fn get(b: &[u8]) -> Key {
        Key { obj: u64::from_le_bytes(b[0..8].try_into().unwrap_or_default()), kind: b[8], off: u64::from_le_bytes(b[9..17].try_into().unwrap_or_default()) }
    }
}

const MAGIC: &[u8; 4] = b"DFSN";
pub const HDR: usize = 48;
const KEY: usize = 17;
const LEAF_ITEM: usize = KEY + 2;
const INNER_ITEM: usize = KEY + super::PTR;
/// Largest value an item may carry (so any single item fits a node).
pub const MAX_VAL: usize = 3000;
const MAX_LEVEL: u8 = 16;

pub struct Node {
    pub level: u8,
    pub keys: Vec<Key>,
    pub vals: Vec<Vec<u8>>,
    pub kids: Vec<Child>,
    pub dirty: bool,
    /// Its new block during a commit.
    assigned: Option<u64>,
    size: usize,
}

pub struct Child {
    /// Where the node is on disk (addr 0: never written).
    pub ptr: Ptr,
    pub node: Option<Box<Node>>,
}

impl Child {
    pub fn on_disk(ptr: Ptr) -> Child {
        Child { ptr, node: None }
    }
}

impl Node {
    pub fn leaf() -> Node {
        Node { level: 0, keys: Vec::new(), vals: Vec::new(), kids: Vec::new(), dirty: true, assigned: None, size: HDR }
    }

    fn item_size(&self, i: usize) -> usize {
        if self.level == 0 { LEAF_ITEM + self.vals[i].len() } else { INNER_ITEM }
    }

    fn recount(&mut self) {
        self.size = HDR + (0..self.keys.len()).map(|i| self.item_size(i)).sum::<usize>();
    }

    fn serialize(&self, tree: u8, generation: u64, uuid: &[u8; 16]) -> Box<[u8; BS]> {
        let mut b = Box::new([0u8; BS]);
        b[0..4].copy_from_slice(MAGIC);
        b[4] = self.level;
        b[5] = tree;
        b[6..8].copy_from_slice(&(self.keys.len() as u16).to_le_bytes());
        b[8..16].copy_from_slice(&generation.to_le_bytes());
        b[16..32].copy_from_slice(uuid);
        let mut o = HDR;
        for i in 0..self.keys.len() {
            self.keys[i].put(&mut b[o..o + KEY]);
            o += KEY;
            if self.level == 0 {
                let v = &self.vals[i];
                b[o..o + 2].copy_from_slice(&(v.len() as u16).to_le_bytes());
                b[o + 2..o + 2 + v.len()].copy_from_slice(v);
                o += 2 + v.len();
            } else {
                self.kids[i].ptr.put(&mut b[o..o + super::PTR]);
                o += super::PTR;
            }
        }
        b
    }

    /// Parse a node block (its hash was already checked). Everything is bounds-checked.
    pub fn parse(b: &[u8; BS], tree: u8, uuid: &[u8; 16], level: Option<u8>) -> Result<Node> {
        if &b[0..4] != MAGIC || b[5] != tree || &b[16..32] != uuid || b[4] > MAX_LEVEL || level.is_some_and(|l| l != b[4]) {
            return Err(Error::Corrupt);
        }
        let lvl = b[4];
        let n = usize::from(u16::from_le_bytes([b[6], b[7]]));
        let mut node = Node { level: lvl, keys: Vec::with_capacity(n), vals: Vec::new(), kids: Vec::new(), dirty: false, assigned: None, size: 0 };
        let mut o = HDR;
        for _ in 0..n {
            if o + KEY > BS {
                return Err(Error::Corrupt);
            }
            let k = Key::get(&b[o..o + KEY]);
            if node.keys.last().is_some_and(|l| *l >= k) {
                return Err(Error::Corrupt); // keys must be strictly increasing
            }
            node.keys.push(k);
            o += KEY;
            if lvl == 0 {
                if o + 2 > BS {
                    return Err(Error::Corrupt);
                }
                let len = usize::from(u16::from_le_bytes([b[o], b[o + 1]]));
                if len > MAX_VAL || o + 2 + len > BS {
                    return Err(Error::Corrupt);
                }
                node.vals.push(b[o + 2..o + 2 + len].to_vec());
                o += 2 + len;
            } else {
                if o + super::PTR > BS {
                    return Err(Error::Corrupt);
                }
                node.kids.push(Child::on_disk(Ptr::get(&b[o..o + super::PTR])));
                o += super::PTR;
            }
        }
        if lvl > 0 && n == 0 {
            return Err(Error::Corrupt);
        }
        node.recount();
        Ok(node)
    }

    fn split(&mut self) -> (Key, Box<Node>) {
        let half = (self.size - HDR) / 2;
        let (mut acc, mut m) = (0, 0);
        while m < self.keys.len() - 1 && acc < half {
            acc += self.item_size(m);
            m += 1;
        }
        let m = m.max(1);
        let mut r = Node { level: self.level, keys: self.keys.split_off(m), vals: Vec::new(), kids: Vec::new(), dirty: true, assigned: None, size: 0 };
        if self.level == 0 {
            r.vals = self.vals.split_off(m);
        } else {
            r.kids = self.kids.split_off(m);
        }
        self.recount();
        r.recount();
        (r.keys[0], Box::new(r))
    }
}

/// The child to descend into for `k`: the last whose lower bound is <= k (or the first).
fn child_index(keys: &[Key], k: &Key) -> usize {
    keys.partition_point(|x| x <= k).saturating_sub(1)
}

pub fn load(io: &mut Io, c: &mut Child, tree: u8, level: Option<u8>) -> Result<()> {
    if c.node.is_none() {
        let b = io.read_verified(&c.ptr)?;
        c.node = Some(Box::new(Node::parse(&b, tree, &io.uuid, level)?));
        io.loaded += 1;
    }
    Ok(())
}

fn kid<'a>(io: &mut Io, n: &'a mut Node, i: usize, tree: u8) -> Result<&'a mut Node> {
    let lvl = n.level - 1;
    let c = &mut n.kids[i];
    load(io, c, tree, Some(lvl))?;
    c.node.as_deref_mut().ok_or(Error::Corrupt)
}

pub struct Tree {
    pub id: u8,
    pub root: Child,
    /// Blocks of nodes removed since the last commit (freed then).
    pub dropped: Vec<Ptr>,
}

impl Tree {
    pub fn new(id: u8) -> Tree {
        Tree { id, root: Child { ptr: Ptr::NONE, node: Some(Box::new(Node::leaf())) }, dropped: Vec::new() }
    }

    pub fn open(id: u8, ptr: Ptr) -> Tree {
        Tree { id, root: Child::on_disk(ptr), dropped: Vec::new() }
    }

    fn root<'a>(&'a mut self, io: &mut Io) -> Result<&'a mut Node> {
        load(io, &mut self.root, self.id, None)?;
        self.root.node.as_deref_mut().ok_or(Error::Corrupt)
    }

    pub fn dirty(&self) -> bool {
        self.root.node.as_ref().is_some_and(|n| n.dirty) || !self.dropped.is_empty()
    }

    pub fn get(&mut self, io: &mut Io, k: &Key) -> Result<Option<Vec<u8>>> {
        let id = self.id;
        let mut n = self.root(io)?;
        while n.level > 0 {
            let i = child_index(&n.keys, k);
            n = kid(io, n, i, id)?;
        }
        Ok(n.keys.binary_search(k).ok().map(|i| n.vals[i].clone()))
    }

    /// The first item with a key >= `k`.
    pub fn next(&mut self, io: &mut Io, k: &Key) -> Result<Option<(Key, Vec<u8>)>> {
        let id = self.id;
        fn rec(io: &mut Io, n: &mut Node, k: &Key, id: u8) -> Result<Option<(Key, Vec<u8>)>> {
            if n.level == 0 {
                let i = n.keys.partition_point(|x| x < k);
                return Ok((i < n.keys.len()).then(|| (n.keys[i], n.vals[i].clone())));
            }
            let mut i = child_index(&n.keys, k);
            while i < n.kids.len() {
                let c = kid(io, n, i, id)?;
                if let Some(r) = rec(io, c, k, id)? {
                    return Ok(Some(r));
                }
                i += 1;
            }
            Ok(None)
        }
        let root = self.root(io)?;
        rec(io, root, k, id)
    }

    /// Insert or replace; returns the old value.
    pub fn insert(&mut self, io: &mut Io, k: Key, v: Vec<u8>) -> Result<Option<Vec<u8>>> {
        if v.len() > MAX_VAL {
            return Err(Error::TooBig);
        }
        let id = self.id;
        fn rec(io: &mut Io, n: &mut Node, k: Key, v: Vec<u8>, id: u8, old: &mut Option<Vec<u8>>) -> Result<Option<(Key, Box<Node>)>> {
            n.dirty = true;
            if n.level == 0 {
                match n.keys.binary_search(&k) {
                    Ok(i) => {
                        n.size = n.size - n.vals[i].len() + v.len();
                        *old = Some(core::mem::replace(&mut n.vals[i], v));
                    }
                    Err(i) => {
                        n.size += LEAF_ITEM + v.len();
                        n.keys.insert(i, k);
                        n.vals.insert(i, v);
                    }
                }
            } else {
                let i = child_index(&n.keys, &k);
                let c = kid(io, n, i, id)?;
                let split = rec(io, c, k, v, id, old)?;
                if k < n.keys[i] {
                    n.keys[i] = k;
                }
                if let Some((sk, sn)) = split {
                    n.keys.insert(i + 1, sk);
                    n.kids.insert(i + 1, Child { ptr: Ptr::NONE, node: Some(sn) });
                    n.size += INNER_ITEM;
                }
            }
            Ok(if n.size > BS { Some(n.split()) } else { None })
        }
        let mut old = None;
        let root = self.root(io)?;
        if let Some((sk, sn)) = rec(io, root, k, v, id, &mut old)? {
            let level = sn.level + 1;
            let left = core::mem::replace(&mut self.root, Child { ptr: Ptr::NONE, node: None });
            let lk = left.node.as_ref().map_or(Key::default(), |n| n.keys[0]);
            let mut r = Node { level, keys: alloc::vec![lk, sk], vals: Vec::new(), kids: alloc::vec![left, Child { ptr: Ptr::NONE, node: Some(sn) }], dirty: true, assigned: None, size: 0 };
            r.recount();
            self.root.node = Some(Box::new(r));
        }
        Ok(old)
    }

    /// Remove `k`; returns its value.
    pub fn delete(&mut self, io: &mut Io, k: &Key) -> Result<Option<Vec<u8>>> {
        let id = self.id;
        fn rec(io: &mut Io, n: &mut Node, k: &Key, id: u8, dropped: &mut Vec<Ptr>) -> Result<Option<Vec<u8>>> {
            if n.level == 0 {
                let Ok(i) = n.keys.binary_search(k) else { return Ok(None) };
                n.dirty = true;
                n.keys.remove(i);
                let v = n.vals.remove(i);
                n.size -= LEAF_ITEM + v.len();
                return Ok(Some(v));
            }
            let i = child_index(&n.keys, k);
            let c = kid(io, n, i, id)?;
            let Some(v) = rec(io, c, k, id, dropped)? else { return Ok(None) };
            n.dirty = true;
            let (empty, small) = n.kids[i].node.as_ref().map_or((false, false), |c| (c.keys.is_empty(), c.size < BS / 3));
            if empty {
                let c = n.kids.remove(i);
                n.keys.remove(i);
                n.size -= INNER_ITEM;
                if c.ptr.addr != 0 {
                    dropped.push(c.ptr);
                }
            } else if small && i + 1 < n.kids.len() {
                // Merge the right neighbour in if both fit comfortably in one node.
                let right_size = kid(io, n, i + 1, id)?.size;
                let left_size = n.kids[i].node.as_ref().map_or(BS, |c| c.size);
                if left_size + right_size - HDR <= BS * 3 / 4 {
                    let r = n.kids.remove(i + 1);
                    n.keys.remove(i + 1);
                    n.size -= INNER_ITEM;
                    if r.ptr.addr != 0 {
                        dropped.push(r.ptr);
                    }
                    let mut rn = r.node.ok_or(Error::Corrupt)?;
                    let l = n.kids[i].node.as_deref_mut().ok_or(Error::Corrupt)?;
                    l.keys.append(&mut rn.keys);
                    l.vals.append(&mut rn.vals);
                    l.kids.append(&mut rn.kids);
                    l.dirty = true;
                    l.recount();
                }
            }
            Ok(Some(v))
        }
        load(io, &mut self.root, id, None)?;
        let root = self.root.node.as_deref_mut().ok_or(Error::Corrupt)?;
        let v = rec(io, root, k, id, &mut self.dropped)?;
        // Collapse a root with a single child (or none).
        while let Some(r) = self.root.node.as_mut() {
            if r.level == 0 {
                break;
            }
            if r.kids.is_empty() {
                if self.root.ptr.addr != 0 {
                    self.dropped.push(self.root.ptr);
                }
                self.root = Child { ptr: Ptr::NONE, node: Some(Box::new(Node::leaf())) };
                break;
            }
            if r.kids.len() > 1 {
                break;
            }
            let mut only = r.kids.pop().ok_or(Error::Corrupt)?;
            load(io, &mut only, id, Some(r.level - 1))?;
            if self.root.ptr.addr != 0 {
                self.dropped.push(self.root.ptr);
            }
            self.root = only;
        }
        Ok(v)
    }

    /// Commit, step 1: give every dirty node a new block. `alloc(old)` frees the node's old
    /// block (if any) and returns a new one. Returns how many nodes were assigned.
    pub fn assign(&mut self, alloc: &mut dyn FnMut(&Ptr) -> Result<u64>) -> Result<usize> {
        fn rec(c: &mut Child, alloc: &mut dyn FnMut(&Ptr) -> Result<u64>) -> Result<usize> {
            let Some(n) = c.node.as_deref_mut() else { return Ok(0) };
            if !n.dirty {
                return Ok(0); // a clean node has no dirty descendants
            }
            let mut cnt = 0;
            for k in n.kids.iter_mut() {
                cnt += rec(k, alloc)?;
            }
            if n.assigned.is_none() {
                n.assigned = Some(alloc(&c.ptr)?);
                cnt += 1;
            }
            Ok(cnt)
        }
        rec(&mut self.root, alloc)
    }

    /// Commit, step 2: serialize, hash and queue every dirty node (children first).
    pub fn write(&mut self, io: &mut Io, generation: u64) -> Result<Ptr> {
        let id = self.id;
        fn rec(c: &mut Child, io: &mut Io, generation: u64, id: u8) -> Result<()> {
            let Some(n) = c.node.as_deref_mut() else { return Ok(()) };
            if !n.dirty {
                return Ok(());
            }
            for k in n.kids.iter_mut() {
                rec(k, io, generation, id)?;
            }
            let addr = n.assigned.take().ok_or(Error::Corrupt)?;
            let b = n.serialize(id, generation, &io.uuid);
            let hash = crate::blake3::hash(&b[..]);
            io.queue(addr, b);
            c.ptr = Ptr { addr, generation, hash };
            n.dirty = false;
            Ok(())
        }
        rec(&mut self.root, io, generation, id)?;
        self.dropped.clear();
        Ok(self.root.ptr)
    }

    /// Forget every loaded node below the root (they are clean after a commit).
    pub fn shrink(&mut self) {
        if let Some(r) = self.root.node.as_deref_mut() {
            for k in r.kids.iter_mut() {
                if k.node.as_ref().is_some_and(|n| !n.dirty) {
                    k.node = None;
                }
            }
        }
    }

    /// The on-disk block of the leaf that holds (or would hold) `k` (test hooks).
    pub fn leaf_of(&mut self, io: &mut Io, k: &Key) -> Result<u64> {
        let id = self.id;
        if self.root(io)?.level == 0 {
            return Ok(self.root.ptr.addr);
        }
        let mut n = self.root(io)?;
        loop {
            let i = child_index(&n.keys, k);
            if n.level == 1 {
                return Ok(n.kids[i].ptr.addr);
            }
            n = kid(io, n, i, id)?;
        }
    }
}

/// What `walk` reports.
pub enum Visit<'a> {
    /// A node block (with its level).
    Node(u64, u8),
    /// A leaf item.
    Item(&'a Key, &'a [u8]),
}

/// Visit every node and item of the tree under `ptr`, reading from disk (nothing is cached),
/// checking hashes, structure and that each node's keys lie within its parent's bounds.
/// `seen(addr)` returning true skips a subtree (already visited through another root).
pub fn walk(io: &mut Io, ptr: &Ptr, tree: u8, seen: &mut dyn FnMut(u64) -> bool, f: &mut dyn FnMut(Visit<'_>) -> Result<()>) -> Result<()> {
    #[allow(clippy::too_many_arguments)] // the recursion's state, passed down as is
    fn rec(
        io: &mut Io,
        ptr: &Ptr,
        tree: u8,
        level: Option<u8>,
        lo: Option<Key>,
        hi: Option<Key>,
        seen: &mut dyn FnMut(u64) -> bool,
        f: &mut dyn FnMut(Visit<'_>) -> Result<()>,
    ) -> Result<()> {
        if seen(ptr.addr) {
            return Ok(());
        }
        let b = io.read_verified(ptr)?;
        let n = Node::parse(&b, tree, &io.uuid, level)?;
        if n.keys.first().is_some_and(|k| lo.is_some_and(|l| *k < l)) || n.keys.last().is_some_and(|k| hi.is_some_and(|h| *k >= h)) {
            return Err(Error::Corrupt); // keys outside the range the parent gave this node
        }
        f(Visit::Node(ptr.addr, n.level))?;
        if n.level == 0 {
            for i in 0..n.keys.len() {
                f(Visit::Item(&n.keys[i], &n.vals[i]))?;
            }
            return Ok(());
        }
        for i in 0..n.kids.len() {
            let clo = if i == 0 { lo } else { Some(n.keys[i]) };
            let chi = if i + 1 < n.kids.len() { Some(n.keys[i + 1]) } else { hi };
            rec(io, &n.kids[i].ptr, tree, Some(n.level - 1), clo, chi, seen, f)?;
        }
        Ok(())
    }
    rec(io, ptr, tree, None, None, None, seen, f)
}
