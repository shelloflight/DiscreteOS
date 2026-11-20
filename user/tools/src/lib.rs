//! The core tools (docs/shell.md): `list`, `show`, `copy`, `move`, `delete`, `make`.
//!
//! Each is its own program (`<name>.dx`, entry `dx_<name>`) with a manifest that declares its
//! parameters and the rights each one needs. A tool holds nothing but what the shell resolved for
//! it (`libd::tool`): the nodes of the paths typed, with exactly the declared rights, and an
//! output channel for its records. It cannot reach anything else, so a mistake in a tool (or a
//! hostile one) is confined to the paths the user named.

#![no_std]

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use libd::fs::{self as fp, Node};
use libd::rec::{Out, Record, Value};
use libd::tool::{self, Item};
use libd::{Startup, sys};

libd::entry!(dx_list, list);
libd::entry!(dx_show, show);
libd::entry!(dx_copy, copy);
libd::entry!(dx_move, move_);
libd::entry!(dx_delete, delete);
libd::entry!(dx_make, make);
libd::entry!(dx_create, create);

/// Start a tool: (output, items). None if this is not a proper start.
fn start(s: *const Startup, name: &'static str) -> Option<Out> {
    // SAFETY: `s` is the startup block pointer the kernel passed to the entry point.
    unsafe { libd::init(s, name) }.then(Out::startup)
}

/// A node handle we were given (owned: closed on drop).
fn node(i: &Item) -> Node {
    Node::from(i.handle)
}

fn fail(out: &mut Out, tool: &str, what: &str, e: i64) -> i32 {
    out.error(e, &format!("{}: {}: {}", tool, what, fp::message(e)));
    1
}

fn last_name(path: &str) -> &str {
    path.trim_end_matches('/').rsplit('/').next().unwrap_or(path)
}

fn kind_name(k: u64) -> &'static str {
    if k == fp::KIND_DIR { "dir" } else { "file" }
}

/// One record per entry: name, kind, size (files), modified.
fn entry_record(name: &str, st: &fp::Stat) -> Record {
    let mut r = Record::new().with("name", Value::Text(String::from(name))).with("kind", Value::Text(String::from(kind_name(st.kind))));
    r = r.with("size", if st.kind == fp::KIND_DIR { Value::Text(String::new()) } else { Value::Size(st.size) });
    r.with("modified", Value::Time(st.modified))
}

fn list(s: *const Startup) -> i32 {
    let Some(mut out) = start(s, "list") else { return 1 };
    let Some(it) = tool::item("place") else { return fail(&mut out, "list", "no place", sys::ERR_INVALID_ARGS) };
    let dir = node(&it);
    let st = match dir.stat() {
        Ok(st) => st,
        Err(e) => return fail(&mut out, "list", it.shown, e),
    };
    if st.kind != fp::KIND_DIR {
        out.record(&entry_record(last_name(it.shown), &st));
        return 0;
    }
    let mut names: Vec<(Vec<u8>, u64)> = Vec::new();
    if let Err(e) = dir.list(|n, k| names.push((n.to_vec(), k))) {
        return fail(&mut out, "list", it.shown, e);
    }
    // Directories first, then by name (case-insensitive).
    names.sort_by(|a, b| (b.1 == fp::KIND_DIR).cmp(&(a.1 == fp::KIND_DIR)).then_with(|| a.0.to_ascii_lowercase().cmp(&b.0.to_ascii_lowercase())));
    for (n, k) in names {
        let name = String::from_utf8_lossy(&n).into_owned();
        let st = match dir.open(&n, 0, fp::R_READ).and_then(|(f, _, _)| f.stat()) {
            Ok(st) => st,
            Err(_) => fp::Stat { kind: k, ..fp::Stat::default() },
        };
        out.record(&entry_record(&name, &st));
    }
    0
}

fn show(s: *const Startup) -> i32 {
    let Some(mut out) = start(s, "show") else { return 1 };
    let Some(it) = tool::item("file") else { return fail(&mut out, "show", "no file", sys::ERR_INVALID_ARGS) };
    let f = node(&it);
    let st = match f.stat() {
        Ok(st) => st,
        Err(e) => return fail(&mut out, "show", it.shown, e),
    };
    if st.kind == fp::KIND_DIR {
        return fail(&mut out, "show", it.shown, fp::ERR_IS_DIR);
    }
    let mut buf = vec![0u8; fp::MAX_IO];
    let mut off = 0u64;
    let mut partial: Vec<u8> = Vec::new();
    loop {
        let n = match f.read(off, &mut buf) {
            Ok(n) => n,
            Err(e) => return fail(&mut out, "show", it.shown, e),
        };
        if n == 0 {
            break;
        }
        if off == 0 && buf[..n.min(4096)].contains(&0) {
            out.error(0, &format!("show: {}: not text ({} bytes of binary data)", it.shown, st.size));
            return 1;
        }
        off += n as u64;
        // Whole UTF-8 sequences only (a character may straddle two reads).
        partial.extend_from_slice(&buf[..n]);
        let cut = match core::str::from_utf8(&partial) {
            Ok(_) => partial.len(),
            Err(e) if e.error_len().is_none() => e.valid_up_to(),
            Err(_) => partial.len(),
        };
        let text = String::from_utf8_lossy(&partial[..cut]).replace('\r', "");
        out.text(&text);
        partial.drain(..cut);
        if n < buf.len() {
            break;
        }
    }
    if !partial.is_empty() {
        out.text(&String::from_utf8_lossy(&partial));
    }
    0
}

/// Copy file `from` to `name` below `dir`: bytes copied.
fn copy_file(from: &Node, dir: &Node, name: &str) -> Result<u64, i64> {
    let (to, _, _) = dir.open(name.as_bytes(), fp::O_CREATE | fp::O_TRUNCATE, fp::R_READ | fp::R_WRITE)?;
    let mut buf = vec![0u8; fp::MAX_IO];
    let mut off = 0u64;
    loop {
        let n = from.read(off, &mut buf)?;
        if n == 0 {
            break;
        }
        let w = to.write(off, &buf[..n])?;
        if w < n {
            return Err(fp::ERR_IO);
        }
        off += n as u64;
        if n < buf.len() {
            break;
        }
    }
    Ok(off)
}

fn copy(s: *const Startup) -> i32 {
    let Some(mut out) = start(s, "copy") else { return 1 };
    let (Some(a), Some(b)) = (tool::item("from"), tool::item("to")) else { return fail(&mut out, "copy", "from and to are needed", sys::ERR_INVALID_ARGS) };
    let from = node(&a);
    if a.shown == b.shown {
        out.error(fp::ERR_EXISTS, &format!("copy: {} would be copied onto itself", a.shown));
        return 1;
    }
    match from.stat() {
        Ok(st) if st.kind == fp::KIND_DIR => {
            out.error(fp::ERR_IS_DIR, &format!("copy: {}: is a directory (copying directories is not supported yet)", a.shown));
            return 1;
        }
        Ok(_) => {}
        Err(e) => return fail(&mut out, "copy", a.shown, e),
    }
    let dir = node(&b);
    match copy_file(&from, &dir, b.rel) {
        Ok(n) => {
            out.record(&Record::new().with("copied", Value::Path(String::from(b.shown))).with("size", Value::Size(n)));
            0
        }
        Err(e) => fail(&mut out, "copy", b.shown, e),
    }
}

fn parent(path: &str) -> &str {
    path.trim_end_matches('/').rsplit_once('/').map_or("", |(p, _)| p)
}

fn move_(s: *const Startup) -> i32 {
    let Some(mut out) = start(s, "move") else { return 1 };
    let (Some(a), Some(b)) = (tool::item("from"), tool::item("to")) else { return fail(&mut out, "move", "from and to are needed", sys::ERR_INVALID_ARGS) };
    let (from_dir, to_dir) = (node(&a), node(&b));
    if a.rel.is_empty() {
        out.error(sys::ERR_ACCESS_DENIED, &format!("move: {}: a whole volume cannot be moved", a.shown));
        return 1;
    }
    if a.shown == b.shown {
        out.error(fp::ERR_EXISTS, &format!("move: {} is already there", a.shown));
        return 1;
    }
    let done = |out: &mut Out| {
        out.record(&Record::new().with("moved", Value::Path(String::from(a.shown))).with("to", Value::Path(String::from(b.shown))));
        0
    };
    // Same directory: a rename (atomic on DFS).
    if parent(a.shown) == parent(b.shown) {
        return match from_dir.rename(a.rel.as_bytes(), b.rel.as_bytes(), false) {
            Ok(()) => done(&mut out),
            Err(e) => fail(&mut out, "move", a.shown, e),
        };
    }
    // Another directory: copy, then delete the original (files only).
    let (f, kind, _) = match from_dir.open(a.rel.as_bytes(), 0, fp::R_READ) {
        Ok(x) => x,
        Err(e) => return fail(&mut out, "move", a.shown, e),
    };
    if kind == fp::KIND_DIR {
        out.error(fp::ERR_IS_DIR, &format!("move: {}: a directory can only be renamed in place for now", a.shown));
        return 1;
    }
    if let Ok((_, _, _)) = to_dir.open(b.rel.as_bytes(), 0, fp::R_READ) {
        return fail(&mut out, "move", b.shown, fp::ERR_EXISTS);
    }
    if let Err(e) = copy_file(&f, &to_dir, b.rel) {
        let _ = to_dir.unlink(b.rel.as_bytes());
        return fail(&mut out, "move", b.shown, e);
    }
    drop(f);
    match from_dir.unlink(a.rel.as_bytes()) {
        Ok(()) => done(&mut out),
        Err(e) => fail(&mut out, "move", a.shown, e),
    }
}

fn delete(s: *const Startup) -> i32 {
    let Some(mut out) = start(s, "delete") else { return 1 };
    let mut code = 0;
    let mut any = false;
    for it in tool::items().filter(|i| i.name == "path") {
        any = true;
        let dir = node(&it);
        if it.rel.is_empty() {
            out.error(sys::ERR_ACCESS_DENIED, &format!("delete: {}: a whole volume cannot be deleted", it.shown));
            code = 1;
            continue;
        }
        match dir.unlink(it.rel.as_bytes()) {
            Ok(()) => out.record(&Record::new().with("deleted", Value::Path(String::from(it.shown)))),
            Err(e) => code = fail(&mut out, "delete", it.shown, e),
        }
    }
    if !any {
        return fail(&mut out, "delete", "nothing to delete", sys::ERR_INVALID_ARGS);
    }
    code
}

fn make(s: *const Startup) -> i32 {
    let Some(mut out) = start(s, "make") else { return 1 };
    let Some(it) = tool::item("place") else { return fail(&mut out, "make", "no place", sys::ERR_INVALID_ARGS) };
    let dir = node(&it);
    if it.rel.is_empty() {
        return fail(&mut out, "make", it.shown, fp::ERR_EXISTS);
    }
    match dir.open(it.rel.as_bytes(), fp::O_CREATE | fp::O_EXCL | fp::O_DIRECTORY, fp::R_READ) {
        Ok(_) => {
            out.record(&Record::new().with("made", Value::Path(String::from(it.shown))));
            0
        }
        Err(e) => fail(&mut out, "make", it.shown, e),
    }
}

fn create(s: *const Startup) -> i32 {
    let Some(mut out) = start(s, "create") else { return 1 };
    let mut code = 0;
    let mut any = false;
    for it in tool::items().filter(|i| i.name == "file") {
        any = true;
        let dir = node(&it);
        if it.rel.is_empty() {
            code = fail(&mut out, "create", it.shown, fp::ERR_EXISTS);
            continue;
        }
        match dir.open(it.rel.as_bytes(), fp::O_CREATE, fp::R_READ | fp::R_WRITE) {
            Ok((_, fp::KIND_DIR, _)) => code = fail(&mut out, "create", it.shown, fp::ERR_IS_DIR),
            Ok(_) => out.record(&Record::new().with("created", Value::Path(String::from(it.shown)))),
            Err(e) => code = fail(&mut out, "create", it.shown, e),
        }
    }
    if !any {
        return fail(&mut out, "create", "no file", sys::ERR_INVALID_ARGS);
    }
    code
}
