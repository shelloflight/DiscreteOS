//! D-OS File Manager (`files.dapp`).
//!
//! Operates strictly inside the identity's granted namespace (`/home`, optional `/data` for
//! Operators, read-only `/system` and `/sys`). Shows a clear status message if `files:read` or
//! `files:write` has been revoked.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::mem::ManuallyDrop;

use dosui::{Length, Node, Tone, button, caption, column, divider, heading, input, item, label, mono, panel, row, scroll, spacer, text};
use libd::fs::{self as fp, Namespace, Node as FsNode};
use libd::sys::Handle;
use libd::{Startup, println};

use crate::common::{App, run_app};

struct Place {
    path: String,
    h: Handle,
    writable: bool,
}

#[derive(Clone)]
struct Entry {
    name: String,
    is_dir: bool,
    size: u64,
}

#[derive(Clone)]
enum Msg {
    SelectPlace(usize),
    SelectEntry(usize),
    OpenEntry(usize),
    OpenSelected,
    Up,
    Refresh,
    NewNameChanged(String),
    CreateFile,
    CreateFolder,
    DeleteSelected,
}

struct FilesApp {
    places: Vec<Place>,
    place_idx: usize,
    rel: String,
    entries: Vec<Entry>,
    selected: Option<usize>,
    selected_dir_count: Option<usize>,
    preview: String,
    new_name: String,
    status: String,
}

fn entry_key(path: &str, name: &str) -> u64 {
    let mut h = 0xcbf2_9ce4_8422_2325u64;
    for &b in path.as_bytes().iter().chain(b"/").chain(name.as_bytes()) {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    h
}

fn borrow(h: Handle) -> ManuallyDrop<FsNode> {
    ManuallyDrop::new(FsNode::from(h))
}

fn fmt_size(sz: u64) -> String {
    if sz >= 1 << 20 {
        format!("{} MiB", sz >> 20)
    } else if sz >= 1024 {
        format!("{} KiB", sz >> 10)
    } else {
        format!("{} B", sz)
    }
}

impl FilesApp {
    fn new() -> Self {
        let mut places: Vec<Place> = Namespace::get()
            .entries()
            .map(|(p, h)| {
                let writable = borrow(h).stat().is_ok_and(|st| st.rights & fp::R_WRITE != 0);
                Place { path: String::from_utf8_lossy(p).into_owned(), h, writable }
            })
            .collect();
        places.sort_by(|a, b| {
            let rank = |p: &str| match p {
                "/home" => 0,
                "/data" => 1,
                "/system" => 2,
                "/sys" => 3,
                _ => 4,
            };
            rank(&a.path).cmp(&rank(&b.path)).then_with(|| a.path.cmp(&b.path))
        });
        let names: Vec<&str> = places.iter().map(|p| p.path.as_str()).collect();
        println!("files: namespace places: {}", if names.is_empty() { "none".to_string() } else { names.join(", ") });
        let mut app = Self {
            places,
            place_idx: 0,
            rel: String::new(),
            entries: Vec::new(),
            selected: None,
            selected_dir_count: None,
            preview: String::new(),
            new_name: String::new(),
            status: String::new(),
        };
        if let Ok(arg) = core::str::from_utf8(libd::args()) {
            let target = arg.trim().trim_end_matches('/');
            if !target.is_empty() {
                // Select the longest granted place matching the requested startup path.
                let mut best: Option<(usize, usize, &str)> = None;
                for (i, p) in app.places.iter().enumerate() {
                    let root = p.path.trim_end_matches('/');
                    if target == root {
                        if best.is_none_or(|(_, bl, _)| root.len() > bl) {
                            best = Some((i, root.len(), ""));
                        }
                    } else if let Some(rest) = target.strip_prefix(root)
                        && let Some(sub) = rest.strip_prefix('/')
                        && best.is_none_or(|(_, bl, _)| root.len() > bl)
                    {
                        best = Some((i, root.len(), sub));
                    }
                }
                if let Some((idx, _, sub)) = best {
                    app.place_idx = idx;
                    app.rel = String::from(sub);
                }
            }
        }
        app.reload();
        app
    }

    fn current_place(&self) -> Option<&Place> {
        self.places.get(self.place_idx)
    }

    fn current_path(&self) -> String {
        let Some(p) = self.current_place() else {
            return String::from("(none)");
        };
        if self.rel.is_empty() {
            p.path.clone()
        } else {
            format!("{}/{}", p.path, self.rel)
        }
    }

    fn open_current_dir(&self, rights: u64) -> Result<FsNode, i64> {
        let Some(p) = self.current_place() else {
            return Err(libd::sys::ERR_ACCESS_DENIED);
        };
        let root = borrow(p.h);
        if self.rel.is_empty() {
            root.clone_with(rights)
        } else {
            root.open(self.rel.as_bytes(), fp::O_DIRECTORY, rights).map(|(n, _, _)| n)
        }
    }

    fn reload(&mut self) {
        self.entries.clear();
        self.selected = None;
        self.selected_dir_count = None;
        self.preview.clear();
        let Some(p) = self.current_place() else {
            self.status = String::from("No filesystem places granted (files:read is revoked).");
            return;
        };
        let _ = p;
        let dir = match self.open_current_dir(fp::R_READ) {
            Ok(d) => d,
            Err(e) => {
                self.status = format!("Cannot open directory: {}", fp::message(e));
                return;
            }
        };
        let mut raw: Vec<(String, bool)> = Vec::new();
        if let Err(e) = dir.list(|n, k| {
            raw.push((String::from_utf8_lossy(n).into_owned(), k == fp::KIND_DIR));
        }) {
            self.status = format!("Cannot list directory: {}", fp::message(e));
            return;
        }
        raw.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        for (name, is_dir) in raw.into_iter().take(128) {
            let size = if is_dir {
                0
            } else {
                dir.open(name.as_bytes(), 0, fp::R_READ).map_or(0, |(_, _, sz)| sz)
            };
            self.entries.push(Entry { name, is_dir, size });
        }
        self.status = format!("{} item(s) in {}", self.entries.len(), self.current_path());
    }

    fn enter_entry(&mut self, idx: usize) {
        let Some(ent) = self.entries.get(idx).cloned() else { return };
        if ent.is_dir {
            if self.rel.is_empty() {
                self.rel = ent.name;
            } else {
                self.rel = format!("{}/{}", self.rel, ent.name);
            }
            self.reload();
        } else {
            self.selected = Some(idx);
            self.load_preview();
        }
    }

    fn load_preview(&mut self) {
        self.preview.clear();
        self.selected_dir_count = None;
        let Some(idx) = self.selected else { return };
        let Some(ent) = self.entries.get(idx).cloned() else { return };
        let Ok(dir) = self.open_current_dir(fp::R_READ) else { return };
        if ent.is_dir {
            if let Ok((sub, _, _)) = dir.open(ent.name.as_bytes(), fp::O_DIRECTORY, fp::R_READ) {
                let mut count = 0usize;
                let _ = sub.list(|_, _| count += 1);
                self.selected_dir_count = Some(count);
            }
            return;
        }
        if let Ok((f, _, sz)) = dir.open(ent.name.as_bytes(), 0, fp::R_READ) {
            let cap = (sz as usize).min(4096);
            let mut buf = alloc::vec![0u8; cap];
            if let Ok(n) = f.read(0, &mut buf) {
                self.preview = String::from_utf8_lossy(&buf[..n]).into_owned();
            }
        }
    }
}

impl App for FilesApp {
    type Msg = Msg;

    fn title(&self) -> &str {
        "Files"
    }

    fn size(&self) -> (u32, u32) {
        (800, 540)
    }

    fn view(&self) -> Node<Msg> {
        let cur_path = self.current_path();
        let mut place_nodes: Vec<Node<Msg>> = alloc::vec![label("Places")];
        if self.places.is_empty() {
            place_nodes.push(caption("No places granted").tone(Tone::Danger));
        } else {
            for (i, p) in self.places.iter().enumerate() {
                let tag = if p.writable { "rw" } else { "ro" };
                place_nodes.push(
                    item(&p.path, i == self.place_idx)
                        .detail(tag)
                        .on_select(Msg::SelectPlace(i)),
                );
            }
        }
        let sidebar = panel(place_nodes).width(Length::Px(170)).height(Length::Fill);

        let mut list_nodes: Vec<Node<Msg>> = Vec::new();
        if self.entries.is_empty() {
            list_nodes.push(caption("Folder is empty").padding(8));
        } else {
            for (i, e) in self.entries.iter().enumerate() {
                let det = if e.is_dir { String::from("Folder") } else { fmt_size(e.size) };
                let lbl = if e.is_dir { format!("{}/", e.name) } else { e.name.clone() };
                list_nodes.push(
                    item(lbl, self.selected == Some(i))
                        .detail(det)
                        .key(entry_key(&cur_path, &e.name))
                        .on_select(Msg::SelectEntry(i))
                        .on_activate(Msg::OpenEntry(i)),
                );
            }
        }
        let file_list = scroll(column(list_nodes).gap(2)).fill();

        let can_write = self.current_place().is_some_and(|p| p.writable);
        let up_btn = if self.rel.is_empty() {
            button("Up")
        } else {
            button("Up").on_press(Msg::Up)
        };
        let top_bar = row([
            up_btn,
            button("Refresh").on_press(Msg::Refresh),
            spacer(),
            mono(&cur_path).tone(Tone::Accent),
        ])
        .gap(8);

        let mut detail_nodes: Vec<Node<Msg>> = alloc::vec![label("Inspector")];
        if let Some(idx) = self.selected
            && let Some(e) = self.entries.get(idx)
        {
            detail_nodes.push(text(&e.name));
            if e.is_dir {
                let summary = match self.selected_dir_count {
                    Some(0) => String::from("Empty folder"),
                    Some(1) => String::from("Folder • 1 item"),
                    Some(n) => format!("Folder • {} items", n),
                    None => String::from("Folder"),
                };
                detail_nodes.push(caption(summary));
                detail_nodes.push(button("Open Folder").primary().on_press(Msg::OpenSelected));
            } else {
                detail_nodes.push(caption(fmt_size(e.size)));
                if !self.preview.is_empty() {
                    detail_nodes.push(divider());
                    detail_nodes.push(scroll(mono(&self.preview).wrap()).fill());
                } else {
                    detail_nodes.push(caption("Empty file"));
                }
            }
            if can_write {
                detail_nodes.push(divider());
                detail_nodes.push(button("Delete").danger().on_press(Msg::DeleteSelected));
            }
        } else {
            detail_nodes.push(text(&cur_path));
            detail_nodes.push(caption(format!("{} item(s)", self.entries.len())));
            detail_nodes.push(caption("Double-click a folder to open it."));
        }
        if can_write {
            detail_nodes.push(divider());
            detail_nodes.push(label("Create"));
            detail_nodes.push(
                input(&self.new_name)
                    .placeholder("name.txt or folder")
                    .width(Length::Fill)
                    .on_change(Msg::NewNameChanged),
            );
            detail_nodes.push(
                row([
                    button("New File").on_press(Msg::CreateFile),
                    button("New Folder").on_press(Msg::CreateFolder),
                ])
                .gap(8),
            );
        } else {
            detail_nodes.push(divider());
            detail_nodes.push(caption("Read-only volume"));
        }
        let inspector = panel(detail_nodes).width(Length::Px(260)).height(Length::Fill);

        let body = row([sidebar, column([top_bar, divider(), file_list]).gap(8).fill(), inspector])
            .gap(10)
            .fill();

        column([
            row([heading("Files"), spacer(), caption(&self.status)]).gap(8),
            body,
        ])
        .padding(12)
        .gap(10)
        .fill()
    }

    fn update(&mut self, msg: Msg) {
        match msg {
            Msg::SelectPlace(i) => {
                if i < self.places.len() {
                    self.place_idx = i;
                    self.rel.clear();
                    self.reload();
                }
            }
            Msg::SelectEntry(i) => {
                self.selected = Some(i);
                self.load_preview();
            }
            Msg::OpenEntry(i) => {
                self.enter_entry(i);
            }
            Msg::OpenSelected => {
                if let Some(idx) = self.selected {
                    self.enter_entry(idx);
                }
            }
            Msg::Up => {
                if let Some((parent, _)) = self.rel.rsplit_once('/') {
                    self.rel = String::from(parent);
                } else {
                    self.rel.clear();
                }
                self.reload();
            }
            Msg::Refresh => self.reload(),
            Msg::NewNameChanged(s) => self.new_name = s,
            Msg::CreateFile => {
                let n = self.new_name.trim().to_string();
                if !fp::valid_name(n.as_bytes()) {
                    self.status = String::from("Invalid file name.");
                    return;
                }
                match self.open_current_dir(fp::R_READ | fp::R_WRITE) {
                    Ok(dir) => match dir.open(n.as_bytes(), fp::O_CREATE, fp::R_READ | fp::R_WRITE) {
                        Ok(_) => {
                            let _ = dir.sync();
                            self.new_name.clear();
                            self.reload();
                            self.status = format!("Created file '{}'", n);
                        }
                        Err(e) => self.status = format!("Create failed: {}", fp::message(e)),
                    },
                    Err(e) => self.status = format!("Write denied: {}", fp::message(e)),
                }
            }
            Msg::CreateFolder => {
                let n = self.new_name.trim().to_string();
                if !fp::valid_name(n.as_bytes()) {
                    self.status = String::from("Invalid folder name.");
                    return;
                }
                match self.open_current_dir(fp::R_READ | fp::R_WRITE) {
                    Ok(dir) => match dir.open(n.as_bytes(), fp::O_DIRECTORY | fp::O_CREATE, fp::R_READ | fp::R_WRITE) {
                        Ok(_) => {
                            let _ = dir.sync();
                            self.new_name.clear();
                            self.reload();
                            self.status = format!("Created folder '{}'", n);
                        }
                        Err(e) => self.status = format!("Create folder failed: {}", fp::message(e)),
                    },
                    Err(e) => self.status = format!("Write denied: {}", fp::message(e)),
                }
            }
            Msg::DeleteSelected => {
                let Some(idx) = self.selected else { return };
                let Some(ent) = self.entries.get(idx).cloned() else { return };
                match self.open_current_dir(fp::R_READ | fp::R_WRITE) {
                    Ok(dir) => match dir.unlink(ent.name.as_bytes()) {
                        Ok(()) => {
                            let _ = dir.sync();
                            self.reload();
                            self.status = format!("Deleted '{}'", ent.name);
                        }
                        Err(e) => self.status = format!("Delete failed: {}", fp::message(e)),
                    },
                    Err(e) => self.status = format!("Delete denied: {}", fp::message(e)),
                }
            }
        }
    }
}

pub fn main(s: *const Startup) -> i32 {
    // SAFETY: `s` is the startup block pointer passed by the kernel.
    if !unsafe { libd::init(s, "files") } {
        return 1;
    }
    run_app("files", FilesApp::new(), 0)
}
