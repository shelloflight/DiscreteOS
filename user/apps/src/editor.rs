//! D-OS Native Text Editor (`editor.dapp`).
//!
//! Uses `dosui::textarea` for multiline monospace editing and respects per-identity namespace
//! grants (`files:read` / `files:write`). Reports read-only mode clearly if `files:write` is
//! denied or revoked.

use alloc::format;
use alloc::string::String;
use core::mem::ManuallyDrop;

use dosui::{Length, Node, Tone, button, caption, column, divider, heading, input, row, spacer, textarea};
use libd::fs::{self as fp, Namespace, Node as FsNode};
use libd::Startup;

use crate::common::{App, run_app};

#[derive(Clone)]
enum Msg {
    PathChanged(String),
    ContentChanged(String),
    Open,
    New,
    Save,
}

struct EditorApp {
    path: String,
    content: String,
    dirty: bool,
    status: String,
    writable: bool,
}

impl EditorApp {
    fn new() -> Self {
        let ns = Namespace::get();
        let writable = ns
            .resolve(b"/home")
            .is_some_and(|(h, _)| ManuallyDrop::new(FsNode::from(h)).stat().is_ok_and(|st| st.rights & fp::R_WRITE != 0));
        let status = if writable {
            String::from("Ready (/home is writable)")
        } else {
            String::from("Read-only mode (files:write not granted or volume read-only)")
        };
        let mut app = Self {
            path: String::from("/home/notes.txt"),
            content: String::new(),
            dirty: false,
            status,
            writable,
        };
        if let Ok(arg) = core::str::from_utf8(libd::args()) {
            let target = arg.trim();
            if !target.is_empty() {
                app.path = String::from(target);
                app.open_file();
            }
        }
        app
    }

    fn open_file(&mut self) {
        let ns = Namespace::get();
        let Some((dir_h, rest)) = ns.resolve(self.path.as_bytes()) else {
            self.status = format!("Path '{}' is outside your granted namespace.", self.path);
            return;
        };
        if rest.is_empty() {
            self.status = String::from("Enter a file path inside a granted folder.");
            return;
        }
        let dir = ManuallyDrop::new(FsNode::from(dir_h));
        match dir.open(rest, 0, fp::R_READ) {
            Ok((f, kind, sz)) => {
                if kind == fp::KIND_DIR {
                    self.status = String::from("Selected path is a directory.");
                    return;
                }
                let len = (sz as usize).min(256 * 1024);
                let mut buf = alloc::vec![0u8; len];
                match f.read(0, &mut buf) {
                    Ok(n) => {
                        self.content = String::from_utf8_lossy(&buf[..n]).into_owned();
                        self.dirty = false;
                        self.status = format!("Opened {} ({} bytes)", self.path, n);
                    }
                    Err(e) => self.status = format!("Read error: {}", fp::message(e)),
                }
            }
            Err(e) => self.status = format!("Cannot open {}: {}", self.path, fp::message(e)),
        }
    }

    fn save_file(&mut self) {
        let ns = Namespace::get();
        let Some((dir_h, rest)) = ns.resolve(self.path.as_bytes()) else {
            self.status = format!("Path '{}' is outside your granted namespace.", self.path);
            return;
        };
        if rest.is_empty() {
            self.status = String::from("Enter a file path to save.");
            return;
        }
        let dir = ManuallyDrop::new(FsNode::from(dir_h));
        match dir.open(rest, fp::O_CREATE | fp::O_TRUNCATE, fp::R_READ | fp::R_WRITE) {
            Ok((f, _, _)) => match f.write(0, self.content.as_bytes()) {
                Ok(n) => {
                    let _ = f.sync();
                    self.dirty = false;
                    self.status = format!("Saved {} ({} bytes)", self.path, n);
                }
                Err(e) => self.status = format!("Write failed: {}", fp::message(e)),
            },
            Err(e) => self.status = format!("Save refused: {}", fp::message(e)),
        }
    }
}

impl App for EditorApp {
    type Msg = Msg;

    fn title(&self) -> &str {
        "Text Editor"
    }

    fn size(&self) -> (u32, u32) {
        (740, 520)
    }

    fn view(&self) -> Node<Msg> {
        let lines = self.content.bytes().filter(|&b| b == b'\n').count() + 1;
        let bytes = self.content.len();
        let dirty_tag = if self.dirty { "Modified" } else { "Saved" };
        let toolbar = row([
            input(&self.path)
                .placeholder("/home/notes.txt")
                .width(Length::Fill)
                .on_change(Msg::PathChanged)
                .on_submit(Msg::Open),
            button("Open").on_press(Msg::Open),
            button("New").on_press(Msg::New),
            button("Save").primary().on_press(Msg::Save),
        ])
        .gap(8);

        let editor = textarea(&self.content)
            .placeholder("Type text here...")
            .on_change(Msg::ContentChanged);

        let footer = row([
            caption(&self.status).tone(if self.writable { Tone::Primary } else { Tone::Muted }),
            spacer(),
            caption(format!("{} line(s) | {} B | {}", lines, bytes, dirty_tag)),
        ])
        .gap(12);

        column([
            heading("Text Editor"),
            toolbar,
            divider(),
            editor,
            divider(),
            footer,
        ])
        .padding(12)
        .gap(8)
        .fill()
    }

    fn update(&mut self, msg: Msg) {
        match msg {
            Msg::PathChanged(p) => self.path = p,
            Msg::ContentChanged(s) => {
                self.content = s;
                self.dirty = true;
            }
            Msg::Open => self.open_file(),
            Msg::New => {
                self.content.clear();
                self.dirty = false;
                self.status = String::from("New empty document");
            }
            Msg::Save => self.save_file(),
        }
    }
}

pub fn main(s: *const Startup) -> i32 {
    // SAFETY: `s` is the startup block pointer passed by the kernel.
    if !unsafe { libd::init(s, "editor") } {
        return 1;
    }
    run_app("editor", EditorApp::new(), 0)
}
