//! The toolkit runtime: lays out an app's view, keeps the state that outlives a build (focus,
//! hover, carets, scroll offsets, transitions) by node key, turns keys and pointer events into
//! the app's messages, and repaints only what changed.
//!
//! Keyboard first (docs/ui.md): Tab / Shift+Tab move the focus through every control, Enter and
//! Space activate, arrows step sliders and move through lists, PgUp/PgDn scroll. A focus ring in
//! the accent tint shows where keyboard focus is (wider in High Contrast). Hover and press fade in
//! over ~110 ms unless motion is reduced.

use alloc::string::String;
use alloc::vec::Vec;

use dosawmi::{Canvas, DamageSet, Point, Rect, Theme, UiSettings};

use crate::font_text::{FontText, TextStyle};
use crate::view::{Align, ButtonKind, Key, Kind, Length, Node, Tone};

const TRANSITION_NS: u64 = 110_000_000;
const DOUBLE_CLICK_NS: u64 = 450_000_000;

/// Key values (`libd::proto::key`).
mod k {
    pub const UP: u32 = 0x101;
    pub const DOWN: u32 = 0x102;
    pub const LEFT: u32 = 0x103;
    pub const RIGHT: u32 = 0x104;
    pub const HOME: u32 = 0x105;
    pub const END: u32 = 0x106;
    pub const PAGE_UP: u32 = 0x107;
    pub const PAGE_DOWN: u32 = 0x108;
    pub const DELETE: u32 = 0x10A;
    pub const SHIFT: u32 = 1 << 16;
    pub const CTRL: u32 = 1 << 17;
    pub const ALT: u32 = 1 << 18;
    pub const SUPER: u32 = 1 << 19;
    pub const RELEASE: u32 = 1 << 20;
}

/// FNV-1a.
#[derive(Clone, Copy)]
struct H(u64);

impl H {
    const fn new() -> H {
        H(0xcbf2_9ce4_8422_2325)
    }
    fn bytes(mut self, b: &[u8]) -> H {
        for &x in b {
            self.0 ^= u64::from(x);
            self.0 = self.0.wrapping_mul(0x0100_0000_01b3);
        }
        self
    }
    fn u64(self, v: u64) -> H {
        self.bytes(&v.to_le_bytes())
    }
    fn rect(self, r: Rect) -> H {
        self.u64(u64::from(r.x as u32) | u64::from(r.y as u32) << 32).u64(u64::from(r.w) | u64::from(r.h) << 32)
    }
}

/// One laid-out node (preorder, parallel to the view's nodes).
#[derive(Clone, Copy)]
struct Laid {
    key: Key,
    rect: Rect,
    /// What of it can be seen (scroll viewports of its ancestors, the window).
    clip: Rect,
    parent: usize,
    tag: u8,
    focusable: bool,
    /// Hash of how it looks (its kind's data), without state.
    vis: u64,
    /// The last signature (vis + rect + state) it was painted with.
    sig: u64,
}

impl Laid {
    /// Where it can paint: its rectangle (with room for the focus ring), clipped.
    fn painted(&self) -> Rect {
        let r = if self.focusable { Rect::new(self.rect.x - 5, self.rect.y - 5, self.rect.w + 10, self.rect.h + 10) } else { self.rect };
        r.intersect(self.clip)
    }
}

const TAG_COLUMN: u8 = 1;
const TAG_ROW: u8 = 2;
const TAG_SCROLL: u8 = 4;

pub struct Ui<M> {
    root: Option<Node<M>>,
    laid: Vec<Laid>,
    damage: DamageSet,
    pub theme: Theme,
    pub settings: UiSettings,
    w: u32,
    h: u32,
    now: u64,
    focus: Option<Key>,
    /// The focus moved by keyboard (the ring shows); a click hides it.
    focus_visible: bool,
    window_focused: bool,
    hover: Option<Key>,
    pressed: Option<Key>,
    buttons: u8,
    carets: Vec<(Key, usize)>,
    scrolls: Vec<(Key, i32)>,
    content_h: Vec<(Key, u32)>,
    trans: Vec<(Key, u64)>,
    slider_drag: Option<Key>,
    last_click: Option<(Key, u64)>,
}

fn find<T: Copy>(v: &[(Key, T)], key: Key) -> Option<T> {
    v.iter().find(|e| e.0 == key).map(|e| e.1)
}

fn set<T: Copy>(v: &mut Vec<(Key, T)>, key: Key, val: T) {
    match v.iter_mut().find(|e| e.0 == key) {
        Some(e) => e.1 = val,
        None => v.push((key, val)),
    }
}

fn mix(a: u32, b: u32, t: u32) -> u32 {
    let t = t.min(255);
    let ch = |s: u32| {
        let (x, y) = ((a >> s) & 0xFF, (b >> s) & 0xFF);
        ((x * (255 - t) + y * t) / 255) << s
    };
    ch(24) | ch(16) | ch(8) | ch(0)
}

/// Fade `color` in from fully transparent without darkening its RGB channels toward black.
fn fade_alpha(color: u32, t: u32) -> u32 {
    let a = ((color >> 24) & 0xFF) * t.min(255) / 255;
    (color & 0x00FF_FFFF) | (a << 24)
}

fn flatten<'a, M>(n: &'a Node<M>, out: &mut Vec<&'a Node<M>>) {
    out.push(n);
    for c in &n.children {
        flatten(c, out);
    }
}

/// Layout context.
struct Cx<'a> {
    text: &'a FontText<'a>,
    scale: u32,
    scrolls: &'a [(Key, i32)],
    content_h: Vec<(Key, u32)>,
    out: Vec<Laid>,
}

impl Cx<'_> {
    fn s(&self, v: u32) -> u32 {
        v * self.scale / 100
    }

    fn lh(&self, st: TextStyle) -> u32 {
        self.text.line_height(st)
    }

    fn length(&self, l: Length, auto: u32, avail: u32) -> u32 {
        match l {
            Length::Auto => auto,
            Length::Px(v) => self.s(v),
            Length::Fill => avail.max(auto),
        }
    }

    /// The preferred size of `n` given `avail_w` pixels of width.
    fn measure<M>(&self, n: &Node<M>, avail_w: u32) -> (u32, u32) {
        let p = self.s(u32::from(n.padding));
        let g = self.s(u32::from(n.gap));
        let inner = avail_w.saturating_sub(p * 2);
        let (w, h) = match &n.kind {
            Kind::Column | Kind::Panel | Kind::Scroll => {
                let mut w = 0u32;
                let mut h = 0u32;
                for (i, c) in n.children.iter().enumerate() {
                    let (cw, ch) = self.measure(c, inner);
                    w = w.max(cw);
                    h += ch + if i > 0 { g } else { 0 };
                }
                (w + p * 2, h + p * 2)
            }
            Kind::Row => {
                let mut w = 0u32;
                let mut h = 0u32;
                for (i, c) in n.children.iter().enumerate() {
                    let (cw, ch) = self.measure(c, inner);
                    w += cw + if i > 0 { g } else { 0 };
                    h = h.max(ch);
                }
                (w + p * 2, h + p * 2)
            }
            Kind::Spacer => (0, 0),
            Kind::Divider => (0, 1),
            Kind::Text { text, style, wrap, .. } => {
                let lh = self.lh(*style);
                if *wrap {
                    let mut lines = Vec::new();
                    self.text.engine.wrap(self.text.style(*style), text, inner.max(1), &mut lines);
                    let w = lines.iter().map(|&(a, b)| self.text.width(*style, &text[a..b])).max().unwrap_or(0);
                    (w + p * 2, lh * lines.len().max(1) as u32 + p * 2)
                } else {
                    (self.text.width(*style, text) + p * 2, lh + p * 2)
                }
            }
            Kind::Button { label, .. } => (self.text.width(TextStyle::Label, label) + self.s(32), (self.lh(TextStyle::Label) + self.s(14)).max(self.s(32))),
            Kind::Checkbox { label, .. } => (self.s(24) + self.text.width(TextStyle::Body, label), self.lh(TextStyle::Body).max(self.s(16)) + self.s(10)),
            Kind::Toggle { label, .. } => (self.s(44) + self.text.width(TextStyle::Body, label), self.lh(TextStyle::Body).max(self.s(18)) + self.s(10)),
            Kind::Slider { .. } => (self.s(220), self.s(28)),
            Kind::Input { .. } => (self.s(260), self.lh(TextStyle::Body) + self.s(18)),
            Kind::TextArea { .. } => (self.s(360), self.lh(TextStyle::Mono) * 8 + self.s(16)),
            Kind::Item { label, detail, .. } => {
                (self.text.width(TextStyle::Body, label) + self.text.width(TextStyle::Small, detail) + self.s(48), self.lh(TextStyle::Body) + self.s(18))
            }
            Kind::Progress { .. } => (self.s(220), self.s(8)),
        };
        (self.length(n.width, w, 0), self.length(n.height, h, 0))
    }

    #[allow(clippy::too_many_arguments)]
    fn arrange<M>(&mut self, n: &Node<M>, rect: Rect, clip: Rect, parent: usize, parent_key: Key, idx: usize) {
        let key = n.key.unwrap_or_else(|| H::new().u64(parent_key).u64(idx as u64).u64(u64::from(n.kind.tag())).0);
        let me = self.out.len();
        self.out.push(Laid { key, rect, clip, parent, tag: n.kind.tag(), focusable: n.kind.focusable(), vis: visual_hash(n), sig: 0 });
        let p = self.s(u32::from(n.padding));
        let g = self.s(u32::from(n.gap)) as i32;
        let inner = rect.inset(p);
        match &n.kind {
            Kind::Column | Kind::Panel => {
                let sizes: Vec<(u32, u32)> = n.children.iter().map(|c| self.measure(c, inner.w)).collect();
                let fills = n.children.iter().filter(|c| c.height == Length::Fill).count() as u32;
                let fixed: u32 = n.children.iter().zip(&sizes).filter(|(c, _)| c.height != Length::Fill).map(|(_, s)| s.1).sum::<u32>()
                    + g.max(0) as u32 * n.children.len().saturating_sub(1) as u32;
                let extra = inner.h.saturating_sub(fixed);
                let mut y = inner.y;
                let mut left = fills;
                let mut pool = extra;
                for (i, (c, &(mw, mh))) in n.children.iter().zip(&sizes).enumerate() {
                    let ch = if c.height == Length::Fill {
                        let share = if left <= 1 { pool } else { extra / fills };
                        left = left.saturating_sub(1);
                        pool = pool.saturating_sub(share);
                        share
                    } else {
                        mh
                    };
                    let cw = match c.width {
                        Length::Fill => inner.w,
                        Length::Px(_) => mw.min(inner.w),
                        Length::Auto => if n.align == Align::Stretch { inner.w } else { mw.min(inner.w) },
                    };
                    let x = match n.align {
                        Align::Center => inner.x + (inner.w.saturating_sub(cw) / 2) as i32,
                        Align::End => inner.x + inner.w.saturating_sub(cw) as i32,
                        _ => inner.x,
                    };
                    self.arrange(c, Rect::new(x, y, cw, ch), clip, me, key, i);
                    y += ch as i32 + g;
                }
            }
            Kind::Row => {
                let sizes: Vec<(u32, u32)> = n.children.iter().map(|c| self.measure(c, inner.w)).collect();
                let fills = n.children.iter().filter(|c| c.width == Length::Fill).count() as u32;
                let fixed: u32 = n.children.iter().zip(&sizes).filter(|(c, _)| c.width != Length::Fill).map(|(_, s)| s.0).sum::<u32>()
                    + g.max(0) as u32 * n.children.len().saturating_sub(1) as u32;
                let extra = inner.w.saturating_sub(fixed);
                let mut x = inner.x;
                let mut left = fills;
                let mut pool = extra;
                for (i, (c, &(mw, mh))) in n.children.iter().zip(&sizes).enumerate() {
                    let cw = if c.width == Length::Fill {
                        let share = if left <= 1 { pool } else { extra / fills };
                        left = left.saturating_sub(1);
                        pool = pool.saturating_sub(share);
                        share
                    } else {
                        mw.min(inner.w)
                    };
                    let ch = match c.height {
                        Length::Fill => inner.h,
                        Length::Px(_) => mh.min(inner.h.max(mh)),
                        Length::Auto => if n.align == Align::Stretch { inner.h } else { mh },
                    };
                    let y = match n.align {
                        Align::Center => inner.y + (inner.h as i32 - ch as i32) / 2,
                        Align::End => inner.y + inner.h as i32 - ch as i32,
                        _ => inner.y,
                    };
                    self.arrange(c, Rect::new(x, y, cw, ch), clip, me, key, i);
                    x += cw as i32 + g;
                }
            }
            Kind::Scroll => {
                let content: u32 = n.children.iter().map(|c| self.measure(c, inner.w).1).max().unwrap_or(0).max(inner.h);
                set(&mut self.content_h, key, content);
                let max_off = content.saturating_sub(inner.h) as i32;
                let off = find(self.scrolls, key).unwrap_or(0).clamp(0, max_off);
                let view = clip.intersect(inner);
                for (i, c) in n.children.iter().enumerate() {
                    self.arrange(c, Rect::new(inner.x, inner.y - off, inner.w, content), view, me, key, i);
                }
            }
            _ => {}
        }
    }
}

fn visual_hash<M>(n: &Node<M>) -> u64 {
    let h = H::new().u64(u64::from(n.kind.tag()));
    match &n.kind {
        Kind::Text { text, style, tone, wrap } => h.bytes(text.as_bytes()).u64(*style as u64 | (*tone as u64) << 8 | u64::from(*wrap) << 16),
        Kind::Button { label, kind, on_press } => h.bytes(label.as_bytes()).u64(*kind as u64 | u64::from(on_press.is_some()) << 8),
        Kind::Checkbox { label, checked, .. } | Kind::Toggle { label, on: checked, .. } => h.bytes(label.as_bytes()).u64(u64::from(*checked)),
        Kind::Slider { value, min, max, .. } => h.u64(*value as u64).u64(*min as u64).u64(*max as u64),
        Kind::Input { value, placeholder, secret, .. } => h.bytes(value.as_bytes()).bytes(b"\0").bytes(placeholder.as_bytes()).u64(u64::from(*secret)),
        Kind::TextArea { value, placeholder, .. } => h.bytes(value.as_bytes()).bytes(b"\0").bytes(placeholder.as_bytes()),
        Kind::Item { label, detail, selected, .. } => h.bytes(label.as_bytes()).bytes(b"\0").bytes(detail.as_bytes()).u64(u64::from(*selected)),
        Kind::Progress { permille } => h.u64(u64::from(*permille)),
        _ => h,
    }
    .0
}

impl<M: Clone> Ui<M> {
    pub fn new(theme: Theme, settings: UiSettings) -> Ui<M> {
        Ui {
            root: None,
            laid: Vec::new(),
            damage: DamageSet::new(),
            theme,
            settings,
            w: 0,
            h: 0,
            now: 0,
            focus: None,
            focus_visible: false,
            window_focused: true,
            hover: None,
            pressed: None,
            buttons: 0,
            carets: Vec::new(),
            scrolls: Vec::new(),
            content_h: Vec::new(),
            trans: Vec::new(),
            slider_drag: None,
            last_click: None,
        }
    }

    pub fn size(&self) -> (u32, u32) {
        (self.w, self.h)
    }

    /// The current time (ns, monotonic): transitions advance with it.
    pub fn set_time(&mut self, now: u64) {
        self.now = now;
        if !self.trans.is_empty() {
            self.restyle();
            let now = self.now;
            let reduce = self.settings.reduce_motion;
            self.trans.retain(|&(_, t)| !reduce && now.saturating_sub(t) < TRANSITION_NS * 2);
        }
    }

    /// A transition is running: the app should draw again soon (on its next frame).
    pub fn animating(&self) -> bool {
        !self.settings.reduce_motion && self.trans.iter().any(|&(_, t)| self.now.saturating_sub(t) < TRANSITION_NS)
    }

    /// True when layout or state changes queued repaint damage not yet flushed by `paint()`.
    pub fn has_damage(&self) -> bool {
        !self.damage.is_empty()
    }

    /// New window size: everything is laid out and painted again.
    pub fn resize(&mut self, w: u32, h: u32, text: &FontText<'_>) {
        if (w, h) != (self.w, self.h) {
            self.w = w;
            self.h = h;
            self.relayout(text);
            self.damage_all();
        }
    }

    pub fn set_theme(&mut self, theme: Theme, settings: UiSettings, text: &FontText<'_>) {
        self.theme = theme;
        self.settings = settings;
        self.relayout(text);
        self.damage_all();
    }

    pub fn set_window_focus(&mut self, focused: bool) {
        if self.window_focused != focused {
            self.window_focused = focused;
            self.restyle();
        }
    }

    pub fn damage_all(&mut self) {
        self.damage.add(Rect::new(0, 0, self.w, self.h));
    }

    /// The app's new view (after its state changed).
    pub fn set_view(&mut self, view: Node<M>, text: &FontText<'_>) {
        self.root = Some(view);
        self.relayout(text);
    }

    fn relayout(&mut self, text: &FontText<'_>) {
        let Some(root) = self.root.as_ref() else { return };
        let window = Rect::new(0, 0, self.w, self.h);
        let mut cx = Cx { text, scale: u32::from(self.settings.text_scale), scrolls: &self.scrolls, content_h: Vec::new(), out: Vec::with_capacity(self.laid.len().max(16)) };
        cx.arrange(root, window, window, 0, 0x0D05, 0);
        let (content_h, out) = (cx.content_h, cx.out);
        self.content_h = content_h;
        let old = core::mem::replace(&mut self.laid, out);
        // Forget state of nodes that are gone; keep the focus on a node that still exists.
        let alive = |k: Key, l: &[Laid]| l.iter().any(|x| x.key == k);
        if self.focus.is_some_and(|f| !alive(f, &self.laid)) {
            self.focus = None;
        }
        if self.hover.is_some_and(|f| !alive(f, &self.laid)) {
            self.hover = None;
        }
        if self.last_click.is_some_and(|(k, _)| !alive(k, &self.laid)) {
            self.last_click = None;
        }
        let laid = &self.laid;
        self.carets.retain(|e| alive(e.0, laid));
        self.scrolls.retain(|e| alive(e.0, laid));
        self.compare(&old);
    }

    /// Signatures with the current state; damage where they differ from `old`.
    fn compare(&mut self, old: &[Laid]) {
        let theme_sig = {
            let mut b = [0u8; dosawmi::THEME_BYTES];
            self.theme.encode(&mut b);
            H::new().bytes(&b).u64(self.settings.pack()).u64(u64::from(self.window_focused)).0
        };
        for i in 0..self.laid.len() {
            let l = self.laid[i];
            let state = self.state_of(l.key);
            self.laid[i].sig = H::new().u64(l.vis).rect(l.rect).rect(l.clip).u64(state).u64(theme_sig).0;
        }
        for (i, l) in self.laid.iter().enumerate() {
            if l.tag == TAG_COLUMN || l.tag == TAG_ROW {
                continue; // transparent
            }
            let prev = old.get(i).filter(|o| o.key == l.key).or_else(|| old.iter().find(|o| o.key == l.key));
            match prev {
                Some(o) if o.sig == l.sig => {}
                Some(o) => {
                    self.damage.add(o.painted());
                    self.damage.add(l.painted());
                }
                None => self.damage.add(l.painted()),
            }
        }
        for o in old {
            if o.tag != TAG_COLUMN && o.tag != TAG_ROW && !self.laid.iter().any(|l| l.key == o.key) {
                self.damage.add(o.painted());
            }
        }
    }

    /// State flags in a node's signature.
    fn state_of(&self, key: Key) -> u64 {
        let focused = self.focus == Some(key) && self.window_focused;
        let mut s = u64::from(focused) | u64::from(focused && self.focus_visible) << 1 | u64::from(self.hover == Some(key)) << 2 | u64::from(self.pressed == Some(key)) << 3;
        s |= u64::from(self.hover_amount(key) / 16) << 8;
        if let Some(c) = find(&self.carets, key) {
            s |= (c as u64) << 16;
        }
        s
    }

    /// Recompute signatures after a state change (no relayout).
    fn restyle(&mut self) {
        let laid = core::mem::take(&mut self.laid);
        self.laid = laid.clone();
        self.compare(&laid);
    }

    /// 0-255: how far `key` is into its hover state.
    fn hover_amount(&self, key: Key) -> u32 {
        let on = self.hover == Some(key) || self.pressed == Some(key);
        let p = match find(&self.trans, key) {
            Some(t) if !self.settings.reduce_motion => (self.now.saturating_sub(t).min(TRANSITION_NS) * 255 / TRANSITION_NS) as u32,
            _ => 255,
        };
        if on { p } else { 255 - p }
    }

    fn set_hover(&mut self, key: Option<Key>) {
        if self.hover == key {
            return;
        }
        let now = self.now;
        if let Some(old) = self.hover {
            set(&mut self.trans, old, now);
        }
        if let Some(new) = key {
            set(&mut self.trans, new, now);
        }
        self.hover = key;
    }

    fn index_of(&self, key: Key) -> Option<usize> {
        self.laid.iter().position(|l| l.key == key)
    }

    fn focusables(&self) -> Vec<usize> {
        self.laid.iter().enumerate().filter(|(_, l)| l.focusable).map(|(i, _)| i).collect()
    }

    /// Move keyboard focus to the next (`dir` 1) or previous (-1) control.
    pub fn focus_next(&mut self, dir: i32, text: &FontText<'_>) {
        let f = self.focusables();
        if f.is_empty() {
            return;
        }
        let cur = self.focus.and_then(|k| self.index_of(k)).and_then(|i| f.iter().position(|&x| x == i));
        let next = match cur {
            None if dir > 0 => 0,
            None => f.len() - 1,
            Some(c) => (c as i32 + dir).rem_euclid(f.len() as i32) as usize,
        };
        self.focus = Some(self.laid[f[next]].key);
        self.focus_visible = true;
        self.scroll_into_view(f[next], text);
        self.restyle();
    }

    /// Scroll the scroll areas around node `i` so it is visible.
    fn scroll_into_view(&mut self, i: usize, text: &FontText<'_>) {
        let mut changed = false;
        let mut j = i;
        while j != 0 {
            let p = self.laid[j].parent;
            if self.laid[p].tag == TAG_SCROLL {
                let view = self.laid[p].rect;
                let r = self.laid[i].rect;
                let off = find(&self.scrolls, self.laid[p].key).unwrap_or(0);
                let mut n = off;
                if r.y < view.y {
                    n -= view.y - r.y + 4;
                } else if r.bottom() > view.bottom() {
                    n += (r.bottom() - view.bottom()) as i32 + 4;
                }
                if n != off {
                    set(&mut self.scrolls, self.laid[p].key, n.max(0));
                    changed = true;
                }
            }
            j = p;
        }
        if changed {
            self.relayout(text);
        }
    }

    fn scroll_by(&mut self, scroll_idx: usize, dy: i32, text: &FontText<'_>) {
        let key = self.laid[scroll_idx].key;
        let view_h = self.laid[scroll_idx].rect.h;
        let max = find(&self.content_h, key).unwrap_or(0).saturating_sub(view_h) as i32;
        let off = find(&self.scrolls, key).unwrap_or(0);
        let n = (off + dy).clamp(0, max.max(0));
        if n != off {
            set(&mut self.scrolls, key, n);
            self.relayout(text);
        }
    }

    /// A key from the compositor (`proto::key` value). The app's messages.
    pub fn key(&mut self, key: u32, text: &FontText<'_>) -> Vec<M> {
        let mut out = Vec::new();
        if key & k::RELEASE != 0 {
            return out;
        }
        let base = key & 0xFFFF;
        let shift = key & k::SHIFT != 0;
        let mods = key & (k::CTRL | k::ALT | k::SUPER);
        if base == 0x09 && mods == 0 {
            self.focus_next(if shift { -1 } else { 1 }, text);
            return out;
        }
        if (base == k::PAGE_UP || base == k::PAGE_DOWN) && mods == 0 {
            let sc = self.focus.and_then(|f| self.index_of(f)).and_then(|mut j| {
                while j != 0 {
                    j = self.laid[j].parent;
                    if self.laid[j].tag == TAG_SCROLL {
                        return Some(j);
                    }
                }
                None
            });
            if let Some(s) = sc.or_else(|| self.laid.iter().position(|l| l.tag == TAG_SCROLL)) {
                let page = self.laid[s].rect.h as i32 * 9 / 10;
                self.scroll_by(s, if base == k::PAGE_UP { -page } else { page }, text);
            }
            return out;
        }
        let Some(fi) = self.focus.and_then(|f| self.index_of(f)) else {
            if base == k::DOWN || base == k::UP {
                self.focus_next(if base == k::DOWN { 1 } else { -1 }, text);
            }
            return out;
        };
        let fkey = self.laid[fi].key;
        let root = self.root.take();
        let mut move_focus: Option<i32> = None;
        if let Some(root) = root.as_ref() {
            let mut nodes = Vec::new();
            flatten(root, &mut nodes);
            if let Some(n) = nodes.get(fi) {
                match &n.kind {
                    Kind::Button { on_press: Some(m), .. } if base == 0x0A || base == 0x0D || base == b' ' as u32 => out.push(m.clone()),
                    Kind::Checkbox { on_toggle: Some(m), .. } | Kind::Toggle { on_toggle: Some(m), .. } if base == 0x0A || base == 0x0D || base == b' ' as u32 => out.push(m.clone()),
                    Kind::Item { on_select, on_activate, .. } if base == 0x0A || base == 0x0D => {
                        if let Some(m) = on_activate.as_ref().or(on_select.as_ref()) {
                            out.push(m.clone());
                        }
                    }
                    Kind::Item { on_select: Some(m), .. } if base == b' ' as u32 => out.push(m.clone()),
                    Kind::Slider { value, min, max, step, on_change: Some(f) } => {
                        let v = match base {
                            k::LEFT | k::DOWN => Some(value - step),
                            k::RIGHT | k::UP => Some(value + step),
                            k::HOME => Some(*min),
                            k::END => Some(*max),
                            _ => None,
                        };
                        if let Some(v) = v.map(|v| v.clamp(*min, *max)).filter(|v| v != value) {
                            out.push(f(v));
                        }
                    }
                    Kind::Input { value, on_change: Some(f), on_submit, .. } => {
                        let caret = find(&self.carets, fkey).unwrap_or(value.len()).min(value.len());
                        let caret = (0..=caret).rev().find(|&i| value.is_char_boundary(i)).unwrap_or(0);
                        let prev = value[..caret].char_indices().last().map_or(0, |(i, _)| i);
                        let next = value[caret..].chars().next().map_or(caret, |c| caret + c.len_utf8());
                        let (new_val, new_caret): (Option<String>, usize) = match base {
                            0x0A | 0x0D => {
                                if let Some(m) = on_submit {
                                    out.push(m.clone());
                                }
                                (None, caret)
                            }
                            0x08 if caret > 0 => (Some([&value[..prev], &value[caret..]].concat()), prev),
                            k::DELETE if caret < value.len() => (Some([&value[..caret], &value[next..]].concat()), caret),
                            k::LEFT => (None, prev),
                            k::RIGHT => (None, next),
                            k::HOME | 0x01 => (None, 0),
                            k::END | 0x05 => (None, value.len()),
                            0x15 => (Some(String::from(&value[caret..])), 0), // Ctrl+U: clear to the start
                            0x20..=0x7E | 0xA0..=0xFF if mods == 0 && value.len() < 1024 => {
                                let ch = char::from_u32(base).unwrap_or('?');
                                let mut s = String::with_capacity(value.len() + ch.len_utf8());
                                s.push_str(&value[..caret]);
                                s.push(ch);
                                s.push_str(&value[caret..]);
                                (Some(s), caret + ch.len_utf8())
                            }
                            _ => (None, caret),
                        };
                        set(&mut self.carets, fkey, new_caret);
                        if let Some(v) = new_val {
                            out.push(f(v));
                        }
                    }
                    Kind::TextArea { value, on_change: Some(f), .. } => {
                        let caret = find(&self.carets, fkey).unwrap_or(value.len()).min(value.len());
                        let caret = (0..=caret).rev().find(|&i| value.is_char_boundary(i)).unwrap_or(0);
                        let prev = value[..caret].char_indices().last().map_or(0, |(i, _)| i);
                        let next = value[caret..].chars().next().map_or(caret, |c| caret + c.len_utf8());
                        let line_start = value[..caret].rfind('\n').map_or(0, |i| i + 1);
                        let line_end = value[caret..].find('\n').map_or(value.len(), |i| caret + i);
                        let col = value[line_start..caret].chars().count();
                        let (new_val, new_caret): (Option<String>, usize) = match base {
                            0x0A | 0x0D if mods == 0 && value.len() < 65536 => {
                                let mut s = String::with_capacity(value.len() + 1);
                                s.push_str(&value[..caret]);
                                s.push('\n');
                                s.push_str(&value[caret..]);
                                (Some(s), caret + 1)
                            }
                            0x08 if caret > 0 => (Some([&value[..prev], &value[caret..]].concat()), prev),
                            k::DELETE if caret < value.len() => (Some([&value[..caret], &value[next..]].concat()), caret),
                            k::LEFT => (None, prev),
                            k::RIGHT => (None, next),
                            k::HOME => (None, line_start),
                            k::END => (None, line_end),
                            k::UP => {
                                if line_start == 0 {
                                    (None, 0)
                                } else {
                                    let prev_end = line_start - 1;
                                    let prev_start = value[..prev_end].rfind('\n').map_or(0, |i| i + 1);
                                    let target = value[prev_start..prev_end]
                                        .char_indices()
                                        .nth(col)
                                        .map_or(prev_end, |(i, _)| prev_start + i);
                                    (None, target)
                                }
                            }
                            k::DOWN => {
                                if line_end >= value.len() {
                                    (None, value.len())
                                } else {
                                    let next_start = line_end + 1;
                                    let next_end = value[next_start..].find('\n').map_or(value.len(), |i| next_start + i);
                                    let target = value[next_start..next_end]
                                        .char_indices()
                                        .nth(col)
                                        .map_or(next_end, |(i, _)| next_start + i);
                                    (None, target)
                                }
                            }
                            0x20..=0x7E | 0xA0..=0xFF if mods == 0 && value.len() < 65536 => {
                                let ch = char::from_u32(base).unwrap_or('?');
                                let mut s = String::with_capacity(value.len() + ch.len_utf8());
                                s.push_str(&value[..caret]);
                                s.push(ch);
                                s.push_str(&value[caret..]);
                                (Some(s), caret + ch.len_utf8())
                            }
                            _ => (None, caret),
                        };
                        set(&mut self.carets, fkey, new_caret);
                        if let Some(v) = new_val {
                            out.push(f(v));
                        }
                    }
                    _ => {}
                }
                // Arrows move through lists and between plain controls.
                let moves = matches!(n.kind, Kind::Item { .. } | Kind::Button { .. } | Kind::Checkbox { .. } | Kind::Toggle { .. });
                if moves && (base == k::DOWN || base == k::UP) && mods == 0 {
                    move_focus = Some(if base == k::DOWN { 1 } else { -1 });
                }
            }
        }
        self.root = root;
        match move_focus {
            Some(dir) => self.focus_next(dir, text),
            None => self.restyle(),
        }
        out
    }

    /// Pointer input in window coordinates. The app's messages.
    pub fn pointer(&mut self, x: i32, y: i32, buttons: u8, wheel: i8, text: &FontText<'_>) -> Vec<M> {
        let mut out = Vec::new();
        let p = Point::new(x, y);
        let prev = self.buttons;
        self.buttons = buttons;
        let down = buttons & 1 != 0 && prev & 1 == 0;
        let up = buttons & 1 == 0 && prev & 1 != 0;
        let visible = |l: &Laid| l.rect.intersect(l.clip).contains_point(p);
        let target = self.laid.iter().rposition(|l| l.focusable && visible(l));
        if wheel != 0 {
            if let Some(s) = self.laid.iter().rposition(|l| l.tag == TAG_SCROLL && visible(l)) {
                let step = (self.text_line(text) * 3) as i32;
                self.scroll_by(s, -i32::from(wheel) * step, text);
            }
            return out;
        }
        self.set_hover(target.map(|i| self.laid[i].key));
        let root = self.root.take();
        if let Some(root) = root.as_ref() {
            let mut nodes = Vec::new();
            flatten(root, &mut nodes);
            // Dragging a slider follows the pointer.
            let drag = self.slider_drag.and_then(|kk| self.index_of(kk));
            let act = if down { target } else { drag };
            if let Some(i) = act
                && let Some(n) = nodes.get(i)
            {
                let l = self.laid[i];
                if down {
                    self.pressed = Some(l.key);
                    self.focus = Some(l.key);
                    self.focus_visible = false;
                }
                match &n.kind {
                    Kind::Slider { value, min, max, step, on_change: Some(f) } if buttons & 1 != 0 => {
                        self.slider_drag = Some(l.key);
                        let pad = (l.rect.h / 2) as i32;
                        let tw = (l.rect.w as i32 - pad * 2).max(1);
                        let rel = (x - l.rect.x - pad).clamp(0, tw);
                        let span = (max - min).max(1);
                        let raw = min + (rel * span + tw / 2) / tw;
                        let v = (min + ((raw - min + step / 2) / step) * step).clamp(*min, *max);
                        if v != *value {
                            out.push(f(v));
                        }
                    }
                    Kind::Input { value, secret, .. } if down => {
                        let st = text.style(TextStyle::Body);
                        let pad = (8 * u32::from(self.settings.text_scale) / 100) as i32;
                        let masked;
                        let shown = if *secret {
                            masked = "*".repeat(value.chars().count());
                            masked.as_str()
                        } else {
                            value.as_str()
                        };
                        let i = text.engine.index_at(st, shown, x - l.rect.x - pad);
                        let idx = if *secret {
                            value.char_indices().nth(i).map_or(value.len(), |(b, _)| b)
                        } else {
                            i
                        };
                        set(&mut self.carets, l.key, idx);
                    }
                    Kind::TextArea { value, .. } if down => {
                        let st = text.style(TextStyle::Mono);
                        let pad = (8 * u32::from(self.settings.text_scale) / 100) as i32;
                        let lh = text.line_height(TextStyle::Mono).max(12) as i32;
                        let scroll_y = find(&self.scrolls, l.key).unwrap_or(0);
                        let target_line = ((y - l.rect.y - pad + scroll_y).max(0) / lh) as usize;
                        let mut off = 0usize;
                        let mut chosen = value.len();
                        for (cur_line, line) in value.split('\n').enumerate() {
                            if cur_line == target_line {
                                let col_b = text.engine.index_at(st, line, x - l.rect.x - pad);
                                chosen = (off + col_b).min(value.len());
                                break;
                            }
                            off += line.len() + 1;
                        }
                        set(&mut self.carets, l.key, chosen);
                    }
                    _ => {}
                }
            }
            if up {
                self.slider_drag = None;
                if let (Some(pk), Some(t)) = (self.pressed.take(), target)
                    && self.laid[t].key == pk
                    && let Some(n) = nodes.get(t)
                {
                    match &n.kind {
                        Kind::Button { on_press: Some(m), .. } => {
                            self.last_click = None;
                            out.push(m.clone());
                        }
                        Kind::Checkbox { on_toggle: Some(m), .. } | Kind::Toggle { on_toggle: Some(m), .. } => {
                            self.last_click = None;
                            out.push(m.clone());
                        }
                        Kind::Item { on_select, on_activate, .. } => {
                            let is_double = self
                                .last_click
                                .is_some_and(|(k, t)| k == pk && self.now.saturating_sub(t) <= DOUBLE_CLICK_NS);
                            if is_double && let Some(m) = on_activate {
                                self.last_click = None;
                                out.push(m.clone());
                            } else {
                                self.last_click = Some((pk, self.now));
                                if let Some(m) = on_select {
                                    out.push(m.clone());
                                }
                            }
                        }
                        _ => self.last_click = None,
                    }
                }
            }
        }
        if up {
            self.pressed = None;
        }
        self.root = root;
        self.restyle();
        out
    }

    fn text_line(&self, text: &FontText<'_>) -> u32 {
        text.line_height(TextStyle::Body).max(12)
    }

    /// Paint what changed; the damaged rectangles (window coordinates) to commit.
    pub fn paint(&mut self, canvas: &mut Canvas<'_>, text: &mut FontText<'_>) -> DamageSet {
        let damage = core::mem::take(&mut self.damage);
        let Some(root) = self.root.as_ref() else { return damage };
        let mut nodes = Vec::new();
        flatten(root, &mut nodes);
        let win = Rect::new(0, 0, self.w, self.h);
        for &r in damage.as_slice() {
            let r = r.intersect(win);
            if r.is_empty() {
                continue;
            }
            canvas.fill_rect(r, r, self.theme.client_bg);
            for (i, l) in self.laid.iter().enumerate() {
                let clip = r.intersect(l.clip);
                if clip.intersect(l.painted()).is_empty() {
                    continue;
                }
                if let Some(n) = nodes.get(i) {
                    self.paint_node(canvas, text, n, l, clip);
                }
            }
        }
        damage
    }

    fn paint_node(&self, c: &mut Canvas<'_>, text: &mut FontText<'_>, n: &Node<M>, l: &Laid, clip: Rect) {
        let t = &self.theme;
        let r = l.rect;
        let s = |v: u32| v * u32::from(self.settings.text_scale) / 100;
        let mid = r.y + (r.h / 2) as i32;
        let focused = self.focus == Some(l.key) && self.window_focused;
        let ring = focused && self.focus_visible;
        let hov = self.hover_amount(l.key);
        let pressed = self.pressed == Some(l.key);
        match &n.kind {
            Kind::Panel => c.fill_rounded_rect(clip, r, t.radius + 2, t.surface_raised, t.border_inactive),
            Kind::Divider => c.fill_rect(clip, Rect::new(r.x, mid, r.w, 1), t.border_inactive),
            Kind::Text { text: s_txt, style, tone, wrap } => {
                let col = match tone {
                    Tone::Primary => t.text_primary,
                    Tone::Muted => t.text_muted,
                    Tone::Accent => t.accent_ring,
                    Tone::Danger => t.ind_alert_red,
                    Tone::Ok => t.status_ok,
                };
                let p = s(u32::from(n.padding)) as i32;
                if *wrap {
                    let lh = text.line_height(*style) as i32;
                    let st = text.style(*style);
                    let mut lines = Vec::new();
                    text.engine.wrap(st, s_txt, r.w.saturating_sub(p as u32 * 2).max(1), &mut lines);
                    let asc = text.metrics(*style).ascent;
                    for (k, &(a, b)) in lines.iter().enumerate() {
                        text.draw_at(c, clip, r.x + p, r.y + p + k as i32 * lh + asc, &s_txt[a..b], st, col, r.w);
                    }
                } else {
                    text.draw_str(c, clip, r.x + p, mid, s_txt, *style, col, r.w.saturating_sub(p as u32 * 2));
                }
            }
            Kind::Button { label, kind, on_press } => {
                let enabled = on_press.is_some();
                let (fill, border, fg) = match kind {
                    ButtonKind::Primary => {
                        let base = if pressed { t.accent_pressed } else { mix(t.accent, t.accent_hover, hov) };
                        (base, 0, t.text_on_accent)
                    }
                    ButtonKind::Secondary => (fade_alpha(t.btn_hover, hov), t.border_active, t.text_primary),
                    ButtonKind::Danger => (fade_alpha(t.btn_hover, hov), t.ind_alert_red, t.ind_alert_red),
                };
                let fg = if enabled { fg } else { t.text_muted };
                c.fill_rounded_rect(clip, r, t.radius, fill, border);
                let tw = text.width(TextStyle::Label, label).min(r.w.saturating_sub(s(16)));
                text.draw_str(c, clip, r.x + (r.w.saturating_sub(tw) / 2) as i32, mid, label, TextStyle::Label, fg, r.w.saturating_sub(s(16)));
            }
            Kind::Checkbox { label, checked, .. } => {
                let b = s(16);
                let bx = Rect::new(r.x + 1, mid - (b / 2) as i32, b, b);
                if *checked {
                    c.fill_rounded_rect(clip, bx, 3, mix(t.accent, t.accent_hover, hov), 0);
                    // The check mark.
                    let (x0, y0) = (bx.x + (b * 3 / 16) as i32, bx.y + (b / 2) as i32);
                    for d in 0..(b / 4) as i32 {
                        c.fill_rect(clip, Rect::new(x0 + d, y0 + d, 2, 2), t.text_on_accent);
                    }
                    let (x1, y1) = (x0 + (b / 4) as i32, y0 + (b / 4) as i32);
                    for d in 0..(b / 2) as i32 {
                        c.fill_rect(clip, Rect::new(x1 + d, y1 - d, 2, 2), t.text_on_accent);
                    }
                } else {
                    c.fill_rounded_rect(clip, bx, 3, t.input_bg, mix(t.text_muted, t.text_primary, hov));
                }
                text.draw_str(c, clip, r.x + s(24) as i32, mid, label, TextStyle::Body, t.text_primary, r.w.saturating_sub(s(24)));
            }
            Kind::Toggle { label, on, .. } => {
                let (tw, th) = (s(34), s(18));
                let track = Rect::new(r.x + 1, mid - (th / 2) as i32, tw, th);
                let fill = if *on { mix(t.accent, t.accent_hover, hov) } else { mix(t.border_inactive, t.border_active, hov) };
                c.fill_rounded_rect(clip, track, th / 2, fill, if *on { 0 } else { t.border_active });
                let kr = (th / 2).saturating_sub(3) as i32;
                let kx = if *on { track.x + tw as i32 - kr - 4 } else { track.x + kr + 4 };
                c.fill_circle(clip, kx, mid, kr, if *on { t.text_on_accent } else { t.text_primary });
                text.draw_str(c, clip, r.x + s(44) as i32, mid, label, TextStyle::Body, t.text_primary, r.w.saturating_sub(s(44)));
            }
            Kind::Slider { value, min, max, .. } => {
                let pad = (r.h / 2) as i32;
                let tw = (r.w as i32 - pad * 2).max(1);
                let span = (max - min).max(1);
                let pos = (value - min) * tw / span;
                c.fill_rounded_rect(clip, Rect::new(r.x + pad, mid - 2, tw as u32, 4), 2, t.border_inactive, 0);
                c.fill_rounded_rect(clip, Rect::new(r.x + pad, mid - 2, pos.max(0) as u32, 4), 2, t.accent, 0);
                let kr = (s(7) + hov / 128) as i32;
                if ring || focused {
                    c.fill_circle(clip, r.x + pad + pos, mid, kr + 3, t.accent_ring);
                }
                c.fill_circle(clip, r.x + pad + pos, mid, kr, t.text_primary);
            }
            Kind::Input { value, placeholder, secret, .. } => {
                let border = if focused { t.accent_ring } else { mix(t.border_inactive, t.border_active, hov) };
                c.fill_rounded_rect(clip, r, t.radius, t.input_bg, border);
                if focused && t.focus_ring > 1 {
                    c.fill_rounded_rect(clip, r.inset(1), t.radius.saturating_sub(1), 0, border);
                }
                let pad = s(8) as i32;
                let inner = Rect::new(r.x + pad, r.y, r.w.saturating_sub(pad as u32 * 2), r.h).intersect(clip);
                let st = text.style(TextStyle::Body);
                let caret = find(&self.carets, l.key).unwrap_or(value.len()).min(value.len());
                let masked;
                let (shown, shown_caret) = if *secret {
                    masked = "*".repeat(value.chars().count());
                    let cc = value[..caret].chars().count();
                    (masked.as_str(), cc)
                } else {
                    (value.as_str(), caret)
                };
                let mut carets = Vec::new();
                text.engine.caret_positions(st, shown, &mut carets);
                let cx = (carets.iter().find(|e| e.0 >= shown_caret).map_or(0, |e| e.1) / 64) as i32;
                let shift = (cx - inner.w as i32 + 4).max(0);
                if shown.is_empty() {
                    text.draw_str(c, inner, r.x + pad, mid, placeholder, TextStyle::Body, t.text_muted, inner.w);
                } else {
                    let m = text.metrics(TextStyle::Body);
                    text.engine.draw(
                        &mut dosfont::Target { px: &mut *c.pixels, w: c.width, h: c.height, stride: c.stride_px },
                        dosfont::Clip::new(inner.x, inner.y, inner.w, inner.h),
                        r.x + pad - shift,
                        mid + (m.ascent - m.descent) / 2,
                        st,
                        shown,
                        t.text_primary,
                        i32::MAX,
                    );
                }
                if focused {
                    let lh = text.line_height(TextStyle::Body) as i32;
                    c.fill_rect(inner, Rect::new(r.x + pad + cx - shift, mid - lh / 2 + 1, 2, (lh - 2).max(2) as u32), t.accent_ring);
                }
            }
            Kind::TextArea { value, placeholder, .. } => {
                let border = if focused { t.accent_ring } else { mix(t.border_inactive, t.border_active, hov) };
                c.fill_rounded_rect(clip, r, t.radius, t.input_bg, border);
                if focused && t.focus_ring > 1 {
                    c.fill_rounded_rect(clip, r.inset(1), t.radius.saturating_sub(1), 0, border);
                }
                let pad = s(8) as i32;
                let inner = Rect::new(r.x + pad, r.y + pad, r.w.saturating_sub(pad as u32 * 2), r.h.saturating_sub(pad as u32 * 2)).intersect(clip);
                let st = text.style(TextStyle::Mono);
                let lh = text.line_height(TextStyle::Mono).max(12) as i32;
                let asc = text.metrics(TextStyle::Mono).ascent;
                let caret = find(&self.carets, l.key).unwrap_or(value.len()).min(value.len());
                let caret_line = value[..caret].bytes().filter(|&b| b == b'\n').count() as i32;
                let vis_lines = (inner.h as i32 / lh).max(1);
                let first_line = (caret_line - vis_lines + 1).max(0);
                if value.is_empty() && !placeholder.is_empty() {
                    text.draw_at(c, inner, r.x + pad, r.y + pad + asc, placeholder, st, t.text_muted, inner.w);
                } else {
                    let mut off = 0usize;
                    for (idx, line) in value.split('\n').enumerate() {
                        let li = idx as i32;
                        if li >= first_line && li < first_line + vis_lines + 1 {
                            let y_top = r.y + pad + (li - first_line) * lh;
                            text.draw_at(c, inner, r.x + pad, y_top + asc, line, st, t.text_primary, inner.w);
                            if focused && caret >= off && caret <= off + line.len() {
                                let local_c = caret - off;
                                let mut carets = Vec::new();
                                text.engine.caret_positions(st, line, &mut carets);
                                let cx = (carets.iter().find(|e| e.0 >= local_c).map_or(0, |e| e.1) / 64) as i32;
                                c.fill_rect(inner, Rect::new(r.x + pad + cx, y_top + 1, 2, (lh - 2).max(2) as u32), t.accent_ring);
                            }
                        }
                        off += line.len() + 1;
                    }
                }
            }
            Kind::Item { label, detail, selected, .. } => {
                let (fill, fg, muted) = if *selected {
                    (mix(t.accent, t.accent_hover, hov), t.text_on_accent, t.text_on_accent)
                } else {
                    (fade_alpha(t.btn_hover, hov), t.text_primary, t.text_muted)
                };
                c.fill_rounded_rect(clip, r, t.radius, fill, 0);
                let pad = s(12) as i32;
                let dw = text.width(TextStyle::Small, detail).min(r.w / 2);
                text.draw_str(c, clip, r.x + pad, mid, label, TextStyle::Body, fg, r.w.saturating_sub(pad as u32 * 2 + dw + 8));
                if dw > 0 {
                    text.draw_str(c, clip, r.x + r.w as i32 - pad - dw as i32, mid, detail, TextStyle::Small, muted, dw);
                }
            }
            Kind::Progress { permille } => {
                c.fill_rounded_rect(clip, r, r.h / 2, t.border_inactive, 0);
                let w = r.w * u32::from(*permille) / 1000;
                if w > 0 {
                    c.fill_rounded_rect(clip, Rect::new(r.x, r.y, w, r.h), r.h / 2, t.accent, 0);
                }
            }
            _ => {}
        }
        if ring && !matches!(n.kind, Kind::Input { .. } | Kind::TextArea { .. } | Kind::Slider { .. }) {
            let w = t.focus_ring.max(1);
            let out = w as i32 + 1;
            let o = Rect::new(r.x - out, r.y - out, r.w + 2 * out as u32, r.h + 2 * out as u32);
            for i in 0..w {
                c.fill_rounded_rect(clip, o.inset(i), t.radius + 3 - i.min(3), 0, t.accent_ring);
            }
        }
    }
}
