//! Views: what an app's `view` function returns. A view is a tree of nodes built fresh from the
//! app's state every time it changes; the toolkit keeps what must persist between builds (focus,
//! hover, carets, scroll offsets, transitions) by each node's key, and redraws only nodes whose
//! appearance changed.
//!
//! ```ignore
//! column([
//!     heading("Settings"),
//!     checkbox("Reduce motion", state.reduce).on_toggle(Msg::Reduce),
//!     input(&state.name).placeholder("Your name").on_change(Msg::Name),
//!     row([spacer(), button("Save").primary().on_press(Msg::Save)]),
//! ]).padding(16).gap(12)
//! ```

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use crate::font_text::TextStyle;

/// Stable identity of a node between builds (automatic from its position unless set).
pub type Key = u64;

/// A size along one axis.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Length {
    /// As large as the content.
    Auto,
    /// Exactly this many pixels (at 100% text size; scaled with the text).
    Px(u32),
    /// Share the space left in the parent.
    Fill,
}

/// Placement of children across a container's main axis.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Align {
    Start,
    Center,
    End,
    /// Children take the container's whole cross size.
    Stretch,
}

/// Text colour roles.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tone {
    Primary,
    Muted,
    Accent,
    Danger,
    Ok,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ButtonKind {
    /// The main action: a Discrete Blue fill.
    Primary,
    /// Other actions: outlined.
    Secondary,
    /// Destructive actions: outlined, red text.
    Danger,
}

pub(crate) enum Kind<M> {
    Column,
    Row,
    /// A raised surface (cards, groups) laid out as a column.
    Panel,
    /// Its child scrolls vertically inside it.
    Scroll,
    Spacer,
    Divider,
    Text { text: String, style: TextStyle, tone: Tone, wrap: bool },
    Button { label: String, kind: ButtonKind, on_press: Option<M> },
    Checkbox { label: String, checked: bool, on_toggle: Option<M> },
    Toggle { label: String, on: bool, on_toggle: Option<M> },
    Slider { value: i32, min: i32, max: i32, step: i32, on_change: Option<Box<dyn Fn(i32) -> M>> },
    Input { value: String, placeholder: String, secret: bool, on_change: Option<Box<dyn Fn(String) -> M>>, on_submit: Option<M> },
    TextArea { value: String, placeholder: String, on_change: Option<Box<dyn Fn(String) -> M>> },
    Item { label: String, detail: String, selected: bool, on_select: Option<M>, on_activate: Option<M> },
    Progress { permille: u16 },
}

impl<M> Kind<M> {
    pub(crate) fn tag(&self) -> u8 {
        match self {
            Kind::Column => 1,
            Kind::Row => 2,
            Kind::Panel => 3,
            Kind::Scroll => 4,
            Kind::Spacer => 5,
            Kind::Divider => 6,
            Kind::Text { .. } => 7,
            Kind::Button { .. } => 8,
            Kind::Checkbox { .. } => 9,
            Kind::Toggle { .. } => 10,
            Kind::Slider { .. } => 11,
            Kind::Input { .. } => 12,
            Kind::Item { .. } => 13,
            Kind::Progress { .. } => 14,
            Kind::TextArea { .. } => 15,
        }
    }

    /// Keyboard focus can land here (and only where the app handles it).
    pub(crate) fn focusable(&self) -> bool {
        match self {
            Kind::Button { on_press, .. } => on_press.is_some(),
            Kind::Checkbox { on_toggle, .. } | Kind::Toggle { on_toggle, .. } => on_toggle.is_some(),
            Kind::Slider { on_change, .. } => on_change.is_some(),
            Kind::Input { on_change, .. } => on_change.is_some(),
            Kind::TextArea { on_change, .. } => on_change.is_some(),
            Kind::Item { on_select, on_activate, .. } => on_select.is_some() || on_activate.is_some(),
            _ => false,
        }
    }
}

/// A node of a view.
pub struct Node<M> {
    pub(crate) kind: Kind<M>,
    pub(crate) width: Length,
    pub(crate) height: Length,
    pub(crate) padding: u16,
    pub(crate) gap: u16,
    pub(crate) align: Align,
    pub(crate) key: Option<Key>,
    pub(crate) children: Vec<Node<M>>,
}

fn node<M>(kind: Kind<M>) -> Node<M> {
    Node { kind, width: Length::Auto, height: Length::Auto, padding: 0, gap: 0, align: Align::Start, key: None, children: Vec::new() }
}

fn container<M>(kind: Kind<M>, children: impl IntoIterator<Item = Node<M>>, align: Align) -> Node<M> {
    Node { children: children.into_iter().collect(), align, ..node(kind) }
}

/// Children top to bottom (stretched to its width by default).
pub fn column<M>(children: impl IntoIterator<Item = Node<M>>) -> Node<M> {
    container(Kind::Column, children, Align::Stretch)
}

/// Children left to right (vertically centred by default).
pub fn row<M>(children: impl IntoIterator<Item = Node<M>>) -> Node<M> {
    container(Kind::Row, children, Align::Center)
}

/// A raised surface holding a column.
pub fn panel<M>(children: impl IntoIterator<Item = Node<M>>) -> Node<M> {
    Node { padding: 16, gap: 10, ..container(Kind::Panel, children, Align::Stretch) }
}

/// A vertically scrolling area (give it `Length::Fill` or a fixed height).
pub fn scroll<M>(child: Node<M>) -> Node<M> {
    Node { height: Length::Fill, ..container(Kind::Scroll, [child], Align::Stretch) }
}

/// Space that grows (pushes siblings apart).
pub fn spacer<M>() -> Node<M> {
    Node { width: Length::Fill, height: Length::Fill, ..node(Kind::Spacer) }
}

/// A 1px separator line.
pub fn divider<M>() -> Node<M> {
    node(Kind::Divider)
}

fn text_node<M>(text: String, style: TextStyle, tone: Tone) -> Node<M> {
    node(Kind::Text { text, style, tone, wrap: false })
}

pub fn text<M>(s: impl Into<String>) -> Node<M> {
    text_node(s.into(), TextStyle::Body, Tone::Primary)
}

/// Secondary, smaller text.
pub fn caption<M>(s: impl Into<String>) -> Node<M> {
    text_node(s.into(), TextStyle::Small, Tone::Muted)
}

pub fn heading<M>(s: impl Into<String>) -> Node<M> {
    text_node(s.into(), TextStyle::Heading, Tone::Primary)
}

/// Emphasised label text.
pub fn label<M>(s: impl Into<String>) -> Node<M> {
    text_node(s.into(), TextStyle::Label, Tone::Primary)
}

/// Monospace text.
pub fn mono<M>(s: impl Into<String>) -> Node<M> {
    text_node(s.into(), TextStyle::Mono, Tone::Primary)
}

pub fn button<M>(label: impl Into<String>) -> Node<M> {
    node(Kind::Button { label: label.into(), kind: ButtonKind::Secondary, on_press: None })
}

pub fn checkbox<M>(label: impl Into<String>, checked: bool) -> Node<M> {
    node(Kind::Checkbox { label: label.into(), checked, on_toggle: None })
}

pub fn toggle<M>(label: impl Into<String>, on: bool) -> Node<M> {
    node(Kind::Toggle { label: label.into(), on, on_toggle: None })
}

pub fn slider<M>(value: i32, min: i32, max: i32) -> Node<M> {
    let (min, max) = (min.min(max), max.max(min));
    let step = ((max - min) / 20).max(1);
    Node { width: Length::Px(220), ..node(Kind::Slider { value: value.clamp(min, max), min, max, step, on_change: None }) }
}

/// A single-line text field showing `value` (the app keeps the text: `on_change` gets each edit).
pub fn input<M>(value: impl Into<String>) -> Node<M> {
    Node { width: Length::Px(260), ..node(Kind::Input { value: value.into(), placeholder: String::new(), secret: false, on_change: None, on_submit: None }) }
}

/// A multi-line monospace editor showing `value` (supports Enter, arrows, Home/End, scrolling).
pub fn textarea<M>(value: impl Into<String>) -> Node<M> {
    Node { width: Length::Fill, height: Length::Fill, ..node(Kind::TextArea { value: value.into(), placeholder: String::new(), on_change: None }) }
}

/// A selectable row of a list (supports single-click `on_select` and double-click/Enter `on_activate`).
pub fn item<M>(label: impl Into<String>, selected: bool) -> Node<M> {
    node(Kind::Item { label: label.into(), detail: String::new(), selected, on_select: None, on_activate: None })
}

/// Progress from 0 to 1000.
pub fn progress<M>(permille: u16) -> Node<M> {
    Node { width: Length::Px(220), ..node(Kind::Progress { permille: permille.min(1000) }) }
}

impl<M> Node<M> {
    pub fn padding(mut self, p: u16) -> Self {
        self.padding = p;
        self
    }
    pub fn gap(mut self, g: u16) -> Self {
        self.gap = g;
        self
    }
    pub fn width(mut self, w: Length) -> Self {
        self.width = w;
        self
    }
    pub fn height(mut self, h: Length) -> Self {
        self.height = h;
        self
    }
    /// Fill the space left in the parent along both axes.
    pub fn fill(mut self) -> Self {
        self.width = Length::Fill;
        self.height = Length::Fill;
        self
    }
    pub fn align(mut self, a: Align) -> Self {
        self.align = a;
        self
    }
    /// Identity across builds (for nodes whose position changes, like rows of a filtered list).
    pub fn key(mut self, k: Key) -> Self {
        self.key = Some(k);
        self
    }
    /// Text colour (text nodes).
    pub fn tone(mut self, t: Tone) -> Self {
        if let Kind::Text { tone, .. } = &mut self.kind {
            *tone = t;
        }
        self
    }
    /// Wrap text at the available width (text nodes).
    pub fn wrap(mut self) -> Self {
        if let Kind::Text { wrap, .. } = &mut self.kind {
            *wrap = true;
        }
        self
    }
    pub fn primary(mut self) -> Self {
        if let Kind::Button { kind, .. } = &mut self.kind {
            *kind = ButtonKind::Primary;
        }
        self
    }
    pub fn danger(mut self) -> Self {
        if let Kind::Button { kind, .. } = &mut self.kind {
            *kind = ButtonKind::Danger;
        }
        self
    }
    pub fn on_press(mut self, m: M) -> Self {
        if let Kind::Button { on_press, .. } = &mut self.kind {
            *on_press = Some(m);
        }
        self
    }
    pub fn on_toggle(mut self, m: M) -> Self {
        if let Kind::Checkbox { on_toggle, .. } | Kind::Toggle { on_toggle, .. } = &mut self.kind {
            *on_toggle = Some(m);
        }
        self
    }
    pub fn on_select(mut self, m: M) -> Self {
        if let Kind::Item { on_select, .. } = &mut self.kind {
            *on_select = Some(m);
        }
        self
    }
    /// Fired on double-click or Enter on a list row.
    pub fn on_activate(mut self, m: M) -> Self {
        if let Kind::Item { on_activate, .. } = &mut self.kind {
            *on_activate = Some(m);
        }
        self
    }
    pub fn on_submit(mut self, m: M) -> Self {
        if let Kind::Input { on_submit, .. } = &mut self.kind {
            *on_submit = Some(m);
        }
        self
    }
    pub fn on_change<F: Fn(String) -> M + 'static>(mut self, f: F) -> Self {
        match &mut self.kind {
            Kind::Input { on_change, .. } | Kind::TextArea { on_change, .. } => *on_change = Some(Box::new(f)),
            _ => {}
        }
        self
    }
    /// Mask typed characters in a text input (for passphrases).
    pub fn secret(mut self) -> Self {
        if let Kind::Input { secret, .. } = &mut self.kind {
            *secret = true;
        }
        self
    }
    pub fn on_slide<F: Fn(i32) -> M + 'static>(mut self, f: F) -> Self {
        if let Kind::Slider { on_change, .. } = &mut self.kind {
            *on_change = Some(Box::new(f));
        }
        self
    }
    pub fn step(mut self, s: i32) -> Self {
        if let Kind::Slider { step, .. } = &mut self.kind {
            *step = s.max(1);
        }
        self
    }
    pub fn placeholder(mut self, p: impl Into<String>) -> Self {
        match &mut self.kind {
            Kind::Input { placeholder, .. } | Kind::TextArea { placeholder, .. } => *placeholder = p.into(),
            _ => {}
        }
        self
    }
    /// Secondary text on the right of a list row.
    pub fn detail(mut self, d: impl Into<String>) -> Self {
        if let Kind::Item { detail, .. } = &mut self.kind {
            *detail = d.into();
        }
        self
    }
}
