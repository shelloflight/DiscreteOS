//! `FontText`: the vector text engine (`dosfont`) at the user's text scale, as the compositor's
//! chrome text (`dosawmi::TextRender`) and the toolkit's text. Text that does not fit is cut with
//! an ellipsis.

use alloc::string::String;
use alloc::vec::Vec;

use dosawmi::{Canvas, Rect, TextRender, TextRole};
use dosfont::{Clip, Face, LineMetrics, Style, Target, Text};

/// The type scale (base sizes at 100%).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TextStyle {
    /// Interface text: 13 px Inter.
    Body,
    /// Secondary text: 12 px.
    Small,
    /// Labels, buttons, titles: 13 px Inter Medium.
    Label,
    /// Search fields: 16 px.
    Large,
    /// Headings: 20 px Inter SemiBold.
    Heading,
    /// Terminal and code: 14 px Iosevka Term.
    Mono,
    /// Icons (Nerd Font symbols, one monospace cell wide): 26 px Iosevka Term, about 13 px wide.
    Icon,
}

impl TextStyle {
    const fn base(self) -> (Face, u32) {
        match self {
            TextStyle::Body => (Face::Sans, 13),
            TextStyle::Small => (Face::Sans, 12),
            TextStyle::Label => (Face::SansMedium, 13),
            TextStyle::Large => (Face::Sans, 16),
            TextStyle::Heading => (Face::SansSemiBold, 20),
            TextStyle::Mono => (Face::Mono, 14),
            TextStyle::Icon => (Face::Mono, 26),
        }
    }

    pub const fn from_role(r: TextRole) -> TextStyle {
        match r {
            TextRole::Body => TextStyle::Body,
            TextRole::Small => TextStyle::Small,
            TextRole::Title => TextStyle::Label,
            TextRole::Large => TextStyle::Large,
            TextRole::Icon => TextStyle::Icon,
        }
    }
}

pub struct FontText<'a> {
    pub engine: Text<'a>,
    /// Text size in percent (the user's setting).
    pub scale: u16,
    carets: Vec<(usize, i64)>,
}

/// A canvas as a text target.
fn target<'c>(c: &'c mut Canvas<'_>) -> Target<'c> {
    Target { px: &mut *c.pixels, w: c.width, h: c.height, stride: c.stride_px }
}

fn clip_of(r: Rect) -> Clip {
    Clip::new(r.x, r.y, r.w, r.h)
}

impl<'a> FontText<'a> {
    pub fn new(engine: Text<'a>, scale: u16) -> FontText<'a> {
        FontText { engine, scale: scale.clamp(50, 400), carets: Vec::new() }
    }

    pub fn style(&self, s: TextStyle) -> Style {
        let (face, px) = s.base();
        Style { face, size64: px * 64 * u32::from(self.scale) / 100 }
    }

    pub fn metrics(&self, s: TextStyle) -> LineMetrics {
        self.engine.metrics(self.style(s))
    }

    pub fn line_height(&self, s: TextStyle) -> u32 {
        self.metrics(s).height.max(1) as u32
    }

    pub fn width(&self, s: TextStyle, text: &str) -> u32 {
        self.engine.measure(self.style(s), text)
    }

    /// Draw `text` vertically centred on `y_mid`, cut with an ellipsis past `max_w`.
    #[allow(clippy::too_many_arguments)]
    pub fn draw_str(&mut self, canvas: &mut Canvas<'_>, clip: Rect, x: i32, y_mid: i32, text: &str, s: TextStyle, color: u32, max_w: u32) -> u32 {
        let st = self.style(s);
        let m = self.engine.metrics(st);
        let baseline = y_mid + (m.ascent - m.descent) / 2;
        self.draw_at(canvas, clip, x, baseline, text, st, color, max_w)
    }

    /// Draw `text` with its baseline at `baseline`, cut with an ellipsis past `max_w`.
    #[allow(clippy::too_many_arguments)]
    pub fn draw_at(&mut self, canvas: &mut Canvas<'_>, clip: Rect, x: i32, baseline: i32, text: &str, st: Style, color: u32, max_w: u32) -> u32 {
        let full = self.engine.measure(st, text);
        let right = x.saturating_add(max_w as i32);
        if full <= max_w {
            return self.engine.draw(&mut target(canvas), clip_of(clip), x, baseline, st, text, color, right);
        }
        // Longest prefix that fits with the ellipsis.
        let ell = "\u{2026}";
        let ew = i64::from(self.engine.measure(st, ell)) * 64;
        let limit = i64::from(max_w) * 64 - ew;
        let mut carets = core::mem::take(&mut self.carets);
        self.engine.caret_positions(st, text, &mut carets);
        let cut = carets.iter().take_while(|&&(_, p)| p <= limit).last().map_or(0, |&(i, _)| i);
        self.carets = carets;
        let mut s = String::with_capacity(cut + 3);
        s.push_str(text[..cut].trim_end());
        s.push_str(ell);
        self.engine.draw(&mut target(canvas), clip_of(clip), x, baseline, st, &s, color, right)
    }

    /// One character in a monospace cell (the terminal).
    #[allow(clippy::too_many_arguments)]
    pub fn draw_cell(&mut self, canvas: &mut Canvas<'_>, clip: Rect, x: i32, baseline: i32, st: Style, c: char, color: u32) {
        self.engine.draw_char(&mut target(canvas), clip_of(clip), x, baseline, st, c, color);
    }
}

impl TextRender for FontText<'_> {
    fn draw(&mut self, canvas: &mut Canvas<'_>, clip: Rect, x: i32, y_mid: i32, text: &[u8], role: TextRole, color: u32, max_w: u32) -> u32 {
        let s = String::from_utf8_lossy(text);
        self.draw_str(canvas, clip, x, y_mid, &s, TextStyle::from_role(role), color, max_w)
    }

    fn measure(&mut self, text: &[u8], role: TextRole) -> u32 {
        let s = String::from_utf8_lossy(text);
        self.width(TextStyle::from_role(role), &s)
    }

    fn line_height(&self, role: TextRole) -> u32 {
        FontText::line_height(self, TextStyle::from_role(role))
    }

    fn icons(&self) -> bool {
        self.engine.has_face(Face::Mono)
    }
}
