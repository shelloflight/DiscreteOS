//! Text drawing for the window chrome, the dock and the launcher, behind a trait: the compositor
//! service passes in its vector font engine (`dosui::FontText`, anti-aliased Inter with the
//! user's text scale); without fonts (or in host tests) the built-in 8x16 bitmap font draws.
//! This keeps `dosawmi` free of allocation and of the font engine itself.

use crate::font::{GLYPH_H, GLYPH_W};
use crate::geom::Rect;
use crate::pixel::Canvas;

/// What a piece of chrome text is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TextRole {
    /// Ordinary interface text (dock labels, launcher rows).
    Body,
    /// Smaller secondary text (identities in the launcher, hints).
    Small,
    /// Window titles and emphasised labels (medium weight).
    Title,
    /// The launcher's search field (larger).
    Large,
    /// A symbol from the monospace face's icon set (`icons()`), sized like an interface icon.
    Icon,
}

/// Measures and draws single lines of text.
pub trait TextRender {
    /// Draw `text` (UTF-8; anything else shows as replacement characters) starting at `x`,
    /// vertically centred on `y_mid`, clipped to `clip` and to `max_w` pixels (an ellipsis marks
    /// cut text where the engine can). The width drawn.
    #[allow(clippy::too_many_arguments)]
    fn draw(&mut self, canvas: &mut Canvas<'_>, clip: Rect, x: i32, y_mid: i32, text: &[u8], role: TextRole, color: u32, max_w: u32) -> u32;
    /// Width of `text` in pixels.
    fn measure(&mut self, text: &[u8], role: TextRole) -> u32;
    /// Height of a line in pixels.
    fn line_height(&self, role: TextRole) -> u32;
    /// The engine can draw icon glyphs (Nerd Font code points); otherwise labels use words.
    fn icons(&self) -> bool {
        false
    }
}

/// The built-in 8x16 bitmap font (ASCII).
#[derive(Clone, Copy, Debug, Default)]
pub struct BitmapText;

impl TextRender for BitmapText {
    fn draw(&mut self, canvas: &mut Canvas<'_>, clip: Rect, x: i32, y_mid: i32, text: &[u8], _role: TextRole, color: u32, max_w: u32) -> u32 {
        canvas.draw_text(clip, x, y_mid - (GLYPH_H / 2) as i32, text, color, max_w)
    }

    fn measure(&mut self, text: &[u8], _role: TextRole) -> u32 {
        text.len() as u32 * GLYPH_W
    }

    fn line_height(&self, _role: TextRole) -> u32 {
        GLYPH_H
    }
}
