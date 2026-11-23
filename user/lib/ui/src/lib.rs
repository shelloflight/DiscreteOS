//! `dosui`: D-OS's native UI toolkit (docs/ui.md). Pure `no_std`, `#![forbid(unsafe_code)]`,
//! zero external crates.
//!
//! An app is declarative: `view(&state) -> Node<Msg>` builds the interface from its state
//! (`view.rs`), `update(&mut state, msg)` handles what the user did. The runtime (`ui.rs`) lays the
//! view out, keeps focus, hover, carets, scroll offsets and transitions between builds by node key,
//! turns keys and pointer events into messages, and repaints only the nodes whose look changed.
//! Themes and the text size come from the compositor; text is drawn with the shipped faces
//! (`font_text.rs`, `fonts.rs`).

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod font_text;
pub mod fonts;
pub mod ui;
pub mod view;

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests;

pub use font_text::{FontText, TextStyle};
pub use ui::Ui;
pub use view::{Align, ButtonKind, Key, Length, Node, Tone, button, caption, checkbox, column, divider, heading, input, item, label, mono, panel, progress, row, scroll, slider, spacer, text, textarea, toggle};
