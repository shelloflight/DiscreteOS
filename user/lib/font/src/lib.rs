//! `dosfont`: pure `no_std`, `#![forbid(unsafe_code)]`, zero-dependency TrueType font engine for
//! D-OS (docs/ui.md): parsing (`ttf`), outlines (`glyph`), integer anti-aliasing (`raster`), text
//! layout and the glyph cache (`text`), and subsetting (`subset`, used by `dbuild font-subset`).

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod glyph;
pub mod raster;
pub mod subset;
pub mod text;
pub mod ttf;

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests;

pub use raster::Bitmap;
pub use text::{Clip, FACE_COUNT, Face, LineMetrics, Style, Target, Text};
pub use ttf::{Font, FontError};

/// The characters kept in the shipped monospace face (Iosevka Term Nerd Font Mono): Latin,
/// Greek, Cyrillic, punctuation, currency, arrows, mathematical and technical symbols, box
/// drawing, blocks, geometric shapes, dingbats, braille (terminal graphics), and the Nerd Font
/// icon sets with clear licences (the "Font Logos" range, F300-F381, is left out).
pub fn mono_subset_keeps(cp: u32) -> bool {
    matches!(cp,
        0x0020..=0x007E
        | 0x00A0..=0x024F   // Latin-1, Latin Extended-A/B
        | 0x0300..=0x036F   // combining marks
        | 0x0370..=0x03FF   // Greek
        | 0x0400..=0x04FF   // Cyrillic
        | 0x2000..=0x206F   // general punctuation
        | 0x20A0..=0x20CF   // currency
        | 0x2100..=0x214F   // letterlike
        | 0x2190..=0x21FF   // arrows
        | 0x2200..=0x22FF   // mathematical operators
        | 0x2300..=0x23FF   // technical (incl. IEC power symbols)
        | 0x2500..=0x25FF   // box drawing, blocks, geometric shapes
        | 0x2600..=0x27BF   // symbols, dingbats (incl. heavy angle brackets)
        | 0x2800..=0x28FF   // braille
        | 0x2B00..=0x2BFF   // misc symbols and arrows (incl. 2B58)
        | 0xE000..=0xE00A   // Pomicons
        | 0xE0A0..=0xE0D7   // Powerline + extra
        | 0xE200..=0xE2A9   // Font Awesome Extension
        | 0xE300..=0xE3E3   // Weather
        | 0xE5FA..=0xE6B7   // Seti-UI
        | 0xE700..=0xE8EF   // Devicons
        | 0xEA60..=0xEC1E   // Codicons
        | 0xED00..=0xF2FF   // Font Awesome
        | 0xF400..=0xF533   // Octicons
        | 0xF0001..=0xF1AF0 // Material Design
        | 0xFFFD
    )
}
