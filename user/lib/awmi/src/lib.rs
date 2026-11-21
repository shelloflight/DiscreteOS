//! `dosawmi`: pure `no_std`, `#![forbid(unsafe_code)]`, zero-dependency compositor & window manager
//! core for D-OS (D-AWMI).

#![no_std]
#![forbid(unsafe_code)]

pub mod dock;
pub mod font;
pub mod geom;
pub mod launcher;
pub mod pixel;
pub mod proto;
pub mod text;
pub mod theme;
pub mod wm;

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests;

pub use dock::{DockHit, DockLayout, DockTrayState, DockWindowEntry};
pub use geom::{DamageSet, MAX_DAMAGE_RECTS, Point, Rect, Size};
pub use pixel::{CURSOR_H, CURSOR_W, Canvas, WinIcon, blend_over, write_hw_cursor_64x64};
pub use proto::{AwmiStatus, MAX_IDENTITY_BYTES, MAX_TITLE_BYTES, STATUS_BYTES, TrustTier, WINDOW_INFO_BYTES, encode_window_info, indicator_bits, ptr_kind, split_connect, win_flags, win_state};
pub use launcher::{LaunchTarget, Launcher, Setting, UiSettings};
pub use text::{BitmapText, TextRender, TextRole};
pub use theme::{ChromeMetrics, DockConfig, THEME_BYTES, Theme, ThemeError, ThemeId, argb, rgb};
pub use wm::{DragOp, KEY_META, MAX_OUTPUTS, MAX_WINDOWS, Output, OutputLayout, ResizeEdge, SnapState, SurfaceView, WORKSPACE_COUNT, WinHit, Window, WmAction, WmState};
