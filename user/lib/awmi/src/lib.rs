//! `dosawmi`: pure `no_std`, `#![forbid(unsafe_code)]`, zero-dependency compositor & window manager
//! core for D-OS (D-AWMI).

#![no_std]
#![forbid(unsafe_code)]

pub mod dock;
pub mod font;
pub mod geom;
pub mod launcher;
pub mod lock;
pub mod perm;
pub mod pixel;
pub mod proto;
pub mod text;
pub mod theme;
pub mod wm;

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests;

pub use dock::{DockHit, DockLayout, DockPinnedEntry, DockTrayState, DockWindowEntry, MAX_DOCK_PINNED};
pub use geom::{DamageSet, MAX_DAMAGE_RECTS, Point, Rect, Size};
pub use launcher::{LaunchTarget, Launcher, SETTING_COUNT, Setting, UiSettings};
pub use lock::{LockIdentity, LockMode, LockOutcome, LockReason, LockScreen, MAX_LOCK_IDENTITIES};
pub use perm::{PERM_ALLOW, PERM_CANCEL, PERM_DENY, PermOutcome, PermPrompt};
pub use pixel::{CURSOR_H, CURSOR_W, Canvas, CursorKind, WinIcon, blend_over, write_hw_cursor_64x64, write_hw_cursor_64x64_kind};
pub use proto::{AwmiStatus, MAX_IDENTITY_BYTES, MAX_TITLE_BYTES, STATUS_BYTES, TrustTier, WINDOW_INFO_BYTES, encode_window_info, indicator_bits, ptr_kind, split_connect, win_flags, win_state};
pub use text::{BitmapText, TextRender, TextRole};
pub use theme::{ChromeMetrics, DockConfig, THEME_BYTES, Theme, ThemeError, ThemeId, argb, rgb};
pub use wm::{DragOp, KEY_META, MAX_OUTPUTS, MAX_WINDOWS, Output, OutputLayout, ResizeEdge, SnapState, SurfaceView, WORKSPACE_COUNT, WinHit, Window, WmAction, WmState};
