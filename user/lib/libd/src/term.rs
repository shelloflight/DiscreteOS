//! The terminal's session protocol (`terminal.session`, docs/shell.md).
//!
//! The terminal owns the screen and the keyboard; the shell talks to it over one channel. Every
//! message has the 32-byte header (`proto::Header`). Text is UTF-8 with two control bytes for
//! style: `STYLE` followed by one attribute byte (`fg | bg << 4`, the 16 VGA colours), and
//! `PLAIN` (back to the default). Everything else below 0x20 except `\n` is not shown.
//!
//! | Op | Direction | Meaning |
//! |---|---|---|
//! | `WRITE` | shell -> terminal | show text |
//! | `READ` | shell -> terminal | show the prompt (payload) and edit a line |
//! | `LINE` | terminal -> shell | the line (payload); `a` = 1 if it was cancelled (Ctrl+C) |
//! | `INTERRUPT` | terminal -> shell | Ctrl+C while no line is being read (stop the command) |
//! | `COMPLETE` | terminal -> shell | Tab: the line up to the cursor (payload) |
//! | `COMPLETIONS` | shell -> terminal | NUL-separated candidates for the last word |
//! | `SIZE` | terminal -> shell | `a` = columns, `b` = rows (when the session starts and when the grid changes) |
//! | `CLEAR` | shell -> terminal | clear the screen |
//!
//! The `view` endpoint (`VIEW_*`, below) shows the session in a window of the graphical session.

pub const WRITE: u32 = 500;
pub const READ: u32 = 501;
/// Flag in `READ`'s `a`: mask characters with `*`, omit from history and log (passwords).
pub const READ_SECRET: u64 = 1 << 0;
pub const LINE: u32 = 502;
pub const INTERRUPT: u32 = 503;
pub const COMPLETE: u32 = 504;
pub const COMPLETIONS: u32 = 505;
pub const SIZE: u32 = 506;
pub const CLEAR: u32 = 507;
/// Shell -> terminal: `a = 1` forwards raw key events (`KEY`) without line editing; `a = 0` restores normal mode.
pub const RAW_MODE: u32 = 516;
/// Terminal -> shell (while `RAW_MODE` is active): a pressed key (`a` = key value from `proto::key`).
pub const KEY: u32 = 517;
/// Audio service -> terminal (`terminal.indicator`): update live indicator state.
/// `a` = flags (`IND_MIC_ACTIVE`), payload = optional short source label.
pub const INDICATOR: u32 = 508;

/// Indicator flag bits for `INDICATOR`.
pub const IND_MIC_ACTIVE: u64 = 1 << 0;

/// Compositor -> terminal (`terminal.display`, a call): stop drawing on the screen (a graphical
/// session owns it). Output is still kept in the scrollback. Reply: the same op.
pub const DISPLAY_RELEASE: u32 = 509;
/// Compositor -> terminal (`terminal.display`, a call): the screen is the terminal's again; it
/// redraws everything. Also implied when the compositor's channel closes (it exited or crashed).
pub const DISPLAY_RECLAIM: u32 = 510;

// ---- `terminal.view`: the session shown in a window (the graphical terminal, `console.dsvc`) ----
//
// While a graphical session holds the screen, a viewer can show the terminal's session: the
// terminal lays the text out for the viewer's grid (the shell is told the new width) and keeps the
// cells in a VMO the viewer maps read-only; the viewer sends the keys typed in its window.

/// Viewer -> terminal (call): show the session in a grid of `a` = columns | rows << 32. Reply:
/// one read-only VMO handle (the grid, `VIEW_*` layout), `a` = its size.
pub const VIEW_ATTACH: u32 = 511;
/// Viewer -> terminal (call): the grid is now `a` = columns | rows << 32.
pub const VIEW_RESIZE: u32 = 512;
/// Viewer -> terminal: a key typed in the window (`a` = key value).
pub const VIEW_KEY: u32 = 513;
/// Terminal -> viewer: rows `a`..`b` (end exclusive) or the cursor changed; read the grid again.
pub const VIEW_DAMAGE: u32 = 514;
/// Viewer -> terminal (call): stop (the window closed); the terminal returns to its own screen size.
pub const VIEW_DETACH: u32 = 515;

/// Grid VMO layout: a header of `VIEW_HEADER` bytes (u32 little-endian: magic `DTVW`, columns,
/// rows, cursor column, cursor row (`u32::MAX`: hidden), the attribute of the default colours),
/// then `columns * rows` cells (u32: character bits 0-20, attribute `fg | bg << 4` bits 24-31).
pub const VIEW_HEADER: usize = 64;
pub const VIEW_MAGIC: u32 = u32::from_le_bytes(*b"DTVW");
pub const VIEW_MAX_COLS: u32 = 400;
pub const VIEW_MAX_ROWS: u32 = 200;
/// The grid VMO's size.
pub const VIEW_BYTES: usize = VIEW_HEADER + (VIEW_MAX_COLS * VIEW_MAX_ROWS) as usize * 4;

/// Style control bytes in text.
pub const STYLE: u8 = 0x01;
pub const PLAIN: u8 = 0x02;

/// The 16 colours.
pub const BLACK: u8 = 0;
pub const BLUE: u8 = 1;
pub const GREEN: u8 = 2;
pub const CYAN: u8 = 3;
pub const RED: u8 = 4;
pub const MAGENTA: u8 = 5;
pub const BROWN: u8 = 6;
pub const GREY: u8 = 7;
pub const DARK_GREY: u8 = 8;
pub const LIGHT_BLUE: u8 = 9;
pub const LIGHT_GREEN: u8 = 10;
pub const LIGHT_CYAN: u8 = 11;
pub const LIGHT_RED: u8 = 12;
pub const LIGHT_MAGENTA: u8 = 13;
pub const YELLOW: u8 = 14;
pub const WHITE: u8 = 15;
/// The default: grey on black.
pub const DEFAULT_ATTR: u8 = GREY;
