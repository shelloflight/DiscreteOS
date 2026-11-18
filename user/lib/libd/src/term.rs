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
//! | `SIZE` | terminal -> shell | `a` = columns, `b` = rows (sent when the session starts) |
//! | `CLEAR` | shell -> terminal | clear the screen |

pub const WRITE: u32 = 500;
pub const READ: u32 = 501;
pub const LINE: u32 = 502;
pub const INTERRUPT: u32 = 503;
pub const COMPLETE: u32 = 504;
pub const COMPLETIONS: u32 = 505;
pub const SIZE: u32 = 506;
pub const CLEAR: u32 = 507;

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
