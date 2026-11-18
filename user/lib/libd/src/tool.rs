//! How the shell starts a tool (docs/shell.md).
//!
//! A tool is a program with a tool manifest (`kind = "tool"`) that declares its parameters and
//! the rights each path needs. The shell resolves what was typed and starts the tool with exactly:
//! - an output channel (`TAG_OUTPUT`) for its records, text and errors (`rec::Out`);
//! - one handle per path argument (`TAG_PARAM + k`): the file or directory itself (`path:read`
//!   that exists), or the directory it goes in (`path:write`, `create`), with only the rights the
//!   manifest declares;
//! - the log (its records are named after the tool by the kernel).
//!
//! Nothing else: no namespace, no endpoint, none of the shell's own handles. The arguments
//! (startup args) list the items in order, NUL-separated: `name=shown` for text and numbers,
//! `name=shown\x1Frel` for paths, where `shown` is the path as the user sees it (for messages)
//! and `rel` the name below the handle ("" = the handle itself).

use crate::sys::{self, Handle};

/// The output channel (records, text, errors).
pub const TAG_OUTPUT: u32 = sys::TAG_USER + 0x300;
/// The handle of argument item `k`: `TAG_PARAM + k` (at most `MAX_ITEMS`).
pub const TAG_PARAM: u32 = sys::TAG_USER + 0x310;
pub const MAX_ITEMS: usize = 64;
/// A channel to the service manager (`grants.manager`; `svc::MGR_*`).
pub const TAG_MANAGER: u32 = sys::TAG_USER + 0x360;
/// Tool manifests handed to a holder of `grants.tools` (read-only VMOs, named after the file).
pub const TAG_TOOL_MANIFEST: u32 = sys::TAG_USER + 0x361;

/// A foreign program `run` hands to D-CMPL (docs/compat.md): its image, read from a file (VMO).
pub const TAG_IMAGE: u32 = sys::TAG_USER + 0x370;
/// The wall clock for a program without a clock connection: a 16-byte VMO, the wall time (ns
/// since 2000-01-01 UTC, `time::Time`) and the monotonic time (`clock_ns`) it corresponds to.
pub const TAG_TIME_BASE: u32 = sys::TAG_USER + 0x371;

/// Separates the shown path from the name below the handle.
pub const SEP: u8 = 0x1F;

/// One argument item.
#[derive(Clone, Copy)]
pub struct Item<'a> {
    /// The parameter it fills.
    pub name: &'a str,
    /// What the user typed (paths: made absolute).
    pub shown: &'a str,
    /// Paths: the name below `handle` ("" = the handle itself).
    pub rel: &'a str,
    /// Paths: the node handle (0 for text and numbers).
    pub handle: Handle,
}

/// The items this tool was started with, in order.
pub fn items() -> impl Iterator<Item = Item<'static>> {
    crate::args()
        .split(|&c| c == 0)
        .filter(|s| !s.is_empty())
        .take(MAX_ITEMS)
        .enumerate()
        .filter_map(|(k, s)| {
            let s = core::str::from_utf8(s).ok()?;
            let (name, v) = s.split_once('=')?;
            let (shown, rel, handle) = match v.split_once(SEP as char) {
                Some((shown, rel)) => (shown, rel, crate::startup_handle(TAG_PARAM + k as u32)),
                None => (v, "", 0),
            };
            Some(Item { name, shown, rel, handle })
        })
}

/// The first item for parameter `name`.
pub fn item(name: &str) -> Option<Item<'static>> {
    items().find(|i| i.name == name)
}
