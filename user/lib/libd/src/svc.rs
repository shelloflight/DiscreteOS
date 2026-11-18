//! Service manager <-> service protocol (docs/services.md).
//!
//! Every service started by the manager (init) gets a control channel to it (startup tag
//! `proto::TAG_CONTROL`). Messages use the driver protocol's 32-byte header (`proto::Header`):
//! - `CONNECT` (manager -> service): a channel for an endpoint, carried by the message; payload =
//!   the endpoint's name. A provider gets one per client, named after its own endpoint (`disks`);
//!   a client gets a new one when its provider was restarted, named `service.endpoint`
//!   (`storaged.disks`), replacing the old one.
//! - `SYNC` (manager -> volume provider, a call): make every volume durable; the reply comes
//!   once it is. Sent to every volume provider before any service is stopped.
//! - `SHUTDOWN` (manager -> service): make everything durable, then exit with code 0. The
//!   manager waits a few seconds, then ends the process.
//! - `LOG_LEVEL` (manager -> the log service): a service's log level, from its manifest.
//!
//! Endpoints a manifest connects to are also passed at start: startup tag `TAG_ENDPOINT + i`, with
//! the names (NUL-separated, in the same order) in a VMO tagged `TAG_ENDPOINT_NAMES`.

use crate::sys::{self, Handle};

pub const CONNECT: u32 = 300;
pub const SHUTDOWN: u32 = 301;
/// Manager -> volume provider (a call): make every volume durable now, while the disk drivers
/// are still running (the first step of a shutdown). Reply: the same op, `a` = volumes synced.
pub const SYNC: u32 = 302;
/// Manager -> a holder of the kernel log (the log service): the log level of service `a`-named
/// processes. Payload: the service's name; `a` = its level (`sys::LOG_*`): records below are
/// not kept.
pub const LOG_LEVEL: u32 = 303;

pub const TAG_ENDPOINT_NAMES: u32 = sys::TAG_USER + 0x1FF;
pub const TAG_ENDPOINT: u32 = sys::TAG_USER + 0x200;
pub const MAX_ENDPOINTS: usize = 16;

/// The startup handle of the endpoint `name` (`service.endpoint`), or 0 if none was granted.
pub fn endpoint(name: &[u8]) -> Handle {
    let v = crate::startup_handle(TAG_ENDPOINT_NAMES);
    if v == 0 {
        return 0;
    }
    let mut buf = [0u8; 512];
    let size = sys::vmo_size(v).unwrap_or(0).min(buf.len() as u64) as usize;
    if sys::vmo_read(v, 0, &mut buf[..size]) != 0 {
        return 0;
    }
    buf[..size]
        .split(|&c| c == 0)
        .take(MAX_ENDPOINTS)
        .position(|n| n == name)
        .map_or(0, |i| crate::startup_handle(TAG_ENDPOINT + i as u32))
}
