//! Device manager <-> driver protocol, over the channel the manager gives each driver
//! (startup tag `TAG_CONTROL`). Every message starts with a 32-byte header; requests from the
//! manager are `channel_call`s (the kernel puts its transaction id in `txid`) and the driver
//! answers with the same `txid`. Messages the driver sends on its own (READY, KEY) have txid 0.
//! Payload (block data) follows the header.
//!
//! Block drivers also announce each disk they serve (`DISK`, one per unit). The
//! manager then attaches a channel per disk (`BLK_ATTACH`, carrying the channel), which it hands
//! to the storage service: block I/O does not pass through the manager. Requests on an attached
//! channel name no unit (the channel is the disk); on the control channel they address unit 0.

pub const TAG_CONTROL: u32 = crate::sys::TAG_USER;
/// Channel handed to a USB class driver (`usbaudio.ddrv`) to talk to its `xhci.ddrv` host.
pub const TAG_USB_BUS: u32 = crate::sys::TAG_USER + 1;
/// Read-only vendor firmware directory channel (`sys:/firmware/<vendor>/`) handed to a `.ddrv`.
pub const TAG_FIRMWARE: u32 = crate::sys::TAG_USER + 2;

/// Driver -> manager: initialised; `a` = capacity in sectors (block) or 0.
pub const READY: u32 = 1;
/// Driver -> manager: a key; `a` = the character, `b` = which keyboard of the driver (an id the
/// driver chooses, e.g. its USB slot; 0 for drivers with one keyboard).
pub const KEY: u32 = 2;
/// Driver -> manager: a pointer moved or a button changed. `a` = dx (low 32 bits, signed) and dy
/// (high 32 bits, signed, down positive); `b` = buttons (bit 0 left, 1 right, 2 middle) | wheel
/// (signed byte, bits 8-15, up positive) | which pointer of the driver (bits 16-31).
pub const POINTER: u32 = 4;
/// Driver -> manager: keyboard `a` (the `KEY` id) is gone (unplugged or failed).
pub const KEYBOARD_GONE: u32 = 5;
/// Audio driver -> manager: audio endpoint announced.
/// `a` = unit (0..15) | kind (16..23) | flags (32..63);
/// `b` = default_rate (0..31) | channels (32..39) | format (40..47);
/// payload = UTF-8 device name.
pub const AUDIO_DEV: u32 = 6;
/// Audio driver -> manager: jack or ELD state update for unit `a`; `b` = new flags; optional payload = name.
pub const AUDIO_JACK: u32 = 7;
/// Audio driver -> manager: audio endpoint unit `a` removed (hot-unplugged).
pub const AUDIO_GONE: u32 = 8;
/// xHCI driver -> manager (carries 1 USB bus channel): spawn `usbaudio.ddrv` for a USB Audio device.
/// `a` = vid (0..15) | pid (16..31) | speed (32..39) | slot (40..47); `b` = port.
pub const USB_AUDIO_ATTACH: u32 = 9;
/// Device manager -> each client of its `input` endpoint: a key typed. `a` = the key value
/// (`key`: a character, US layout, or a named key with modifiers), `b` = which input device (an
/// index); payload: the driver's name (`ps2`, `xhci`, `virtio-input`).
pub const INPUT_KEY: u32 = 410;
/// Device manager -> each client of its `input` endpoint: pointer input. `a` as in `POINTER`
/// (or `(abs_x_0_32767 | abs_y_0_32767 << 32)` when `POINTER_ABS` bit 16 is set in `b`);
/// `b` = buttons and wheel as in `POINTER` (bits 0-15) | `POINTER_ABS` (bit 16) | which input
/// device (bits 32-47); payload: the driver's name.
pub const INPUT_POINTER: u32 = 411;
/// Client -> device manager on `devmgr.input`: grab (`a = 1`) or release (`a = 0`) exclusive
/// input routing (used by the compositor during an active GUI session; automatically released on
/// channel close).
pub const INPUT_GRAB: u32 = 412;

/// Flag bit in `POINTER` / `INPUT_POINTER` `Header::b`: `a` carries absolute `[0..=32767]` coords.
pub const POINTER_ABS: u64 = 1 << 16;

/// Key values (`KEY`, `INPUT_KEY`): below 0x100 a character (`\n` Enter, 0x08 Backspace, 0x1B
/// Escape, `\t` Tab, Ctrl+letter its control character); from 0x100 a named key, with the
/// modifier bits held when it was pressed. Shortcuts holding Alt or Super also carry modifier bits.
pub mod key {
    pub const UP: u32 = 0x101;
    pub const DOWN: u32 = 0x102;
    pub const LEFT: u32 = 0x103;
    pub const RIGHT: u32 = 0x104;
    pub const HOME: u32 = 0x105;
    pub const END: u32 = 0x106;
    pub const PAGE_UP: u32 = 0x107;
    pub const PAGE_DOWN: u32 = 0x108;
    pub const INSERT: u32 = 0x109;
    pub const DELETE: u32 = 0x10A;
    pub const F1: u32 = 0x110;
    pub const F2: u32 = 0x111;
    pub const F3: u32 = 0x112;
    pub const F4: u32 = 0x113;
    pub const F5: u32 = 0x114;
    pub const F6: u32 = 0x115;
    pub const F7: u32 = 0x116;
    pub const F8: u32 = 0x117;
    pub const F9: u32 = 0x118;
    pub const F10: u32 = 0x119;
    pub const F11: u32 = 0x11A;
    pub const F12: u32 = 0x11B;
    /// The Super key on its own: pressed, and released (`RELEASE` set).
    pub const META: u32 = 0x11C;
    pub const SHIFT: u32 = 1 << 16;
    pub const CTRL: u32 = 1 << 17;
    pub const ALT: u32 = 1 << 18;
    pub const SUPER: u32 = 1 << 19;
    pub const RELEASE: u32 = 1 << 20;
    /// The key without its modifiers.
    pub const MASK: u32 = 0xFFFF;
}
/// Manager -> block driver: read `b` sectors from `a`; reply carries the data.
pub const BLK_READ: u32 = 10;
/// Manager -> block driver: write `b` sectors at `a` (data in the payload).
pub const BLK_WRITE: u32 = 11;
/// Manager -> driver: report counters; reply `a` = interrupts handled, `b` = requests done.
pub const STATS: u32 = 12;
/// -> block driver: make everything written so far durable (device cache flushed).
pub const BLK_FLUSH: u32 = 13;
/// Driver -> manager: unit `a` is a disk of `b` sectors; payload = a short model name.
pub const DISK: u32 = 3;
/// Manager -> block driver: serve unit `a` on the channel this message carries (no reply).
pub const BLK_ATTACH: u32 = 14;
/// Client -> block driver (attached channel): attach a shared-memory `libd::ring::IoRing` VMO
/// carried by this message for zero-copy transfers; reply `status` = 0 on success.
pub const BLK_RING_SETUP: u32 = 15;
/// Client -> block driver (attached channel): drain pending SQEs in the attached ring, post CQEs,
/// and reply with `a` = completions posted.
pub const BLK_RING_DOORBELL: u32 = 16;
/// Manager -> audio driver: serve audio unit `a` on the channel this message carries (no reply).
pub const AUDIO_ATTACH: u32 = 17;
/// Network driver -> manager: NIC announced.
/// `a` = mac[0..6] in bits 0..47 | link_up in bit 48; `b` = mtu; payload = UTF-8 NIC name.
pub const NET_DEV: u32 = 18;
/// Network driver -> manager: link state changed; `a` = link_up (0 or 1).
pub const NET_LINK: u32 = 19;
/// Manager -> network driver: serve `net.dsvc` on the channel this message carries (no reply).
pub const NET_ATTACH: u32 = 23;
/// GPU driver -> manager: GPU adapter announced.
/// `a` = `gpu::pack_dev_a(kind, vendor, device, vram_mib)`;
/// `b` = `gpu::pack_dev_b(width, height, caps)`;
/// payload = UTF-8 adapter name.
pub const GPU_DEV: u32 = 24;
/// Manager -> GPU driver: serve `gpu.dsvc` on the channel this message carries (no reply).
pub const GPU_ATTACH: u32 = 25;
/// GPU driver -> manager: GPU adapter removed/offline.
pub const GPU_GONE: u32 = 26;
/// Manager -> driver (tests): fault on purpose (restart test).
pub const TEST_CRASH: u32 = 20;
/// Manager -> block driver (tests): point a request at memory the device was not given (the
/// kernel image's physical address); reply `status` = what the device reported.
pub const TEST_DMA_ESCAPE: u32 = 21;
/// Manager -> block driver (tests): make the device write MSI data into the MSI window (a forged
/// interrupt the IOMMU must block); reply `status` = what the device reported.
pub const TEST_MSI_FORGE: u32 = 22;

pub const HEADER: usize = 32;
pub const SECTOR: usize = 512;
/// Largest transfer in one message (fits a channel message with the header).
pub const MAX_SECTORS: u64 = 64;

#[derive(Clone, Copy, Default, Debug)]
pub struct Header {
    pub txid: u32,
    pub op: u32,
    pub status: i32,
    pub a: u64,
    pub b: u64,
}

impl Header {
    pub fn put(&self, buf: &mut [u8]) {
        buf[0..4].copy_from_slice(&self.txid.to_le_bytes());
        buf[4..8].copy_from_slice(&self.op.to_le_bytes());
        buf[8..12].copy_from_slice(&self.status.to_le_bytes());
        buf[12..16].copy_from_slice(&[0; 4]);
        buf[16..24].copy_from_slice(&self.a.to_le_bytes());
        buf[24..32].copy_from_slice(&self.b.to_le_bytes());
    }

    /// Parse a message (untrusted: from the other process). None if it is too short.
    pub fn get(buf: &[u8]) -> Option<Header> {
        if buf.len() < HEADER {
            return None;
        }
        let u32_at = |i: usize| u32::from_le_bytes([buf[i], buf[i + 1], buf[i + 2], buf[i + 3]]);
        let u64_at = |i: usize| u64::from(u32_at(i)) | u64::from(u32_at(i + 4)) << 32;
        Some(Header { txid: u32_at(0), op: u32_at(4), status: u32_at(8) as i32, a: u64_at(16), b: u64_at(24) })
    }
}

/// Driver status for a failed request (the device reported an error).
pub const ERR_IO: i32 = -105;

/// Send an unsolicited message (txid 0).
pub fn send(ch: crate::Handle, op: u32, a: u64, b: u64) -> i64 {
    let mut buf = [0u8; HEADER];
    Header { txid: 0, op, status: 0, a, b }.put(&mut buf);
    crate::sys::channel_write(ch, &buf)
}
