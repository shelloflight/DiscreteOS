//! xHCI (USB 3) host controller driver (`xhci.ddrv`): USB keyboards, mice and storage, on root
//! ports or behind USB 2 and USB 3 hubs (up to five tiers).
//!
//! - **Keyboards** (HID boot protocol): up to `MAX_KBDS` at once, each with its own interrupt
//!   ring (a PC often has several devices that offer a boot keyboard interface: receivers,
//!   lighting controllers, and the real keyboard must not be left unprobed behind one of them).
//!   Keys are diffed between reports and go through the same US keymap as the other keyboards;
//!   a held key repeats (after 500 ms, 30 per second); the Caps Lock LED follows the state. Each
//!   keyboard is named in its KEY messages (its slot), so the device manager can tell them apart
//!   (trust.rs).
//! - **Mice**: the HID report descriptor is parsed for relative X, Y, wheel and buttons (report
//!   protocol); a boot mouse whose descriptor says nothing usable falls back to the boot protocol.
//!   Movements go to the device manager (POINTER). Absolute pointers (tablets) are left unused.
//!   A receiver with a keyboard and a mouse interface gets both.
//! - **Storage**: USB mass storage, bulk-only transport with SCSI commands (INQUIRY, TEST UNIT
//!   READY, READ CAPACITY 10/16, READ/WRITE 10/16, SYNCHRONIZE CACHE), 512-byte sectors, LUN 0;
//!   served like any block device (DISK, then requests on the channel the device manager
//!   attaches; blkserve.rs). Read-only unless the driver was started with `rw`. A stalled
//!   endpoint is reset and its halt cleared; a disk that stops answering is dropped.
//! - **Hubs**: USB 2 hubs (transaction translators for low/full-speed devices behind high-speed
//!   hubs) and USB 3 hubs (SET_HUB_DEPTH, SuperSpeed port status); their ports are polled once a
//!   second. Other devices are disabled again. Every port stays watched, so a device plugged in
//!   later, or again, is picked up.
//!
//! Bring-up: firmware ownership taken (USB legacy support capability, SMIs off), controller
//! reset, one command ring, one interrupter with a one-segment event ring (MSI-X entry 0 or MSI),
//! device context array. Per device: Enable Slot, Address Device (route string, and the
//! transaction translator for low/full-speed devices behind a high-speed hub), descriptors read on
//! endpoint 0, then the device's endpoints configured.
//!
//! Connections are debounced, and a device that keeps reconnecting is left alone after its third
//! identical probe (until its port has been empty for two seconds): unconfigured devices on some
//! boards drop off and come back, which would otherwise be probed forever. Each device is reported
//! once.
//!
//! Everything the controller and the devices write is untrusted: event TRB pointers must point
//! into our rings, descriptor and report lengths are bounded by what was read, every wait has a
//! deadline, and an impossible value ends the driver (it is restarted). All rings, contexts and
//! buffers are pinned for the device: with an IOMMU it reaches nothing else.
//!
//! Not supported: isochronous endpoints (audio, video), USB Attached SCSI, sectors other than 512
//! bytes, more than one interrupter, Num Lock and Scroll Lock (no keymap state for them).

use libd::handle::sleep;
use libd::proto::{self, HEADER, Header, MAX_SECTORS, SECTOR};
use libd::sys::{self, Handle};
use libd::{Dma, Mapping, Port, Startup, println};

use crate::keymap::{self, Keys};

const MS: u64 = 1_000_000;

// Capability registers
const CAPLENGTH: u64 = 0x00;
const HCSPARAMS1: u64 = 0x04;
const HCSPARAMS2: u64 = 0x08;
const HCCPARAMS1: u64 = 0x10;
const DBOFF: u64 = 0x14;
const RTSOFF: u64 = 0x18;

// Operational registers (from CAPLENGTH)
const USBCMD: u64 = 0x00;
const USBSTS: u64 = 0x04;
const PAGESIZE: u64 = 0x08;
const CRCR: u64 = 0x18;
const DCBAAP: u64 = 0x30;
const CONFIG: u64 = 0x38;
const PORTSC: u64 = 0x400;

const CMD_RUN: u32 = 1 << 0;
const CMD_HCRST: u32 = 1 << 1;
const CMD_INTE: u32 = 1 << 2;
const STS_HCH: u32 = 1 << 0;
const STS_CNR: u32 = 1 << 11;

// PORTSC
const PS_CCS: u32 = 1 << 0;
const PS_PED: u32 = 1 << 1;
const PS_PR: u32 = 1 << 4;
const PS_PP: u32 = 1 << 9;
const PS_CSC: u32 = 1 << 17;
const PS_PRC: u32 = 1 << 21;
const PS_WRC: u32 = 1 << 19;
const PS_WPR: u32 = 1 << 31;
/// Change bits (write 1 to clear).
const PS_CHANGES: u32 = 0x00FE_0000;
/// Bits written back unchanged (power and wake enables); PED and the change bits never are.
const PS_KEEP: u32 = PS_PP | 0x0E00_0000;

// Interrupter 0 (runtime registers + 0x20)
const IMAN: u64 = 0x20;
const ERSTSZ: u64 = 0x28;
const ERSTBA: u64 = 0x30;
const ERDP: u64 = 0x38;
const IMAN_IP: u32 = 1 << 0;
const IMAN_IE: u32 = 1 << 1;
const ERDP_EHB: u64 = 1 << 3;

// TRBs
const TRB_CYCLE: u32 = 1 << 0;
const TRB_TC: u32 = 1 << 1;
const TRB_ISP: u32 = 1 << 2;
const TRB_IOC: u32 = 1 << 5;
const TRB_IDT: u32 = 1 << 6;
const T_NORMAL: u32 = 1;
const T_SETUP: u32 = 2;
const T_DATA: u32 = 3;
const T_STATUS: u32 = 4;
const T_LINK: u32 = 6;
const T_ENABLE_SLOT: u32 = 9;
const T_DISABLE_SLOT: u32 = 10;
const T_ADDRESS_DEVICE: u32 = 11;
const T_CONFIGURE_EP: u32 = 12;
const T_EVALUATE_CTX: u32 = 13;
const T_RESET_EP: u32 = 14;
const T_SET_TR_DEQ: u32 = 16;
const TRB_CH: u32 = 1 << 4;
const CC_STALL: u32 = 6;
const E_TRANSFER: u32 = 32;
const E_COMMAND: u32 = 33;
const E_PORT: u32 = 34;
const CC_SUCCESS: u32 = 1;
const CC_SHORT: u32 = 13;

// Hub class (USB 2.0 11.24): port features and status bits.
const F_PORT_RESET: u8 = 4;
const F_PORT_POWER: u8 = 8;
const F_C_PORT_CONNECTION: u8 = 16;
const F_C_PORT_RESET: u8 = 20;
// USB 3 hubs (USB 3.2 10.16): the change bits beyond the USB 2 ones, and their clear features.
const F_C_PORT_LINK_STATE: u8 = 25;
const F_C_PORT_CONFIG_ERROR: u8 = 26;
const F_C_BH_PORT_RESET: u8 = 29;
const REQ_SET_HUB_DEPTH: u8 = 12;
const HS_CONNECTION: u16 = 1 << 0;
const HS_ENABLE: u16 = 1 << 1;
const HS_LOW_SPEED: u16 = 1 << 9;
const HS_HIGH_SPEED: u16 = 1 << 10;
const HC_CONNECTION: u16 = 1 << 0;
const HC_RESET: u16 = 1 << 4;

/// Ring geometry: one page, 256 TRBs; on command and transfer rings the last is the Link TRB.
const RING_TRBS: u32 = 256;

// Pages of `mem`
const PG_DCBAA: u64 = 0; // device context pointers; the scratchpad array at +0x800
const PG_CMD: u64 = 1;
const PG_EVENT: u64 = 2;
const PG_ERST: u64 = 3;
const PG_IN: u64 = 4; // input context
const PG_DESC: u64 = 6; // descriptor / status buffer
const PG_REPORT: u64 = 7; // report buffers, 64 bytes each (REPORTS per keyboard)
const PG_INTR: u64 = 8; // the interrupt ring of keyboard i: PG_INTR + i
const MAX_KBDS: usize = 4;
const PAGES: u64 = PG_INTR + MAX_KBDS as u64;
/// Pages from here are in slot_mem (a pinned buffer holds at most 32 pages): per slot, the
/// output device context, then the endpoint 0 ring.
const PG_SLOTS: u64 = PAGES;
const MAX_SLOTS: u32 = 16;
const SLOT_PAGES: u64 = 2 * MAX_SLOTS as u64;
const SCRATCH_ARRAY: u64 = 0x800;
const MAX_SCRATCH: u32 = 31;

/// Pages from here are in fun_mem: mouse rings and reports, then per disk its two bulk rings,
/// the command/status page and the data pages.
const PG_FUN: u64 = PG_SLOTS + SLOT_PAGES;
const MAX_MICE: usize = 2;
const PG_MOUSE: u64 = PG_FUN; // the interrupt ring of mouse i: PG_MOUSE + i
const PG_MOUSE_REPORT: u64 = PG_FUN + MAX_MICE as u64; // 64 bytes per report, REPORTS per mouse
const MAX_DISKS: usize = 2;
const DATA_PAGES: u64 = 8; // one transfer: 64 sectors
const DISK_PAGES: u64 = 3 + DATA_PAGES;
const PG_DISK: u64 = PG_MOUSE_REPORT + 1; // disk i: PG_DISK + DISK_PAGES * i
const FUN_PAGES: u64 = MAX_MICE as u64 + 1 + DISK_PAGES * MAX_DISKS as u64;
/// Offsets in a disk's command page: the CBW, then the CSW.
const CBW: u64 = 0;
const CSW: u64 = 512;

const REPORTS: usize = 8;
const MAX_HUBS: usize = 8;
/// Hub ports used per hub (a route string nibble holds 1-15).
const HUB_PORTS: u32 = 15;
/// Tiers of hubs below a root port (the route string has five nibbles).
const MAX_DEPTH: u32 = 5;

/// A connection must be stable this long before the device is probed (USB 2.0 7.1.7.3: 100 ms).
const DEBOUNCE: u64 = 100 * MS;
/// Identical probes of one port closer together than this count as the device reconnecting.
const REPEAT_WINDOW: u64 = 10_000 * MS;
/// The probe that leaves a reconnecting device alone (the third identical one).
const MAX_STRIKES: u8 = 2;
/// A port left alone is watched again once it has been empty this long.
const GONE_FOR: u64 = 2_000 * MS;
const HUB_POLL: u64 = 1_000 * MS;
const SETTLE_TICK: u64 = 50 * MS;
/// Key repeat: delay, then interval.
const REPEAT_DELAY: u64 = 500 * MS;
const REPEAT_EVERY: u64 = 33 * MS;

const ADDR_FAILED: &str = "Address Device failed";

const KEY_IRQ: u64 = 1;
const KEY_CTL: u64 = 2;
/// Port key of disk i's attached channel: KEY_DISK + i.
const KEY_DISK: u64 = 16;

macro_rules! say {
    ($x:expr, $($t:tt)*) => { println!("xhci {}: {}", $x.tag(), format_args!($($t)*)) };
}

#[derive(Clone, Copy)]
struct Trb {
    param: u64,
    status: u32,
    control: u32,
}

impl Trb {
    fn ty(&self) -> u32 {
        (self.control >> 10) & 0x3F
    }
    fn code(&self) -> u32 {
        self.status >> 24
    }
    fn slot(&self) -> u32 {
        self.control >> 24
    }
    fn endpoint(&self) -> u32 {
        (self.control >> 16) & 0x1F
    }
}

/// A producer ring (command or transfer) in page `page` of `mem`.
struct Ring {
    page: u64,
    enq: u32,
    cycle: u32,
}

impl Ring {
    fn new(page: u64) -> Ring {
        Ring { page, enq: 0, cycle: 1 }
    }
}

/// Where a device is: root port, route string (one nibble per hub tier), tier, speed (xHCI
/// speed id: 1 full, 2 low, 3 high, 4+ SuperSpeed) and, for a low/full-speed device behind a
/// high-speed hub, the hub slot and port of its transaction translator.
#[derive(Clone, Copy, Default)]
struct Loc {
    root: u32,
    route: u32,
    depth: u32,
    speed: u32,
    tt_slot: u32,
    tt_port: u32,
}

impl Loc {
    /// The device on port `port` of the hub at `self` (slot `hub_slot`).
    fn child(&self, hub_slot: u32, port: u32, speed: u32) -> Loc {
        let (tt_slot, tt_port) = if speed > 2 {
            (0, 0)
        } else if self.speed == 3 {
            (hub_slot, port)
        } else {
            (self.tt_slot, self.tt_port)
        };
        Loc { root: self.root, route: self.route | port.min(HUB_PORTS) << (4 * self.depth), depth: self.depth + 1, speed, tt_slot, tt_port }
    }
}

/// Port path: root port, then the hub port at each tier ("5.1.3").
impl core::fmt::Display for Loc {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.root)?;
        for i in 0..self.depth {
            write!(f, ".{}", (self.route >> (4 * i)) & 0xF)?;
        }
        Ok(())
    }
}

/// What a device says it is (device descriptor; the first interface if the device class is 0).
#[derive(Clone, Copy, Default)]
struct Ident {
    vid: u16,
    pid: u16,
    class: u8,
    sub: u8,
    proto: u8,
}

impl Ident {
    fn key(&self) -> u32 {
        (u32::from(self.vid) << 16 | u32::from(self.pid)).max(1)
    }
    fn kind(&self) -> &'static str {
        match (self.class, self.sub, self.proto) {
            (9, _, _) => "hub (not usable: too deep)",
            (3, 1, 1) => "keyboard (no usable boot interface)",
            (3, _, 2) => "mouse",
            (3, _, _) => "HID device",
            (1, _, _) => "audio device",
            (2, _, _) | (0x0A, _, _) => "communications device",
            (6, _, _) => "imaging device",
            (7, _, _) => "printer",
            (8, _, _) => "storage device",
            (0x0B, _, _) => "smart card reader",
            (0x0E, _, _) => "video device",
            (0xE0, _, _) => "wireless controller",
            (0xEF, _, _) => "composite device",
            (0xFF, _, _) => "vendor-specific device",
            _ => "device",
        }
    }
}

/// Bookkeeping of one port (root or hub).
#[derive(Clone, Copy, Default)]
struct PortState {
    /// A connection waits for its debounce before being probed.
    pending: bool,
    changed_at: u64,
    /// The device there has been probed (and kept, or left unused).
    done: bool,
    /// Last probe: identity key (0: a keyboard or nothing), time, identical repeats.
    last: u32,
    last_probe: u64,
    strikes: u8,
    /// Reconnecting device left alone; `gone_since`: empty since (0: connected).
    ignored: bool,
    gone_since: u64,
}

/// A configured hub (USB 2, or the SuperSpeed half of a USB 3 hub).
#[derive(Clone, Copy)]
struct Hub {
    slot: u32,
    loc: Loc,
    ports: u32,
    /// A USB 3 hub (SuperSpeed port status and features).
    ss: bool,
    /// Stopped answering (its parent reports the unplug).
    dead: bool,
    ps: [PortState; HUB_PORTS as usize],
}

/// A boot keyboard being served.
struct Kbd {
    /// Which of the `MAX_KBDS` (its interrupt ring page, its report buffers).
    idx: usize,
    id: Ident,
    slot: u32,
    loc: Loc,
    iface: u8,
    dci: u32,
    intr: Ring,
    /// Report buffer of each interrupt-ring position (u8::MAX: none queued there).
    buf_at: [u8; RING_TRBS as usize],
    last: [u8; 8],
    keys: Keys,
    /// The key held down: (key value, its usage, when it repeats next).
    repeat: Option<(u32, u8, u64)>,
    /// Caps Lock as the keyboard's LED shows it; `leds_due`: the LED must be updated.
    leds_caps: bool,
    leds_due: bool,
}

/// Where a value is in a HID report (bits after the report id).
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
struct Field {
    bit: u16,
    size: u8,
    signed: bool,
}

impl Field {
    /// The value in report `r` (little-endian bit order, as HID reports are).
    fn get(&self, r: &[u8]) -> i32 {
        let mut v: u32 = 0;
        for i in 0..u16::from(self.size.min(32)) {
            let b = self.bit + i;
            let byte = r.get(usize::from(b / 8)).copied().unwrap_or(0);
            v |= u32::from((byte >> (b % 8)) & 1) << i;
        }
        let n = u32::from(self.size.clamp(1, 32));
        if self.signed && n < 32 && v & (1 << (n - 1)) != 0 { (v | !((1u32 << n) - 1)) as i32 } else { v as i32 }
    }
}

/// How a mouse reports: from its report descriptor, or the boot protocol's fixed layout.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
struct MouseFormat {
    /// The report id of the pointer report (0: the device uses no ids).
    id: u8,
    /// One bit per button, from `buttons.bit` (size = how many).
    buttons: Field,
    x: Field,
    y: Field,
    wheel: Option<Field>,
    boot: bool,
}

const BOOT_MOUSE: MouseFormat = MouseFormat {
    id: 0,
    buttons: Field { bit: 0, size: 3, signed: false },
    x: Field { bit: 8, size: 8, signed: true },
    y: Field { bit: 16, size: 8, signed: true },
    wheel: None,
    boot: true,
};

/// A mouse being served.
struct Mouse {
    /// Which of the `MAX_MICE` (its interrupt ring page, its report buffers).
    idx: usize,
    id: Ident,
    slot: u32,
    loc: Loc,
    dci: u32,
    /// Bytes asked for per report (the endpoint's max packet, at most 64).
    len: u32,
    intr: Ring,
    buf_at: [u8; RING_TRBS as usize],
    fmt: MouseFormat,
    buttons: u32,
}

/// A USB disk (bulk-only mass storage) being served.
struct UsbDisk {
    /// Which of the `MAX_DISKS` (its pages, its unit number).
    idx: usize,
    id: Ident,
    slot: u32,
    loc: Loc,
    iface: u8,
    in_ep: u8,
    out_ep: u8,
    in_ring: Ring,
    out_ring: Ring,
    mps: u32,
    tag: u32,
    sectors: u64,
    model: [u8; 40],
    model_len: usize,
    /// The channel the device manager attached for this unit (0: none yet).
    ch: Handle,
}

impl UsbDisk {
    fn in_dci(&self) -> u32 {
        u32::from(self.in_ep) * 2 + 1
    }
    fn out_dci(&self) -> u32 {
        u32::from(self.out_ep) * 2
    }
    fn page(&self, i: u64) -> u64 {
        PG_DISK + DISK_PAGES * self.idx as u64 + i
    }
}

/// Result of a probe. Keyboards, mice and disks are large but short-lived (moved into `Xhci`).
#[allow(clippy::large_enum_variant)]
enum Found {
    /// A keyboard, a mouse, or both on one device (a receiver).
    Input(Option<Kbd>, Option<Mouse>),
    Disk(UsbDisk),
    /// A hub: ports, identity, USB 3.
    Hub(u32, Ident, bool),
    Other(Ident),
}

/// An interface of the configuration, as far as this driver uses it.
#[derive(Clone, Copy, Default)]
struct Iface {
    num: u8,
    class: u8,
    sub: u8,
    proto: u8,
    /// Interrupt or bulk IN endpoint: (number, max packet, interval, max burst).
    ep_in: Option<(u8, u32, u8, u8)>,
    /// Bulk OUT endpoint: (number, max packet, max burst).
    ep_out: Option<(u8, u32, u8)>,
    /// HID: the report descriptor's length.
    hid_len: u16,
}

struct Xhci {
    bar: Mapping,
    op: u64,
    rt: u64,
    db: u64,
    mem: Dma,
    slot_mem: Dma,
    /// Mouse rings and reports, disk rings, commands and data.
    fun_mem: Dma,
    _scratch: Option<Dma>,
    irq: Handle,
    tag: [u8; 16],
    tag_len: usize,
    ports: u32,
    usb3: u64, // bit p-1: port p is a USB 3 port
    csz: u64,  // context size: 32 or 64 bytes
    slots: u32,
    cmd: Ring,
    ev_deq: u32,
    ev_cycle: u32,
    /// Endpoint 0 ring of each slot.
    ep0: [Ring; MAX_SLOTS as usize + 1],
    /// Where each enabled slot is: (hub slot or 0 for a root port, port); (0, 0) = free.
    owner: [(u32, u32); MAX_SLOTS as usize + 1],
    hubs: [Option<Hub>; MAX_HUBS],
    root: [PortState; 64],
    kbds: [Option<Kbd>; MAX_KBDS],
    mice: [Option<Mouse>; MAX_MICE],
    disks: [Option<UsbDisk>; MAX_DISKS],
    /// The control channel to the device manager (KEY, POINTER, DISK messages).
    ctl: Handle,
    /// Disks may be written (started with `rw`).
    writable: bool,
    /// Block requests served.
    requests: u64,
    /// Root port status changes seen (bit p-1).
    port_events: u64,
    /// Keyboard transfer events seen while waiting for something else.
    deferred: [Trb; REPORTS * 4],
    ndeferred: usize,
    next_poll: u64,
    /// Completion code of the last failed command or transfer.
    last_cc: u32,
    reports: u64,
}

impl Xhci {
    fn tag(&self) -> &str {
        core::str::from_utf8(&self.tag[..self.tag_len]).unwrap_or("?")
    }
    fn op_r(&self, o: u64) -> u32 {
        self.bar.r32(self.op + o)
    }
    fn op_w(&self, o: u64, v: u32) {
        self.bar.w32(self.op + o, v)
    }
    fn op_w64(&self, o: u64, v: u64) {
        self.bar.w32(self.op + o, v as u32);
        self.bar.w32(self.op + o + 4, (v >> 32) as u32);
    }
    fn rt_w64(&self, o: u64, v: u64) {
        self.bar.w32(self.rt + o, v as u32);
        self.bar.w32(self.rt + o + 4, (v >> 32) as u32);
    }
    fn portsc(&self, p: u32) -> u32 {
        self.op_r(PORTSC + 0x10 * u64::from(p - 1))
    }
    fn set_portsc(&self, p: u32, v: u32) {
        self.op_w(PORTSC + 0x10 * u64::from(p - 1), v)
    }
    fn ring_doorbell(&self, slot: u32, target: u32) {
        self.bar.w32(self.db + 4 * u64::from(slot), target);
    }
    /// The buffer holding page, and the page's offset in it.
    fn page(&self, page: u64) -> (&Dma, u64) {
        if page >= PG_FUN {
            (&self.fun_mem, (page - PG_FUN) * 4096)
        } else if page >= PG_SLOTS {
            (&self.slot_mem, (page - PG_SLOTS) * 4096)
        } else {
            (&self.mem, page * 4096)
        }
    }
    fn addr(&self, page: u64, off: u64) -> u64 {
        let (m, o) = self.page(page);
        m.dev_addr(o + off)
    }
    fn desc(&self, i: u64) -> u8 {
        self.mem.map.r8(PG_DESC * 4096 + i)
    }

    // ---- rings ----------------------------------------------------------------------------------

    fn put(&self, page: u64, i: u32, t: Trb) {
        let (m, o) = self.page(page);
        let (m, o) = (&m.map, o + u64::from(i) * 16);
        m.w64(o, t.param);
        m.w32(o + 8, t.status);
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        m.w32(o + 12, t.control); // the cycle bit hands the TRB over: written last
    }

    /// Append a TRB (its cycle bit set here); returns its device address.
    fn enqueue(&self, r: &mut Ring, mut t: Trb) -> u64 {
        t.control = (t.control & !TRB_CYCLE) | r.cycle;
        let at = self.addr(r.page, u64::from(r.enq) * 16);
        self.put(r.page, r.enq, t);
        r.enq += 1;
        if r.enq == RING_TRBS - 1 {
            let link = Trb { param: self.addr(r.page, 0), status: 0, control: T_LINK << 10 | TRB_TC | r.cycle };
            self.put(r.page, r.enq, link);
            r.enq = 0;
            r.cycle ^= 1;
        }
        at
    }

    /// The next event, if one is waiting (the dequeue pointer is moved past it).
    fn poll_event(&mut self) -> Option<Trb> {
        let m = &self.mem.map;
        let o = PG_EVENT * 4096 + u64::from(self.ev_deq) * 16;
        let control = m.r32(o + 12);
        if control & TRB_CYCLE != self.ev_cycle {
            return None;
        }
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        let t = Trb { param: m.r64(o), status: m.r32(o + 8), control };
        self.ev_deq += 1;
        if self.ev_deq == RING_TRBS {
            self.ev_deq = 0;
            self.ev_cycle ^= 1;
        }
        self.rt_w64(ERDP, self.addr(PG_EVENT, u64::from(self.ev_deq) * 16) | ERDP_EHB);
        Some(t)
    }

    /// Wait until the interrupt fires or `ms` pass; acknowledge it.
    fn sleep_irq(&self, ms: u64) {
        let _ = sys::object_wait(self.irq, sys::SIGNALED, ms * MS);
        let _ = sys::interrupt_ack(self.irq);
        self.bar.w32(self.rt + IMAN, IMAN_IE | IMAN_IP);
    }

    /// Wait for the event `want` accepts. Root port changes seen meanwhile are noted, keyboard
    /// and mouse reports kept for the main loop, the rest dropped.
    fn wait_event(&mut self, ms: u64, mut want: impl FnMut(&Trb) -> bool) -> Option<Trb> {
        let deadline = sys::clock_ns() + ms * MS;
        let mut eps = [(0u32, 0u32); MAX_KBDS + MAX_MICE];
        for (i, k) in self.kbds.iter().enumerate() {
            eps[i] = k.as_ref().map_or((0, 0), |k| (k.slot, k.dci));
        }
        for (i, m) in self.mice.iter().enumerate() {
            eps[MAX_KBDS + i] = m.as_ref().map_or((0, 0), |m| (m.slot, m.dci));
        }
        loop {
            while let Some(e) = self.poll_event() {
                if want(&e) {
                    return Some(e);
                }
                match e.ty() {
                    E_PORT => {
                        let p = (e.param >> 24) as u32 & 0xFF;
                        if (1..=self.ports).contains(&p) {
                            self.port_events |= 1 << (p - 1);
                        }
                    }
                    E_TRANSFER if eps.iter().any(|&k| k.0 != 0 && (e.slot(), e.endpoint()) == k) && self.ndeferred < self.deferred.len() => {
                        self.deferred[self.ndeferred] = e;
                        self.ndeferred += 1;
                    }
                    _ => {}
                }
            }
            let now = sys::clock_ns();
            if now >= deadline {
                return None;
            }
            self.sleep_irq(((deadline - now) / MS).clamp(1, 10));
        }
    }

    /// Run one command; Ok(completion event) or Err(completion code, 0 = timeout).
    fn command(&mut self, t: Trb) -> Result<Trb, u32> {
        let mut r = core::mem::replace(&mut self.cmd, Ring::new(PG_CMD));
        let at = self.enqueue(&mut r, t);
        self.cmd = r;
        self.ring_doorbell(0, 0);
        let code = match self.wait_event(500, |e| e.ty() == E_COMMAND && e.param == at) {
            Some(e) if e.code() == CC_SUCCESS => return Ok(e),
            Some(e) => e.code(),
            None => 0,
        };
        self.last_cc = code;
        Err(code)
    }

    // ---- endpoint 0 -----------------------------------------------------------------------------

    /// A control transfer on endpoint 0 of `slot`; the data stage (if `len` > 0) uses the
    /// descriptor page. Returns the bytes transferred.
    fn control(&mut self, slot: u32, setup: [u8; 8], len: u16) -> Result<u32, u32> {
        let s = slot as usize;
        let mut ep0 = core::mem::replace(&mut self.ep0[s], Ring::new(0));
        let r = self.control_on(slot, &mut ep0, setup, len);
        self.ep0[s] = ep0;
        if let Err(c) = r {
            self.last_cc = c;
        }
        r
    }

    fn control_on(&mut self, slot: u32, ep0: &mut Ring, setup: [u8; 8], len: u16) -> Result<u32, u32> {
        let input = setup[0] & 0x80 != 0;
        let trt = if len == 0 { 0 } else if input { 3 } else { 2 };
        let s = Trb { param: u64::from_le_bytes(setup), status: 8, control: T_SETUP << 10 | TRB_IDT | trt << 16 };
        self.enqueue(ep0, s);
        if len > 0 {
            let d = Trb { param: self.addr(PG_DESC, 0), status: u32::from(len), control: T_DATA << 10 | TRB_ISP | u32::from(input) << 16 };
            self.enqueue(ep0, d);
        }
        let status_in = len == 0 || !input;
        let st = Trb { param: 0, status: 0, control: T_STATUS << 10 | TRB_IOC | u32::from(status_in) << 16 };
        let at = self.enqueue(ep0, st);
        self.ring_doorbell(slot, 1);
        let e = self.wait_event(1000, |e| e.ty() == E_TRANSFER && e.slot() == slot && e.endpoint() == 1).ok_or(0u32)?;
        // A short data stage ends the transfer at the data TRB (event data: our status TRB or not).
        match e.code() {
            CC_SUCCESS if e.param == at => Ok(u32::from(len)),
            CC_SUCCESS | CC_SHORT => {
                let left = e.status & 0xFF_FFFF;
                if e.param != at {
                    // Short packet on the data stage: the status stage still completes.
                    let _ = self.wait_event(1000, |x| x.ty() == E_TRANSFER && x.slot() == slot && x.param == at);
                }
                Ok(u32::from(len).saturating_sub(left))
            }
            c => Err(c),
        }
    }

    fn get_descriptor(&mut self, slot: u32, ty: u8, len: u16) -> Result<u32, u32> {
        let l = len.to_le_bytes();
        self.control(slot, [0x80, 6, 0, ty, 0, 0, l[0], l[1]], len)
    }

    // ---- contexts -------------------------------------------------------------------------------

    fn ctx_w(&self, page: u64, index: u64, dword: u64, v: u32) {
        self.mem.map.w32(page * 4096 + index * self.csz + dword * 4, v);
    }

    fn clear_page(&self, page: u64) {
        let (m, base) = self.page(page);
        for o in (0..4096).step_by(8) {
            m.map.w64(base + o, 0);
        }
    }

    /// The slot context of the input context: where the device is, `entries` contexts, and for
    /// a hub its port count and think time.
    fn slot_ctx(&self, loc: &Loc, entries: u32, hub_ports: u32, ttt: u32) {
        let hub = u32::from(hub_ports != 0);
        self.ctx_w(PG_IN, 1, 0, loc.route | loc.speed << 20 | hub << 26 | entries << 27);
        self.ctx_w(PG_IN, 1, 1, loc.root << 16 | hub_ports << 24);
        self.ctx_w(PG_IN, 1, 2, loc.tt_slot | loc.tt_port << 8 | ttt << 16);
    }

    /// Input context for Address Device / Evaluate Context: the slot and endpoint 0 (control,
    /// max packet `mps`, the slot's ring).
    fn input_ep0(&self, slot: u32, add: u32, loc: &Loc, mps: u32) {
        self.clear_page(PG_IN);
        self.ctx_w(PG_IN, 0, 1, add);
        self.slot_ctx(loc, 1, 0, 0);
        self.ctx_w(PG_IN, 2, 1, 3 << 1 | 4 << 3 | mps << 16);
        let ring = self.addr(slot_page(slot) + 1, 0) | 1;
        self.ctx_w(PG_IN, 2, 2, ring as u32);
        self.ctx_w(PG_IN, 2, 3, (ring >> 32) as u32);
        self.ctx_w(PG_IN, 2, 4, 8);
    }

    // ---- ports and devices ----------------------------------------------------------------------

    /// Reset root port `p` (USB 2) or check its link (USB 3); true when enabled.
    fn reset_port(&mut self, p: u32) -> bool {
        let sc = self.portsc(p);
        if sc & PS_CCS == 0 {
            return false;
        }
        let usb3 = self.usb3 & (1 << (p - 1)) != 0;
        if usb3 && sc & PS_PED != 0 {
            return true; // a USB 3 link enables itself
        }
        let (bit, done) = if usb3 { (PS_WPR, PS_WRC | PS_PRC) } else { (PS_PR, PS_PRC) };
        self.set_portsc(p, (sc & PS_KEEP) | bit);
        let ok = wait_until(|| self.portsc(p) & done != 0, 500);
        let sc = self.portsc(p);
        self.set_portsc(p, (sc & PS_KEEP) | (sc & PS_CHANGES));
        ok && sc & PS_PED != 0
    }

    fn hub_index(&self, slot: u32) -> Option<usize> {
        self.hubs.iter().position(|h| h.is_some_and(|h| h.slot == slot))
    }

    /// Where the device on (`parent`, `port`) is (speed unknown).
    fn loc_of(&self, parent: u32, port: u32) -> Loc {
        match self.hub_index(parent).and_then(|i| self.hubs[i]) {
            Some(h) if parent != 0 => h.loc.child(parent, port, 0),
            _ => Loc { root: port, ..Loc::default() },
        }
    }

    fn port_state(&mut self, parent: u32, port: u32) -> Option<&mut PortState> {
        if parent == 0 {
            return self.root.get_mut(port.checked_sub(1)? as usize);
        }
        let i = self.hub_index(parent)?;
        self.hubs[i].as_mut()?.ps.get_mut(port.checked_sub(1)? as usize)
    }

    fn hub_status(&mut self, slot: u32, port: u32) -> Result<(u16, u16), u32> {
        if self.control(slot, [0xA3, 0, 0, 0, port as u8, 0, 4, 0], 4)? < 4 {
            return Err(0);
        }
        Ok((u16::from_le_bytes([self.desc(0), self.desc(1)]), u16::from_le_bytes([self.desc(2), self.desc(3)])))
    }

    fn hub_feature(&mut self, slot: u32, port: u32, set: bool, feature: u8) -> Result<u32, u32> {
        self.control(slot, [0x23, if set { 3 } else { 1 }, feature, 0, port as u8, 0, 0, 0], 0)
    }

    /// Reset hub port `port`; the speed of the device there. On a USB 3 hub every device is
    /// SuperSpeed (its USB 2 half has the others).
    fn hub_reset(&mut self, slot: u32, port: u32, ss: bool) -> Result<u32, &'static str> {
        self.hub_feature(slot, port, true, F_PORT_RESET).map_err(|_| "hub port reset refused")?;
        let deadline = sys::clock_ns() + 500 * MS;
        let status = loop {
            sleep(10 * MS);
            let (st, chg) = self.hub_status(slot, port).map_err(|_| "hub port status unreadable")?;
            if chg & HC_RESET != 0 {
                break st;
            }
            if sys::clock_ns() >= deadline {
                return Err("hub port reset timed out");
            }
        };
        let _ = self.hub_feature(slot, port, false, F_C_PORT_RESET);
        if status & HS_ENABLE == 0 {
            return Err("hub port did not enable");
        }
        sleep(20 * MS); // reset recovery (USB 2.0 7.1.7.5: 10 ms)
        if ss {
            return Ok(4);
        }
        Ok(if status & HS_LOW_SPEED != 0 {
            2
        } else if status & HS_HIGH_SPEED != 0 {
            3
        } else {
            1
        })
    }

    /// Probe the device on (`parent` hub slot or 0, `port`); an Address Device failure is retried
    /// once after a new reset.
    fn probe(&mut self, parent: u32, port: u32) -> Result<Found, &'static str> {
        let r = self.probe_once(parent, port);
        if matches!(r, Err(e) if e == ADDR_FAILED) {
            sleep(100 * MS);
            return self.probe_once(parent, port);
        }
        r
    }

    fn probe_once(&mut self, parent: u32, port: u32) -> Result<Found, &'static str> {
        let loc = if parent == 0 {
            if !self.reset_port(port) {
                return Err("port did not enable");
            }
            sleep(20 * MS); // reset recovery
            Loc { root: port, speed: (self.portsc(port) >> 10) & 0xF, ..Loc::default() }
        } else {
            let hub = self.hub_index(parent).and_then(|i| self.hubs[i]).ok_or("hub gone")?;
            let speed = self.hub_reset(parent, port, hub.ss)?;
            hub.loc.child(parent, port, speed)
        };
        let slot = self.command(Trb { param: 0, status: 0, control: T_ENABLE_SLOT << 10 }).map_err(|_| "Enable Slot failed")?.slot();
        if slot == 0 || slot > self.slots || self.owner[slot as usize].1 != 0 {
            return Err("controller returned an invalid slot");
        }
        self.owner[slot as usize] = (parent, port);
        self.ep0[slot as usize] = Ring::new(slot_page(slot) + 1);
        match self.setup_device(slot, loc) {
            Ok(Found::Other(id)) => {
                self.disable_slot(slot);
                Ok(Found::Other(id))
            }
            Ok(f) => Ok(f),
            Err(e) => {
                self.disable_slot(slot);
                Err(e)
            }
        }
    }

    fn disable_slot(&mut self, slot: u32) {
        let _ = self.command(Trb { param: 0, status: 0, control: T_DISABLE_SLOT << 10 | slot << 24 });
        self.mem.map.w64(PG_DCBAA * 4096 + u64::from(slot) * 8, 0);
        self.owner[slot as usize] = (0, 0);
    }

    /// Everything on (`parent`, `port`) is gone: its slot, and for a hub everything below it.
    fn teardown(&mut self, parent: u32, port: u32) {
        for s in 1..=MAX_SLOTS {
            if port == 0 || self.owner[s as usize] != (parent, port) {
                continue;
            }
            if let Some(i) = self.hub_index(s) {
                let (n, loc) = self.hubs[i].map_or((0, Loc::default()), |h| (h.ports, h.loc));
                for p in 1..=n {
                    self.teardown(s, p);
                }
                self.hubs[i] = None;
                say!(self, "hub on port {} unplugged", loc);
            }
            for k in self.kbds.iter_mut() {
                if let Some(k) = k.take_if(|k| k.slot == s) {
                    println!("xhci: keyboard {:04x}:{:04x} on port {} unplugged", k.id.vid, k.id.pid, k.loc);
                    proto::send(self.ctl, proto::KEYBOARD_GONE, u64::from(s), 0);
                }
            }
            for m in self.mice.iter_mut() {
                if let Some(m) = m.take_if(|m| m.slot == s) {
                    println!("xhci: mouse {:04x}:{:04x} on port {} unplugged", m.id.vid, m.id.pid, m.loc);
                }
            }
            for d in self.disks.iter_mut() {
                if let Some(d) = d.take_if(|d| d.slot == s) {
                    println!("xhci: disk {:04x}:{:04x} on port {} unplugged", d.id.vid, d.id.pid, d.loc);
                    if d.ch != 0 {
                        sys::handle_close(d.ch); // the storage service sees the disk go
                    }
                }
            }
            self.disable_slot(s);
        }
    }

    fn setup_device(&mut self, slot: u32, loc: Loc) -> Result<Found, &'static str> {
        let out = slot_page(slot);
        self.clear_page(out);
        self.clear_page(out + 1);
        self.mem.map.w64(PG_DCBAA * 4096 + u64::from(slot) * 8, self.addr(out, 0));
        let mut mps = match loc.speed {
            3 => 64,      // high speed
            4 | 5 => 512, // SuperSpeed (+)
            _ => 8,       // low speed; full speed: read from the device descriptor
        };
        self.input_ep0(slot, 0b11, &loc, mps);
        let addr_cmd = Trb { param: self.addr(PG_IN, 0), status: 0, control: T_ADDRESS_DEVICE << 10 | slot << 24 };
        self.command(addr_cmd).map_err(|_| ADDR_FAILED)?;
        // Endpoint 0's real max packet size (full speed: 8, 16, 32 or 64).
        if self.get_descriptor(slot, 1, 8).map_err(|_| "device descriptor unreadable")? < 8 {
            return Err("device descriptor too short");
        }
        let m0 = u32::from(self.desc(7));
        if loc.speed == 1 && m0 != mps && matches!(m0, 8 | 16 | 32 | 64) {
            mps = m0;
            self.input_ep0(slot, 0b10, &loc, mps);
            let ev = Trb { param: self.addr(PG_IN, 0), status: 0, control: T_EVALUATE_CTX << 10 | slot << 24 };
            self.command(ev).map_err(|_| "Evaluate Context failed")?;
        }
        if self.get_descriptor(slot, 1, 18).map_err(|_| "device descriptor unreadable")? < 18 {
            return Err("device descriptor too short");
        }
        let mut id = Ident {
            vid: u16::from_le_bytes([self.desc(8), self.desc(9)]),
            pid: u16::from_le_bytes([self.desc(10), self.desc(11)]),
            class: self.desc(4),
            sub: self.desc(5),
            proto: self.desc(6),
        };
        // Configuration descriptor: the header for the total length, then all of it (bounded).
        if self.get_descriptor(slot, 2, 9).map_err(|_| "configuration unreadable")? < 9 {
            return Err("configuration descriptor too short");
        }
        let total = u16::from_le_bytes([self.desc(2), self.desc(3)]).min(1024);
        let got = u64::from(self.get_descriptor(slot, 2, total).map_err(|_| "configuration unreadable")?);
        let cfg_value = self.desc(5);
        // The interfaces (alternate setting 0) and their endpoints.
        let mut ifs = [Iface::default(); 8];
        let (mut nif, mut cur, mut first_if) = (0usize, None::<usize>, true);
        // The last endpoint seen (for its SuperSpeed companion): (interface, IN).
        let mut last_ep: Option<(usize, bool)> = None;
        let mut o = 0u64;
        while o + 2 <= got {
            let len = u64::from(self.desc(o));
            let ty = self.desc(o + 1);
            if len < 2 || o + len > got {
                break;
            }
            let b = |i: u64| self.desc(o + i);
            match ty {
                4 if len >= 9 => {
                    if first_if && id.class == 0 {
                        (id.class, id.sub, id.proto) = (b(5), b(6), b(7));
                    }
                    first_if = false;
                    cur = None;
                    last_ep = None;
                    if b(3) == 0 && nif < ifs.len() {
                        ifs[nif] = Iface { num: b(2), class: b(5), sub: b(6), proto: b(7), ..Iface::default() };
                        cur = Some(nif);
                        nif += 1;
                    }
                }
                0x21 if len >= 9 && b(6) == 0x22 => {
                    if let Some(c) = cur {
                        ifs[c].hid_len = u16::from_le_bytes([b(7), b(8)]);
                    }
                }
                5 if len >= 7 => {
                    last_ep = None;
                    let Some(c) = cur else {
                        o += len;
                        continue;
                    };
                    let (addr, attr) = (b(2), b(3) & 3);
                    let mps = u32::from(u16::from_le_bytes([b(4), b(5)]) & 0x7FF);
                    let input = addr & 0x80 != 0;
                    let f = &mut ifs[c];
                    let usable = (attr == 3 && input && f.class == 3) || (attr == 2 && f.class == 8);
                    if usable && input && f.ep_in.is_none() {
                        f.ep_in = Some((addr & 0x0F, mps, b(6), 0));
                        last_ep = Some((c, true));
                    } else if usable && !input && attr == 2 && f.ep_out.is_none() {
                        f.ep_out = Some((addr & 0x0F, mps, 0));
                        last_ep = Some((c, false));
                    }
                }
                0x30 if len >= 6 => {
                    // SuperSpeed endpoint companion: the endpoint's max burst.
                    match last_ep {
                        Some((c, true)) => {
                            if let Some(e) = ifs[c].ep_in.as_mut() {
                                e.3 = b(2).min(15);
                            }
                        }
                        Some((c, false)) => {
                            if let Some(e) = ifs[c].ep_out.as_mut() {
                                e.2 = b(2).min(15);
                            }
                        }
                        None => {}
                    }
                }
                _ => {}
            }
            o += len;
        }
        if id.class == 9 && loc.depth < MAX_DEPTH {
            return self.setup_hub(slot, loc, cfg_value, id);
        }
        let ifs = &ifs[..nif];
        let ok_ep = |e: Option<(u8, u32, u8, u8)>| e.is_some_and(|e| e.0 != 0 && e.1 != 0);
        let kbd = ifs.iter().find(|f| (f.class, f.sub, f.proto) == (3, 1, 1) && ok_ep(f.ep_in)).copied();
        let mouse = ifs.iter().find(|f| f.class == 3 && (f.sub, f.proto) != (1, 1) && ok_ep(f.ep_in)).copied();
        let disk = ifs.iter().find(|f| (f.class, f.sub, f.proto) == (8, 6, 0x50) && ok_ep(f.ep_in) && f.ep_out.is_some_and(|e| e.0 != 0 && e.1 != 0)).copied();
        if kbd.is_some() || mouse.is_some() {
            return self.setup_input(slot, loc, cfg_value, id, kbd, mouse);
        }
        if let Some(d) = disk {
            return self.setup_storage(slot, loc, cfg_value, id, d);
        }
        Ok(Found::Other(id))
    }

    /// The interrupt interval exponent of an endpoint (2^exp * 125 us).
    fn interval_exp(loc: &Loc, interval: u8) -> u32 {
        if loc.speed <= 2 {
            // Full / low speed: bInterval in 1 ms frames.
            (32 - (u32::from(interval.max(1)) * 8).leading_zeros() - 1).clamp(3, 10)
        } else {
            u32::from(interval.clamp(1, 16)) - 1
        }
    }

    /// Endpoint context `dci` of the input context: type (2 bulk OUT, 6 bulk IN, 7 interrupt IN),
    /// max packet, interval, max burst, its ring.
    #[allow(clippy::too_many_arguments)]
    fn ep_ctx(&self, dci: u32, ty: u32, mps: u32, exp: u32, burst: u32, ring_page: u64) {
        let e = u64::from(dci) + 1;
        self.clear_page(ring_page);
        self.ctx_w(PG_IN, e, 0, exp << 16);
        self.ctx_w(PG_IN, e, 1, 3 << 1 | ty << 3 | burst << 8 | mps << 16);
        let ring = self.addr(ring_page, 0) | 1;
        self.ctx_w(PG_IN, e, 2, ring as u32);
        self.ctx_w(PG_IN, e, 3, (ring >> 32) as u32);
        let esit = if ty == 7 { mps * (burst + 1) } else { 0 };
        self.ctx_w(PG_IN, e, 4, (if ty == 7 { mps } else { 3072 }) | esit << 16);
    }

    /// A keyboard, a mouse, or both (one device, e.g. a receiver): configure the device and the
    /// interrupt endpoints, choose the protocols, queue the first reports.
    fn setup_input(&mut self, slot: u32, loc: Loc, cfg_value: u8, id: Ident, kbd: Option<Iface>, mouse: Option<Iface>) -> Result<Found, &'static str> {
        let kidx = kbd.and_then(|_| self.kbds.iter().position(Option::is_none));
        let midx = mouse.and_then(|_| self.mice.iter().position(Option::is_none));
        self.control(slot, [0, 9, cfg_value, 0, 0, 0, 0, 0], 0).map_err(|_| "SET_CONFIGURATION failed")?;
        // A mouse: its report descriptor, or the boot protocol if it offers that.
        let mut fmt = None;
        if let (Some(m), Some(_)) = (mouse, midx) {
            let len = m.hid_len.min(1024);
            if len > 0 {
                let l = len.to_le_bytes();
                if let Ok(got) = self.control(slot, [0x81, 6, 0, 0x22, m.num, 0, l[0], l[1]], len) {
                    let mut d = [0u8; 1024];
                    let n = (got as usize).min(d.len());
                    for (i, x) in d.iter_mut().enumerate().take(n) {
                        *x = self.desc(i as u64);
                    }
                    fmt = parse_mouse(&d[..n]);
                }
            }
            if fmt.is_none() && (m.sub, m.proto) == (1, 2) {
                fmt = Some(BOOT_MOUSE);
            }
        }
        let use_kbd = kbd.zip(kidx);
        let use_mouse = mouse.zip(midx).zip(fmt).map(|((m, i), f)| (m, i, f));
        if use_kbd.is_none() && use_mouse.is_none() {
            return Ok(Found::Other(id));
        }
        self.clear_page(PG_IN);
        let mut add = 1u32;
        let mut top = 1;
        if let Some((k, i)) = use_kbd {
            let (epn, mps, interval, _) = k.ep_in.unwrap_or_default();
            let dci = u32::from(epn) * 2 + 1;
            self.ep_ctx(dci, 7, mps, Self::interval_exp(&loc, interval), 0, PG_INTR + i as u64);
            add |= 1 << dci;
            top = top.max(dci);
        }
        if let Some((m, i, _)) = use_mouse {
            let (epn, mps, interval, _) = m.ep_in.unwrap_or_default();
            let dci = u32::from(epn) * 2 + 1;
            if add & (1 << dci) != 0 {
                return Err("keyboard and mouse share an endpoint");
            }
            self.ep_ctx(dci, 7, mps, Self::interval_exp(&loc, interval), 0, PG_MOUSE + i as u64);
            add |= 1 << dci;
            top = top.max(dci);
        }
        self.ctx_w(PG_IN, 0, 1, add);
        self.slot_ctx(&loc, top, 0, 0);
        let cfg = Trb { param: self.addr(PG_IN, 0), status: 0, control: T_CONFIGURE_EP << 10 | slot << 24 };
        self.command(cfg).map_err(|_| "Configure Endpoint failed")?;
        let mut kb = None;
        if let Some((k, idx)) = use_kbd {
            self.control(slot, [0x21, 0x0B, 0, 0, k.num, 0, 0, 0], 0).map_err(|_| "SET_PROTOCOL(boot) failed")?;
            // Reports only on change. Optional: a device that stalls it still works.
            let _ = self.control(slot, [0x21, 0x0A, 0, 0, k.num, 0, 0, 0], 0);
            let dci = u32::from(k.ep_in.unwrap_or_default().0) * 2 + 1;
            let mut x = Kbd {
                idx,
                id,
                slot,
                loc,
                iface: k.num,
                dci,
                intr: Ring::new(PG_INTR + idx as u64),
                buf_at: [u8::MAX; RING_TRBS as usize],
                last: [0; 8],
                keys: Keys::default(),
                repeat: None,
                leds_caps: false,
                leds_due: false,
            };
            for b in 0..REPORTS as u8 {
                self.queue_report(&mut x, b);
            }
            self.ring_doorbell(slot, dci);
            kb = Some(x);
        }
        let mut ms = None;
        if let Some((m, idx, f)) = use_mouse {
            // Boot-capable interfaces: the protocol chosen explicitly (firmware may have left boot).
            if m.sub == 1 {
                let p = if f.boot { 0 } else { 1 };
                let _ = self.control(slot, [0x21, 0x0B, p, 0, m.num, 0, 0, 0], 0);
            }
            let _ = self.control(slot, [0x21, 0x0A, 0, 0, m.num, 0, 0, 0], 0);
            let (epn, mps, _, _) = m.ep_in.unwrap_or_default();
            let dci = u32::from(epn) * 2 + 1;
            let mut x = Mouse {
                idx,
                id,
                slot,
                loc,
                dci,
                len: mps.min(64),
                intr: Ring::new(PG_MOUSE + idx as u64),
                buf_at: [u8::MAX; RING_TRBS as usize],
                fmt: f,
                buttons: 0,
            };
            for b in 0..REPORTS as u8 {
                self.queue_mouse_report(&mut x, b);
            }
            self.ring_doorbell(slot, dci);
            ms = Some(x);
        }
        Ok(Found::Input(kb, ms))
    }

    /// USB mass storage (bulk-only transport, SCSI): configure the bulk endpoints, then ask the
    /// device what it is and how big.
    fn setup_storage(&mut self, slot: u32, loc: Loc, cfg_value: u8, id: Ident, f: Iface) -> Result<Found, &'static str> {
        let Some(idx) = self.disks.iter().position(Option::is_none) else {
            return Ok(Found::Other(id)); // MAX_DISKS served already
        };
        let ((ie, imps, _, iburst), (oe, omps, oburst)) = (f.ep_in.unwrap_or_default(), f.ep_out.unwrap_or_default());
        self.control(slot, [0, 9, cfg_value, 0, 0, 0, 0, 0], 0).map_err(|_| "SET_CONFIGURATION failed")?;
        let mut d = UsbDisk {
            idx,
            id,
            slot,
            loc,
            iface: f.num,
            in_ep: ie,
            out_ep: oe,
            in_ring: Ring::new(0),
            out_ring: Ring::new(0),
            mps: imps.min(omps),
            tag: 0,
            sectors: 0,
            model: [0; 40],
            model_len: 0,
            ch: 0,
        };
        d.in_ring = Ring::new(d.page(0));
        d.out_ring = Ring::new(d.page(1));
        self.clear_page(PG_IN);
        self.ep_ctx(d.in_dci(), 6, imps, 0, u32::from(iburst), d.page(0));
        self.ep_ctx(d.out_dci(), 2, omps, 0, u32::from(oburst), d.page(1));
        self.ctx_w(PG_IN, 0, 1, 1 | 1 << d.in_dci() | 1 << d.out_dci());
        self.slot_ctx(&loc, d.in_dci().max(d.out_dci()), 0, 0);
        let cfg = Trb { param: self.addr(PG_IN, 0), status: 0, control: T_CONFIGURE_EP << 10 | slot << 24 };
        self.command(cfg).map_err(|_| "Configure Endpoint (storage) failed")?;
        self.disk_init(&mut d)?;
        Ok(Found::Disk(d))
    }

    /// A hub: configure it, tell the controller it is a hub (ports, think time), power its ports;
    /// they are probed once power is good and the connections have settled. A USB 3 hub (on a
    /// SuperSpeed link) also learns its depth, for the route strings of the packets it forwards.
    fn setup_hub(&mut self, slot: u32, loc: Loc, cfg_value: u8, id: Ident) -> Result<Found, &'static str> {
        let i = self.hubs.iter().position(|h| h.is_none()).ok_or("too many hubs")?;
        let ss = loc.speed >= 4;
        self.control(slot, [0, 9, cfg_value, 0, 0, 0, 0, 0], 0).map_err(|_| "SET_CONFIGURATION failed")?;
        let (ty, want) = if ss { (0x2A, 12) } else { (0x29, 9) };
        if self.control(slot, [0xA0, 6, 0, ty, 0, 0, want, 0], u16::from(want)).map_err(|_| "hub descriptor unreadable")? < 7 {
            return Err("hub descriptor too short");
        }
        let ports = u32::from(self.desc(2)).min(HUB_PORTS);
        if ports == 0 {
            return Err("hub without ports");
        }
        let ttt = if ss { 0 } else { (u32::from(self.desc(3)) >> 5) & 3 };
        let power_good = u64::from(self.desc(5)) * 2 * MS;
        if ss {
            // Depth below the root port: 0 for a hub on a root port.
            self.control(slot, [0x20, REQ_SET_HUB_DEPTH, loc.depth as u8, 0, 0, 0, 0, 0], 0).map_err(|_| "SET_HUB_DEPTH failed")?;
        }
        self.clear_page(PG_IN);
        self.ctx_w(PG_IN, 0, 1, 1);
        self.slot_ctx(&loc, 1, ports, ttt);
        let cfg = Trb { param: self.addr(PG_IN, 0), status: 0, control: T_CONFIGURE_EP << 10 | slot << 24 };
        self.command(cfg).map_err(|_| "Configure Endpoint (hub) failed")?;
        for p in 1..=ports {
            self.hub_feature(slot, p, true, F_PORT_POWER).map_err(|_| "hub port power refused")?;
        }
        let ready = PortState { pending: true, changed_at: sys::clock_ns() + power_good.max(DEBOUNCE), ..PortState::default() };
        self.hubs[i] = Some(Hub { slot, loc, ports, ss, dead: false, ps: [ready; HUB_PORTS as usize] });
        Ok(Found::Hub(ports, id, ss))
    }

    // ---- mass storage (bulk-only transport) -----------------------------------------------------

    /// One transfer on a bulk endpoint of `d`: `len` bytes at `off` of page `page` (several pages
    /// if `off` is 0), one TRB per page. Ok(bytes moved) or Err(completion code, 0 = timeout).
    fn bulk(&mut self, d: &mut UsbDisk, input: bool, page: u64, off: u64, len: u32) -> Result<u32, u32> {
        let (dci, mut ring) = if input {
            (d.in_dci(), core::mem::replace(&mut d.in_ring, Ring::new(0)))
        } else {
            (d.out_dci(), core::mem::replace(&mut d.out_ring, Ring::new(0)))
        };
        let r = self.bulk_on(d.slot, dci, &mut ring, page, off, len, d.mps);
        if input {
            d.in_ring = ring;
        } else {
            d.out_ring = ring;
        }
        if let Err(c) = r {
            self.last_cc = c;
        }
        r
    }

    #[allow(clippy::too_many_arguments)]
    fn bulk_on(&mut self, slot: u32, dci: u32, ring: &mut Ring, page: u64, off: u64, len: u32, mps: u32) -> Result<u32, u32> {
        let n = (len as usize).div_ceil(4096).clamp(1, DATA_PAGES as usize);
        let mut at = [0u64; DATA_PAGES as usize];
        let mut lens = [0u32; DATA_PAGES as usize];
        for k in 0..n {
            let l = (len - (k as u32) * 4096).min(4096);
            let last = k == n - 1;
            // TD Size: packets still to come after this TRB (at most 31).
            let left = len - (k as u32) * 4096 - l;
            let td = left.div_ceil(mps.max(1)).min(31);
            let ctl = T_NORMAL << 10 | TRB_ISP | if last { TRB_IOC } else { TRB_CH };
            lens[k] = l;
            at[k] = self.enqueue(ring, Trb { param: self.addr(page + k as u64, if k == 0 { off } else { 0 }), status: l | td << 17, control: ctl });
        }
        self.ring_doorbell(slot, dci);
        let last = at[n - 1];
        let e = self.wait_event(5000, |e| e.ty() == E_TRANSFER && e.slot() == slot && e.endpoint() == dci).ok_or(0u32)?;
        match e.code() {
            CC_SUCCESS if e.param == last => Ok(len),
            CC_SUCCESS | CC_SHORT => {
                let k = at[..n].iter().position(|&a| a == e.param).ok_or(0u32)?;
                let moved = (k as u32) * 4096 + lens[k].saturating_sub(e.status & 0xFF_FFFF);
                if e.param != last {
                    // The end of the TD may still report.
                    let _ = self.wait_event(20, |x| x.ty() == E_TRANSFER && x.slot() == slot && x.param == last);
                }
                Ok(moved)
            }
            c => Err(c),
        }
    }

    /// A halted (stalled) endpoint: reset it, move its dequeue pointer past what was queued, and
    /// clear the device's halt.
    fn clear_halt(&mut self, d: &mut UsbDisk, input: bool) {
        let (dci, ep, ring) = if input { (d.in_dci(), d.in_ep | 0x80, &d.in_ring) } else { (d.out_dci(), d.out_ep, &d.out_ring) };
        let deq = self.addr(ring.page, u64::from(ring.enq) * 16) | u64::from(ring.cycle);
        let _ = self.command(Trb { param: 0, status: 0, control: T_RESET_EP << 10 | dci << 16 | d.slot << 24 });
        let _ = self.command(Trb { param: deq, status: 0, control: T_SET_TR_DEQ << 10 | dci << 16 | d.slot << 24 });
        let _ = self.control(d.slot, [0x02, 1, 0, 0, ep, 0, 0, 0], 0);
    }

    /// Bulk-only reset recovery (BOT 5.3.4): the class reset, then both halts cleared.
    fn reset_recovery(&mut self, d: &mut UsbDisk) {
        let _ = self.control(d.slot, [0x21, 0xFF, 0, 0, d.iface, 0, 0, 0], 0);
        self.clear_halt(d, true);
        self.clear_halt(d, false);
    }

    /// One SCSI command through the bulk-only transport: CBW, data (`len` bytes in the disk's data
    /// pages, in or out), CSW. Ok(residue); Err when the command failed or the transport broke.
    fn bot(&mut self, d: &mut UsbDisk, cdb: &[u8], len: u32, input: bool) -> Result<u32, &'static str> {
        d.tag = d.tag.wrapping_add(1);
        let cmd = d.page(2);
        {
            let (m, base) = self.page(cmd);
            let m = &m.map;
            let o = base + CBW;
            m.w32(o, 0x4342_5355);
            m.w32(o + 4, d.tag);
            m.w32(o + 8, len);
            m.w8(o + 12, if input { 0x80 } else { 0 });
            m.w8(o + 13, 0); // LUN 0
            m.w8(o + 14, cdb.len().min(16) as u8);
            for i in 0..16u64 {
                m.w8(o + 15 + i, cdb.get(i as usize).copied().unwrap_or(0));
            }
        }
        if self.bulk(d, false, cmd, CBW, 31).is_err() {
            self.reset_recovery(d);
            return Err("command block refused");
        }
        if len > 0 {
            match self.bulk(d, input, d.page(3), 0, len) {
                Ok(_) => {}
                Err(CC_STALL) => self.clear_halt(d, input),
                Err(_) => {
                    self.reset_recovery(d);
                    return Err("data transfer failed");
                }
            }
        }
        let mut got = self.bulk(d, true, cmd, CSW, 13);
        if got == Err(CC_STALL) {
            self.clear_halt(d, true);
            got = self.bulk(d, true, cmd, CSW, 13);
        }
        if got != Ok(13) {
            self.reset_recovery(d);
            return Err("no command status");
        }
        let (m, base) = self.page(cmd);
        let o = base + CSW;
        let (sig, tag, residue, status) = (m.map.r32(o), m.map.r32(o + 4), m.map.r32(o + 8), m.map.r8(o + 12));
        if sig != 0x5342_5355 || tag != d.tag {
            self.reset_recovery(d);
            return Err("bad command status");
        }
        match status {
            0 => Ok(residue),
            1 => Err("command failed"),
            _ => {
                self.reset_recovery(d);
                Err("phase error")
            }
        }
    }

    /// INQUIRY, TEST UNIT READY (until ready, bounded), READ CAPACITY.
    fn disk_init(&mut self, d: &mut UsbDisk) -> Result<(), &'static str> {
        self.bot(d, &[0x12, 0, 0, 0, 36, 0], 36, true)?;
        let data = d.page(3);
        let mut model = [0u8; 40];
        let mut n = 0;
        let (m, base) = self.page(data);
        // Vendor (8-15) and product (16-31), spaces trimmed.
        for i in 8..32u64 {
            let c = m.map.r8(base + i);
            if i == 16 && n > 0 && model[n - 1] != b' ' {
                model[n] = b' ';
                n += 1;
            }
            if (b' '..=b'~').contains(&c) && !(c == b' ' && (n == 0 || model[n - 1] == b' ')) {
                model[n] = c;
                n += 1;
            }
        }
        while n > 0 && model[n - 1] == b' ' {
            n -= 1;
        }
        (d.model, d.model_len) = (model, n);
        let mut ready = false;
        for _ in 0..20 {
            if self.bot(d, &[0, 0, 0, 0, 0, 0], 0, false).is_ok() {
                ready = true;
                break;
            }
            let _ = self.bot(d, &[0x03, 0, 0, 0, 18, 0], 18, true); // REQUEST SENSE clears the condition
            sleep(100 * MS);
        }
        if !ready {
            return Err("medium not ready");
        }
        self.bot(d, &[0x25, 0, 0, 0, 0, 0, 0, 0, 0, 0], 8, true)?;
        let (m, base) = self.page(data);
        let be32 = |o: u64| u32::from_be_bytes([m.map.r8(base + o), m.map.r8(base + o + 1), m.map.r8(base + o + 2), m.map.r8(base + o + 3)]);
        let (mut last, mut bl) = (u64::from(be32(0)), be32(4));
        if last == 0xFFFF_FFFF {
            self.bot(d, &[0x9E, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0], 32, true)?;
            let (m, base) = self.page(data);
            let be32 = |o: u64| u32::from_be_bytes([m.map.r8(base + o), m.map.r8(base + o + 1), m.map.r8(base + o + 2), m.map.r8(base + o + 3)]);
            last = u64::from(be32(0)) << 32 | u64::from(be32(4));
            bl = be32(8);
        }
        if bl != 512 {
            return Err("sector size is not 512 bytes");
        }
        d.sectors = last.checked_add(1).ok_or("bad capacity")?;
        Ok(())
    }

    /// Read (`out`) or write (`data`) `count` sectors at `lba` on disk `unit`.
    fn disk_io(&mut self, unit: usize, lba: u64, count: u64, out: Option<&mut [u8]>, data: Option<&[u8]>) -> Result<(), i32> {
        let Some(mut d) = self.disks.get_mut(unit).and_then(Option::take) else { return Err(sys::ERR_BAD_STATE as i32) };
        let r = self.disk_io_on(&mut d, lba, count, out, data);
        self.disks[unit] = Some(d);
        self.requests += 1;
        r
    }

    fn disk_io_on(&mut self, d: &mut UsbDisk, lba: u64, count: u64, out: Option<&mut [u8]>, data: Option<&[u8]>) -> Result<(), i32> {
        let write = data.is_some();
        let bytes = count as usize * 512;
        if count == 0 || count > DATA_PAGES * 8 {
            return Err(sys::ERR_INVALID_ARGS as i32);
        }
        if let Some(src) = data {
            let base = (d.page(3) - PG_FUN) as usize * 4096;
            self.fun_mem.map.bytes_mut()[base..base + bytes].copy_from_slice(&src[..bytes]);
        }
        let mut cdb = [0u8; 16];
        let len = if lba + count <= 1 << 32 {
            cdb[0] = if write { 0x2A } else { 0x28 };
            cdb[2..6].copy_from_slice(&(lba as u32).to_be_bytes());
            cdb[7..9].copy_from_slice(&(count as u16).to_be_bytes());
            10
        } else {
            cdb[0] = if write { 0x8A } else { 0x88 };
            cdb[2..10].copy_from_slice(&lba.to_be_bytes());
            cdb[10..14].copy_from_slice(&(count as u32).to_be_bytes());
            16
        };
        match self.bot(d, &cdb[..len], bytes as u32, !write) {
            Ok(0) => {}
            Ok(_) => return Err(sys::ERR_OUT_OF_RANGE as i32), // short: the device did less
            Err(why) => {
                say!(self, "disk on port {}: {} at sector {} ({})", d.loc, if write { "write" } else { "read" }, lba, why);
                return Err(sys::ERR_BAD_STATE as i32);
            }
        }
        if let Some(out) = out {
            let base = (d.page(3) - PG_FUN) as usize * 4096;
            out[..bytes].copy_from_slice(&self.fun_mem.map.bytes()[base..base + bytes]);
        }
        Ok(())
    }

    fn disk_flush(&mut self, unit: usize) -> Result<(), i32> {
        let Some(mut d) = self.disks.get_mut(unit).and_then(Option::take) else { return Err(sys::ERR_BAD_STATE as i32) };
        // SYNCHRONIZE CACHE (10); a device without a cache may refuse it: not an error.
        let r = self.bot(&mut d, &[0x35, 0, 0, 0, 0, 0, 0, 0, 0, 0], 0, false);
        self.disks[unit] = Some(d);
        match r {
            Ok(_) | Err("command failed") => Ok(()),
            Err(_) => Err(sys::ERR_BAD_STATE as i32),
        }
    }

    /// Probe (`parent`, `port`) and record the outcome: report it once, serve a keyboard, and
    /// leave a device that keeps reconnecting alone.
    fn probe_port(&mut self, parent: u32, port: u32, now: u64) {
        let r = self.probe(parent, port);
        let at = match &r {
            Ok(Found::Input(Some(k), _)) => k.loc,
            Ok(Found::Input(None, Some(m))) => m.loc,
            Ok(Found::Disk(d)) => d.loc,
            _ => self.loc_of(parent, port),
        };
        let key = match &r {
            Ok(Found::Input(..)) | Ok(Found::Disk(_)) => 0,
            Ok(Found::Hub(_, id, _)) | Ok(Found::Other(id)) => id.key(),
            Err(_) => u32::MAX,
        };
        let Some(ps) = self.port_state(parent, port) else { return };
        let repeat = key != 0 && ps.last == key && now.saturating_sub(ps.last_probe) < REPEAT_WINDOW;
        ps.strikes = if repeat { ps.strikes.saturating_add(1) } else { 0 };
        (ps.last, ps.last_probe, ps.done) = (key, now, true);
        let give_up = ps.strikes >= MAX_STRIKES;
        if give_up {
            (ps.ignored, ps.gone_since) = (true, 0);
        }
        match r {
            Ok(Found::Input(k, m)) => {
                if let Some(k) = k {
                    say!(self, "keyboard ready on port {} (USB HID boot protocol, US layout, slot {}): {:04x}:{:04x}", at, k.slot, k.id.vid, k.id.pid);
                    let i = k.idx;
                    self.kbds[i] = Some(k);
                }
                if let Some(m) = m {
                    let f = m.fmt;
                    say!(
                        self,
                        "mouse ready on port {} (USB HID {} protocol, {} buttons{}, slot {}): {:04x}:{:04x}",
                        at,
                        if f.boot { "boot" } else { "report" },
                        f.buttons.size,
                        if f.wheel.is_some() { ", wheel" } else { "" },
                        m.slot,
                        m.id.vid,
                        m.id.pid
                    );
                    let i = m.idx;
                    self.mice[i] = Some(m);
                }
            }
            Ok(Found::Disk(d)) => {
                let model = core::str::from_utf8(&d.model[..d.model_len]).unwrap_or("?");
                say!(self, "disk ready on port {}: {} MiB, \"{}\" (USB mass storage, unit {}, slot {}): {:04x}:{:04x}", at, d.sectors / 2048, model, d.idx, d.slot, d.id.vid, d.id.pid);
                let mut m = [0u8; HEADER + 40];
                Header { txid: 0, op: proto::DISK, status: 0, a: d.idx as u64, b: d.sectors }.put(&mut m);
                m[HEADER..HEADER + d.model_len].copy_from_slice(&d.model[..d.model_len]);
                sys::channel_write(self.ctl, &m[..HEADER + d.model_len]);
                let i = d.idx;
                self.disks[i] = Some(d);
            }
            Ok(Found::Hub(n, id, ss)) if !repeat => say!(self, "port {}: hub {:04x}:{:04x}, {} ports{}", at, id.vid, id.pid, n, if ss { " (USB 3)" } else { "" }),
            Ok(Found::Other(id)) if !repeat => say!(self, "port {}: {} {:04x}:{:04x} (left unused)", at, id.kind(), id.vid, id.pid),
            Err(e) if !repeat => say!(self, "port {}: device not set up ({}, completion code {})", at, e, self.last_cc),
            _ => {}
        }
        if give_up {
            say!(self, "port {}: device keeps reconnecting; left alone until unplugged", at);
        }
    }

    // ---- watching ports -------------------------------------------------------------------------

    /// Root port changes: a connect change (or an empty port) ends what was there; a connection
    /// is probed after its debounce. Our own port resets also report changes: they are ignored.
    fn root_changes(&mut self, now: u64) {
        let changed = core::mem::take(&mut self.port_events);
        for p in 1..=self.ports {
            if changed & (1 << (p - 1)) == 0 {
                continue;
            }
            let sc = self.portsc(p);
            self.set_portsc(p, (sc & PS_KEEP) | (sc & PS_CHANGES));
            if sc & PS_CSC == 0 && sc & PS_CCS != 0 {
                continue;
            }
            self.teardown(0, p);
            let ps = &mut self.root[(p - 1) as usize];
            ps.done = false;
            if sc & PS_CCS != 0 {
                ps.gone_since = 0;
                if !ps.ignored {
                    (ps.pending, ps.changed_at) = (true, now);
                }
            } else {
                ps.pending = false;
                if ps.gone_since == 0 {
                    ps.gone_since = now;
                }
            }
        }
    }

    /// Ports waiting for a probe, ports left alone that emptied, hub ports.
    fn service(&mut self, now: u64) {
        for p in 1..=self.ports {
            let i = (p - 1) as usize;
            if self.root[i].ignored {
                let empty = self.portsc(p) & PS_CCS == 0;
                let ps = &mut self.root[i];
                if !empty {
                    ps.gone_since = 0;
                } else if ps.gone_since == 0 {
                    ps.gone_since = now;
                } else if now - ps.gone_since >= GONE_FOR {
                    *ps = PortState::default();
                }
                continue;
            }
            let ps = self.root[i];
            if ps.pending && now >= ps.changed_at + DEBOUNCE {
                self.root[i].pending = false;
                if self.portsc(p) & PS_CCS != 0 && !ps.done {
                    self.probe_port(0, p, now);
                }
            }
        }
        let due = now >= self.next_poll;
        if due {
            self.next_poll = now + HUB_POLL;
        }
        for h in 0..MAX_HUBS {
            let Some(hub) = self.hubs[h] else { continue };
            let pending = hub.ps[..hub.ports as usize].iter().any(|p| p.pending);
            if hub.dead || !(due || pending) {
                continue;
            }
            self.poll_hub(h, hub.slot, hub.ports, now);
        }
    }

    fn poll_hub(&mut self, h: usize, slot: u32, ports: u32, now: u64) {
        for port in 1..=ports {
            let Ok((st, chg)) = self.hub_status(slot, port) else {
                if let Some(hub) = self.hubs[h].as_mut() {
                    hub.dead = true;
                    let loc = hub.loc;
                    say!(self, "hub on port {} stopped answering", loc);
                }
                return;
            };
            let ss = self.hubs[h].is_some_and(|x| x.ss);
            for b in 0..8u8 {
                let feature = match b {
                    0..=4 => F_C_PORT_CONNECTION + b,
                    5 if ss => F_C_BH_PORT_RESET,
                    6 if ss => F_C_PORT_LINK_STATE,
                    7 if ss => F_C_PORT_CONFIG_ERROR,
                    _ => continue,
                };
                if chg & (1 << b) != 0 {
                    let _ = self.hub_feature(slot, port, false, feature);
                }
            }
            let connected = st & HS_CONNECTION != 0;
            if chg & HC_CONNECTION != 0 {
                self.teardown(slot, port);
            }
            let Some(ps) = self.port_state(slot, port) else { return };
            if chg & HC_CONNECTION != 0 {
                ps.done = false;
                if connected && !ps.ignored {
                    (ps.pending, ps.changed_at) = (true, now);
                }
            }
            if ps.ignored {
                if connected {
                    ps.gone_since = 0;
                } else if ps.gone_since == 0 {
                    ps.gone_since = now;
                } else if now - ps.gone_since >= GONE_FOR {
                    *ps = PortState::default();
                }
                continue;
            }
            if !connected {
                ps.pending = false;
                continue;
            }
            if ps.pending && now >= ps.changed_at + DEBOUNCE && !ps.done {
                ps.pending = false;
                self.probe_port(slot, port, now);
                if self.hubs[h].is_none_or(|x| x.slot != slot) {
                    return;
                }
            }
        }
    }

    /// How long the main loop may sleep: briefly while connections settle, a second while hubs
    /// are polled or ports are left alone, until the next key repeat, otherwise until an interrupt.
    fn wake_after(&self, now: u64) -> u64 {
        let repeat = self.kbds.iter().flatten().filter_map(|k| k.repeat.map(|r| r.2.saturating_sub(now).max(MS))).min();
        let live = |h: &&Hub| !h.dead;
        let hubs = self.hubs.iter().flatten().filter(live);
        let base = {
            let root = self.root[..self.ports as usize].iter().any(|p| p.pending);
            if root || hubs.clone().any(|h| h.ps[..h.ports as usize].iter().any(|p| p.pending)) {
                SETTLE_TICK
            } else if hubs.count() > 0 || self.root[..self.ports as usize].iter().any(|p| p.ignored) {
                HUB_POLL
            } else {
                sys::WAIT_FOREVER
            }
        };
        repeat.map_or(base, |r| r.min(base))
    }

    // ---- keyboard and mouse reports -------------------------------------------------------------

    fn queue_report(&self, k: &mut Kbd, buf: u8) {
        let pos = k.intr.enq as usize;
        let t = Trb { param: self.addr(PG_REPORT, report_off(k.idx, buf)), status: 8, control: T_NORMAL << 10 | TRB_IOC | TRB_ISP };
        k.buf_at[pos] = buf;
        let mut r = core::mem::replace(&mut k.intr, Ring::new(PG_INTR + k.idx as u64));
        self.enqueue(&mut r, t);
        k.intr = r;
    }

    fn queue_mouse_report(&self, m: &mut Mouse, buf: u8) {
        let pos = m.intr.enq as usize;
        let t = Trb { param: self.addr(PG_MOUSE_REPORT, report_off(m.idx, buf)), status: m.len, control: T_NORMAL << 10 | TRB_IOC | TRB_ISP };
        m.buf_at[pos] = buf;
        let mut r = core::mem::replace(&mut m.intr, Ring::new(PG_MOUSE + m.idx as u64));
        self.enqueue(&mut r, t);
        m.intr = r;
    }

    /// The report buffer a transfer event on an interrupt ring finished, after checking the event
    /// points at a TRB of that ring that has one queued.
    fn finished(&self, ring_page: u64, buf_at: &mut [u8; RING_TRBS as usize], e: &Trb) -> Result<u8, &'static str> {
        let base = self.addr(ring_page, 0);
        if e.param < base || e.param >= base + u64::from(RING_TRBS - 1) * 16 || !(e.param - base).is_multiple_of(16) {
            return Err("transfer event for a TRB that is not ours");
        }
        let buf = core::mem::replace(&mut buf_at[((e.param - base) / 16) as usize], u8::MAX);
        if usize::from(buf) >= REPORTS {
            return Err("transfer event for a TRB that is not queued");
        }
        match e.code() {
            CC_SUCCESS | CC_SHORT => Ok(buf),
            c => {
                println!("xhci: report transfer failed with completion code {}", c);
                Err("transfer failed (device gone?)")
            }
        }
    }

    /// A finished keyboard report: diff it against the last one, send the keys, note the key to
    /// repeat and whether the LEDs changed, requeue.
    fn report(&mut self, k: &mut Kbd, e: &Trb, ch: Handle) -> Result<(), &'static str> {
        let buf = self.finished(PG_INTR + k.idx as u64, &mut k.buf_at, e)?;
        let got = 8u32.saturating_sub(e.status & 0xFF_FFFF);
        if got >= 3 {
            self.reports += 1;
            let mut r = [0u8; 8];
            for (i, x) in r.iter_mut().enumerate().take(got as usize) {
                *x = self.mem.map.r8(PG_REPORT * 4096 + report_off(k.idx, buf) + i as u64);
            }
            // Rollover (too many keys): every key slot reads 1; keep the last state.
            if r[2] != 1 {
                let (typed, n, held) = diff(&mut k.keys, &k.last, &r);
                for &c in &typed[..n] {
                    proto::send(ch, proto::KEY, u64::from(c), u64::from(k.slot));
                }
                let now = sys::clock_ns();
                match held {
                    Some((u, v)) => k.repeat = Some((v, u, now + REPEAT_DELAY)),
                    None => {
                        if k.repeat.is_some_and(|(_, u, _)| !r[2..].contains(&u)) {
                            k.repeat = None;
                        }
                    }
                }
                k.last = r;
                if k.keys.caps() != k.leds_caps {
                    k.leds_due = true;
                }
            }
        }
        self.queue_report(k, buf);
        self.ring_doorbell(k.slot, k.dci);
        Ok(())
    }

    /// The keyboard's LEDs follow Caps Lock (SET_REPORT, output report: bit 1 Caps Lock).
    fn set_leds(&mut self, i: usize) {
        let Some((slot, iface, caps)) = self.kbds[i].as_ref().map(|k| (k.slot, k.iface, k.keys.caps())) else { return };
        if let Some(k) = self.kbds[i].as_mut() {
            (k.leds_caps, k.leds_due) = (caps, false);
        }
        self.mem.map.w8(PG_DESC * 4096, if caps { 2 } else { 0 });
        if self.control(slot, [0x21, 0x09, 0, 0x02, iface, 0, 1, 0], 1).is_err() {
            say!(self, "keyboard in slot {}: LED report refused (completion code {})", slot, self.last_cc);
        }
    }

    /// A finished mouse report: the movement, wheel and buttons to the device manager; requeue.
    fn mouse_report(&mut self, m: &mut Mouse, e: &Trb, ch: Handle) -> Result<(), &'static str> {
        let buf = self.finished(PG_MOUSE + m.idx as u64, &mut m.buf_at, e)?;
        let got = m.len.saturating_sub(e.status & 0xFF_FFFF) as usize;
        let mut r = [0u8; 64];
        let base = report_off(m.idx, buf);
        let (mem, off) = self.page(PG_MOUSE_REPORT);
        for (i, x) in r.iter_mut().enumerate().take(got.min(64)) {
            *x = mem.map.r8(off + base + i as u64);
        }
        let f = m.fmt;
        let data = if f.id != 0 {
            if got == 0 || r[0] != f.id {
                None // another report of the device (e.g. a receiver's keyboard keys)
            } else {
                Some(&r[1..got.min(64)])
            }
        } else {
            Some(&r[..got.min(64)])
        };
        if let Some(d) = data
            && !d.is_empty()
        {
            self.reports += 1;
            let (dx, dy) = (f.x.get(d), f.y.get(d));
            let wheel = f.wheel.map_or(0, |w| w.get(d)).clamp(-127, 127);
            let buttons = (f.buttons.get(d) as u32) & 0xFF;
            if dx != 0 || dy != 0 || wheel != 0 || buttons != m.buttons {
                m.buttons = buttons;
                let a = u64::from(dx as u32) | u64::from(dy as u32) << 32;
                let b = u64::from(buttons) | u64::from(wheel as i8 as u8) << 8 | (m.idx as u64) << 16;
                proto::send(ch, proto::POINTER, a, b);
            }
        }
        self.queue_mouse_report(m, buf);
        self.ring_doorbell(m.slot, m.dci);
        Ok(())
    }

    fn on_event(&mut self, e: Trb, ch: Handle) {
        match e.ty() {
            E_TRANSFER => {
                let at = (e.slot(), e.endpoint());
                if let Some(i) = self.kbds.iter().position(|k| k.as_ref().is_some_and(|k| at == (k.slot, k.dci))) {
                    let Some(mut k) = self.kbds[i].take() else { return };
                    match self.report(&mut k, &e, ch) {
                        Ok(()) => {
                            let due = k.leds_due;
                            self.kbds[i] = Some(k);
                            if due {
                                self.set_leds(i);
                            }
                        }
                        Err(why) => {
                            say!(self, "keyboard {:04x}:{:04x} on port {}: {}", k.id.vid, k.id.pid, k.loc, why);
                            proto::send(ch, proto::KEYBOARD_GONE, u64::from(k.slot), 0);
                            self.drop_slot(k.slot);
                        }
                    }
                } else if let Some(i) = self.mice.iter().position(|m| m.as_ref().is_some_and(|m| at == (m.slot, m.dci))) {
                    let Some(mut m) = self.mice[i].take() else { return };
                    match self.mouse_report(&mut m, &e, ch) {
                        Ok(()) => self.mice[i] = Some(m),
                        Err(why) => {
                            say!(self, "mouse {:04x}:{:04x} on port {}: {}", m.id.vid, m.id.pid, m.loc, why);
                            self.drop_slot(m.slot);
                        }
                    }
                }
            }
            E_PORT => {
                let p = (e.param >> 24) as u32 & 0xFF;
                if (1..=self.ports).contains(&p) {
                    self.port_events |= 1 << (p - 1);
                }
            }
            _ => {}
        }
    }

    /// A device whose transfers failed: everything on its slot ends (a receiver's other
    /// interface too), the slot is disabled.
    fn drop_slot(&mut self, slot: u32) {
        for k in self.kbds.iter_mut() {
            if k.take_if(|k| k.slot == slot).is_some() {
                proto::send(self.ctl, proto::KEYBOARD_GONE, u64::from(slot), 0);
            }
        }
        for m in self.mice.iter_mut() {
            let _ = m.take_if(|m| m.slot == slot);
        }
        self.disable_slot(slot);
    }

    /// Held keys that are due repeat (each keyboard on its own).
    fn repeat_keys(&mut self, ch: Handle, now: u64) {
        for k in self.kbds.iter_mut().flatten() {
            if let Some((v, u, next)) = k.repeat
                && now >= next
            {
                proto::send(ch, proto::KEY, u64::from(v), u64::from(k.slot));
                let next = if next + REPEAT_EVERY > now { next + REPEAT_EVERY } else { now + REPEAT_EVERY };
                k.repeat = Some((v, u, next));
            }
        }
    }

    /// Handle the events kept during waits, then the new ones.
    fn drain(&mut self, ch: Handle) {
        let n = core::mem::take(&mut self.ndeferred);
        for i in 0..n {
            let e = self.deferred[i];
            self.on_event(e, ch);
        }
        for _ in 0..RING_TRBS {
            let Some(e) = self.poll_event() else { break };
            self.on_event(e, ch);
        }
    }
}

/// The block-device view of the USB disks (blkserve.rs): unit = disk index.
struct UsbDisks<'a>(&'a mut Xhci);

impl crate::blkserve::Disk for UsbDisks<'_> {
    fn units(&self) -> usize {
        MAX_DISKS
    }
    fn capacity(&self, unit: usize) -> u64 {
        self.0.disks.get(unit).and_then(|d| d.as_ref()).map_or(0, |d| d.sectors)
    }
    fn model(&self, unit: usize) -> &[u8] {
        self.0.disks.get(unit).and_then(|d| d.as_ref()).map_or(&[], |d| &d.model[..d.model_len])
    }
    fn read(&mut self, unit: usize, lba: u64, count: u64, out: &mut [u8]) -> Result<(), i32> {
        self.0.disk_io(unit, lba, count, Some(out), None)
    }
    fn write(&mut self, unit: usize, lba: u64, count: u64, data: &[u8]) -> Result<(), i32> {
        self.0.disk_io(unit, lba, count, None, Some(data))
    }
    fn flush(&mut self, unit: usize) -> Result<(), i32> {
        self.0.disk_flush(unit)
    }
    fn stats(&self) -> (u64, u64) {
        (0, self.0.requests)
    }
}

/// Where report buffer `buf` of keyboard `idx` is in the report page.
fn report_off(idx: usize, buf: u8) -> u64 {
    ((idx * REPORTS) as u64 + u64::from(buf)) * 64
}

/// Output device context page of `slot` (its endpoint 0 ring is the next page).
fn slot_page(slot: u32) -> u64 {
    PG_SLOTS + 2 * u64::from(slot - 1)
}

fn wait_until(mut f: impl FnMut() -> bool, ms: u64) -> bool {
    let deadline = sys::clock_ns() + ms * MS;
    while sys::clock_ns() < deadline {
        if f() {
            return true;
        }
        sys::yield_now();
    }
    f()
}

/// HID keyboard usage (boot report) -> the keymap's key code (PC set 1 / Linux input codes).
fn usage_code(u: u8) -> Option<u16> {
    const LETTERS: [u8; 26] = [30, 48, 46, 32, 18, 33, 34, 35, 23, 36, 37, 38, 50, 49, 24, 25, 16, 19, 31, 20, 22, 47, 17, 45, 21, 44];
    const OTHER: [u8; 21] = [28, 1, 14, 15, 57, 12, 13, 26, 27, 43, 43, 39, 40, 41, 51, 52, 53, 58, 0, 0, 0];
    match u {
        0x04..=0x1D => Some(u16::from(LETTERS[usize::from(u - 0x04)])),
        0x1E..=0x26 => Some(u16::from(u - 0x1E + 2)), // 1-9
        0x27 => Some(11),                              // 0
        0x28..=0x39 => Some(u16::from(OTHER[usize::from(u - 0x28)])).filter(|&c| c != 0),
        // Insert, Home, PgUp, Delete, End, PgDn, Right, Left, Down, Up: the keypad's set 1 codes.
        0x49..=0x52 => Some([82, 71, 73, 83, 79, 81, 77, 75, 80, 72][usize::from(u - 0x49)]),
        _ => None,
    }
}

/// Feed the change from `old` to `new` (boot reports) through `keys`: the key values typed (and
/// how many), and the last newly pressed key that typed something (usage, value), to repeat.
fn diff(keys: &mut Keys, old: &[u8; 8], new: &[u8; 8]) -> ([u32; 8], usize, Option<(u8, u32)>) {
    let mut out = [0u32; 8];
    let mut n = 0;
    let mut held = None;
    // Modifiers first: left/right control, shift and alt.
    let mods = [(0, keymap::CTRL), (1, keymap::LSHIFT), (2, keymap::ALT), (4, keymap::CTRL), (5, keymap::RSHIFT), (6, keymap::ALT)];
    for (bit, code) in mods {
        let (was, is) = (old[0] >> bit & 1, new[0] >> bit & 1);
        if was != is {
            keys.key(code, is == 1);
        }
    }
    for &u in &old[2..] {
        if u > 1 && !new[2..].contains(&u)
            && let Some(c) = usage_code(u)
        {
            keys.key(c, false);
        }
    }
    for &u in &new[2..] {
        if u > 1 && !old[2..].contains(&u)
            && let Some(c) = usage_code(u).and_then(|c| keys.key(c, true))
            && n < out.len()
        {
            out[n] = c;
            n += 1;
            held = Some((u, c));
        }
    }
    (out, n, held)
}

/// Parse a HID report descriptor (HID 1.11, 6.2.2) for a relative pointer: X and Y (Generic
/// Desktop 0x30, 0x31, relative), the wheel (0x38) and buttons (Button page) in one input report.
/// None if there is no relative X and Y in one report (an absolute pointer, a keyboard, anything
/// else). Bounded by the descriptor's length; long items are skipped; push/pop are not followed.
fn parse_mouse(d: &[u8]) -> Option<MouseFormat> {
    const IDS: usize = 8;
    let (mut page, mut lmin, mut size, mut count, mut rid) = (0u32, 0i32, 0u32, 0u32, 0u8);
    let mut usages = [0u32; 16];
    let (mut nu, mut umin, mut umax) = (0usize, None::<u32>, None::<u32>);
    // Input bits so far per report id, and what was found per report id.
    let mut bits: [(u8, u32); IDS] = [(0, 0); IDS];
    let mut found: [(u8, MouseFormat, u8); IDS] = [(0, MouseFormat::default(), 0); IDS]; // (id, format, have: 1 x, 2 y)
    let slot = |t: &mut [(u8, u32); IDS], id: u8| -> Option<usize> {
        match t.iter().position(|e| e.0 == id) {
            Some(i) => Some(i),
            None => {
                let i = t.iter().position(|e| e.0 == 0 && e.1 == 0 && id != 0).or_else(|| (id == 0).then_some(0))?;
                t[i].0 = id;
                Some(i)
            }
        }
    };
    let mut o = 0;
    while o < d.len() {
        let b = d[o];
        if b == 0xFE {
            // Long item: size byte, tag byte, data.
            let n = usize::from(*d.get(o + 1)?);
            o += 3 + n;
            continue;
        }
        let n = [0usize, 1, 2, 4][usize::from(b & 3)];
        let data = d.get(o + 1..o + 1 + n)?;
        o += 1 + n;
        let mut u: u32 = 0;
        for (i, &x) in data.iter().enumerate() {
            u |= u32::from(x) << (8 * i);
        }
        let s = match n {
            1 => i32::from(u as u8 as i8),
            2 => i32::from(u as u16 as i16),
            _ => u as i32,
        };
        match (b >> 2) & 3 {
            0 => {
                // Main: Input (8), Output (9), Collection (10), Feature (11), End Collection (12).
                if b >> 4 == 8 {
                    let i = slot(&mut bits, rid)?;
                    let (constant, variable, relative) = (u & 1 != 0, u & 2 != 0, u & 4 != 0);
                    let f = &mut found[i];
                    f.0 = rid;
                    for k in 0..count.min(64) {
                        let bit = bits[i].1 + k * size;
                        let usage = match (umin, umax) {
                            (Some(a), Some(z)) if a <= z => a.saturating_add(k).min(z),
                            _ if nu > 0 => usages[(k as usize).min(nu - 1)],
                            _ => 0,
                        };
                        let full = if usage > 0xFFFF { usage } else { page << 16 | usage };
                        if constant || !variable || bit > u32::from(u16::MAX) || size == 0 || size > 32 {
                            continue;
                        }
                        let field = Field { bit: bit as u16, size: size as u8, signed: lmin < 0 };
                        match full {
                            0x0001_0030 if relative && f.2 & 1 == 0 => {
                                f.1.x = field;
                                f.2 |= 1;
                            }
                            0x0001_0031 if relative && f.2 & 2 == 0 => {
                                f.1.y = field;
                                f.2 |= 2;
                            }
                            0x0001_0038 if relative && f.1.wheel.is_none() => f.1.wheel = Some(field),
                            x if x >> 16 == 9 && size == 1 => {
                                // Buttons: the first run of one-bit button fields.
                                let bt = &mut f.1.buttons;
                                if bt.size == 0 {
                                    *bt = Field { bit: bit as u16, size: 1, signed: false };
                                } else if u32::from(bt.bit) + u32::from(bt.size) == bit && bt.size < 16 {
                                    bt.size += 1;
                                }
                            }
                            _ => {}
                        }
                    }
                    bits[i].1 = bits[i].1.saturating_add(count.saturating_mul(size));
                }
                (nu, umin, umax) = (0, None, None);
            }
            1 => match b >> 4 {
                0 => page = u & 0xFFFF,
                1 => lmin = s,
                7 => size = u,
                8 => rid = u as u8,
                9 => count = u,
                _ => {}
            },
            2 => match b >> 4 {
                0 if nu < usages.len() => {
                    usages[nu] = u;
                    nu += 1;
                }
                1 => umin = Some(if n == 4 { u } else { page << 16 | u }),
                2 => umax = Some(if n == 4 { u } else { page << 16 | u }),
                _ => {}
            },
            _ => {}
        }
    }
    let (id, mut fmt, _) = *found.iter().find(|f| f.2 == 3)?;
    fmt.id = id;
    Some(fmt)
}

pub fn main(s: *const Startup) -> i32 {
    // SAFETY: `s` is the startup block pointer the kernel passed to the entry point.
    if !unsafe { libd::init(s, "xhci") } {
        return -1;
    }
    let dev = libd::startup_handle(sys::TAG_DEVICE);
    let ch = libd::startup_handle(proto::TAG_CONTROL);
    match run(dev, ch) {
        Ok(code) => code,
        Err(e) => {
            println!("xhci: {}", e);
            2
        }
    }
}

/// Take the controller from the firmware (USB legacy support), find the USB 3 ports.
fn extended_caps(bar: &Mapping, len: u64, hcc: u32) -> u64 {
    let mut usb3 = 0u64;
    let mut off = u64::from(hcc >> 16) * 4;
    for _ in 0..64 {
        if off == 0 || off + 16 > len {
            break;
        }
        let v = bar.r32(off);
        match v & 0xFF {
            1 => {
                // OS owned semaphore, then wait (bounded) for the BIOS to let go; SMIs off.
                bar.w8(off + 3, 1);
                let gone = wait_until(|| bar.r8(off + 2) & 1 == 0, 1000);
                if !gone {
                    println!("xhci: firmware did not release the controller; taking it anyway");
                    bar.w8(off + 2, 0);
                }
                let ctl = bar.r32(off + 4);
                bar.w32(off + 4, (ctl & !0x0000_E011) | 0xE000_0000); // enables off, status RW1C
            }
            2 if v >> 24 == 3 => {
                let ports = bar.r32(off + 8);
                let (first, count) = (ports & 0xFF, (ports >> 8) & 0xFF);
                for p in first..first.saturating_add(count) {
                    if (1..=64).contains(&p) {
                        usb3 |= 1 << (p - 1);
                    }
                }
            }
            _ => {}
        }
        let next = u64::from((v >> 8) & 0xFF) * 4;
        if next == 0 {
            break;
        }
        off += next;
    }
    usb3
}

fn run(dev: Handle, ch: Handle) -> Result<i32, &'static str> {
    let info = sys::device_info(dev).map_err(|_| "device_info failed")?;
    if info.bar_kind[0] != 1 || info.bar_size[0] < 0x1000 {
        return Err("BAR 0 is not a memory BAR");
    }
    sys::config_write(dev, 0x04, 2, 0x6).map_err(|_| "cannot enable the device")?;
    let vmo = sys::device_map_bar(dev, 0).map_err(|_| "cannot map BAR 0")?;
    let bar = Mapping::of(vmo, info.bar_size[0]).map_err(|_| "cannot map BAR 0")?;
    let len = info.bar_size[0];
    let caplen = u64::from(bar.r8(CAPLENGTH));
    let hcs1 = bar.r32(HCSPARAMS1);
    let hcs2 = bar.r32(HCSPARAMS2);
    let hcc = bar.r32(HCCPARAMS1);
    let db = u64::from(bar.r32(DBOFF) & !3);
    let rt = u64::from(bar.r32(RTSOFF) & !0x1F);
    let ports = (hcs1 >> 24).min(64);
    let slots = (hcs1 & 0xFF).min(MAX_SLOTS);
    if caplen < 0x20 || caplen + PORTSC + 0x10 * u64::from(ports) > len || rt + 0x40 > len || db + 4 * 256 > len || slots == 0 {
        return Err("register layout outside BAR 0");
    }
    let usb3 = extended_caps(&bar, len, hcc);
    // Messages name the controller by its PCI address ("12:00.4").
    let name = info.name().strip_prefix("pci-").unwrap_or(info.name()).as_bytes();
    let mut tag = [0u8; 16];
    let tag_len = name.len().min(16);
    tag[..tag_len].copy_from_slice(&name[..tag_len]);
    let mut x = Xhci {
        bar,
        op: caplen,
        rt,
        db,
        mem: Dma::new(dev, PAGES * 4096, sys::DMA_DEVICE_READ | sys::DMA_DEVICE_WRITE).map_err(|_| "cannot pin controller memory")?,
        slot_mem: Dma::new(dev, SLOT_PAGES * 4096, sys::DMA_DEVICE_READ | sys::DMA_DEVICE_WRITE).map_err(|_| "cannot pin device contexts")?,
        fun_mem: Dma::new(dev, FUN_PAGES * 4096, sys::DMA_DEVICE_READ | sys::DMA_DEVICE_WRITE).map_err(|_| "cannot pin mouse and disk memory")?,
        _scratch: None,
        irq: sys::device_interrupt(dev, 0).map_err(|_| "no interrupt")?,
        tag,
        tag_len,
        ports,
        usb3,
        csz: if hcc & (1 << 2) != 0 { 64 } else { 32 },
        slots,
        cmd: Ring::new(PG_CMD),
        ev_deq: 0,
        ev_cycle: 1,
        ep0: core::array::from_fn(|_| Ring::new(0)),
        owner: [(0, 0); MAX_SLOTS as usize + 1],
        hubs: [None; MAX_HUBS],
        root: [PortState::default(); 64],
        kbds: [const { None }; MAX_KBDS],
        mice: [const { None }; MAX_MICE],
        disks: [const { None }; MAX_DISKS],
        ctl: ch,
        writable: libd::args() == b"rw",
        requests: 0,
        port_events: 0,
        deferred: [Trb { param: 0, status: 0, control: 0 }; REPORTS * 4],
        ndeferred: 0,
        next_poll: 0,
        last_cc: 0,
        reports: 0,
    };
    if x.op_r(PAGESIZE) & 1 == 0 {
        return Err("controller does not support 4 KiB pages");
    }
    let high = |m: &Dma| m.addrs[..m.pages].iter().any(|a| a >> 32 != 0);
    if hcc & 1 == 0 && (high(&x.mem) || high(&x.slot_mem) || high(&x.fun_mem)) {
        return Err("32-bit controller but DMA addresses above 4 GiB");
    }
    // Stop and reset.
    x.op_w(USBCMD, x.op_r(USBCMD) & !CMD_RUN);
    if !wait_until(|| x.op_r(USBSTS) & STS_HCH != 0, 100) {
        return Err("controller did not halt");
    }
    x.op_w(USBCMD, CMD_HCRST);
    if !wait_until(|| x.op_r(USBCMD) & CMD_HCRST == 0 && x.op_r(USBSTS) & STS_CNR == 0, 1000) {
        return Err("controller did not finish its reset");
    }
    // Scratchpad buffers the controller asks for.
    let nscratch = (hcs2 >> 27) & 0x1F | ((hcs2 >> 21) & 0x1F) << 5;
    if nscratch > MAX_SCRATCH {
        return Err("controller wants too many scratchpad buffers");
    }
    if nscratch > 0 {
        let sp = Dma::new(dev, u64::from(nscratch) * 4096, sys::DMA_DEVICE_READ | sys::DMA_DEVICE_WRITE)
            .map_err(|_| "cannot pin scratchpad buffers")?;
        for (i, &a) in sp.addrs[..nscratch as usize].iter().enumerate() {
            x.mem.map.w64(PG_DCBAA * 4096 + SCRATCH_ARRAY + 8 * i as u64, a);
        }
        x.mem.map.w64(PG_DCBAA * 4096, x.addr(PG_DCBAA, SCRATCH_ARRAY));
        x._scratch = Some(sp);
    }
    x.op_w(CONFIG, slots);
    x.op_w64(DCBAAP, x.addr(PG_DCBAA, 0));
    x.op_w64(CRCR, x.addr(PG_CMD, 0) | 1);
    // Event ring: one segment of 256 TRBs.
    x.mem.map.w64(PG_ERST * 4096, x.addr(PG_EVENT, 0));
    x.mem.map.w32(PG_ERST * 4096 + 8, RING_TRBS);
    x.bar.w32(x.rt + ERSTSZ, 1);
    x.rt_w64(ERDP, x.addr(PG_EVENT, 0));
    x.rt_w64(ERSTBA, x.addr(PG_ERST, 0));
    x.bar.w32(x.rt + IMAN, IMAN_IE | IMAN_IP);
    x.op_w(USBCMD, CMD_RUN | CMD_INTE);
    if !wait_until(|| x.op_r(USBSTS) & STS_HCH == 0, 100) {
        return Err("controller did not start");
    }
    // Power every port (if power switching is software-controlled) and let connections settle.
    for p in 1..=x.ports {
        let sc = x.portsc(p);
        if sc & PS_PP == 0 {
            x.set_portsc(p, (sc & PS_KEEP) | PS_PP);
        }
    }
    sleep(DEBOUNCE);
    let port = Port::new(16).map_err(|_| "no port")?;
    port.arm(x.irq, sys::SIGNALED, KEY_IRQ);
    port.arm(ch, sys::READABLE | sys::PEER_CLOSED, KEY_CTL);
    // What is connected now is probed right away (the wait above was its debounce); devices
    // behind hubs follow once the hubs' ports have power.
    x.drain(ch);
    x.root_changes(sys::clock_ns());
    for p in 1..=x.ports {
        if x.portsc(p) & PS_CCS != 0 && !x.root[(p - 1) as usize].ignored {
            x.root[(p - 1) as usize].pending = true;
            x.root[(p - 1) as usize].changed_at = 0;
        }
    }
    x.service(sys::clock_ns());
    println!(
        "xhci: controller ready on {}: {} ports ({} USB 3), {} slots, {}-byte contexts, {} scratchpad page(s), DMA {}",
        info.name(),
        x.ports,
        x.usb3.count_ones(),
        x.slots,
        x.csz,
        nscratch,
        if info.flags & sys::DEV_FLAG_IOMMU != 0 { "confined by the IOMMU" } else { "NOT confined (no IOMMU)" }
    );
    proto::send(ch, proto::READY, 0, 0);
    let mut msg = [0u8; HEADER + MAX_SECTORS as usize * SECTOR];
    let mut data = [0u8; MAX_SECTORS as usize * SECTOR];
    loop {
        if let Some((key, _)) = port.wait(x.wake_after(sys::clock_ns())) {
            if key == KEY_CTL {
                loop {
                    let mut hs = [0 as Handle; 1];
                    match sys::channel_read_h(ch, &mut msg, &mut hs, 0) {
                        Ok((n, nh)) => {
                            let Some(h) = Header::get(&msg[..n]) else { continue };
                            if h.op == proto::BLK_ATTACH {
                                // The channel the storage service will use for disk `a`.
                                let u = h.a as usize;
                                match x.disks.get_mut(u).and_then(|d| d.as_mut()) {
                                    Some(d) if nh == 1 => {
                                        if d.ch != 0 {
                                            sys::handle_close(d.ch);
                                        }
                                        d.ch = hs[0];
                                        port.arm(hs[0], sys::READABLE | sys::PEER_CLOSED, KEY_DISK + u as u64);
                                    }
                                    _ if nh == 1 => {
                                        sys::handle_close(hs[0]);
                                    }
                                    _ => {}
                                }
                                continue;
                            }
                            if nh > 0 {
                                sys::handle_close(hs[0]);
                            }
                            let (st, a, b) = match h.op {
                                proto::STATS => (0, sys::interrupt_ack(x.irq).unwrap_or(0), x.reports + x.requests),
                                proto::TEST_CRASH => {
                                    // SAFETY: deliberately faults (test).
                                    unsafe { core::ptr::write_volatile(0x10 as *mut u32, 1) };
                                    (0, 0, 0)
                                }
                                _ => (sys::ERR_INVALID_ARGS as i32, 0, 0),
                            };
                            let mut out = [0u8; HEADER];
                            Header { txid: h.txid, op: h.op, status: st, a, b }.put(&mut out);
                            sys::channel_write(ch, &out);
                        }
                        Err(sys::ERR_SHOULD_WAIT) => break,
                        Err(_) => return Ok(0), // the device manager is gone
                    }
                }
                port.arm(ch, sys::READABLE | sys::PEER_CLOSED, KEY_CTL);
            } else if (KEY_DISK..KEY_DISK + MAX_DISKS as u64).contains(&key) {
                let u = (key - KEY_DISK) as usize;
                serve_disk(&mut x, u, &port, key, &mut msg, &mut data);
            } else {
                let _ = sys::interrupt_ack(x.irq);
                x.bar.w32(x.rt + IMAN, IMAN_IE | IMAN_IP);
                port.arm(x.irq, sys::SIGNALED, KEY_IRQ);
            }
        }
        x.drain(ch);
        let now = sys::clock_ns();
        x.root_changes(now);
        x.service(now);
        x.drain(ch); // keyboard and mouse reports that arrived during hub requests
        x.repeat_keys(ch, sys::clock_ns());
    }
}

/// Requests on disk `u`'s attached channel, until it is empty (then it is watched again) or
/// closed (the storage service let the disk go).
fn serve_disk(x: &mut Xhci, u: usize, port: &Port, key: u64, msg: &mut [u8], data: &mut [u8]) {
    let Some(ch) = x.disks[u].as_ref().map(|d| d.ch).filter(|&c| c != 0) else { return };
    let writable = x.writable;
    loop {
        let n = match sys::channel_read(ch, msg, 0) {
            Ok(n) => n as usize,
            Err(sys::ERR_SHOULD_WAIT) => {
                port.arm(ch, sys::READABLE | sys::PEER_CLOSED, key);
                return;
            }
            Err(_) => {
                sys::handle_close(ch);
                if let Some(d) = x.disks[u].as_mut() {
                    d.ch = 0;
                }
                return;
            }
        };
        let Some(h) = Header::get(&msg[..n]) else { continue };
        crate::blkserve::block_op(&mut UsbDisks(x), ch, u, &h, &msg[..n], data, writable);
    }

}

