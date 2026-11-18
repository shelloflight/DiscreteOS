//! xHCI (USB 3) host controller driver (`xhci.ddrv`): USB keyboards through the HID boot
//! protocol, on a root port or behind USB 2 hubs (up to five tiers). One keyboard at a time: the
//! first boot keyboard found is used; hubs stay configured, other devices are disabled again.
//! Ports are watched, so a keyboard plugged in later, or again, is picked up.
//!
//! Bring-up: firmware ownership taken (USB legacy support capability, SMIs off), controller
//! reset, one command ring, one interrupter with a one-segment event ring (MSI-X entry 0 or MSI),
//! device context array. Per device: Enable Slot, Address Device (route string, and the
//! transaction translator for low/full-speed devices behind a high-speed hub), descriptors read on
//! endpoint 0. A keyboard: SET_CONFIGURATION, the interrupt-IN endpoint configured,
//! SET_PROTOCOL(boot), SET_IDLE(0); eight 8-byte reports stay queued on the interrupt ring; keys
//! are diffed between reports and go through the same US keymap as the other keyboards. A hub:
//! configured, its slot marked as a hub, its ports powered, then polled (port status) for
//! connections.
//!
//! Connections are debounced, and a device that keeps reconnecting is left alone after its third
//! identical probe (until its port has been empty for two seconds): unconfigured devices on some
//! boards drop off and come back, which would otherwise be probed forever. Each device is reported
//! once.
//!
//! Everything the controller and the devices write is untrusted: event TRB pointers must point
//! into our rings, descriptor lengths are bounded by what was read, every wait has a deadline,
//! and an impossible value ends the driver (it is restarted). All rings, contexts and buffers are
//! pinned for the device: with an IOMMU it reaches nothing else.
//!
//! Not supported yet: USB 3 hubs (their USB 2 half is used), key repeat, LEDs, mice and storage
//! (HID report parsing, bulk transfers), isochronous endpoints, more than one interrupter. Hub
//! ports are polled (once a second) rather than watched through the hubs' status endpoints.

use libd::handle::sleep;
use libd::proto::{self, HEADER, Header};
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
const PG_INTR: u64 = 5; // the keyboard's interrupt ring
const PG_DESC: u64 = 6; // descriptor / status buffer
const PG_REPORT: u64 = 7; // report buffers, 64 bytes each
const PAGES: u64 = 8;
/// Pages from here are in slot_mem (a pinned buffer holds at most 32 pages): per slot, the
/// output device context, then the endpoint 0 ring.
const PG_SLOTS: u64 = PAGES;
const MAX_SLOTS: u32 = 16;
const SLOT_PAGES: u64 = 2 * MAX_SLOTS as u64;
const SCRATCH_ARRAY: u64 = 0x800;
const MAX_SCRATCH: u32 = 31;

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

const ADDR_FAILED: &str = "Address Device failed";

const KEY_IRQ: u64 = 1;
const KEY_CTL: u64 = 2;

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
            (9, _, _) => "hub (not usable: USB 3 or too deep)",
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

/// A configured USB 2 hub.
#[derive(Clone, Copy)]
struct Hub {
    slot: u32,
    loc: Loc,
    ports: u32,
    /// Stopped answering (its parent reports the unplug).
    dead: bool,
    ps: [PortState; HUB_PORTS as usize],
}

/// The boot keyboard being served.
struct Kbd {
    slot: u32,
    loc: Loc,
    dci: u32,
    /// The hub it is on (slot, port); 0 = a root port.
    parent: u32,
    port: u32,
    intr: Ring,
    /// Report buffer of each interrupt-ring position (u8::MAX: none queued there).
    buf_at: [u8; RING_TRBS as usize],
    last: [u8; 8],
    keys: Keys,
}

/// Result of a probe. The keyboard is large but short-lived (moved into `Xhci::kbd`).
#[allow(clippy::large_enum_variant)]
enum Found {
    Keyboard(Kbd),
    Hub(u32, Ident),
    Other(Ident),
}

struct Xhci {
    bar: Mapping,
    op: u64,
    rt: u64,
    db: u64,
    mem: Dma,
    slot_mem: Dma,
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
    kbd: Option<Kbd>,
    /// Root port status changes seen (bit p-1).
    port_events: u64,
    /// Keyboard transfer events seen while waiting for something else.
    deferred: [Trb; REPORTS * 2],
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
        if page >= PG_SLOTS { (&self.slot_mem, (page - PG_SLOTS) * 4096) } else { (&self.mem, page * 4096) }
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
    /// reports kept for the main loop, the rest dropped.
    fn wait_event(&mut self, ms: u64, mut want: impl FnMut(&Trb) -> bool) -> Option<Trb> {
        let deadline = sys::clock_ns() + ms * MS;
        let kbd = self.kbd.as_ref().map_or((0, 0), |k| (k.slot, k.dci));
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
                    E_TRANSFER if kbd.0 != 0 && (e.slot(), e.endpoint()) == kbd && self.ndeferred < self.deferred.len() => {
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

    /// Reset hub port `port`; the speed of the device there.
    fn hub_reset(&mut self, slot: u32, port: u32) -> Result<u32, &'static str> {
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
            let speed = self.hub_reset(parent, port)?;
            hub.loc.child(parent, port, speed)
        };
        let slot = self.command(Trb { param: 0, status: 0, control: T_ENABLE_SLOT << 10 }).map_err(|_| "Enable Slot failed")?.slot();
        if slot == 0 || slot > self.slots || self.owner[slot as usize].1 != 0 {
            return Err("controller returned an invalid slot");
        }
        self.owner[slot as usize] = (parent, port);
        self.ep0[slot as usize] = Ring::new(slot_page(slot) + 1);
        match self.setup_device(slot, loc, parent, port) {
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
            if let Some(k) = self.kbd.take_if(|k| k.slot == s) {
                say!(self, "keyboard on port {} unplugged", k.loc);
            }
            self.disable_slot(s);
        }
    }

    fn setup_device(&mut self, slot: u32, loc: Loc, parent: u32, port: u32) -> Result<Found, &'static str> {
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
        // Find a boot keyboard interface (class 3, subclass 1, protocol 1) and its interrupt-IN endpoint.
        let (mut iface, mut in_kbd, mut ep, mut first_if) = (None, false, None, true);
        let mut o = 0u64;
        while o + 2 <= got {
            let len = u64::from(self.desc(o));
            let ty = self.desc(o + 1);
            if len < 2 || o + len > got {
                break;
            }
            let b = |i: u64| self.desc(o + i);
            if ty == 4 && len >= 9 {
                if first_if && id.class == 0 {
                    (id.class, id.sub, id.proto) = (b(5), b(6), b(7));
                }
                first_if = false;
                in_kbd = b(3) == 0 && (b(5), b(6), b(7)) == (3, 1, 1) && ep.is_none();
                if in_kbd {
                    iface = Some(b(2));
                }
            } else if ty == 5 && len >= 7 && in_kbd && ep.is_none() && b(2) & 0x80 != 0 && b(3) & 3 == 3 {
                ep = Some((b(2) & 0x0F, u32::from(u16::from_le_bytes([b(4), b(5)]) & 0x7FF), b(6)));
            }
            o += len;
        }
        if id.class == 9 && loc.speed <= 3 && loc.depth < MAX_DEPTH {
            return self.setup_hub(slot, loc, cfg_value, id);
        }
        let (Some(iface), Some((epn, ep_mps, interval))) = (iface, ep) else {
            return Ok(Found::Other(id));
        };
        if epn == 0 || ep_mps == 0 {
            return Err("bad keyboard endpoint descriptor");
        }
        self.control(slot, [0, 9, cfg_value, 0, 0, 0, 0, 0], 0).map_err(|_| "SET_CONFIGURATION failed")?;
        // The interrupt-IN endpoint: device context index 2 * n + 1.
        let dci = u32::from(epn) * 2 + 1;
        let exp = if loc.speed <= 2 {
            // Full / low speed: bInterval in 1 ms frames -> 2^exp * 125 us.
            (32 - (u32::from(interval.max(1)) * 8).leading_zeros() - 1).clamp(3, 10)
        } else {
            u32::from(interval.clamp(1, 16)) - 1
        };
        self.clear_page(PG_IN);
        self.clear_page(PG_INTR);
        self.ctx_w(PG_IN, 0, 1, 1 | 1 << dci);
        self.slot_ctx(&loc, dci, 0, 0);
        let e = u64::from(dci) + 1;
        self.ctx_w(PG_IN, e, 0, exp << 16);
        self.ctx_w(PG_IN, e, 1, 3 << 1 | 7 << 3 | ep_mps << 16);
        let ring = self.addr(PG_INTR, 0) | 1;
        self.ctx_w(PG_IN, e, 2, ring as u32);
        self.ctx_w(PG_IN, e, 3, (ring >> 32) as u32);
        self.ctx_w(PG_IN, e, 4, ep_mps | ep_mps << 16);
        let cfg = Trb { param: self.addr(PG_IN, 0), status: 0, control: T_CONFIGURE_EP << 10 | slot << 24 };
        self.command(cfg).map_err(|_| "Configure Endpoint failed")?;
        self.control(slot, [0x21, 0x0B, 0, 0, iface, 0, 0, 0], 0).map_err(|_| "SET_PROTOCOL(boot) failed")?;
        // Reports only on change. Optional: a device that stalls it still works (endpoint 0 is
        // not used again).
        let _ = self.control(slot, [0x21, 0x0A, 0, 0, iface, 0, 0, 0], 0);
        let mut k = Kbd {
            slot,
            loc,
            dci,
            parent,
            port,
            intr: Ring::new(PG_INTR),
            buf_at: [u8::MAX; RING_TRBS as usize],
            last: [0; 8],
            keys: Keys::default(),
        };
        for b in 0..REPORTS as u8 {
            self.queue_report(&mut k, b);
        }
        self.ring_doorbell(slot, dci);
        Ok(Found::Keyboard(k))
    }

    /// A USB 2 hub: configure it, tell the controller it is a hub (ports, think time), power its
    /// ports; they are probed once power is good and the connections have settled.
    fn setup_hub(&mut self, slot: u32, loc: Loc, cfg_value: u8, id: Ident) -> Result<Found, &'static str> {
        let i = self.hubs.iter().position(|h| h.is_none()).ok_or("too many hubs")?;
        self.control(slot, [0, 9, cfg_value, 0, 0, 0, 0, 0], 0).map_err(|_| "SET_CONFIGURATION failed")?;
        if self.control(slot, [0xA0, 6, 0, 0x29, 0, 0, 9, 0], 9).map_err(|_| "hub descriptor unreadable")? < 7 {
            return Err("hub descriptor too short");
        }
        let ports = u32::from(self.desc(2)).min(HUB_PORTS);
        if ports == 0 {
            return Err("hub without ports");
        }
        let ttt = (u32::from(self.desc(3)) >> 5) & 3;
        let power_good = u64::from(self.desc(5)) * 2 * MS;
        self.clear_page(PG_IN);
        self.ctx_w(PG_IN, 0, 1, 1);
        self.slot_ctx(&loc, 1, ports, ttt);
        let cfg = Trb { param: self.addr(PG_IN, 0), status: 0, control: T_CONFIGURE_EP << 10 | slot << 24 };
        self.command(cfg).map_err(|_| "Configure Endpoint (hub) failed")?;
        for p in 1..=ports {
            self.hub_feature(slot, p, true, F_PORT_POWER).map_err(|_| "hub port power refused")?;
        }
        let ready = PortState { pending: true, changed_at: sys::clock_ns() + power_good.max(DEBOUNCE), ..PortState::default() };
        self.hubs[i] = Some(Hub { slot, loc, ports, dead: false, ps: [ready; HUB_PORTS as usize] });
        Ok(Found::Hub(ports, id))
    }

    /// Probe (`parent`, `port`) and record the outcome: report it once, serve a keyboard, and
    /// leave a device that keeps reconnecting alone.
    fn probe_port(&mut self, parent: u32, port: u32, now: u64) {
        let r = self.probe(parent, port);
        let at = match &r {
            Ok(Found::Keyboard(k)) => k.loc,
            _ => self.loc_of(parent, port),
        };
        let key = match &r {
            Ok(Found::Keyboard(_)) => 0,
            Ok(Found::Hub(_, id)) | Ok(Found::Other(id)) => id.key(),
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
            Ok(Found::Keyboard(k)) => {
                say!(self, "keyboard ready on port {} (USB HID boot protocol, US layout, slot {})", at, k.slot);
                self.kbd = Some(k);
            }
            Ok(Found::Hub(n, id)) if !repeat => say!(self, "port {}: hub {:04x}:{:04x}, {} ports", at, id.vid, id.pid, n),
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
            if ps.pending && self.kbd.is_none() && now >= ps.changed_at + DEBOUNCE {
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
            if hub.dead || !(due || pending && self.kbd.is_none()) {
                continue;
            }
            // While a keyboard is served only its own port is watched (for the unplug).
            let only = match &self.kbd {
                Some(k) if k.parent == hub.slot => Some(k.port),
                Some(_) => continue,
                None => None,
            };
            self.poll_hub(h, hub.slot, hub.ports, only, now);
        }
    }

    fn poll_hub(&mut self, h: usize, slot: u32, ports: u32, only: Option<u32>, now: u64) {
        for port in 1..=ports {
            if only.is_some_and(|o| o != port) {
                continue;
            }
            let Ok((st, chg)) = self.hub_status(slot, port) else {
                if let Some(hub) = self.hubs[h].as_mut() {
                    hub.dead = true;
                    let loc = hub.loc;
                    say!(self, "hub on port {} stopped answering", loc);
                }
                return;
            };
            for b in 0..5u8 {
                if chg & (1 << b) != 0 {
                    let _ = self.hub_feature(slot, port, false, F_C_PORT_CONNECTION + b);
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
            if ps.pending && now >= ps.changed_at + DEBOUNCE && !ps.done && only.is_none() {
                ps.pending = false;
                self.probe_port(slot, port, now);
                if self.kbd.is_some() || self.hubs[h].is_none_or(|x| x.slot != slot) {
                    return;
                }
            }
        }
    }

    /// How long the main loop may sleep: briefly while connections settle, a second while hubs
    /// are polled or ports are left alone, otherwise until an interrupt.
    fn wake_after(&self) -> u64 {
        let live = |h: &&Hub| !h.dead;
        let hubs = self.hubs.iter().flatten().filter(live);
        if self.kbd.is_none() {
            let root = self.root[..self.ports as usize].iter().any(|p| p.pending);
            if root || hubs.clone().any(|h| h.ps[..h.ports as usize].iter().any(|p| p.pending)) {
                return SETTLE_TICK;
            }
        }
        if hubs.count() > 0 || self.root[..self.ports as usize].iter().any(|p| p.ignored) {
            return HUB_POLL;
        }
        sys::WAIT_FOREVER
    }

    // ---- keyboard reports -----------------------------------------------------------------------

    fn queue_report(&self, k: &mut Kbd, buf: u8) {
        let pos = k.intr.enq as usize;
        let t = Trb { param: self.addr(PG_REPORT, u64::from(buf) * 64), status: 8, control: T_NORMAL << 10 | TRB_IOC | TRB_ISP };
        k.buf_at[pos] = buf;
        let mut r = core::mem::replace(&mut k.intr, Ring::new(PG_INTR));
        self.enqueue(&mut r, t);
        k.intr = r;
    }

    /// A finished report transfer: diff it against the last one, send the characters, requeue.
    fn report(&mut self, k: &mut Kbd, e: &Trb, ch: Handle) -> Result<(), &'static str> {
        let base = self.addr(PG_INTR, 0);
        if e.param < base || e.param >= base + u64::from(RING_TRBS - 1) * 16 || !(e.param - base).is_multiple_of(16) {
            return Err("transfer event for a TRB that is not ours");
        }
        let pos = ((e.param - base) / 16) as usize;
        let buf = core::mem::replace(&mut k.buf_at[pos], u8::MAX);
        if usize::from(buf) >= REPORTS {
            return Err("transfer event for a TRB that is not queued");
        }
        match e.code() {
            CC_SUCCESS | CC_SHORT => {}
            _ => return Err("keyboard transfer failed (device gone?)"),
        }
        let got = 8u32.saturating_sub(e.status & 0xFF_FFFF);
        if got >= 3 {
            self.reports += 1;
            let mut r = [0u8; 8];
            for (i, x) in r.iter_mut().enumerate().take(got as usize) {
                *x = self.mem.map.r8(PG_REPORT * 4096 + u64::from(buf) * 64 + i as u64);
            }
            // Rollover (too many keys): every key slot reads 1; keep the last state.
            if r[2] != 1 {
                for c in diff(&mut k.keys, &k.last, &r) {
                    proto::send(ch, proto::KEY, u64::from(c), 0);
                }
                k.last = r;
            }
        }
        self.queue_report(k, buf);
        self.ring_doorbell(k.slot, k.dci);
        Ok(())
    }

    fn on_event(&mut self, e: Trb, ch: Handle) {
        match e.ty() {
            E_TRANSFER => {
                let Some(mut k) = self.kbd.take() else { return };
                if (e.slot(), e.endpoint()) != (k.slot, k.dci) {
                    self.kbd = Some(k);
                    return;
                }
                match self.report(&mut k, &e, ch) {
                    Ok(()) => self.kbd = Some(k),
                    Err(why) => {
                        say!(self, "keyboard on port {}: {}", k.loc, why);
                        self.disable_slot(k.slot);
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
        _ => None,
    }
}

/// Feed the change from `old` to `new` (boot reports) through `keys`; the characters typed.
fn diff(keys: &mut Keys, old: &[u8; 8], new: &[u8; 8]) -> impl Iterator<Item = u8> {
    let mut out = [0u8; 8];
    let mut n = 0;
    // Modifiers first: left/right control and shift.
    for (bit, code) in [(0, keymap::CTRL), (1, keymap::LSHIFT), (4, keymap::CTRL), (5, keymap::RSHIFT)] {
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
        }
    }
    out.into_iter().take(n)
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
        kbd: None,
        port_events: 0,
        deferred: [Trb { param: 0, status: 0, control: 0 }; REPORTS * 2],
        ndeferred: 0,
        next_poll: 0,
        last_cc: 0,
        reports: 0,
    };
    if x.op_r(PAGESIZE) & 1 == 0 {
        return Err("controller does not support 4 KiB pages");
    }
    let high = |m: &Dma| m.addrs[..m.pages].iter().any(|a| a >> 32 != 0);
    if hcc & 1 == 0 && (high(&x.mem) || high(&x.slot_mem)) {
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
    let mut msg = [0u8; 256];
    loop {
        if let Some((key, _)) = port.wait(x.wake_after()) {
            if key == KEY_CTL {
                match sys::channel_read(ch, &mut msg, 0) {
                    Ok(n) => {
                        if let Some(h) = Header::get(&msg[..n as usize]) {
                            let (st, a, b) = match h.op {
                                proto::STATS => (0, sys::interrupt_ack(x.irq).unwrap_or(0), x.reports),
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
                    }
                    Err(sys::ERR_SHOULD_WAIT) => {}
                    Err(_) => return Ok(0), // the device manager is gone
                }
                port.arm(ch, sys::READABLE | sys::PEER_CLOSED, KEY_CTL);
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
        x.drain(ch); // keyboard reports that arrived during hub requests
    }
}
