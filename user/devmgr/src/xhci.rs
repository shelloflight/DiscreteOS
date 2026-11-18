//! xHCI (USB 3) host controller driver (`xhci.ddrv`): USB keyboards on the controller's root
//! ports, through the HID boot protocol. One keyboard at a time; the first boot keyboard found on
//! a root port is used (other devices are disabled again), and ports are watched, so a keyboard
//! plugged in later, or again, is picked up.
//!
//! Bring-up: firmware ownership taken (USB legacy support capability, SMIs off), controller
//! reset, one command ring, one interrupter with a one-segment event ring (MSI-X entry 0 or MSI),
//! device context array. Per device: Enable Slot, Address Device, descriptors read on endpoint 0,
//! SET_CONFIGURATION, the interrupt-IN endpoint configured, SET_PROTOCOL(boot), SET_IDLE(0); then
//! eight 8-byte reports stay queued on the interrupt ring. Keys are diffed between reports and go
//! through the same US keymap as the other keyboards.
//!
//! Everything the controller and the device write is untrusted: event TRB pointers must point into
//! our rings, descriptor lengths are bounded by what was read, every wait has a deadline, and an
//! impossible value ends the driver (it is restarted). All rings, contexts and buffers are pinned
//! for the device: with an IOMMU it reaches nothing else.
//!
//! Not supported yet: keyboards behind a hub, key repeat, LEDs, mice and storage (HID report
//! parsing, bulk transfers), isochronous endpoints, more than one interrupter.

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

/// Ring geometry: one page, 256 TRBs; on command and transfer rings the last is the Link TRB.
const RING_TRBS: u32 = 256;

// Pages of `mem`
const PG_DCBAA: u64 = 0; // device context pointers; the scratchpad array at +0x800
const PG_CMD: u64 = 1;
const PG_EVENT: u64 = 2;
const PG_ERST: u64 = 3;
const PG_OUT: u64 = 4; // the slot's output device context
const PG_IN: u64 = 5; // input context
const PG_EP0: u64 = 6;
const PG_INTR: u64 = 7;
const PG_DESC: u64 = 8; // descriptor buffer
const PG_REPORT: u64 = 9; // report buffers, 64 bytes each
const PAGES: u64 = 10;
const SCRATCH_ARRAY: u64 = 0x800;
const MAX_SCRATCH: u32 = 31;

const REPORTS: usize = 8;
const MAX_SLOTS: u32 = 16;

const KEY_IRQ: u64 = 1;
const KEY_CTL: u64 = 2;

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

/// The boot keyboard being served.
struct Kbd {
    slot: u32,
    port: u32,
    dci: u32,
    intr: Ring,
    /// Report buffer of each interrupt-ring position (u8::MAX: none queued there).
    buf_at: [u8; RING_TRBS as usize],
    last: [u8; 8],
    keys: Keys,
}

struct Xhci {
    bar: Mapping,
    op: u64,
    rt: u64,
    db: u64,
    mem: Dma,
    _scratch: Option<Dma>,
    irq: Handle,
    ports: u32,
    usb3: u64, // bit p-1: port p is a USB 3 port
    csz: u64,  // context size: 32 or 64 bytes
    slots: u32,
    cmd: Ring,
    ev_deq: u32,
    ev_cycle: u32,
    /// Port status changes seen while waiting for something else (bit p-1).
    port_events: u64,
    reports: u64,
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

impl Xhci {
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
    fn addr(&self, page: u64, off: u64) -> u64 {
        self.mem.dev_addr(page * 4096 + off)
    }

    // ---- rings ----------------------------------------------------------------------------------

    fn put(&self, page: u64, i: u32, t: Trb) {
        let m = &self.mem.map;
        let o = page * 4096 + u64::from(i) * 16;
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

    /// Wait for the event `want` accepts; port changes seen meanwhile are noted, the rest dropped.
    fn wait_event(&mut self, ms: u64, mut want: impl FnMut(&Trb) -> bool) -> Option<Trb> {
        let deadline = sys::clock_ns() + ms * MS;
        loop {
            while let Some(e) = self.poll_event() {
                if want(&e) {
                    return Some(e);
                }
                if e.ty() == E_PORT {
                    let p = (e.param >> 24) as u32 & 0xFF;
                    if (1..=self.ports).contains(&p) {
                        self.port_events |= 1 << (p - 1);
                    }
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
        let e = self.wait_event(500, |e| e.ty() == E_COMMAND && e.param == at).ok_or(0u32)?;
        if e.code() == CC_SUCCESS { Ok(e) } else { Err(e.code()) }
    }

    // ---- endpoint 0 -----------------------------------------------------------------------------

    /// A control transfer on endpoint 0 of `slot`; the data stage (if `len` > 0) uses the
    /// descriptor page. Returns the bytes transferred.
    fn control(&mut self, slot: u32, ep0: &mut Ring, setup: [u8; 8], len: u16) -> Result<u32, u32> {
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
        let e = self
            .wait_event(1000, |e| e.ty() == E_TRANSFER && e.slot() == slot && ((e.control >> 16) & 0x1F) == 1)
            .ok_or(0u32)?;
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

    fn get_descriptor(&mut self, slot: u32, ep0: &mut Ring, ty: u8, len: u16) -> Result<u32, u32> {
        let l = len.to_le_bytes();
        self.control(slot, ep0, [0x80, 6, 0, ty, 0, 0, l[0], l[1]], len)
    }

    // ---- contexts -------------------------------------------------------------------------------

    fn ctx_w(&self, page: u64, index: u64, dword: u64, v: u32) {
        self.mem.map.w32(page * 4096 + index * self.csz + dword * 4, v);
    }

    fn clear_page(&self, page: u64) {
        for o in (0..4096).step_by(8) {
            self.mem.map.w64(page * 4096 + o, 0);
        }
    }

    /// Input context for Address Device / Evaluate Context: slot (route 0, speed, root port) and
    /// endpoint 0 (control, max packet `mps`, ring at PG_EP0).
    fn input_ep0(&self, add: u32, speed: u32, port: u32, mps: u32) {
        self.clear_page(PG_IN);
        self.ctx_w(PG_IN, 0, 1, add);
        self.ctx_w(PG_IN, 1, 0, speed << 20 | 1 << 27);
        self.ctx_w(PG_IN, 1, 1, port << 16);
        self.ctx_w(PG_IN, 2, 1, 3 << 1 | 4 << 3 | mps << 16);
        let ring = self.addr(PG_EP0, 0) | 1;
        self.ctx_w(PG_IN, 2, 2, ring as u32);
        self.ctx_w(PG_IN, 2, 3, (ring >> 32) as u32);
        self.ctx_w(PG_IN, 2, 4, 8);
    }

    // ---- ports and devices ----------------------------------------------------------------------

    /// Reset port `p` (USB 2) or check its link (USB 3); true when enabled.
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

    /// Enumerate the device on port `p`: a boot keyboard is configured and returned; any other
    /// device gets its slot disabled again (None).
    fn probe(&mut self, p: u32) -> Result<Option<Kbd>, &'static str> {
        if !self.reset_port(p) {
            return Err("port did not enable");
        }
        wait_until(|| false, 20); // reset recovery (USB 2.0 7.1.7.5: 10 ms)
        let speed = (self.portsc(p) >> 10) & 0xF;
        let mut mps = match speed {
            2 => 8,      // low speed
            3 => 64,     // high speed
            4 | 5 => 512, // SuperSpeed (+)
            _ => 8,      // full speed: read from the device descriptor
        };
        let slot = self.command(Trb { param: 0, status: 0, control: T_ENABLE_SLOT << 10 }).map_err(|_| "Enable Slot failed")?.slot();
        if slot == 0 || slot > self.slots {
            return Err("controller returned an invalid slot");
        }
        match self.setup_device(slot, p, speed, &mut mps) {
            Ok(Some(k)) => Ok(Some(k)),
            Ok(None) => {
                self.disable_slot(slot);
                Ok(None)
            }
            Err(e) => {
                self.disable_slot(slot);
                Err(e)
            }
        }
    }

    fn disable_slot(&mut self, slot: u32) {
        let _ = self.command(Trb { param: 0, status: 0, control: T_DISABLE_SLOT << 10 | slot << 24 });
        self.mem.map.w64(PG_DCBAA * 4096 + u64::from(slot) * 8, 0);
    }

    fn setup_device(&mut self, slot: u32, port: u32, speed: u32, mps: &mut u32) -> Result<Option<Kbd>, &'static str> {
        self.clear_page(PG_OUT);
        self.clear_page(PG_EP0);
        self.mem.map.w64(PG_DCBAA * 4096 + u64::from(slot) * 8, self.addr(PG_OUT, 0));
        self.input_ep0(0b11, speed, port, *mps);
        let mut ep0 = Ring::new(PG_EP0);
        let addr_cmd = Trb { param: self.addr(PG_IN, 0), status: 0, control: T_ADDRESS_DEVICE << 10 | slot << 24 };
        self.command(addr_cmd).map_err(|_| "Address Device failed")?;
        // Endpoint 0's real max packet size (full speed: 8, 16, 32 or 64).
        let n = self.get_descriptor(slot, &mut ep0, 1, 8).map_err(|_| "device descriptor unreadable")?;
        if n < 8 {
            return Err("device descriptor too short");
        }
        let m0 = u32::from(self.mem.map.r8(PG_DESC * 4096 + 7));
        if speed == 1 && m0 != *mps && matches!(m0, 8 | 16 | 32 | 64) {
            *mps = m0;
            self.input_ep0(0b10, speed, port, *mps);
            let ev = Trb { param: self.addr(PG_IN, 0), status: 0, control: T_EVALUATE_CTX << 10 | slot << 24 };
            self.command(ev).map_err(|_| "Evaluate Context failed")?;
        }
        // Configuration descriptor: the header for the total length, then all of it (bounded).
        if self.get_descriptor(slot, &mut ep0, 2, 9).map_err(|_| "configuration unreadable")? < 9 {
            return Err("configuration descriptor too short");
        }
        let total = u16::from_le_bytes([self.mem.map.r8(PG_DESC * 4096 + 2), self.mem.map.r8(PG_DESC * 4096 + 3)]).min(1024);
        let got = self.get_descriptor(slot, &mut ep0, 2, total).map_err(|_| "configuration unreadable")? as u64;
        let cfg_value = self.mem.map.r8(PG_DESC * 4096 + 5);
        // Find a boot keyboard interface (class 3, subclass 1, protocol 1) and its interrupt-IN endpoint.
        let (mut iface, mut in_kbd, mut ep) = (None, false, None);
        let mut o = 0u64;
        while o + 2 <= got {
            let len = u64::from(self.mem.map.r8(PG_DESC * 4096 + o));
            let ty = self.mem.map.r8(PG_DESC * 4096 + o + 1);
            if len < 2 || o + len > got {
                break;
            }
            let b = |i: u64| self.mem.map.r8(PG_DESC * 4096 + o + i);
            if ty == 4 && len >= 9 {
                in_kbd = b(3) == 0 && (b(5), b(6), b(7)) == (3, 1, 1) && ep.is_none();
                if in_kbd {
                    iface = Some(b(2));
                }
            } else if ty == 5 && len >= 7 && in_kbd && ep.is_none() && b(2) & 0x80 != 0 && b(3) & 3 == 3 {
                ep = Some((b(2) & 0x0F, u32::from(u16::from_le_bytes([b(4), b(5)]) & 0x7FF), b(6)));
            }
            o += len;
        }
        let (Some(iface), Some((epn, ep_mps, interval))) = (iface, ep) else {
            return Ok(None); // not a boot keyboard
        };
        if epn == 0 || ep_mps == 0 {
            return Err("bad keyboard endpoint descriptor");
        }
        self.control(slot, &mut ep0, [0, 9, cfg_value, 0, 0, 0, 0, 0], 0).map_err(|_| "SET_CONFIGURATION failed")?;
        // The interrupt-IN endpoint: device context index 2 * n + 1.
        let dci = u32::from(epn) * 2 + 1;
        let exp = if speed <= 2 {
            // Full / low speed: bInterval in 1 ms frames -> 2^exp * 125 us.
            (32 - (u32::from(interval.max(1)) * 8).leading_zeros() - 1).clamp(3, 10)
        } else {
            u32::from(interval.clamp(1, 16)) - 1
        };
        self.clear_page(PG_IN);
        self.clear_page(PG_INTR);
        self.ctx_w(PG_IN, 0, 1, 1 | 1 << dci);
        self.ctx_w(PG_IN, 1, 0, speed << 20 | dci << 27);
        self.ctx_w(PG_IN, 1, 1, port << 16);
        let e = u64::from(dci) + 1;
        self.ctx_w(PG_IN, e, 0, exp << 16);
        self.ctx_w(PG_IN, e, 1, 3 << 1 | 7 << 3 | ep_mps << 16);
        let ring = self.addr(PG_INTR, 0) | 1;
        self.ctx_w(PG_IN, e, 2, ring as u32);
        self.ctx_w(PG_IN, e, 3, (ring >> 32) as u32);
        self.ctx_w(PG_IN, e, 4, ep_mps | ep_mps << 16);
        let cfg = Trb { param: self.addr(PG_IN, 0), status: 0, control: T_CONFIGURE_EP << 10 | slot << 24 };
        self.command(cfg).map_err(|_| "Configure Endpoint failed")?;
        self.control(slot, &mut ep0, [0x21, 0x0B, 0, 0, iface, 0, 0, 0], 0).map_err(|_| "SET_PROTOCOL(boot) failed")?;
        // Reports only on change. Optional: a device that stalls it still works (endpoint 0 is
        // not used again).
        let _ = self.control(slot, &mut ep0, [0x21, 0x0A, 0, 0, iface, 0, 0, 0], 0);
        let mut k = Kbd {
            slot,
            port,
            dci,
            intr: Ring::new(PG_INTR),
            buf_at: [u8::MAX; RING_TRBS as usize],
            last: [0; 8],
            keys: Keys::default(),
        };
        for b in 0..REPORTS as u8 {
            self.queue_report(&mut k, b);
        }
        self.ring_doorbell(slot, dci);
        Ok(Some(k))
    }

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
    let mut x = Xhci {
        bar,
        op: caplen,
        rt,
        db,
        mem: Dma::new(dev, PAGES * 4096, sys::DMA_DEVICE_READ | sys::DMA_DEVICE_WRITE).map_err(|_| "cannot pin controller memory")?,
        _scratch: None,
        irq: sys::device_interrupt(dev, 0).map_err(|_| "no interrupt")?,
        ports,
        usb3,
        csz: if hcc & (1 << 2) != 0 { 64 } else { 32 },
        slots,
        cmd: Ring::new(PG_CMD),
        ev_deq: 0,
        ev_cycle: 1,
        port_events: 0,
        reports: 0,
    };
    if x.op_r(PAGESIZE) & 1 == 0 {
        return Err("controller does not support 4 KiB pages");
    }
    if hcc & 1 == 0 && (0..x.mem.pages).any(|i| x.mem.addrs[i] >> 32 != 0) {
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
    wait_until(|| false, 50);
    let port = Port::new(16).map_err(|_| "no port")?;
    port.arm(x.irq, sys::SIGNALED, KEY_IRQ);
    port.arm(ch, sys::READABLE | sys::PEER_CLOSED, KEY_CTL);
    let all = if x.ports >= 64 { u64::MAX } else { (1u64 << x.ports) - 1 };
    let mut kbd = scan(&mut x, all);
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
        let Some((key, _)) = port.wait(sys::WAIT_FOREVER) else { continue };
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
            continue;
        }
        let _ = sys::interrupt_ack(x.irq);
        x.bar.w32(x.rt + IMAN, IMAN_IE | IMAN_IP);
        port.arm(x.irq, sys::SIGNALED, KEY_IRQ);
        for _ in 0..RING_TRBS {
            let Some(e) = x.poll_event() else { break };
            match e.ty() {
                E_TRANSFER => {
                    if let Some(k) = kbd.as_mut()
                        && e.slot() == k.slot
                        && let Err(why) = x.report(k, &e, ch)
                    {
                        println!("xhci: keyboard on port {}: {}", k.port, why);
                        let slot = k.slot;
                        kbd = None;
                        x.disable_slot(slot);
                    }
                }
                E_PORT => {
                    let p = (e.param >> 24) as u32 & 0xFF;
                    if (1..=x.ports).contains(&p) {
                        x.port_events |= 1 << (p - 1);
                    }
                }
                _ => {}
            }
        }
        // Port changes: a keyboard unplugged, or a device plugged in while none is served.
        let changed = core::mem::take(&mut x.port_events);
        if changed != 0 {
            for p in 1..=x.ports {
                if changed & (1 << (p - 1)) == 0 {
                    continue;
                }
                let sc = x.portsc(p);
                x.set_portsc(p, (sc & PS_KEEP) | (sc & PS_CHANGES));
                if let Some(k) = kbd.as_ref()
                    && k.port == p
                    && sc & PS_CCS == 0
                {
                    println!("xhci: keyboard on port {} unplugged", p);
                    let slot = k.slot;
                    kbd = None;
                    x.disable_slot(slot);
                }
            }
            if kbd.is_none() {
                kbd = scan(&mut x, changed);
            }
        }
    }
}

/// Probe the connected ports in `mask` until a boot keyboard is configured.
fn scan(x: &mut Xhci, mask: u64) -> Option<Kbd> {
    for p in 1..=x.ports {
        if mask & (1 << (p - 1)) == 0 || x.portsc(p) & PS_CCS == 0 {
            continue;
        }
        match x.probe(p) {
            Ok(Some(k)) => {
                println!("xhci: keyboard ready on port {} (USB HID boot protocol, US layout, slot {})", p, k.slot);
                return Some(k);
            }
            Ok(None) => println!("xhci: port {}: not a boot keyboard (left unused)", p),
            Err(e) => println!("xhci: port {}: {}", p, e),
        }
    }
    None
}
