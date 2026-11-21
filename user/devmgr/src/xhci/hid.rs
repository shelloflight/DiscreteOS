//! USB HID keyboards (boot protocol, repeat, Caps Lock LED) and mice (HID report descriptor
//! parser + boot-protocol fallback).

use libd::proto;
use libd::sys::{self, Handle};

use crate::keymap::{self, Keys};

use super::*;

/// A boot keyboard being served.
pub(super) struct Kbd {
    /// Which of the `MAX_KBDS` (its interrupt ring page, its report buffers).
    pub(super) idx: usize,
    pub(super) id: Ident,
    pub(super) slot: u32,
    pub(super) loc: Loc,
    pub(super) iface: u8,
    pub(super) dci: u32,
    pub(super) intr: Ring,
    /// Report buffer of each interrupt-ring position (u8::MAX: none queued there).
    pub(super) buf_at: [u8; RING_TRBS as usize],
    pub(super) last: [u8; 8],
    pub(super) keys: Keys,
    /// The key held down: (key value, its usage, when it repeats next).
    pub(super) repeat: Option<(u32, u8, u64)>,
    /// Caps Lock as the keyboard's LED shows it; `leds_due`: the LED must be updated.
    pub(super) leds_caps: bool,
    pub(super) leds_due: bool,
}

/// Where a value is in a HID report (bits after the report id).
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub(super) struct Field {
    pub(super) bit: u16,
    pub(super) size: u8,
    pub(super) signed: bool,
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
pub(super) struct MouseFormat {
    /// The report id of the pointer report (0: the device uses no ids).
    pub(super) id: u8,
    /// One bit per button, from `buttons.bit` (size = how many).
    pub(super) buttons: Field,
    pub(super) x: Field,
    pub(super) y: Field,
    pub(super) wheel: Option<Field>,
    pub(super) boot: bool,
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
pub(super) struct Mouse {
    /// Which of the `MAX_MICE` (its interrupt ring page, its report buffers).
    pub(super) idx: usize,
    pub(super) id: Ident,
    pub(super) slot: u32,
    pub(super) loc: Loc,
    pub(super) dci: u32,
    /// Bytes asked for per report (the endpoint's max packet, at most 64).
    pub(super) len: u32,
    pub(super) intr: Ring,
    pub(super) buf_at: [u8; RING_TRBS as usize],
    pub(super) fmt: MouseFormat,
    pub(super) buttons: u32,
}

impl Xhci {
    /// A keyboard, a mouse, or both (one device, e.g. a receiver): configure the device and the
    /// interrupt endpoints, choose the protocols, queue the first reports.
    pub(super) fn setup_input(&mut self, slot: u32, loc: Loc, cfg_value: u8, id: Ident, kbd: Option<Iface>, mouse: Option<Iface>) -> Result<Found, &'static str> {
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
    pub(super) fn report(&mut self, k: &mut Kbd, e: &Trb, ch: Handle) -> Result<(), &'static str> {
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
    pub(super) fn set_leds(&mut self, i: usize) {
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
    pub(super) fn mouse_report(&mut self, m: &mut Mouse, e: &Trb, ch: Handle) -> Result<(), &'static str> {
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

    /// Held keys that are due repeat (each keyboard on its own).
    pub(super) fn repeat_keys(&mut self, ch: Handle, now: u64) {
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
}

/// Where report buffer `buf` of keyboard `idx` is in the report page.
fn report_off(idx: usize, buf: u8) -> u64 {
    ((idx * REPORTS) as u64 + u64::from(buf)) * 64
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
    // Modifiers first: left/right control, shift, alt, and Super/GUI.
    let mods = [
        (0, keymap::CTRL),
        (1, keymap::LSHIFT),
        (2, keymap::ALT),
        (3, keymap::LMETA),
        (4, keymap::CTRL),
        (5, keymap::RSHIFT),
        (6, keymap::ALT),
        (7, keymap::RMETA),
    ];
    for (bit, code) in mods {
        let (was, is) = (old[0] >> bit & 1, new[0] >> bit & 1);
        if was != is
            && let Some(c) = keys.key(code, is == 1)
            && n < out.len()
        {
            // Super on its own (the compositor's launcher key).
            out[n] = c;
            n += 1;
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

