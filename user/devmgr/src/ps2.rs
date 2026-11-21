//! PS/2 keyboard driver (`ps2.ddrv`), runs in user space. The 8042 is a platform
//! device: I/O window 0 is the data port (0x60), window 1 status/command (0x64); interrupt 0 is
//! ISA IRQ 1. Scancode set 1 (controller translation), US layout. Every controller wait is
//! bounded, so a missing or stuck controller ends the driver instead of hanging it.

use libd::proto::{self, HEADER, Header};
use libd::sys::{self, Handle};
use libd::{Port, Startup, println};

use crate::keymap::{self, Keys};

const DATA: u64 = 0;
const CTL: u64 = 1;
const ST_OUT_FULL: u64 = 1;
const ST_IN_FULL: u64 = 2;
const SPIN: u32 = 100_000;

const KEY_IRQ: u64 = 1;
const KEY_CTL: u64 = 2;

struct Ps2 {
    dev: Handle,
}

impl Ps2 {
    fn status(&self) -> u64 {
        sys::io_read(self.dev, CTL, 0, 1).unwrap_or(0xFF)
    }
    fn wait_write(&self) -> bool {
        (0..SPIN).any(|_| self.status() & ST_IN_FULL == 0)
    }
    fn wait_read(&self) -> bool {
        (0..SPIN).any(|_| self.status() & ST_OUT_FULL != 0)
    }
    fn cmd(&self, c: u64) -> bool {
        self.wait_write() && sys::io_write(self.dev, CTL, 0, 1, c).is_ok()
    }
    fn data(&self, d: u64) -> bool {
        self.wait_write() && sys::io_write(self.dev, DATA, 0, 1, d).is_ok()
    }
    fn read(&self) -> u64 {
        sys::io_read(self.dev, DATA, 0, 1).unwrap_or(0)
    }

    /// Ports off, flush, IRQ 1 on (IRQ 12 off), translation on, keyboard port on.
    fn init(&self) -> bool {
        if self.status() == 0xFF || !self.cmd(0xAD) || !self.cmd(0xA7) {
            return false;
        }
        for _ in 0..32 {
            if self.status() & ST_OUT_FULL == 0 {
                break;
            }
            self.read();
        }
        if !self.cmd(0x20) || !self.wait_read() {
            return false;
        }
        let cfg = (self.read() | 0x01 | 0x40) & !0x02;
        self.cmd(0x60) && self.data(cfg) && self.cmd(0xAE)
    }
}

pub fn main(s: *const Startup) -> i32 {
    // SAFETY: `s` is the startup block pointer the kernel passed to the entry point.
    if !unsafe { libd::init(s, "ps2") } {
        return -1;
    }
    let dev = libd::startup_handle(sys::TAG_DEVICE);
    let ch = libd::startup_handle(proto::TAG_CONTROL);
    let k = Ps2 { dev };
    if !k.init() {
        println!("ps2: controller not responding");
        return 2;
    }
    let Ok(irq) = sys::device_interrupt(dev, 0) else {
        println!("ps2: no interrupt line");
        return 2;
    };
    let Ok(port) = Port::new(16) else { return 2 };
    port.arm(irq, sys::SIGNALED, KEY_IRQ);
    port.arm(ch, sys::READABLE | sys::PEER_CLOSED, KEY_CTL);
    println!("ps2: keyboard ready (US layout, IRQ 1)");
    proto::send(ch, proto::READY, 0, 0);
    let mut keys = Keys::default();
    let mut extended = false;
    let mut msg = [0u8; 256];
    loop {
        let Some((key, _)) = port.wait(sys::WAIT_FOREVER) else { continue };
        if key == KEY_CTL {
            match sys::channel_read(ch, &mut msg, 0) {
                Ok(n) => {
                    if let Some(h) = Header::get(&msg[..n as usize]) {
                        let (st, a) = match h.op {
                            proto::STATS => (0, sys::interrupt_ack(irq).unwrap_or(0)),
                            _ => (sys::ERR_INVALID_ARGS as i32, 0),
                        };
                        let mut out = [0u8; HEADER];
                        Header { txid: h.txid, op: h.op, status: st, a, b: 0 }.put(&mut out);
                        sys::channel_write(ch, &out);
                    }
                }
                Err(sys::ERR_SHOULD_WAIT) => {}
                Err(_) => return 0,
            }
            port.arm(ch, sys::READABLE | sys::PEER_CLOSED, KEY_CTL);
            continue;
        }
        let _ = sys::interrupt_ack(irq);
        port.arm(irq, sys::SIGNALED, KEY_IRQ);
        // Drain everything available (bounded) so no scancode is left behind.
        for _ in 0..16 {
            if k.status() & ST_OUT_FULL == 0 {
                break;
            }
            let sc = k.read() as u8;
            if sc == 0xE0 {
                extended = true;
                continue;
            }
            let ext = core::mem::take(&mut extended);
            let raw = u16::from(sc & 0x7F);
            if ext && (raw == keymap::LSHIFT || raw == keymap::RSHIFT) {
                continue; // the fake shifts some keyboards send around the navigation block
            }
            let code = if ext && raw == 0x5B {
                keymap::LMETA
            } else if ext && raw == 0x5C {
                keymap::RMETA
            } else {
                raw
            };
            if let Some(c) = keys.key(code, sc & 0x80 == 0) {
                proto::send(ch, proto::KEY, u64::from(c), 0);
            }
        }
    }
}
