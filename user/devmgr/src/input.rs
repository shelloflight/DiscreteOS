//! virtio-input driver (`virtio-input.ddrv`): a keyboard. Every event buffer of the event queue
//! (queue 0, MSI-X entry 0) is offered to the device; key events become characters (US layout)
//! sent to the device manager. Waits on the interrupt and the control channel together (a port).

use libd::proto::{self, HEADER, Header};
use libd::sys::{self, Handle};
use libd::{Dma, Port, Startup, println};

use crate::keymap::Keys;
use crate::virtio::{DESC_WRITE, Virtio};

const EV_SYN: u16 = 0;
const EV_KEY: u16 = 1;
const EV_REL: u16 = 2;
const EV_ABS: u16 = 3;
const REL_X: u16 = 0;
const REL_Y: u16 = 1;
const REL_WHEEL: u16 = 8;
const ABS_X: u16 = 0;
const ABS_Y: u16 = 1;
const BTN_LEFT: u16 = 0x110;
const BTN_RIGHT: u16 = 0x111;
const BTN_MIDDLE: u16 = 0x112;
const EVENT: u64 = 8; // struct virtio_input_event { u16 type, code; u32 value }

const KEY_IRQ: u64 = 1;
const KEY_CTL: u64 = 2;

pub fn main(s: *const Startup) -> i32 {
    // SAFETY: `s` is the startup block pointer the kernel passed to the entry point.
    if !unsafe { libd::init(s, "virtio-input") } {
        return -1;
    }
    let dev = libd::startup_handle(sys::TAG_DEVICE);
    let ch = libd::startup_handle(proto::TAG_CONTROL);
    match run(dev, ch) {
        Ok(code) => code,
        Err(e) => {
            println!("virtio-input: {}", e);
            2
        }
    }
}

fn post(q: &mut crate::virtio::Queue, events: &Dma, id: u16) {
    q.desc(id, events.dev_addr(u64::from(id) * EVENT), EVENT as u32, DESC_WRITE, 0);
    q.push(id);
}

fn run(dev: Handle, ch: Handle) -> Result<i32, &'static str> {
    let v = Virtio::open(dev)?;
    let mut q = v.queue(0)?;
    let events = Dma::new(dev, 4096, sys::DMA_DEVICE_WRITE).map_err(|_| "cannot pin the event buffers")?;
    for id in 0..q.size {
        post(&mut q, &events, id);
    }
    v.driver_ok();
    v.notify(&q);
    let port = Port::new(16).map_err(|_| "no port")?;
    port.arm(q.irq, sys::SIGNALED, KEY_IRQ);
    port.arm(ch, sys::READABLE | sys::PEER_CLOSED, KEY_CTL);
    println!("virtio-input: device ready (US keyboard + pointer, {} event buffers, MSI-X)", q.size);
    proto::send(ch, proto::READY, 0, 0);
    let mut keys = Keys::default();
    let mut buttons = 0u8;
    let mut rel_dx = 0i32;
    let mut rel_dy = 0i32;
    let mut rel_wheel = 0i8;
    let mut abs_x = 0u32;
    let mut abs_y = 0u32;
    let mut abs_dirty = false;
    let mut ptr_dirty = false;
    let mut msg = [0u8; 256];
    loop {
        let Some((key, _)) = port.wait(sys::WAIT_FOREVER) else { continue };
        if key == KEY_CTL {
            match sys::channel_read(ch, &mut msg, 0) {
                Ok(n) => {
                    if let Some(h) = Header::get(&msg[..n as usize]) {
                        let mut out = [0u8; HEADER];
                        let (st, a) = match h.op {
                            proto::STATS => (0, q.interrupts()),
                            proto::SET_KEYMAP => {
                                keys.set_layout(h.a as u8);
                                (0, 0)
                            }
                            proto::TEST_CRASH => {
                                // SAFETY: deliberately faults (test).
                                unsafe { core::ptr::write_volatile(0x10 as *mut u32, 1) };
                                (0, 0)
                            }
                            _ => (sys::ERR_INVALID_ARGS as i32, 0),
                        };
                        if h.txid != 0 {
                            Header { txid: h.txid, op: h.op, status: st, a, b: 0 }.put(&mut out);
                            sys::channel_write(ch, &out);
                        }
                    }
                }
                Err(sys::ERR_SHOULD_WAIT) => {}
                Err(_) => return Ok(0), // the device manager is gone
            }
            port.arm(ch, sys::READABLE | sys::PEER_CLOSED, KEY_CTL);
            continue;
        }
        let _ = sys::interrupt_ack(q.irq);
        port.arm(q.irq, sys::SIGNALED, KEY_IRQ);
        let mut reposted = false;
        while let Some((id, len)) = q.pop() {
            if u64::from(len) >= EVENT {
                let m = &events.map;
                let off = u64::from(id) * EVENT;
                let (ty, code, value) = (m.r16(off), m.r16(off + 2), m.r32(off + 4));
                match ty {
                    EV_KEY => match code {
                        BTN_LEFT => {
                            if value != 0 { buttons |= 1; } else { buttons &= !1; }
                            ptr_dirty = true;
                        }
                        BTN_RIGHT => {
                            if value != 0 { buttons |= 2; } else { buttons &= !2; }
                            ptr_dirty = true;
                        }
                        BTN_MIDDLE => {
                            if value != 0 { buttons |= 4; } else { buttons &= !4; }
                            ptr_dirty = true;
                        }
                        _ => {
                            if let Some(c) = keys.key(code, value != 0) {
                                proto::send(ch, proto::KEY, u64::from(c), 0);
                            }
                        }
                    },
                    EV_REL => {
                        let v = value as i32;
                        match code {
                            REL_X => { rel_dx = rel_dx.saturating_add(v); ptr_dirty = true; }
                            REL_Y => { rel_dy = rel_dy.saturating_add(v); ptr_dirty = true; }
                            REL_WHEEL => { rel_wheel = rel_wheel.saturating_add(v.clamp(-127, 127) as i8); ptr_dirty = true; }
                            _ => {}
                        }
                    }
                    EV_ABS => {
                        match code {
                            ABS_X => { abs_x = value.min(32767); abs_dirty = true; ptr_dirty = true; }
                            ABS_Y => { abs_y = value.min(32767); abs_dirty = true; ptr_dirty = true; }
                            _ => {}
                        }
                    }
                    EV_SYN if ptr_dirty => {
                        let (a, flags) = if abs_dirty {
                            (u64::from(abs_x) | (u64::from(abs_y) << 32), proto::POINTER_ABS)
                        } else {
                            (u64::from(rel_dx as u32) | (u64::from(rel_dy as u32) << 32), 0)
                        };
                        let b = u64::from(buttons) | (u64::from(rel_wheel as u8) << 8) | flags;
                        proto::send(ch, proto::POINTER, a, b);
                        rel_dx = 0;
                        rel_dy = 0;
                        rel_wheel = 0;
                        abs_dirty = false;
                        ptr_dirty = false;
                    }
                    _ => {}
                }
            }
            post(&mut q, &events, id);
            reposted = true;
        }
        if reposted {
            v.notify(&q);
        }
    }
}
