//! virtio-input driver (`virtio-input.ddrv`): a keyboard. Every event buffer of the event queue
//! (queue 0, MSI-X entry 0) is offered to the device; key events become characters (US layout)
//! sent to the device manager. Waits on the interrupt and the control channel together (a port).

use libd::proto::{self, HEADER, Header};
use libd::sys::{self, Handle};
use libd::{Dma, Port, Startup, println};

use crate::keymap::Keys;
use crate::virtio::{DESC_WRITE, Virtio};

const EV_KEY: u16 = 1;
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
    println!("virtio-input: keyboard ready (US layout, {} event buffers, MSI-X)", q.size);
    proto::send(ch, proto::READY, 0, 0);
    let mut keys = Keys::default();
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
                            proto::TEST_CRASH => {
                                // SAFETY: deliberately faults (test).
                                unsafe { core::ptr::write_volatile(0x10 as *mut u32, 1) };
                                (0, 0)
                            }
                            _ => (sys::ERR_INVALID_ARGS as i32, 0),
                        };
                        Header { txid: h.txid, op: h.op, status: st, a, b: 0 }.put(&mut out);
                        sys::channel_write(ch, &out);
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
                if ty == EV_KEY
                    && let Some(c) = keys.key(code, value != 0)
                {
                    proto::send(ch, proto::KEY, u64::from(c), 0);
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
