//! The console service (`console.dx`, docs/services.md): keyboard input, the start of the
//! terminal.
//!
//! It connects to the device manager's `input` endpoint (manifest grant `connect =
//! ["devmgr.input"]`) and gets every key typed on any keyboard (`proto::INPUT_KEY`). Typed
//! characters are echoed, Backspace erases, and Enter completes a line, which is reported. A
//! restarted device manager reaches it again through the service manager (`svc::CONNECT
//! "devmgr.input"`).

#![no_std]

use libd::proto::{self, HEADER, Header};
use libd::sys::{self, Handle};
use libd::{Port, Startup, println, svc};

libd::entry!(_start, main);

const KEY_CTL: u64 = 1;
const KEY_INPUT: u64 = 2;

struct Console {
    line: [u8; 128],
    len: usize,
}

impl Console {
    fn key(&mut self, c: u8, from: &[u8]) {
        match c {
            b'\n' => {
                libd::print(format_args!("\n"));
                println!(
                    "console: you typed: {} ({})",
                    core::str::from_utf8(&self.line[..self.len]).unwrap_or("?"),
                    core::str::from_utf8(from).unwrap_or("?")
                );
                self.len = 0;
            }
            0x08 if self.len > 0 => {
                self.len -= 1;
                libd::print(format_args!("\x08 \x08")); // erase the character
            }
            b' '..=b'~' if self.len < self.line.len() => {
                self.line[self.len] = c;
                self.len += 1;
                libd::print(format_args!("{}", c as char));
            }
            _ => {}
        }
    }
}

fn main(s: *const Startup) -> i32 {
    // SAFETY: `s` is the startup block pointer the kernel passed to the entry point.
    if !unsafe { libd::init(s, "console") } {
        return 1;
    }
    let ctl = libd::startup_handle(proto::TAG_CONTROL);
    let mut input: Handle = svc::endpoint(b"devmgr.input");
    let Ok(port) = Port::new(16) else { return 1 };
    if ctl != 0 {
        port.arm(ctl, sys::READABLE | sys::PEER_CLOSED, KEY_CTL);
    }
    if input != 0 {
        port.arm(input, sys::READABLE | sys::PEER_CLOSED, KEY_INPUT);
    }
    println!("console: ready: keyboard input from devmgr.input (Enter ends a line)");
    let mut con = Console { line: [0; 128], len: 0 };
    let mut buf = [0u8; HEADER + 64];
    loop {
        let Some((key, _)) = port.wait(sys::WAIT_FOREVER) else { continue };
        if key == KEY_INPUT {
            loop {
                match sys::channel_read(input, &mut buf, 0) {
                    Ok(n) => {
                        let n = n as usize;
                        if let Some(h) = Header::get(&buf[..n])
                            && h.op == proto::INPUT_KEY
                        {
                            let from = (n - HEADER).min(32);
                            let mut name = [0u8; 32];
                            name[..from].copy_from_slice(&buf[HEADER..HEADER + from]);
                            con.key(h.a as u8, &name[..from]);
                        }
                    }
                    Err(sys::ERR_SHOULD_WAIT) => {
                        port.arm(input, sys::READABLE | sys::PEER_CLOSED, KEY_INPUT);
                        break;
                    }
                    Err(_) => break, // the device manager is gone; the service manager links us again
                }
            }
            continue;
        }
        // The service manager: a new input channel (devmgr restarted), or stop.
        loop {
            let mut hs = [0 as Handle; 1];
            match sys::channel_read_h(ctl, &mut buf, &mut hs, 0) {
                Ok((n, nh)) => {
                    let handle = if nh > 0 { hs[0] } else { 0 };
                    match Header::get(&buf[..n]) {
                        Some(h) if h.op == svc::CONNECT && &buf[HEADER..n] == b"devmgr.input" && handle != 0 => {
                            if input != 0 {
                                sys::handle_close(input);
                            }
                            input = handle;
                            port.arm(input, sys::READABLE | sys::PEER_CLOSED, KEY_INPUT);
                        }
                        Some(h) if h.op == svc::SHUTDOWN => return 0,
                        _ => {
                            if handle != 0 {
                                sys::handle_close(handle);
                            }
                        }
                    }
                }
                Err(sys::ERR_SHOULD_WAIT) => {
                    port.arm(ctl, sys::READABLE | sys::PEER_CLOSED, KEY_CTL);
                    break;
                }
                Err(_) => break,
            }
        }
    }
}
