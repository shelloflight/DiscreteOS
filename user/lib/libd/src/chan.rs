//! Channels with owned handles: messages carry data and handles, and handles that arrive are
//! owned by the receiver (closed if nobody takes them), so a message can never leak a capability.

use crate::handle::Owned;
use crate::sys::{self, Handle, MsgHandle};

/// Most handles one message carries (ABI limit).
pub const MAX_HANDLES: usize = 64;
/// Most bytes one message carries (ABI limit).
pub const MAX_BYTES: usize = 65536;

/// One end of a channel.
#[derive(Debug, Default)]
pub struct Channel(pub Owned);

/// Handles received with a message. Take them with `take`/`iter`; the rest close on drop.
pub struct Received {
    h: [Handle; MAX_HANDLES],
    n: usize,
}

impl Received {
    const fn empty() -> Received {
        Received { h: [0; MAX_HANDLES], n: 0 }
    }

    pub fn len(&self) -> usize {
        self.h[..self.n].iter().filter(|&&h| h != 0).count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The `i`-th handle of the message (once).
    pub fn take(&mut self, i: usize) -> Option<Owned> {
        if i >= self.n || self.h[i] == 0 {
            return None;
        }
        Some(Owned::from_raw(core::mem::take(&mut self.h[i])))
    }

    /// All handles not taken yet, in order.
    pub fn iter(&mut self) -> impl Iterator<Item = Owned> + '_ {
        (0..self.n).filter_map(|i| self.take(i))
    }
}

impl Drop for Received {
    fn drop(&mut self) {
        for &h in &self.h[..self.n] {
            if h != 0 {
                sys::handle_close(h);
            }
        }
    }
}

/// Handles to send: moved out of this program by the write, even if it fails (ABI rule).
fn outgoing<I: IntoIterator<Item = Owned>>(handles: I, out: &mut [MsgHandle; MAX_HANDLES]) -> Result<usize, i64> {
    let mut n = 0;
    for h in handles {
        if n == MAX_HANDLES {
            return Err(sys::ERR_OUT_OF_RANGE); // `h` and the rest close here; nothing was sent
        }
        out[n] = MsgHandle { handle: h.into_raw(), rights: sys::RIGHTS_SAME };
        n += 1;
    }
    Ok(n)
}

fn close_all(hs: &[MsgHandle]) {
    for h in hs {
        sys::handle_close(h.handle);
    }
}

impl Channel {
    /// Both ends of a new channel.
    pub fn pair() -> Result<(Channel, Channel), i64> {
        let (a, b) = sys::channel_pair()?;
        Ok((Channel(Owned::from_raw(a)), Channel(Owned::from_raw(b))))
    }

    pub fn raw(&self) -> Handle {
        self.0.raw()
    }

    /// Send `data` and `handles`.
    pub fn write<I: IntoIterator<Item = Owned>>(&self, data: &[u8], handles: I) -> Result<(), i64> {
        let mut hs = [MsgHandle::default(); MAX_HANDLES];
        let n = match outgoing(handles, &mut hs) {
            Ok(n) => n,
            Err(e) => {
                close_all(&hs[..MAX_HANDLES]);
                return Err(e);
            }
        };
        let r = sys::channel_write_h(self.raw(), data, &hs[..n]);
        if r < 0 { Err(r) } else { Ok(()) }
    }

    /// Receive one message into `buf` (waiting up to `timeout` ns): (bytes, handles).
    pub fn read(&self, buf: &mut [u8], timeout: u64) -> Result<(usize, Received), i64> {
        let mut r = Received::empty();
        let (n, nh) = sys::channel_read_h(self.raw(), buf, &mut r.h, timeout)?;
        r.n = nh.min(MAX_HANDLES);
        Ok((n, r))
    }

    /// A call: `req` (its first 4 bytes are the kernel's transaction id) with `handles`; the
    /// reply into `buf`: (bytes, handles).
    pub fn call<I: IntoIterator<Item = Owned>>(&self, req: &[u8], handles: I, buf: &mut [u8], timeout: u64) -> Result<(usize, Received), i64> {
        let mut hs = [MsgHandle::default(); MAX_HANDLES];
        let n = match outgoing(handles, &mut hs) {
            Ok(n) => n,
            Err(e) => {
                close_all(&hs[..MAX_HANDLES]);
                return Err(e);
            }
        };
        let mut r = Received::empty();
        let (len, nh) = sys::channel_call_h(self.raw(), req, &hs[..n], buf, &mut r.h, timeout)?;
        r.n = nh.min(MAX_HANDLES);
        Ok((len, r))
    }

    /// Wait until a message is waiting or the peer is gone: the signals seen.
    pub fn wait_readable(&self, timeout: u64) -> Result<u32, i64> {
        self.0.wait(sys::READABLE | sys::PEER_CLOSED, timeout)
    }
}
