//! Which keyboards may type. Input from every keyboard is merged into one stream, so a device
//! that claims to be a keyboard (a "BadUSB" stick, a compromised receiver) could type commands
//! into the shell. The rule:
//!
//! - when no keyboard is in use, the first one that types is accepted (there is nothing to
//!   confirm it with; this is the keyboard at the desk at boot);
//! - while keyboards are in use, a new one's keys are held (dropped) until someone accepts it with
//!   Ctrl+Alt+Insert on a keyboard already in use (a device can only type through itself, so it
//!   cannot accept itself);
//! - a keyboard that goes away (unplugged, its driver ended) is no longer in use; plugged in
//!   again it is a new keyboard.

use libd::proto::key;

/// The accept chord.
pub const ACCEPT: u32 = key::INSERT | key::CTRL | key::ALT;

const MAX_TRUSTED: usize = 8;
const MAX_HELD: usize = 4;

/// A keyboard: (driver index, the driver's keyboard id).
type Kbd = (usize, u32);

pub struct Trust {
    trusted: [Option<Kbd>; MAX_TRUSTED],
    held: [Option<Kbd>; MAX_HELD],
}

#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Pass the key on.
    Pass,
    /// The first keyboard in use: pass the key on.
    FirstInUse,
    /// Drop the key: the keyboard is not accepted (`first`: the first key held from it).
    Held { first: bool },
    /// The accept chord on a keyboard in use: this many held keyboards are accepted (the chord
    /// itself is not passed on).
    Accepted(usize),
}

impl Trust {
    pub const fn new() -> Trust {
        Trust { trusted: [None; MAX_TRUSTED], held: [None; MAX_HELD] }
    }

    pub fn key(&mut self, kbd: Kbd, k: u32) -> Verdict {
        if self.trusted.contains(&Some(kbd)) {
            if k != ACCEPT {
                return Verdict::Pass;
            }
            let mut n = 0;
            for h in self.held.iter_mut() {
                if let Some(x) = h.take()
                    && let Some(slot) = self.trusted.iter_mut().find(|t| t.is_none())
                {
                    *slot = Some(x);
                    n += 1;
                }
            }
            return Verdict::Accepted(n);
        }
        if self.trusted.iter().all(Option::is_none) {
            self.held.iter_mut().filter(|h| **h == Some(kbd)).for_each(|h| *h = None);
            self.trusted[0] = Some(kbd);
            return Verdict::FirstInUse;
        }
        if self.held.contains(&Some(kbd)) {
            return Verdict::Held { first: false };
        }
        match self.held.iter_mut().find(|h| h.is_none()) {
            Some(slot) => {
                *slot = Some(kbd);
                Verdict::Held { first: true }
            }
            None => Verdict::Held { first: false }, // too many new keyboards: still held
        }
    }

    /// Keyboard `kbd` is gone.
    pub fn gone(&mut self, kbd: Kbd) {
        for t in self.trusted.iter_mut().chain(self.held.iter_mut()) {
            if *t == Some(kbd) {
                *t = None;
            }
        }
    }

    /// Every keyboard of driver `drv` is gone (it ended or was restarted).
    pub fn driver_gone(&mut self, drv: usize) {
        for t in self.trusted.iter_mut().chain(self.held.iter_mut()) {
            if t.is_some_and(|(d, _)| d == drv) {
                *t = None;
            }
        }
    }
}
