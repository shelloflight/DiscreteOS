//! US keyboard layout. PC scancode set 1 (what the 8042 delivers with translation on) and Linux
//! input keycodes (what virtio-input delivers) agree for every key mapped here; the xHCI driver
//! turns HID usages into these codes too.
//!
//! A key is reported as a key value (`libd::proto::key`): a character (below 0x100; Enter `\n`,
//! Backspace 0x08, Ctrl+letter its control character), or a named key (arrows, Home/End,
//! PgUp/PgDn, Insert/Delete) with the modifier bits held at the time.

use libd::proto::key;

const PLAIN: [u8; 58] = *b"\0\x1b1234567890-=\x08\tqwertyuiop[]\n\0asdfghjkl;'`\0\\zxcvbnm,./\0*\0 ";
const SHIFT: [u8; 58] = *b"\0\x1b!@#$%^&*()_+\x08\tQWERTYUIOP{}\n\0ASDFGHJKL:\"~\0|ZXCVBNM<>?\0*\0 ";

pub const LSHIFT: u16 = 42;
pub const RSHIFT: u16 = 54;
pub const CTRL: u16 = 29;
pub const ALT: u16 = 56;
pub const CAPS: u16 = 58;
/// Linux input codes only (virtio-input): right control and right alt.
const RCTRL: u16 = 97;
const RALT: u16 = 100;

/// The named key of a code: the navigation block (Linux codes 102-111, or set 1 after an E0
/// prefix) and the keypad with Num Lock off (set 1 and Linux agree on 71-83).
fn named(code: u16) -> Option<u32> {
    Some(match code {
        71 | 102 => key::HOME,
        72 | 103 => key::UP,
        73 | 104 => key::PAGE_UP,
        75 | 105 => key::LEFT,
        77 | 106 => key::RIGHT,
        79 | 107 => key::END,
        80 | 108 => key::DOWN,
        81 | 109 => key::PAGE_DOWN,
        82 | 110 => key::INSERT,
        83 | 111 => key::DELETE,
        _ => return None,
    })
}

#[derive(Default)]
pub struct Keys {
    shift_l: bool,
    shift_r: bool,
    ctrl: bool,
    alt: bool,
    caps: bool,
}

impl Keys {
    /// Caps Lock is on (a keyboard's LED follows it).
    pub fn caps(&self) -> bool {
        self.caps
    }

    /// A key went down (`down`) or up; the key value it produces, if any.
    pub fn key(&mut self, code: u16, down: bool) -> Option<u32> {
        match code {
            LSHIFT => self.shift_l = down,
            RSHIFT => self.shift_r = down,
            CTRL | RCTRL => self.ctrl = down,
            ALT | RALT => self.alt = down,
            CAPS if down => self.caps = !self.caps,
            _ if down => {
                let shift = self.shift_l || self.shift_r;
                if let Some(k) = named(code) {
                    let mods = if shift { key::SHIFT } else { 0 } | if self.ctrl { key::CTRL } else { 0 } | if self.alt { key::ALT } else { 0 };
                    return Some(k | mods);
                }
                let i = usize::from(code);
                let mut c = *if shift { SHIFT.get(i)? } else { PLAIN.get(i)? };
                if c == 0 {
                    return None;
                }
                if self.caps && c.is_ascii_alphabetic() {
                    c ^= 0x20;
                }
                if self.ctrl && c.is_ascii_alphabetic() {
                    c &= 0x1F;
                }
                return Some(u32::from(c));
            }
            _ => {}
        }
        None
    }
}
