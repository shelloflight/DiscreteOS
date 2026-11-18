//! US keyboard layout. PC scancode set 1 (what the 8042 delivers with translation on) and Linux
//! input keycodes (what virtio-input delivers) agree for every key mapped here.

const PLAIN: [u8; 58] = *b"\0\x1b1234567890-=\x08\tqwertyuiop[]\n\0asdfghjkl;'`\0\\zxcvbnm,./\0*\0 ";
const SHIFT: [u8; 58] = *b"\0\x1b!@#$%^&*()_+\x08\tQWERTYUIOP{}\n\0ASDFGHJKL:\"~\0|ZXCVBNM<>?\0*\0 ";

pub const LSHIFT: u16 = 42;
pub const RSHIFT: u16 = 54;
pub const CTRL: u16 = 29;
pub const CAPS: u16 = 58;

#[derive(Default)]
pub struct Keys {
    shift_l: bool,
    shift_r: bool,
    ctrl: bool,
    caps: bool,
}

impl Keys {
    /// A key went down (`down`) or up; the character it types, if any.
    pub fn key(&mut self, code: u16, down: bool) -> Option<u8> {
        match code {
            LSHIFT => self.shift_l = down,
            RSHIFT => self.shift_r = down,
            CTRL => self.ctrl = down,
            CAPS if down => self.caps = !self.caps,
            _ if down => {
                let i = usize::from(code);
                let mut c = *if self.shift_l || self.shift_r { SHIFT.get(i)? } else { PLAIN.get(i)? };
                if c == 0 {
                    return None;
                }
                if self.caps && c.is_ascii_alphabetic() {
                    c ^= 0x20;
                }
                if self.ctrl && c.is_ascii_alphabetic() {
                    c &= 0x1F;
                }
                return Some(c);
            }
            _ => {}
        }
        None
    }
}
