//! Multi-layout keyboard mapper (`us`, `uk`, `de`, `fr`, `es`). PC scancode Set 1 (what the 8042
//! delivers with translation on) and Linux input keycodes (what virtio-input delivers) agree for
//! every key mapped here; the xHCI driver turns HID usages into these codes too.
//!
//! A key is reported as a key value (`libd::proto::key`): a Unicode Latin-1 character (`<= 0xFF`;
//! Enter `\n`, Backspace 0x08, Ctrl+letter its control character, or accented symbols like `£`,
//! `ä`, `ö`, `ü`, `ß`, `é`, `è`, `ç`, `à`, `ñ`, `¡`, `¿`), or a named key (arrows, Home/End,
//! PgUp/PgDn, Insert/Delete, F1-F12, Meta) with the modifier bits held at the time.

use libd::proto::key;

pub const LAYOUT_US: u8 = 0;
pub const LAYOUT_UK: u8 = 1;
pub const LAYOUT_DE: u8 = 2;
pub const LAYOUT_FR: u8 = 3;
pub const LAYOUT_ES: u8 = 4;

pub fn layout_name(id: u8) -> &'static str {
    match id {
        LAYOUT_UK => "uk",
        LAYOUT_DE => "de",
        LAYOUT_FR => "fr",
        LAYOUT_ES => "es",
        _ => "us",
    }
}

const US_PLAIN: [u8; 58] = *b"\0\x1b1234567890-=\x08\tqwertyuiop[]\n\0asdfghjkl;'`\0\\zxcvbnm,./\0*\0 ";
const US_SHIFT: [u8; 58] = *b"\0\x1b!@#$%^&*()_+\x08\tQWERTYUIOP{}\n\0ASDFGHJKL:\"~\0|ZXCVBNM<>?\0*\0 ";

pub const LSHIFT: u16 = 42;
pub const RSHIFT: u16 = 54;
pub const CTRL: u16 = 29;
pub const ALT: u16 = 56;
pub const CAPS: u16 = 58;
/// ISO 102nd key (`< > |` on DE/FR/ES, `\ |` on UK).
pub const ISO_102: u16 = 86;
/// Linux input codes (also emitted by PS/2 extended 0x5B/0x5C and xHCI HID GUI modifiers).
pub const LMETA: u16 = 125;
pub const RMETA: u16 = 126;
/// Right control and right alt (AltGr).
pub const RCTRL: u16 = 97;
pub const RALT: u16 = 100;

fn named(code: u16) -> Option<u32> {
    Some(match code {
        59 => key::F1,
        60 => key::F2,
        61 => key::F3,
        62 => key::F4,
        63 => key::F5,
        64 => key::F6,
        65 => key::F7,
        66 => key::F8,
        67 => key::F9,
        68 => key::F10,
        87 => key::F11,
        88 => key::F12,
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

fn map_char(layout: u8, code: u16, shift: bool, altgr: bool) -> Option<u32> {
    if code == ISO_102 {
        return Some(match layout {
            LAYOUT_US | LAYOUT_UK => if shift { u32::from(b'|') } else { u32::from(b'\\') },
            LAYOUT_DE => if altgr { u32::from(b'|') } else if shift { u32::from(b'>') } else { u32::from(b'<') },
            LAYOUT_FR | LAYOUT_ES => if shift { u32::from(b'>') } else { u32::from(b'<') },
            _ => u32::from(b'\\'),
        });
    }
    let idx = usize::from(code);
    if idx >= 58 {
        return None;
    }
    if altgr {
        let ag = match layout {
            LAYOUT_DE => match code {
                8 => Some(u32::from(b'{')),
                9 => Some(u32::from(b'[')),
                10 => Some(u32::from(b']')),
                11 => Some(u32::from(b'}')),
                12 => Some(u32::from(b'\\')),
                16 => Some(u32::from(b'@')),
                27 => Some(u32::from(b'~')),
                50 => Some(0xB5), // µ
                _ => None,
            },
            LAYOUT_FR => match code {
                3 => Some(u32::from(b'~')),
                4 => Some(u32::from(b'#')),
                5 => Some(u32::from(b'{')),
                6 => Some(u32::from(b'[')),
                7 => Some(u32::from(b'|')),
                8 => Some(u32::from(b'`')),
                9 => Some(u32::from(b'\\')),
                10 => Some(u32::from(b'^')),
                11 => Some(u32::from(b'@')),
                12 => Some(u32::from(b']')),
                13 => Some(u32::from(b'}')),
                _ => None,
            },
            LAYOUT_ES => match code {
                2 => Some(u32::from(b'|')),
                3 => Some(u32::from(b'@')),
                4 => Some(u32::from(b'#')),
                5 => Some(u32::from(b'~')),
                26 => Some(u32::from(b'[')),
                27 => Some(u32::from(b']')),
                40 => Some(u32::from(b'{')),
                41 => Some(u32::from(b'\\')),
                43 => Some(u32::from(b'}')),
                _ => None,
            },
            LAYOUT_UK => match code {
                41 => Some(u32::from(b'|')),
                _ => None,
            },
            _ => None,
        };
        if ag.is_some() {
            return ag;
        }
    }
    let ch: u32 = match layout {
        LAYOUT_UK => match (code, shift) {
            (3, true) => u32::from(b'"'),
            (4, true) => 0xA3, // £
            (40, true) => u32::from(b'@'),
            (41, false) => u32::from(b'`'),
            (41, true) => 0xAC, // ¬
            (43, false) => u32::from(b'#'),
            (43, true) => u32::from(b'~'),
            _ => u32::from(if shift { US_SHIFT[idx] } else { US_PLAIN[idx] }),
        },
        LAYOUT_DE => match (code, shift) {
            (3, true) => u32::from(b'"'),
            (4, true) => 0xA7, // §
            (7, true) => u32::from(b'&'),
            (8, true) => u32::from(b'/'),
            (9, true) => u32::from(b'('),
            (10, true) => u32::from(b')'),
            (11, true) => u32::from(b'='),
            (12, false) => 0xDF, // ß
            (12, true) => u32::from(b'?'),
            (13, false) => 0xB4, // ´
            (13, true) => u32::from(b'`'),
            (21, false) => u32::from(b'z'),
            (21, true) => u32::from(b'Z'),
            (26, false) => 0xFC, // ü
            (26, true) => 0xDC,  // Ü
            (27, false) => u32::from(b'+'),
            (27, true) => u32::from(b'*'),
            (39, false) => 0xF6, // ö
            (39, true) => 0xD6,  // Ö
            (40, false) => 0xE4, // ä
            (40, true) => 0xC4,  // Ä
            (41, false) => u32::from(b'^'),
            (41, true) => 0xB0, // °
            (43, false) => u32::from(b'#'),
            (43, true) => u32::from(b'\''),
            (44, false) => u32::from(b'y'),
            (44, true) => u32::from(b'Y'),
            (51, true) => u32::from(b';'),
            (52, true) => u32::from(b':'),
            (53, false) => u32::from(b'-'),
            (53, true) => u32::from(b'_'),
            _ => u32::from(if shift { US_SHIFT[idx] } else { US_PLAIN[idx] }),
        },
        LAYOUT_FR => match (code, shift) {
            (2, false) => u32::from(b'&'),
            (2, true) => u32::from(b'1'),
            (3, false) => 0xE9, // é
            (3, true) => u32::from(b'2'),
            (4, false) => u32::from(b'"'),
            (4, true) => u32::from(b'3'),
            (5, false) => u32::from(b'\''),
            (5, true) => u32::from(b'4'),
            (6, false) => u32::from(b'('),
            (6, true) => u32::from(b'5'),
            (7, false) => u32::from(b'-'),
            (7, true) => u32::from(b'6'),
            (8, false) => 0xE8, // è
            (8, true) => u32::from(b'7'),
            (9, false) => u32::from(b'_'),
            (9, true) => u32::from(b'8'),
            (10, false) => 0xE7, // ç
            (10, true) => u32::from(b'9'),
            (11, false) => 0xE0, // à
            (11, true) => u32::from(b'0'),
            (12, false) => u32::from(b')'),
            (12, true) => 0xB0, // °
            (13, false) => u32::from(b'='),
            (13, true) => u32::from(b'+'),
            (16, false) => u32::from(b'a'),
            (16, true) => u32::from(b'A'),
            (17, false) => u32::from(b'z'),
            (17, true) => u32::from(b'Z'),
            (26, false) => u32::from(b'^'),
            (26, true) => 0xA8, // ¨
            (27, false) => u32::from(b'$'),
            (27, true) => 0xA3, // £
            (30, false) => u32::from(b'q'),
            (30, true) => u32::from(b'Q'),
            (39, false) => u32::from(b'm'),
            (39, true) => u32::from(b'M'),
            (40, false) => 0xF9, // ù
            (40, true) => u32::from(b'%'),
            (41, false) => 0xB2, // ²
            (41, true) => 0xB2,
            (43, false) => u32::from(b'*'),
            (43, true) => 0xB5, // µ
            (44, false) => u32::from(b'w'),
            (44, true) => u32::from(b'W'),
            (50, false) => u32::from(b','),
            (50, true) => u32::from(b'?'),
            (51, false) => u32::from(b';'),
            (51, true) => u32::from(b'.'),
            (52, false) => u32::from(b':'),
            (52, true) => u32::from(b'/'),
            (53, false) => u32::from(b'!'),
            (53, true) => 0xA7, // §
            _ => u32::from(if shift { US_SHIFT[idx] } else { US_PLAIN[idx] }),
        },
        LAYOUT_ES => match (code, shift) {
            (3, true) => u32::from(b'"'),
            (4, true) => 0xB7, // ·
            (7, true) => u32::from(b'&'),
            (8, true) => u32::from(b'/'),
            (9, true) => u32::from(b'('),
            (10, true) => u32::from(b')'),
            (11, true) => u32::from(b'='),
            (12, false) => u32::from(b'\''),
            (12, true) => u32::from(b'?'),
            (13, false) => 0xA1, // ¡
            (13, true) => 0xBF,  // ¿
            (26, false) => u32::from(b'`'),
            (26, true) => u32::from(b'^'),
            (27, false) => u32::from(b'+'),
            (27, true) => u32::from(b'*'),
            (39, false) => 0xF1, // ñ
            (39, true) => 0xD1,  // Ñ
            (40, false) => 0xB4, // ´
            (40, true) => 0xA8,  // ¨
            (41, false) => 0xBA, // º
            (41, true) => 0xAA,  // ª
            (43, false) => 0xE7, // ç
            (43, true) => 0xC7,  // Ç
            (51, true) => u32::from(b';'),
            (52, true) => u32::from(b':'),
            (53, false) => u32::from(b'-'),
            (53, true) => u32::from(b'_'),
            _ => u32::from(if shift { US_SHIFT[idx] } else { US_PLAIN[idx] }),
        },
        _ => u32::from(if shift { US_SHIFT[idx] } else { US_PLAIN[idx] }),
    };
    (ch != 0).then_some(ch)
}

#[derive(Default)]
pub struct Keys {
    layout: u8,
    shift_l: bool,
    shift_r: bool,
    ctrl: bool,
    alt_l: bool,
    alt_r: bool,
    meta_l: bool,
    meta_r: bool,
    caps: bool,
}

impl Keys {
    pub fn with_layout(layout: u8) -> Self {
        Self { layout: layout.min(LAYOUT_ES), ..Self::default() }
    }

    pub fn set_layout(&mut self, layout: u8) {
        self.layout = layout.min(LAYOUT_ES);
    }

    /// Caps Lock is on (a keyboard's LED follows it).
    pub fn caps(&self) -> bool {
        self.caps
    }

    fn mods(&self) -> u32 {
        let shift = self.shift_l || self.shift_r;
        let meta = self.meta_l || self.meta_r;
        let alt = self.alt_l || (self.alt_r && self.layout == LAYOUT_US);
        (if shift { key::SHIFT } else { 0 })
            | (if self.ctrl { key::CTRL } else { 0 })
            | (if alt { key::ALT } else { 0 })
            | (if meta { key::SUPER } else { 0 })
    }

    /// A key went down (`down`) or up; the key value it produces, if any.
    pub fn key(&mut self, code: u16, down: bool) -> Option<u32> {
        match code {
            LSHIFT => self.shift_l = down,
            RSHIFT => self.shift_r = down,
            CTRL | RCTRL => self.ctrl = down,
            ALT => self.alt_l = down,
            RALT => self.alt_r = down,
            LMETA | RMETA => {
                let was = self.meta_l || self.meta_r;
                if code == LMETA {
                    self.meta_l = down;
                } else {
                    self.meta_r = down;
                }
                let is = self.meta_l || self.meta_r;
                if was != is {
                    return Some(if is { key::META | self.mods() } else { key::META | key::RELEASE });
                }
            }
            CAPS if down => self.caps = !self.caps,
            _ if down => {
                let shift = self.shift_l || self.shift_r;
                let meta = self.meta_l || self.meta_r;
                if let Some(k) = named(code) {
                    return Some(k | self.mods());
                }
                let altgr = self.alt_r && self.layout != LAYOUT_US && !self.ctrl && !meta;
                let mut c = map_char(self.layout, code, shift && !meta, altgr)?;
                if meta || self.alt_l || (self.alt_r && self.layout == LAYOUT_US) {
                    return Some(c | self.mods());
                }
                if c == u32::from(b'\t') && shift {
                    return Some(c | key::SHIFT);
                }
                if self.caps {
                    if (u32::from(b'a')..=u32::from(b'z')).contains(&c) {
                        c -= 32;
                    } else if (u32::from(b'A')..=u32::from(b'Z')).contains(&c) {
                        c += 32;
                    } else if matches!(c, 0xE4 | 0xF6 | 0xFC | 0xF1 | 0xE7) {
                        c -= 32;
                    } else if matches!(c, 0xC4 | 0xD6 | 0xDC | 0xD1 | 0xC7) {
                        c += 32;
                    }
                }
                if self.ctrl && c < 0x80 && (c as u8).is_ascii_alphabetic() {
                    c &= 0x1F;
                }
                return Some(c);
            }
            _ => {}
        }
        None
    }
}
