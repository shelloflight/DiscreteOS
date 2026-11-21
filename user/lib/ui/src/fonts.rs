//! The font pack: the compositor reads the shipped faces from the system volume once and shares
//! them with every window program as one read-only VMO (`OP_FONTS`), so programs need no file
//! access and the faces are in memory once. Layout: `DFNT`, a count, then per face its id
//! (`dosfont::Face`), offset and length (all `u32` little-endian), then the font files.

use alloc::vec::Vec;

use dosfont::{FACE_COUNT, Face, Font, Text};

pub const MAGIC: &[u8; 4] = b"DFNT";
/// The files of each face on the system volume (`sys:/fonts/<file>`).
pub const FACE_FILES: [(Face, &str); FACE_COUNT] = [
    (Face::Sans, "inter-regular.ttf"),
    (Face::SansMedium, "inter-medium.ttf"),
    (Face::SansSemiBold, "inter-semibold.ttf"),
    (Face::Mono, "iosevka-term-nf-mono.ttf"),
];

/// Build a font pack from face files.
pub fn build(faces: &[(Face, &[u8])]) -> Vec<u8> {
    let head = 8 + faces.len() * 12;
    let mut out = Vec::with_capacity(head + faces.iter().map(|f| f.1.len() + 3).sum::<usize>());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&(faces.len() as u32).to_le_bytes());
    let mut off = head;
    for (face, data) in faces {
        out.extend_from_slice(&(*face as u32).to_le_bytes());
        out.extend_from_slice(&(off as u32).to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        off += data.len().div_ceil(4) * 4;
    }
    for (_, data) in faces {
        out.extend_from_slice(data);
        while out.len() % 4 != 0 {
            out.push(0);
        }
    }
    out
}

/// The faces in a font pack (untrusted bytes: every entry is bounds-checked, every font parsed).
pub fn faces(pack: &[u8]) -> [Option<Font<'_>>; FACE_COUNT] {
    let mut out = [None; FACE_COUNT];
    if pack.len() < 8 || &pack[..4] != MAGIC {
        return out;
    }
    let n = u32::from_le_bytes([pack[4], pack[5], pack[6], pack[7]]) as usize;
    for i in 0..n.min(16) {
        let e = 8 + i * 12;
        let Some(rec) = pack.get(e..e + 12) else { break };
        let field = |k: usize| u32::from_le_bytes([rec[k], rec[k + 1], rec[k + 2], rec[k + 3]]) as usize;
        let (face, off, len) = (field(0), field(4), field(8));
        if face >= FACE_COUNT {
            continue;
        }
        let Some(data) = off.checked_add(len).and_then(|end| pack.get(off..end)) else { continue };
        if let Ok(f) = Font::parse(data) {
            out[face] = Some(f);
        }
    }
    out
}

/// A text engine with every face of a pack.
pub fn engine(pack: &[u8]) -> Text<'_> {
    let mut t = Text::new();
    for (i, f) in faces(pack).into_iter().enumerate() {
        if let Some(f) = f {
            t.set_face(Face::from_u8(i as u8), f);
        }
    }
    t
}
