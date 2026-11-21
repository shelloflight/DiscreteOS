//! Host unit tests and fuzzers for `dosfont` (the shipped faces from user/init/fonts).

use std::vec::Vec;

use crate::glyph::{self, Outline, SUB, Scale};
use crate::raster::{Bitmap, Raster};
use crate::subset::subset;
use crate::text::{Clip, Face, Style, Target, Text};
use crate::ttf::{Font, FontError};

static INTER: &[u8] = include_bytes!("../../../init/fonts/inter-regular.ttf");
static INTER_MEDIUM: &[u8] = include_bytes!("../../../init/fonts/inter-medium.ttf");
static MONO: &[u8] = include_bytes!("../../../init/fonts/iosevka-term-nf-mono.ttf");

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
}

fn render(font: &Font<'_>, g: u16, px: u32) -> Bitmap {
    let mut o = Outline::default();
    let s = Scale { sx: i64::from(px) * 64 * 4, sy: i64::from(px) * 64 * 4, den: i64::from(font.units_per_em()), ox: 0, oy: 0 };
    assert!(glyph::outline(font, g, &s, &mut o));
    let mut r = Raster::default();
    let mut b = Bitmap::default();
    r.render(&o, &mut b);
    b
}

#[test]
fn parses_the_shipped_faces() {
    for data in [INTER, INTER_MEDIUM, MONO] {
        let f = Font::parse(data).expect("shipped face parses");
        assert!(f.num_glyphs() > 500);
        assert!(f.ascender > 0 && f.descender < 0);
        assert!(f.x_height > 0, "OS/2 x-height present");
        for c in "AaZz09 .,;:!?ÀéßΩЖ€".chars() {
            assert_ne!(f.glyph_index(c), 0, "{c:?} mapped");
        }
        assert_eq!(f.glyph_index('\u{10FFFE}'), 0);
    }
    let inter = Font::parse(INTER).unwrap();
    assert_eq!(inter.units_per_em(), 2048);
    assert!(inter.has_kerning());
    let (a, v) = (inter.glyph_index('A'), inter.glyph_index('V'));
    assert!(inter.kerning(a, v) < 0, "A-V kerns closer: {}", inter.kerning(a, v));
    assert_eq!(inter.kerning(inter.glyph_index('l'), inter.glyph_index('l')), 0);
    // The monospace face: one advance for letters, box drawing and icons alike.
    let mono = Font::parse(MONO).unwrap();
    let adv = mono.advance(mono.glyph_index('M'));
    for c in ['i', 'W', '─', '█', '\u{E0B0}', '\u{F015}', '\u{F0001}', '⠿'] {
        let g = mono.glyph_index(c);
        assert_ne!(g, 0, "{c:?} in the mono subset");
        assert_eq!(mono.advance(g), adv, "{c:?} is one cell");
    }
    assert_eq!(mono.glyph_index('\u{F300}'), 0, "Font Logos range left out");
}

#[test]
fn refuses_non_truetype() {
    assert_eq!(Font::parse(b"OTTO\0\0\0\0\0\0\0\0").err(), Some(FontError::NotTrueType));
    assert_eq!(Font::parse(&[]).err(), Some(FontError::NotTrueType));
    let mut bad = INTER.to_vec();
    bad.truncate(400);
    assert!(Font::parse(&bad).is_err());
}

#[test]
fn rasterizer_is_exact_on_squares() {
    let mut r = Raster::default();
    let mut b = Bitmap::default();
    let mut o = Outline::default();
    // A 4x3 px square on pixel edges: every pixel fully covered.
    let sq = |o: &mut Outline, x0: i32, y0: i32, x1: i32, y1: i32| {
        o.clear();
        o.lines.extend([[x0, y0, x1, y0], [x1, y0, x1, y1], [x1, y1, x0, y1], [x0, y1, x0, y0]].iter().filter(|l| l[1] != l[3]).copied());
        o.min_x = x0.min(x1);
        o.max_x = x0.max(x1);
        o.min_y = y0.min(y1);
        o.max_y = y0.max(y1);
    };
    sq(&mut o, 0, 0, 4 * SUB, 3 * SUB);
    r.render(&o, &mut b);
    assert_eq!((b.w, b.h), (4, 3));
    assert!(b.data.iter().all(|&c| c == 255), "{:?}", b.data);
    // Shifted by half a pixel: the edge columns are half covered, the inside full.
    sq(&mut o, SUB / 2, 0, 4 * SUB + SUB / 2, 2 * SUB);
    r.render(&o, &mut b);
    assert_eq!((b.w, b.h), (5, 2));
    for y in 0..2 {
        let row = &b.data[y * 5..y * 5 + 5];
        assert_eq!(row[1..4], [255, 255, 255]);
        assert!((140..=160).contains(&row[0]) && row[0] == row[4], "half coverage (with gamma): {row:?}");
    }
    // Reversed winding gives the same coverage.
    sq(&mut o, 4 * SUB, 3 * SUB, 0, 0);
    r.render(&o, &mut b);
    assert!(b.data.iter().all(|&c| c == 255));
    // A diagonal edge (triangle): coverage falls monotonically across it.
    o.clear();
    o.lines.extend([[0, 0, 8 * SUB, 8 * SUB], [8 * SUB, 8 * SUB, 0, 8 * SUB], [0, 8 * SUB, 0, 0]]);
    (o.min_x, o.min_y, o.max_x, o.max_y) = (0, 0, 8 * SUB, 8 * SUB);
    r.render(&o, &mut b);
    for y in 0..8usize {
        let diag = b.data[y * 8 + y];
        assert!((95..=160).contains(&diag), "diagonal pixel about half: {diag}");
        if y > 0 {
            assert_eq!(b.data[y * 8], 255);
        }
        if y < 7 {
            assert_eq!(b.data[y * 8 + 7], 0);
        }
    }
}

#[test]
fn glyphs_render_with_expected_shape() {
    let f = Font::parse(INTER).unwrap();
    let o = render(&f, f.glyph_index('O'), 32);
    assert!(o.w >= 18 && o.w <= 30 && o.h >= 20 && o.h <= 28, "{}x{}", o.w, o.h);
    assert!(o.top < 0, "above the baseline");
    let at = |x: u32, y: u32| o.data[(y * o.w + x) as usize];
    assert!(at(o.w / 2, o.h / 2) < 30, "the counter of O is empty");
    assert!(at(o.w / 2, 1) > 200 || at(o.w / 2, 2) > 200, "the top stroke is inked");
    // A composite glyph (Ä = A + dieresis) has more ink above the cap height than A.
    let a = render(&f, f.glyph_index('A'), 32);
    let ad = render(&f, f.glyph_index('Ä'), 32);
    assert!(ad.h > a.h && ad.top < a.top);
    // The space has no outline.
    let sp = render(&f, f.glyph_index(' '), 32);
    assert_eq!((sp.w, sp.h), (0, 0));
}

#[test]
fn subset_keeps_exactly_the_requested_glyphs() {
    let (sub, n) = subset(INTER, |c| (0x20..0x7F).contains(&c) || c == 0xC4).unwrap();
    assert!(sub.len() < INTER.len() / 3, "{} bytes", sub.len());
    assert!(n > 90 && n < 200, "{n} glyphs");
    let s = Font::parse(&sub).unwrap();
    let f = Font::parse(INTER).unwrap();
    assert_eq!(s.glyph_index('Ж'), 0);
    for c in ['A', 'g', '~', 'Ä'] {
        let (a, b) = (render(&f, f.glyph_index(c), 24), render(&s, s.glyph_index(c), 24));
        assert_eq!((a.w, a.h, a.left, a.top), (b.w, b.h, b.left, b.top), "{c:?}");
        assert_eq!(a.data, b.data, "{c:?} pixels identical after subsetting");
        assert_eq!(f.advance(f.glyph_index(c)), s.advance(s.glyph_index(c)));
    }
    // Subsetting a subset changes nothing.
    let (again, m) = subset(&sub, |c| (0x20..0x7F).contains(&c) || c == 0xC4).unwrap();
    assert_eq!((again.len(), m), (sub.len(), n));
}

fn engine() -> Text<'static> {
    let mut t = Text::new();
    t.set_face(Face::Sans, Font::parse(INTER).unwrap());
    t.set_face(Face::SansMedium, Font::parse(INTER_MEDIUM).unwrap());
    t.set_face(Face::Mono, Font::parse(MONO).unwrap());
    t
}

#[test]
fn text_layout_measure_wrap_and_carets() {
    let t = engine();
    let st = Style::px(Face::Sans, 13);
    let m = t.metrics(st);
    assert!(m.ascent >= 11 && m.ascent <= 15 && m.descent >= 2 && m.height >= 15 && m.height <= 18, "{m:?}");
    let w = t.measure(st, "Hello, world");
    assert!((60..=90).contains(&w), "{w}");
    let end = |s: &str| {
        let mut p = Vec::new();
        t.caret_positions(Style::px(Face::Sans, 40), s, &mut p);
        p.last().unwrap().1
    };
    assert!(end("AV") < end("A") + end("V"), "kerned pair is narrower");
    assert_eq!(t.measure(st, ""), 0);
    // Fallback: an icon only the mono face has still measures one advance.
    assert!(t.measure(st, "\u{F015}") > 0);
    let mut pos = Vec::new();
    t.caret_positions(st, "aé c", &mut pos);
    assert_eq!(pos.iter().map(|p| p.0).collect::<Vec<_>>(), [0, 1, 3, 4, 5]);
    assert!(pos.windows(2).all(|p| p[0].1 <= p[1].1));
    assert_eq!(t.index_at(st, "aé c", 0), 0);
    assert_eq!(t.index_at(st, "aé c", 10_000), 5);
    let mut lines = Vec::new();
    let text = "The quick brown fox jumps over the lazy dog\nand then naps";
    t.wrap(st, text, 120, &mut lines);
    assert!(lines.len() >= 4, "{lines:?}");
    for &(a, b) in &lines {
        assert!(t.measure(st, &text[a..b]) <= 120, "{:?}", &text[a..b]);
        assert!(!text[a..b].starts_with(' ') && !text[a..b].ends_with(' '));
    }
    assert_eq!(&text[lines.last().unwrap().0..lines.last().unwrap().1], "and then naps");
    // A word longer than the width is broken inside.
    t.wrap(st, "Supercalifragilistic", 30, &mut lines);
    assert!(lines.len() > 2 && lines.iter().all(|&(a, b)| b > a));
    // Monospace cells: every character of the grid advances the same.
    let ms = Style::px(Face::Mono, 14);
    let cell = t.advance64(ms, 'M');
    assert!(cell > 0 && ['i', '─', '\u{F015}'].iter().all(|&c| t.advance64(ms, c) == cell));
}

#[test]
fn draws_clipped_and_cached() {
    let mut t = engine();
    let mut px = std::vec![0xFF10_1218u32; 200 * 40];
    let st = Style::px(Face::Sans, 15);
    let adv = {
        let mut dst = Target { px: &mut px, w: 200, h: 40, stride: 200 };
        t.draw(&mut dst, Clip::new(0, 0, 200, 40), 4, 24, st, "Discrete Blue", 0xFFE5_E7F0, 200)
    };
    assert!(adv > 60);
    let inked = px.iter().filter(|&&p| p != 0xFF10_1218).count();
    assert!(inked > 150, "{inked} pixels inked");
    assert!(px.iter().all(|&p| p >> 24 == 0xFF), "stays opaque");
    // Clipped to the left half: nothing drawn on the right.
    let mut px2 = std::vec![0xFF00_0000u32; 200 * 40];
    {
        let mut dst = Target { px: &mut px2, w: 200, h: 40, stride: 200 };
        t.draw(&mut dst, Clip::new(0, 0, 40, 40), 4, 24, st, "Discrete Blue", 0xFFFF_FFFF, 200);
    }
    assert!((0..40).all(|y| (40..200).all(|x| px2[y * 200 + x] == 0xFF00_0000)));
    let (_, misses) = t.cache_stats();
    {
        let mut dst = Target { px: &mut px2, w: 200, h: 40, stride: 200 };
        t.draw(&mut dst, Clip::new(0, 0, 200, 40), 4, 24, st, "Discrete Blue", 0xFFFF_FFFF, 200);
    }
    let (hits, misses2) = t.cache_stats();
    assert!(hits > 10 && misses2 - misses <= 4, "second draw hits the cache ({hits}, {misses} -> {misses2})");
    // Out-of-bounds positions never panic.
    let mut dst = Target { px: &mut px2, w: 200, h: 40, stride: 200 };
    t.draw(&mut dst, Clip::new(-50, -50, 400, 400), -500, -300, st, "x", 0xFFFF_FFFF, 1000);
    t.draw(&mut dst, Clip::new(0, 0, 200, 40), 190, 39, Style::px(Face::Mono, 48), "\u{2588}\u{F015}", 0xFFFF_FFFF, 1000);
}

#[test]
fn fuzz_parser_outlines_and_raster_6000_rounds() {
    let mut rng = Rng(0x0D05_F0E7);
    let base = subset(INTER, |c| (0x20..0x80).contains(&c) || (0xC0..0x100).contains(&c)).unwrap().0;
    let mut o = Outline::default();
    let mut r = Raster::default();
    let mut b = Bitmap::default();
    for round in 0..6000 {
        let mut d = base.clone();
        match round % 4 {
            0 => {
                for _ in 0..1 + rng.below(16) {
                    let i = rng.below(d.len() as u64) as usize;
                    d[i] = rng.next() as u8;
                }
            }
            1 => d.truncate(rng.below(d.len() as u64) as usize),
            2 => {
                // Corrupt table directory offsets and lengths.
                let i = 12 + rng.below(16) as usize * 16 + 8 + rng.below(8) as usize;
                if i < d.len() {
                    d[i] = rng.next() as u8;
                }
            }
            _ => {
                // Corrupt one glyph's data.
                let i = d.len() / 2 + rng.below((d.len() / 2) as u64) as usize;
                for k in 0..32 {
                    if i + k < d.len() {
                        d[i + k] = rng.next() as u8;
                    }
                }
            }
        }
        let Ok(f) = Font::parse(&d) else { continue };
        for _ in 0..4 {
            let g = rng.below(u64::from(f.num_glyphs()) + 8) as u16;
            let px = 1 + rng.below(96) as i64;
            let s = Scale { sx: px * 256, sy: px * 256, den: i64::from(f.units_per_em()), ox: rng.below(256) as i64, oy: 0 };
            glyph::outline(&f, g, &s, &mut o);
            r.render(&o, &mut b);
            assert_eq!(b.data.len(), (b.w * b.h) as usize);
            let _ = f.kerning(g, rng.below(500) as u16);
            let _ = f.advance(g);
            let _ = f.glyph_index(char::from_u32(rng.below(0x3000) as u32).unwrap_or('a'));
        }
    }
    // Random line soups (self-intersecting, out of range) rasterize without panicking.
    for _ in 0..2000 {
        o.clear();
        let n = 1 + rng.below(40);
        let mut c = || (rng.next() as i32) % (300 * SUB);
        for _ in 0..n {
            let l = [c(), c(), c(), c()];
            o.lines.push(l);
            o.min_x = o.min_x.min(l[0]).min(l[2]);
            o.max_x = o.max_x.max(l[0]).max(l[2]);
            o.min_y = o.min_y.min(l[1]).min(l[3]);
            o.max_y = o.max_y.max(l[1]).max(l[3]);
        }
        r.render(&o, &mut b);
        assert!(b.w <= 512 && b.h <= 512);
    }
}

/// `DOSFONT_PREVIEW=<file.png>`: a sample sheet of the shipped faces for checking by eye.
#[test]
fn preview_sheet() {
    let Ok(path) = std::env::var("DOSFONT_PREVIEW") else { return };
    let mut t = engine();
    let (w, h) = (760u32, 300u32);
    let mut px = std::vec![0xFF0E_1016u32; (w * h) as usize];
    let lines: &[(Style, &str, u32)] = &[
        (Style::px(Face::SansMedium, 13), "Terminal  —  console · native", 0xFFE5_E7F0),
        (Style::px(Face::Sans, 13), "The quick brown fox jumps over the lazy dog. AVATAR Wavy 0123456789", 0xFFE5_E7F0),
        (Style::px(Face::Sans, 12), "Muted interface text at 12 px: Settings, Network, Audio, 21:14 UTC", 0xFF88_8EA4),
        (Style::px(Face::Sans, 20), "Discrete Blue #566087 headings", 0xFF83_8EB9),
        (Style::px(Face::Mono, 14), "shell> list /sys/fonts  ─┤ █▓▒░ ⠿ \u{F015} \u{E0B0} \u{F0001} λ→≠", 0xFFE5_E7F0),
        (Style::px(Face::Mono, 14), "fn main() -> i32 { let x = [0u8; 64]; x.len() as i32 }", 0xFFA7_B0D2),
        (Style::px(Face::Sans, 28), "Inter 28 px Ag", 0xFFE5_E7F0),
    ];
    let mut y = 24;
    for &(st, s, col) in lines {
        let m = t.metrics(st);
        let mut dst = Target { px: &mut px, w, h, stride: w };
        t.draw(&mut dst, Clip::new(0, 0, w, h), 16, y + m.ascent, st, s, col, w as i32);
        y += m.height + 12;
    }
    std::fs::write(&path, png(w, h, &px)).unwrap();
}

fn png(w: u32, h: u32, px: &[u32]) -> Vec<u8> {
    fn crc(data: &[u8]) -> u32 {
        let mut c = 0xFFFF_FFFFu32;
        for &b in data {
            c ^= u32::from(b);
            for _ in 0..8 {
                c = if c & 1 != 0 { 0xEDB8_8320 ^ (c >> 1) } else { c >> 1 };
            }
        }
        !c
    }
    let mut raw = Vec::new();
    for y in 0..h {
        raw.push(0);
        for x in 0..w {
            let p = px[(y * w + x) as usize];
            raw.extend_from_slice(&[(p >> 16) as u8, (p >> 8) as u8, p as u8]);
        }
    }
    let mut z = std::vec![0x78, 0x01];
    for (i, chunk) in raw.chunks(65535).enumerate() {
        let last = (i + 1) * 65535 >= raw.len();
        z.push(u8::from(last));
        z.extend_from_slice(&(chunk.len() as u16).to_le_bytes());
        z.extend_from_slice(&(!(chunk.len() as u16)).to_le_bytes());
        z.extend_from_slice(chunk);
    }
    let (mut a, mut b) = (1u32, 0u32);
    for &x in &raw {
        a = (a + u32::from(x)) % 65521;
        b = (b + a) % 65521;
    }
    z.extend_from_slice(&(b << 16 | a).to_be_bytes());
    let mut out = std::vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
    let mut chunk = |tag: &[u8], data: &[u8]| {
        out.extend_from_slice(&(data.len() as u32).to_be_bytes());
        let mut c = tag.to_vec();
        c.extend_from_slice(data);
        out.extend_from_slice(&c);
        out.extend_from_slice(&crc(&c).to_be_bytes());
    };
    let mut ihdr = Vec::new();
    ihdr.extend_from_slice(&w.to_be_bytes());
    ihdr.extend_from_slice(&h.to_be_bytes());
    ihdr.extend_from_slice(&[8, 2, 0, 0, 0]);
    chunk(b"IHDR", &ihdr);
    chunk(b"IDAT", &z);
    chunk(b"IEND", &[]);
    out
}
