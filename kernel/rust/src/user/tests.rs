//! `fuzz` test case (KTEST_FUZZ), kernel half: the ELF parser against mutated images.
//!
//! Starts from the real embedded executables, then flips, overwrites and truncates bytes at
//! random (biased towards the headers, where the parser looks), and parses each result. The
//! parser must never panic, never accept an image whose segments leave the file or overlap, and
//! never hand out a relocation outside a segment. (The ring-3 half fuzzes the syscalls.)

use alloc::vec::Vec;

use super::boot::programs;
use super::elf::{self, Source};
use crate::ffi::{USER_BASE, USER_TOP};

const ROUNDS: u32 = 30_000;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

/// Invariants of an accepted image.
fn sane(img: &elf::Image, file: &[u8]) -> bool {
    let size = file.len() as u64;
    let mut prev_end = 0;
    for s in &img.segs[..img.nseg] {
        if s.offset.checked_add(s.filesz).is_none_or(|e| e > size) || s.filesz > s.memsz {
            return false;
        }
        if s.page_start() < prev_end || (s.flags & elf::PF_W != 0 && s.flags & elf::PF_X != 0) {
            return false;
        }
        prev_end = s.page_end();
    }
    let mut ok = true;
    let r = img.relocations(&file, 0, |seg, off, _| {
        let s = &img.segs[seg];
        ok &= off + 8 <= s.page_end() - s.page_start();
        ok
    });
    r.is_err() || ok
}

#[unsafe(no_mangle)]
pub extern "C" fn rust_elf_fuzz() -> u32 {
    let mut failures = 0;
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15 ^ crate::ffi::now_ns());
    let mut accepted = 0u32;
    let mut images = 0u32;
    for (name, data) in programs() {
        if !data.starts_with(b"\x7FELF") {
            continue; // the D-CMPL proof PEs (w1*.exe): fuzzed in ring 3 by `dcmpl pefuzz`
        }
        images += 1;
        let Ok(img) = elf::parse(&data, USER_BASE, USER_TOP) else {
            crate::kprintln!("  FAIL elf: embedded {} does not parse", name);
            failures += 1;
            continue;
        };
        if !sane(&img, data) {
            crate::kprintln!("  FAIL elf: embedded {} breaks an invariant", name);
            failures += 1;
        }
        let mut buf = Vec::new();
        if buf.try_reserve_exact(data.len()).is_err() {
            failures += 1;
            continue;
        }
        buf.extend_from_slice(data);
        for _ in 0..ROUNDS {
            buf.clear();
            buf.extend_from_slice(data);
            let n = 1 + rng.next() % 8;
            for _ in 0..n {
                let span = if rng.next().is_multiple_of(4) { buf.len() } else { buf.len().min(512) };
                let at = (rng.next() % span as u64) as usize;
                match rng.next() % 4 {
                    0 => buf[at] ^= 1 << (rng.next() % 8),
                    1 => buf[at] = rng.next() as u8,
                    2 => buf[at] = [0x00, 0xFF, 0x7F, 0x80][(rng.next() % 4) as usize],
                    _ => {
                        let w = at & !7;
                        if w + 8 <= buf.len() {
                            let v = [0u64, u64::MAX, 1 << 63, 4096, rng.next()][(rng.next() % 5) as usize];
                            buf[w..w + 8].copy_from_slice(&v.to_le_bytes());
                        }
                    }
                }
            }
            if rng.next().is_multiple_of(16) {
                let keep = (rng.next() % buf.len() as u64) as usize;
                buf.truncate(keep);
            }
            let file: &[u8] = &buf;
            if let Ok(img) = elf::parse(&file, USER_BASE, USER_TOP) {
                accepted += 1;
                if !sane(&img, file) {
                    crate::kprintln!("  FAIL elf: a mutated {} was accepted with broken invariants", name);
                    failures += 1;
                }
            }
            let _ = file.size();
        }
    }
    crate::kprintln!(
        "  elf fuzz: {} mutated images of {} programs parsed ({} accepted), no panic",
        ROUNDS * images,
        images,
        accepted
    );
    failures
}
