//! PE parser fuzzing (like the kernel's ELF fuzzer, kernel/rust/src/user/tests.rs): every
//! embedded `.exe` is mutated `rounds` times (bit flips, random bytes, boundary values, 64-bit
//! words, truncation) and run through everything the loader does before mapping: parse, layout,
//! relocation (to a random base), import binding and the TLS directory. Accepted images must keep the parser's
//! invariants. A missed check shows up as a panic (an out-of-bounds index), which fails the test.

use alloc::vec::Vec;

use libd::println;

use crate::pe::{self, Image};
use crate::{programs, read_image, text};

const STAGE: u64 = 1 << 20; // images with a larger SizeOfImage are parsed, not laid out

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        // xorshift64*
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
}

/// What an accepted image must satisfy (the loader maps by these numbers).
fn sane(img: &Image, file_len: usize) -> bool {
    let mut prev = img.size_of_headers;
    let mut entry_ok = false;
    for s in img.sections() {
        let end = u64::from(s.rva) + u64::from(s.pages());
        if s.rva < prev
            || end > u64::from(img.size_of_image)
            || s.rva % 4096 != 0
            || (s.writable() && s.executable())
            || s.copy > s.mem
            || (s.copy > 0 && s.raw_off as usize + s.copy as usize > file_len)
        {
            return false;
        }
        entry_ok |= s.executable() && img.entry >= s.rva && u64::from(img.entry) < end;
        prev = end as u32;
    }
    entry_ok && img.size_of_image <= pe::MAX_IMAGE && img.size_of_headers as usize <= file_len
}

fn dummy_resolve(dll: &[u8], func: &[u8]) -> Option<u64> {
    // Real resolver for KERNEL32.dll, anything else accepted too so binding is fully exercised.
    crate::win::k32::resolve(dll, func).or(Some(0x1000 + func.len() as u64))
}

pub fn run(rounds: u64) -> i32 {
    let rounds = rounds.max(1);
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15 ^ libd::sys::clock_ns());
    let (mut images, mut failures) = (0u64, 0u64);
    let (mut accepted, mut laid_out) = (0u64, 0u64);
    let mut stage: Vec<u8> = alloc::vec![0; STAGE as usize];
    let mut work: Vec<u8> = alloc::vec![0; 256 * 1024];
    programs(|h, name| {
        if !name.ends_with(b".exe") {
            return;
        }
        let Ok(file) = read_image(h, 256 * 1024) else {
            println!("dcmpl: pe fuzz: FAIL: cannot read {}", text(name));
            failures += 1;
            return;
        };
        let len = file.len();
        let orig = &file[..];
        images += 1;
        match pe::parse(orig) {
            Ok(img) if sane(&img, len) => {}
            _ => {
                println!("dcmpl: pe fuzz: FAIL: embedded {} does not parse cleanly", text(name));
                failures += 1;
                return;
            }
        }
        let buf = &mut work[..len];
        for _ in 0..rounds {
            buf.copy_from_slice(orig);
            let mut n = len;
            for _ in 0..1 + rng.next() % 8 {
                // Headers are where the parser looks: mutate there 3 times out of 4.
                let span = if rng.next().is_multiple_of(4) { len } else { len.min(1024) };
                let at = (rng.next() % span as u64) as usize;
                match rng.next() % 4 {
                    0 => buf[at] ^= 1 << (rng.next() % 8),
                    1 => buf[at] = rng.next() as u8,
                    2 => buf[at] = [0x00, 0xFF, 0x7F, 0x80][(rng.next() % 4) as usize],
                    _ => {
                        let w = at & !3;
                        if w + 4 <= len {
                            let v = [0u32, u32::MAX, 1 << 31, 4096, 0x1000_0000, rng.next() as u32][(rng.next() % 6) as usize];
                            buf[w..w + 4].copy_from_slice(&v.to_le_bytes());
                        }
                    }
                }
            }
            if rng.next().is_multiple_of(16) {
                n = (rng.next() % len as u64) as usize;
            }
            let data = &buf[..n];
            let Ok(img) = pe::parse(data) else { continue };
            accepted += 1;
            if !sane(&img, n) {
                println!("dcmpl: pe fuzz: FAIL: a mutated {} was accepted with broken invariants", text(name));
                failures += 1;
                continue;
            }
            if u64::from(img.size_of_image) > STAGE {
                continue;
            }
            let out = &mut stage[..img.size_of_image as usize];
            out.fill(0);
            if img.layout(data, out).is_err() {
                println!("dcmpl: pe fuzz: FAIL: accepted {} could not be laid out", text(name));
                failures += 1;
                continue;
            }
            laid_out += 1;
            let delta = (rng.next() & 0x0000_7FFF_FFFF_0000).wrapping_sub(img.image_base);
            let _ = img.relocate(out, delta);
            let _ = img.bind(out, dummy_resolve);
            let _ = img.tls(out, img.image_base.wrapping_add(delta));
        }
    });
    println!(
        "dcmpl: pe fuzz: {} mutated images of {} programs parsed ({} accepted, {} laid out, relocated and bound), no panic",
        rounds * images,
        images,
        accepted,
        laid_out
    );
    if images == 0 || failures > 0 {
        println!("dcmpl: pe fuzz: FAIL ({} failures, {} images)", failures, images);
        return 1;
    }
    0
}
