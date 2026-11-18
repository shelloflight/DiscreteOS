//! Spectre v1 (bounds-check bypass): speculation-safe indices (the C side: `array_index_nospec`
//! in spec.h).
//!
//! A bounds check is a conditional branch, and the CPU may run past it speculatively with an
//! out-of-range index chosen by user mode, loading from wherever that index points and leaving a
//! trace in the cache. `index` turns the index into 0 on that path without a branch, so the
//! speculative load stays inside the table. Use it after the real bounds check, on indices that
//! come from user mode.

/// `i` if `i < len`, else 0, computed without a branch.
#[inline(always)]
pub fn index(i: usize, len: usize) -> usize {
    let mask: usize;
    // SAFETY: arithmetic on registers only (cmp + sbb: mask = all ones when i < len).
    unsafe {
        core::arch::asm!(
            "cmp {i}, {len}",
            "sbb {m}, {m}",
            i = in(reg) i,
            len = in(reg) len,
            m = out(reg) mask,
            options(pure, nomem, nostack),
        );
    }
    i & mask
}

#[cfg(ktest)]
pub fn selftest() -> bool {
    index(0, 4) == 0 && index(3, 4) == 3 && index(4, 4) == 0 && index(usize::MAX, 4) == 0 && index(7, 0) == 0
        && index(65535, 65536) == 65535
}
