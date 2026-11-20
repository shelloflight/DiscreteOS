//! Constant-time primitives with compiler optimization barriers.
//!
//! Uses `core::hint::black_box` on mask generation so LLVM cannot rewrite branchless
//! constant-time selections back into secret-dependent conditional branches, and uses
//! volatile writes for secret zeroization so key wiping cannot be eliminated as dead stores.

use core::hint::black_box;

/// Return `u64::MAX` if `(bit & 1) == 1`, else `0`, with an optimization barrier.
#[inline(always)]
pub fn ct_mask_u64(bit: u64) -> u64 {
    black_box(0u64.wrapping_sub(black_box(bit & 1)))
}

/// Return `u32::MAX` if `(bit & 1) == 1`, else `0`, with an optimization barrier.
#[inline(always)]
pub fn ct_mask_u32(bit: u32) -> u32 {
    black_box(0u32.wrapping_sub(black_box(bit & 1)))
}

/// Return `0xFF` if `(bit & 1) == 1`, else `0x00`, with an optimization barrier.
#[inline(always)]
pub fn ct_mask_u8(bit: u8) -> u8 {
    black_box(0u8.wrapping_sub(black_box(bit & 1)))
}

/// Constant-time byte-slice equality.
#[inline(never)]
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    black_box(diff) == 0
}

/// Constant-time check that every byte in `a` is zero.
#[inline(never)]
pub fn ct_is_zero(a: &[u8]) -> bool {
    let mut acc = 0u8;
    for &x in a {
        acc |= x;
    }
    black_box(acc) == 0
}

/// Constant-time selection: writes `if_true` into `out` when `cond` is 1, else `if_false`.
/// All three slices must have the same length.
#[inline(never)]
pub fn ct_select_bytes(cond: u8, if_true: &[u8], if_false: &[u8], out: &mut [u8]) {
    debug_assert!(if_true.len() == if_false.len() && if_true.len() == out.len());
    let mask = ct_mask_u8(cond);
    for i in 0..out.len() {
        out[i] = (if_true[i] & mask) | (if_false[i] & !mask);
    }
}

/// Volatile zeroization of sensitive memory (cannot be elided by the optimizer).
#[inline(never)]
pub fn wipe_bytes(buf: &mut [u8]) {
    for x in buf.iter_mut() {
        // SAFETY: volatile write to a live mutable reference.
        unsafe { core::ptr::write_volatile(x, 0) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}
