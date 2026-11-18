//! Safe access to user memory (copy_from_user / copy_to_user).
//!
//! Every user pointer is checked first: the whole range must lie below `USER_TOP` without
//! wrapping. The copy itself runs in `user_copy` (syscall.asm), the only kernel code that may
//! touch user pages: SMAP is opened (STAC) only around it, and a fault inside it (unmapped page,
//! write to a read-only page) is fixed up into an error instead of a kernel crash. So a bad
//! pointer is always `BadAddress`, and the kernel never reads user memory by accident.
//!
//! Syscalls copy arguments in once and work on the kernel copy (no double fetch).

use super::super::object::{KResult, Status};
use crate::ffi::{self, USER_TOP};

/// [ptr, ptr+len) is a user range (len 0 is always fine).
pub fn check(ptr: u64, len: u64) -> KResult<()> {
    if len == 0 {
        return Ok(());
    }
    match ptr.checked_add(len) {
        Some(end) if end <= USER_TOP => Ok(()),
        _ => Err(Status::BadAddress),
    }
}

/// # Safety
/// `dst..dst+n` must be valid kernel memory for writes.
pub unsafe fn copy_from_user_raw(dst: *mut u8, src: u64, n: usize) -> KResult<()> {
    check(src, n as u64)?;
    if n == 0 {
        return Ok(());
    }
    // SAFETY: the user range is below USER_TOP (faults there are fixed up); `dst` per contract.
    let left = unsafe { ffi::user_copy(dst, src as *const u8, n as u64) };
    if left == 0 { Ok(()) } else { Err(Status::BadAddress) }
}

/// # Safety
/// `src..src+n` must be valid kernel memory for reads.
pub unsafe fn copy_to_user_raw(dst: u64, src: *const u8, n: usize) -> KResult<()> {
    check(dst, n as u64)?;
    if n == 0 {
        return Ok(());
    }
    // SAFETY: as above.
    let left = unsafe { ffi::user_copy(dst as *mut u8, src, n as u64) };
    if left == 0 { Ok(()) } else { Err(Status::BadAddress) }
}

pub fn copy_from_user(dst: &mut [u8], src: u64) -> KResult<()> {
    // SAFETY: `dst` is a valid mutable slice.
    unsafe { copy_from_user_raw(dst.as_mut_ptr(), src, dst.len()) }
}

pub fn copy_to_user(dst: u64, src: &[u8]) -> KResult<()> {
    // SAFETY: `src` is a valid slice.
    unsafe { copy_to_user_raw(dst, src.as_ptr(), src.len()) }
}

/// Plain-data ABI structs: `repr(C)`, only integer fields, every bit pattern valid.
///
/// # Safety
/// Implement only for such types.
pub unsafe trait Pod: Copy + Default {}

// SAFETY: plain integers: every bit pattern is valid, no padding.
unsafe impl Pod for u32 {}
// SAFETY: as above.
unsafe impl Pod for u64 {}

pub fn read<T: Pod>(src: u64) -> KResult<T> {
    let mut v = T::default();
    // SAFETY: `v` is a valid T; any bytes written form a valid T (Pod).
    unsafe { copy_from_user_raw((&raw mut v).cast(), src, core::mem::size_of::<T>())? };
    Ok(v)
}

pub fn write<T: Pod>(dst: u64, v: &T) -> KResult<()> {
    // SAFETY: `v` is a valid T, readable as bytes (Pod: no padding with secrets, only integers).
    unsafe { copy_to_user_raw(dst, (v as *const T).cast(), core::mem::size_of::<T>()) }
}
