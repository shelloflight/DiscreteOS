//! Rust global allocator on top of the hardened C heap (`kmalloc`/`kfree`, kernel/mm/heap.c).
//! kmalloc returns zeroed, 16-byte-aligned memory. Larger alignments over-allocate and keep the
//! original pointer just below the aligned block.

use core::alloc::{GlobalAlloc, Layout};
use core::ptr;

use crate::ffi;

const NATIVE_ALIGN: usize = 16;

pub struct KernelHeap;

// SAFETY: kmalloc/kfree are a thread-safe (locked) allocator; blocks are never handed out twice,
// meet the requested size and alignment, and stay valid until dealloc.
unsafe impl GlobalAlloc for KernelHeap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if layout.align() <= NATIVE_ALIGN {
            // SAFETY: kmalloc accepts any size; it returns NULL on failure (or for size 0).
            return unsafe { ffi::kmalloc(layout.size()) };
        }
        // Over-aligned: room for the alignment slack. kmalloc's 16-byte alignment guarantees that
        // align_up(raw + 16) <= raw + align, leaving at least 8 bytes below it for the header.
        let Some(total) = layout.size().checked_add(layout.align()) else {
            return ptr::null_mut();
        };
        // SAFETY: as above.
        let raw = unsafe { ffi::kmalloc(total) };
        if raw.is_null() {
            return raw;
        }
        let addr = (raw as usize + NATIVE_ALIGN).next_multiple_of(layout.align());
        let aligned = raw.wrapping_add(addr - raw as usize);
        // SAFETY: `aligned - 8 .. aligned + size` lies inside the `total`-byte block (see above).
        unsafe { (aligned as *mut *mut u8).sub(1).write(raw) };
        aligned
    }

    unsafe fn dealloc(&self, p: *mut u8, layout: Layout) {
        // SAFETY: `p` came from `alloc` with the same layout, so for over-aligned blocks the
        // original pointer is stored just below it.
        unsafe {
            if layout.align() <= NATIVE_ALIGN {
                ffi::kfree(p);
            } else {
                ffi::kfree((p as *mut *mut u8).sub(1).read());
            }
        }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: kmalloc memory is always zeroed.
        unsafe { self.alloc(layout) }
    }
}
