//! D-KRNL, Rust part (`dkrnl` static library, linked into the kernel next to the C objects).
//!
//! Bridge to the C kernel:
//!   - allocator:  `alloc` (Box, Vec, ...) on top of the hardened C heap   (heap.rs)
//!   - panics:     a Rust panic is a kernel panic with message and location (below)
//!   - output:     `kprint!` / `kprintln!` on the kernel console            (console.rs)
//!   - logging:    the kernel log ring buffer, `klog!`                       (klog.rs)
//!   - locking:    `SpinLock<T>` over the C spinlock (same lock-order rules) (sync.rs)
//!   - blocking:   `Mutex<T>`, `Semaphore`, `Event` over the C wait primitives (sync.rs)
//!   - threads:    `thread::spawn` a closure, `join` for its exit code       (thread.rs)
//!   - assertions: `kassert!`, always on, like KASSERT
//!   - objects:    kernel objects, handles with rights, quotas               (object/)
//!   - user mode:  syscalls, user threads, ELF loader, init                   (user/)
//!   - devices:    PCI, IOMMU, device interrupts for user-space drivers      (dev/)
//!
//! `unsafe` lives only in the FFI-facing modules (ffi, sync, heap, console, klog's C exports);
//! each block states why it is sound.

#![no_std]

extern crate alloc;

pub mod console;
pub mod dev;
pub mod ffi;
pub mod fmtbuf;
pub mod heap;
pub mod klog;
pub mod nospec;
pub mod object;
pub mod security;
pub mod sync;
pub mod thread;
pub mod user;

#[cfg(ktest)]
mod ktest;

use core::fmt::Write;
use core::panic::PanicInfo;

#[global_allocator]
static ALLOCATOR: heap::KernelHeap = heap::KernelHeap;

/// Always-on assertion (fail closed), the Rust twin of C's KASSERT.
#[macro_export]
macro_rules! kassert {
    ($cond:expr $(,)?) => {
        if !$cond {
            panic!("KASSERT failed: {}", stringify!($cond));
        }
    };
}

#[panic_handler]
fn panic(info: &PanicInfo<'_>) -> ! {
    let mut msg = fmtbuf::FmtBuf::<256>::new();
    let _ = write!(msg, "{}", info.message());
    let (file, line) = info
        .location()
        .map_or(("<unknown>", 0), |l| (l.file(), l.line()));
    // SAFETY: both slices are valid for the call; rust_panic never returns.
    unsafe {
        ffi::rust_panic(
            file.as_ptr(),
            file.len(),
            line,
            msg.as_bytes().as_ptr(),
            msg.as_bytes().len(),
        )
    }
}

/// Called once from kmain after the heap and the time source are up.
#[unsafe(no_mangle)]
pub extern "C" fn dkrnl_init() {
    // Prove the allocator round-trips before anything relies on it.
    let probe = alloc::boxed::Box::new(0x0D05_u32);
    kassert!(*probe == 0x0D05);
    drop(probe);
    kprintln!(
        "Rust: dkrnl {} ready (allocator, panic, console, klog, SpinLock, Mutex, threads)",
        env!("CARGO_PKG_VERSION")
    );
    object::init();
    dev::init();
}
