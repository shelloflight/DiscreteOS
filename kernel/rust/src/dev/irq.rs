//! Device interrupt delivery: vector -> interrupt object.
//!
//! Device vectors (`VEC_DEV_BASE`..`VEC_DEV_END`, allocated by the C side) all arrive at the boot
//! CPU and end in `dkrnl_dev_irq`. The binding table is lock-free so the handler never waits on a
//! thread: a slot holds a pointer to the bound object, and an in-flight counter per slot lets
//! `unbind` wait until no handler can still be using the object before it is freed.

use core::sync::atomic::{AtomicPtr, AtomicU32, AtomicU64, Ordering};

use crate::object::device::InterruptObj;

static SLOTS: [AtomicPtr<InterruptObj>; 256] = [const { AtomicPtr::new(core::ptr::null_mut()) }; 256];
static INFLIGHT: [AtomicU32; 256] = [const { AtomicU32::new(0) }; 256];
static SPURIOUS: AtomicU64 = AtomicU64::new(0);

/// MSI address and data for `vector` (fixed delivery, edge, physical destination: the boot CPU).
pub fn msi_message(vector: u32) -> (u64, u32) {
    // SAFETY: plain read of the boot CPU's APIC id.
    let apic = unsafe { crate::ffi::irq_target_apic() };
    (0xFEE0_0000 | u64::from(apic & 0xFF) << 12, vector & 0xFF)
}

/// Deliver `vector` to `obj` from now on. The object must stay alive until `unbind`.
pub fn bind(vector: u32, obj: *const InterruptObj) {
    let old = SLOTS[vector as usize & 255].swap(obj.cast_mut(), Ordering::AcqRel);
    crate::kassert!(old.is_null());
}

/// Stop delivering `vector` and wait until no handler still uses the object it was bound to.
pub fn unbind(vector: u32) {
    let v = vector as usize & 255;
    SLOTS[v].store(core::ptr::null_mut(), Ordering::SeqCst);
    while INFLIGHT[v].load(Ordering::SeqCst) != 0 {
        core::hint::spin_loop();
    }
}

pub fn spurious() -> u64 {
    SPURIOUS.load(Ordering::Relaxed)
}

/// Called by the C dispatcher (idt.c) for every device vector, in interrupt context.
#[unsafe(no_mangle)]
pub extern "C" fn dkrnl_dev_irq(vector: u32) {
    if super::iommu::fault_irq(vector) {
        return;
    }
    let v = vector as usize & 255;
    INFLIGHT[v].fetch_add(1, Ordering::SeqCst);
    let p = SLOTS[v].load(Ordering::SeqCst);
    if p.is_null() {
        SPURIOUS.fetch_add(1, Ordering::Relaxed);
    } else {
        // SAFETY: a bound object stays alive until `unbind` has seen INFLIGHT drop to 0, and this
        // handler incremented it before loading the pointer (both SeqCst).
        unsafe { &*p }.fire();
    }
    INFLIGHT[v].fetch_sub(1, Ordering::SeqCst);
}
