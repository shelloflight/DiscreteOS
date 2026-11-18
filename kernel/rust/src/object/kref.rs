//! `KRef<T>`: the reference count behind every kernel object.
//!
//! Like `alloc::sync::Arc`, but **creation is fallible**: `KRef::try_new` returns the value back
//! when the heap is out of memory instead of aborting the kernel. (`Arc::try_new` is unstable.)
//! Cloning and dropping never allocate, so they are safe anywhere, including under spinlocks.
//! The last reference drops the object (its `Drop` refunds quotas and frees pages) and frees it.

use alloc::alloc::{Layout, alloc, dealloc};
use core::marker::PhantomData;
use core::ops::Deref;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicUsize, Ordering, fence};

struct Inner<T> {
    refs: AtomicUsize,
    value: T,
}

pub struct KRef<T> {
    ptr: NonNull<Inner<T>>,
    _owns: PhantomData<Inner<T>>,
}

// SAFETY: like Arc: shared access to T from many threads needs T: Sync, and the last reference may
// drop T on any thread, which needs T: Send.
unsafe impl<T: Send + Sync> Send for KRef<T> {}
// SAFETY: as above.
unsafe impl<T: Send + Sync> Sync for KRef<T> {}

/// More references than this means a reference leak; fail closed before the count can overflow.
const MAX_REFS: usize = isize::MAX as usize;

impl<T> KRef<T> {
    /// Allocate the object. On out-of-memory the value is handed back (so its own `Drop` can undo
    /// whatever was charged for it).
    pub fn try_new(value: T) -> Result<Self, T> {
        let layout = Layout::new::<Inner<T>>();
        const { assert!(core::mem::size_of::<Inner<T>>() != 0) };
        // SAFETY: the layout has a non-zero size (asserted above).
        let raw = unsafe { alloc(layout) }.cast::<Inner<T>>();
        let Some(ptr) = NonNull::new(raw) else {
            return Err(value);
        };
        // SAFETY: `ptr` is a fresh allocation with the layout of Inner<T>.
        unsafe {
            ptr.as_ptr().write(Inner {
                refs: AtomicUsize::new(1),
                value,
            })
        };
        Ok(KRef {
            ptr,
            _owns: PhantomData,
        })
    }

    fn inner(&self) -> &Inner<T> {
        // SAFETY: the object stays allocated while any KRef (this one) exists.
        unsafe { self.ptr.as_ref() }
    }

    /// Same object?
    pub fn ptr_eq(a: &Self, b: &Self) -> bool {
        a.ptr == b.ptr
    }

    /// Current number of references (a snapshot; for tests and inspection).
    pub fn ref_count(this: &Self) -> usize {
        this.inner().refs.load(Ordering::Relaxed)
    }

    /// Stable address of the object (for inspection only).
    pub fn addr(this: &Self) -> usize {
        this.ptr.as_ptr() as usize
    }

    /// Address of the value inside (what `&*kref` points at): the key of a registry that must
    /// find the object again from inside its own `Drop` (channel cycle collection).
    pub fn value_addr(this: &Self) -> usize {
        &this.inner().value as *const T as usize
    }

    /// A new reference to the object whose value is at `value`, unless its count already reached
    /// zero (it is being destroyed). Never resurrects.
    ///
    /// # Safety
    /// `value` came from `value_addr` and the memory is still allocated: the caller holds a lock
    /// that the object's `Drop` must take before the memory can be freed.
    pub unsafe fn try_from_value_addr(value: usize) -> Option<KRef<T>> {
        let off = core::mem::offset_of!(Inner<T>, value);
        let inner = (value - off) as *mut Inner<T>;
        // SAFETY: by the contract, `inner` is a live allocation of Inner<T>.
        let refs = unsafe { &(*inner).refs };
        let mut n = refs.load(Ordering::Relaxed);
        loop {
            if n == 0 {
                return None;
            }
            crate::kassert!(n < MAX_REFS);
            match refs.compare_exchange_weak(n, n + 1, Ordering::Acquire, Ordering::Relaxed) {
                Ok(_) => break,
                Err(cur) => n = cur,
            }
        }
        // SAFETY: non-null (it was a reference) and we now own one count.
        Some(KRef { ptr: unsafe { NonNull::new_unchecked(inner) }, _owns: PhantomData })
    }
}

impl<T> Clone for KRef<T> {
    fn clone(&self) -> Self {
        // Relaxed is enough to take a new reference from an existing one (as in Arc).
        let old = self.inner().refs.fetch_add(1, Ordering::Relaxed);
        crate::kassert!(old < MAX_REFS);
        KRef {
            ptr: self.ptr,
            _owns: PhantomData,
        }
    }
}

impl<T> Drop for KRef<T> {
    fn drop(&mut self) {
        if self.inner().refs.fetch_sub(1, Ordering::Release) != 1 {
            return;
        }
        // Last reference: see every other thread's writes before destroying the object.
        fence(Ordering::Acquire);
        // SAFETY: no other reference exists; the object was allocated by `try_new` with this layout.
        unsafe {
            core::ptr::drop_in_place(self.ptr.as_ptr());
            dealloc(self.ptr.as_ptr().cast(), Layout::new::<Inner<T>>());
        }
    }
}

impl<T> Deref for KRef<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.inner().value
    }
}
