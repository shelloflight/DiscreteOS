//! GEM buffer objects, per-context GPU Virtual Memory (`GpuVm`) range allocator, and
//! monotonic timeline `drm_syncobj` state machines (`VK_KHR_timeline_semaphore` semantics).

pub const MAX_GEM_BOS: usize = 32;
pub const MAX_GPU_VMS: usize = 8;
pub const MAX_VM_MAPPINGS: usize = 32;
pub const MAX_SYNCOBJS: usize = 64;

// GEM BO creation/import flags.
pub const BO_SCANOUT: u32 = 1 << 0;
pub const BO_CURSOR: u32 = 1 << 1;
pub const BO_RENDER: u32 = 1 << 2;
pub const BO_VRAM: u32 = 1 << 3;
pub const BO_GTT: u32 = 1 << 4;
pub const BO_WC: u32 = 1 << 5;
pub const BO_HOST_VISIBLE: u32 = 1 << 6;

// GPU VM bind flags.
pub const VM_READ: u32 = 1 << 0;
pub const VM_WRITE: u32 = 1 << 1;
pub const VM_EXEC: u32 = 1 << 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DrmMemError {
    InvalidArgs,
    UnknownHandle,
    Unaligned,
    AddressOverlap,
    OutOfRange,
    NoResources,
    Busy,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GemBo {
    pub handle: u32,
    pub size: u64,
    pub flags: u32,
    pub res_id: u32,
    pub uuid: [u8; 16],
    pub refcount: u32,
}

pub struct GemTable {
    slots: [Option<GemBo>; MAX_GEM_BOS],
    next_handle: u32,
}

impl GemTable {
    pub const fn new() -> Self {
        Self {
            slots: [None; MAX_GEM_BOS],
            next_handle: 1,
        }
    }

    pub fn insert(&mut self, size: u64, flags: u32, res_id: u32, uuid: [u8; 16]) -> Result<u32, DrmMemError> {
        if size == 0 {
            return Err(DrmMemError::InvalidArgs);
        }
        let Some(slot) = self.slots.iter_mut().find(|s| s.is_none()) else {
            return Err(DrmMemError::NoResources);
        };
        let handle = self.next_handle;
        self.next_handle = self.next_handle.wrapping_add(1).max(1);
        *slot = Some(GemBo {
            handle,
            size,
            flags,
            res_id,
            uuid,
            refcount: 1,
        });
        Ok(handle)
    }

    pub fn get(&self, handle: u32) -> Option<GemBo> {
        self.slots.iter().flatten().copied().find(|b| b.handle == handle)
    }

    pub fn add_ref(&mut self, handle: u32) -> bool {
        if let Some(bo) = self.slots.iter_mut().flatten().find(|b| b.handle == handle) {
            bo.refcount = bo.refcount.saturating_add(1);
            true
        } else {
            false
        }
    }

    /// Decrement refcount; returns `Some(GemBo)` when the last reference drops so the driver can
    /// unpin IOMMU DMA and release hardware resources.
    pub fn release(&mut self, handle: u32) -> Result<Option<GemBo>, DrmMemError> {
        for slot in &mut self.slots {
            if let Some(bo) = slot
                && bo.handle == handle
            {
                if bo.refcount > 1 {
                    bo.refcount -= 1;
                    return Ok(None);
                }
                return Ok(slot.take());
            }
        }
        Err(DrmMemError::UnknownHandle)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GpuVmMapping {
    pub gpu_va: u64,
    pub size: u64,
    pub gem_handle: u32,
    pub bo_offset: u64,
    pub flags: u32,
}

#[derive(Clone, Copy)]
pub struct GpuVmSpace {
    pub vm_id: u32,
    pub va_base: u64,
    pub va_limit: u64,
    mappings: [Option<GpuVmMapping>; MAX_VM_MAPPINGS],
}

impl GpuVmSpace {
    pub const DEFAULT_VA_BASE: u64 = 0x0000_0001_0000_0000; // 4 GiB
    pub const DEFAULT_VA_LIMIT: u64 = 0x0000_8000_0000_0000; // 128 TiB (47-bit canonical GPU VA)

    pub const fn new(vm_id: u32) -> Self {
        Self {
            vm_id,
            va_base: Self::DEFAULT_VA_BASE,
            va_limit: Self::DEFAULT_VA_LIMIT,
            mappings: [None; MAX_VM_MAPPINGS],
        }
    }

    pub fn bind(
        &mut self,
        gem: &GemTable,
        gpu_va: u64,
        size: u64,
        gem_handle: u32,
        bo_offset: u64,
        flags: u32,
    ) -> Result<(), DrmMemError> {
        if size == 0 || !gpu_va.is_multiple_of(4096) || !size.is_multiple_of(4096) || !bo_offset.is_multiple_of(4096) {
            return Err(DrmMemError::Unaligned);
        }
        let end_va = gpu_va.checked_add(size).ok_or(DrmMemError::OutOfRange)?;
        if gpu_va < self.va_base || end_va > self.va_limit {
            return Err(DrmMemError::OutOfRange);
        }
        let bo = gem.get(gem_handle).ok_or(DrmMemError::UnknownHandle)?;
        let bo_end = bo_offset.checked_add(size).ok_or(DrmMemError::OutOfRange)?;
        let bo_aligned_sz = bo.size.div_ceil(4096) * 4096;
        if bo_end > bo_aligned_sz {
            return Err(DrmMemError::OutOfRange);
        }
        for existing in self.mappings.iter().flatten() {
            let ex_end = existing.gpu_va.saturating_add(existing.size);
            if gpu_va < ex_end && existing.gpu_va < end_va {
                return Err(DrmMemError::AddressOverlap);
            }
        }
        let Some(slot) = self.mappings.iter_mut().find(|s| s.is_none()) else {
            return Err(DrmMemError::NoResources);
        };
        *slot = Some(GpuVmMapping {
            gpu_va,
            size,
            gem_handle,
            bo_offset,
            flags,
        });
        Ok(())
    }

    pub fn unbind(&mut self, gpu_va: u64, size: u64) -> Result<GpuVmMapping, DrmMemError> {
        for slot in &mut self.mappings {
            if let Some(m) = *slot
                && m.gpu_va == gpu_va
                && (size == 0 || m.size == size)
            {
                *slot = None;
                return Ok(m);
            }
        }
        Err(DrmMemError::UnknownHandle)
    }

    pub fn lookup(&self, gpu_va: u64, len: u64) -> Option<GpuVmMapping> {
        let end = gpu_va.checked_add(len)?;
        self.mappings
            .iter()
            .flatten()
            .copied()
            .find(|m| gpu_va >= m.gpu_va && end <= m.gpu_va.saturating_add(m.size))
    }
}

pub struct GpuVmTable {
    vms: [Option<GpuVmSpace>; MAX_GPU_VMS],
    next_vm_id: u32,
}

impl GpuVmTable {
    pub const fn new() -> Self {
        Self {
            vms: [None; MAX_GPU_VMS],
            next_vm_id: 1,
        }
    }

    pub fn create(&mut self) -> Result<u32, DrmMemError> {
        let Some(slot) = self.vms.iter_mut().find(|s| s.is_none()) else {
            return Err(DrmMemError::NoResources);
        };
        let id = self.next_vm_id;
        self.next_vm_id = self.next_vm_id.wrapping_add(1).max(1);
        *slot = Some(GpuVmSpace::new(id));
        Ok(id)
    }

    pub fn destroy(&mut self, vm_id: u32) -> Result<(), DrmMemError> {
        for slot in &mut self.vms {
            if slot.as_ref().is_some_and(|v| v.vm_id == vm_id) {
                *slot = None;
                return Ok(());
            }
        }
        Err(DrmMemError::UnknownHandle)
    }

    pub fn get_mut(&mut self, vm_id: u32) -> Option<&mut GpuVmSpace> {
        self.vms.iter_mut().flatten().find(|v| v.vm_id == vm_id)
    }

    pub fn get(&self, vm_id: u32) -> Option<&GpuVmSpace> {
        self.vms.iter().flatten().find(|v| v.vm_id == vm_id)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Syncobj {
    pub id: u32,
    pub value: u64,
}

/// Binary and monotonic timeline `drm_syncobj` table (`VK_KHR_timeline_semaphore`).
pub struct SyncobjTable {
    slots: [Option<Syncobj>; MAX_SYNCOBJS],
    next_id: u32,
}

impl SyncobjTable {
    pub const fn new() -> Self {
        Self {
            slots: [None; MAX_SYNCOBJS],
            next_id: 1,
        }
    }

    pub fn create(&mut self, initial_value: u64) -> Result<u32, DrmMemError> {
        let Some(slot) = self.slots.iter_mut().find(|s| s.is_none()) else {
            return Err(DrmMemError::NoResources);
        };
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1).max(1);
        *slot = Some(Syncobj { id, value: initial_value });
        Ok(id)
    }

    pub fn destroy(&mut self, id: u32) -> Result<(), DrmMemError> {
        for slot in &mut self.slots {
            if slot.is_some_and(|s| s.id == id) {
                *slot = None;
                return Ok(());
            }
        }
        Err(DrmMemError::UnknownHandle)
    }

    /// Monotonically advance timeline syncobj `id` to `max(current, point)`.
    pub fn signal(&mut self, id: u32, point: u64) -> Result<u64, DrmMemError> {
        let Some(s) = self.slots.iter_mut().flatten().find(|s| s.id == id) else {
            return Err(DrmMemError::UnknownHandle);
        };
        let eff = if point == 0 { s.value.max(1) } else { s.value.max(point) };
        s.value = eff;
        Ok(eff)
    }

    pub fn reset(&mut self, id: u32) -> Result<(), DrmMemError> {
        let Some(s) = self.slots.iter_mut().flatten().find(|s| s.id == id) else {
            return Err(DrmMemError::UnknownHandle);
        };
        s.value = 0;
        Ok(())
    }

    pub fn query(&self, id: u32) -> Result<u64, DrmMemError> {
        self.slots
            .iter()
            .flatten()
            .find(|s| s.id == id)
            .map(|s| s.value)
            .ok_or(DrmMemError::UnknownHandle)
    }

    pub fn is_signaled(&self, id: u32, point: u64) -> Result<bool, DrmMemError> {
        let cur = self.query(id)?;
        let need = point.max(1);
        Ok(cur >= need)
    }

    /// Evaluate a multi-syncobj wait (`wait_all = true` requires every `(id, point)` to be reached;
    /// `wait_all = false` succeeds as soon as at least one is reached).
    pub fn check_wait(&self, pairs: &[(u32, u64)], wait_all: bool) -> Result<bool, DrmMemError> {
        if pairs.is_empty() {
            return Ok(true);
        }
        let mut any = false;
        let mut all = true;
        for &(id, pt) in pairs {
            let ready = self.is_signaled(id, pt)?;
            any |= ready;
            all &= ready;
        }
        Ok(if wait_all { all } else { any })
    }
}

impl Default for GemTable {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for GpuVmTable {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for SyncobjTable {
    fn default() -> Self {
        Self::new()
    }
}
