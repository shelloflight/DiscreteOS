//! Ring-3 hardware, scatter-gather IOMMU DMA, `sys:/firmware/<vendor>/` VMO loader, and C/C++
//! vendor runtime shim (`features = ["shim"]`).
//!
//! Used inside unprivileged `.ddrv` GPU driver processes so upstream C (`amdgpu`/`dc`, `xe`) and
//! freestanding C++ (`open-gpu-kernel-modules` `nvkms`) run isolated in user space.

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use libd::fs::{self as fp, Node};
use libd::proto;
use libd::sys::{self, DeviceInfo, Handle};
use libd::{Dma, Mapping, println};

use crate::MAX_FB_BYTES;

pub const MAX_SG_RUNS: usize = 64;
const MAX_SG_PAGES: usize = 16384; // 64 MiB
const MAX_FIRMWARE_BYTES: u64 = 32 << 20; // 32 MiB max single firmware blob

/// Scatter-gather IOMMU DMA pin of a VMO inside a GPU driver's per-device IOMMU domain.
pub struct SgPin {
    pub vmo: Handle,
    pub pin: Handle,
    pub size: u64,
    pub runs: [(u64, u32); MAX_SG_RUNS],
    pub run_count: usize,
}

impl SgPin {
    /// Pin `size` bytes of `vmo` into `dev`'s IOMMU domain with `dma_flags` (`DMA_DEVICE_READ` / `WRITE`).
    /// Takes ownership of `vmo` (closing it on error or drop).
    pub fn pin(
        dev: Handle,
        scratch: &mut Mapping,
        vmo: Handle,
        size: u64,
        dma_flags: u32,
    ) -> Result<Self, i64> {
        if size == 0 || size > MAX_FB_BYTES {
            sys::handle_close(vmo);
            return Err(sys::ERR_INVALID_ARGS);
        }
        let vmo_sz = match sys::vmo_size(vmo) {
            Ok(s) if s >= size && s <= MAX_FB_BYTES => s,
            Ok(_) => {
                sys::handle_close(vmo);
                return Err(sys::ERR_OUT_OF_RANGE);
            }
            Err(e) => {
                sys::handle_close(vmo);
                return Err(e);
            }
        };
        let pin_len = size.div_ceil(sys::PAGE) * sys::PAGE;
        let pages = (pin_len / sys::PAGE) as usize;
        if pages == 0 || pages > MAX_SG_PAGES || scratch.len < (pages as u64) * 8 {
            sys::handle_close(vmo);
            return Err(sys::ERR_OUT_OF_RANGE);
        }
        // SAFETY: `scratch` is a private page-aligned RW mapping of at least `pages * 8` bytes.
        let addrs: &mut [u64] = unsafe {
            core::slice::from_raw_parts_mut(scratch.addr as *mut u64, pages)
        };
        let pin = match sys::dma_map(dev, vmo, 0, pin_len, dma_flags, addrs) {
            Ok(p) => p,
            Err(e) => {
                sys::handle_close(vmo);
                return Err(e);
            }
        };
        let mut runs = [(0u64, 0u32); MAX_SG_RUNS];
        let mut run_count = 0usize;
        for &pa in addrs.iter() {
            if run_count > 0 {
                let (prev_addr, prev_len) = runs[run_count - 1];
                if prev_addr.saturating_add(u64::from(prev_len)) == pa && prev_len <= u32::MAX - 4096 {
                    runs[run_count - 1].1 = prev_len + 4096;
                    continue;
                }
            }
            if run_count >= MAX_SG_RUNS {
                sys::handle_close(pin);
                sys::handle_close(vmo);
                return Err(sys::ERR_NO_RESOURCES);
            }
            runs[run_count] = (pa, 4096);
            run_count += 1;
        }
        let _ = vmo_sz;
        Ok(Self {
            vmo,
            pin,
            size,
            runs,
            run_count,
        })
    }

    pub fn runs(&self) -> &[(u64, u32)] {
        &self.runs[..self.run_count]
    }
}

impl Drop for SgPin {
    fn drop(&mut self) {
        if self.pin != 0 {
            sys::handle_close(self.pin);
        }
        if self.vmo != 0 {
            sys::handle_close(self.vmo);
        }
    }
}

/// Allocate the reusable 128 KiB scratch buffer for [`SgPin::pin`].
pub fn alloc_sg_scratch() -> Result<Mapping, i64> {
    Mapping::new((MAX_SG_PAGES as u64) * 8)
}

/// Read-only capability handle to this driver's vendor firmware directory (`sys:/firmware/<vendor>/`).
#[derive(Clone, Copy)]
pub struct FirmwareDir {
    ch: Handle,
}

impl FirmwareDir {
    pub fn from_startup() -> Self {
        Self {
            ch: libd::startup_handle(proto::TAG_FIRMWARE),
        }
    }

    pub const fn raw(&self) -> Handle {
        self.ch
    }

    pub const fn is_available(&self) -> bool {
        self.ch != 0
    }

    /// Load a firmware file relative to `sys:/firmware/<vendor>/` into a read-only VMO.
    /// Returns `(ro_vmo, file_byte_len)`.
    pub fn load_vmo(&self, rel_path: &[u8]) -> Result<(Handle, usize), i64> {
        if self.ch == 0 {
            return Err(fp::ERR_NOT_FOUND);
        }
        let dir = Node::from(self.ch);
        let res = (|| {
            let (file, kind, size) = dir.open(rel_path, 0, fp::R_READ)?;
            if kind != fp::KIND_FILE || size == 0 || size > MAX_FIRMWARE_BYTES {
                return Err(sys::ERR_OUT_OF_RANGE);
            }
            let vmo = sys::vmo_create(size)?;
            let mut chunk = [0u8; 4096];
            let mut off = 0u64;
            while off < size {
                let want = ((size - off) as usize).min(chunk.len());
                let got = match file.read(off, &mut chunk[..want]) {
                    Ok(g) if g > 0 => g,
                    Ok(_) => {
                        sys::handle_close(vmo);
                        return Err(fp::ERR_IO);
                    }
                    Err(e) => {
                        sys::handle_close(vmo);
                        return Err(e);
                    }
                };
                if sys::vmo_write(vmo, off, &chunk[..got]) != 0 {
                    sys::handle_close(vmo);
                    return Err(sys::ERR_NO_MEMORY);
                }
                off += got as u64;
            }
            let ro = match sys::handle_replace(
                vmo,
                sys::RIGHT_READ | sys::RIGHT_MAP | sys::RIGHT_DUPLICATE | sys::RIGHT_TRANSFER | sys::RIGHT_INSPECT,
            ) {
                Ok(r) => r,
                Err(e) => {
                    sys::handle_close(vmo);
                    return Err(e);
                }
            };
            Ok((ro, size as usize))
        })();
        let _ = dir.into_handle();
        res
    }

    /// Load and map a firmware file read-only into this `.ddrv` address space.
    pub fn load_mapped(&self, rel_path: &[u8]) -> Result<(Mapping, usize), i64> {
        let (vmo, len) = self.load_vmo(rel_path)?;
        let map_len = (len as u64).div_ceil(sys::PAGE) * sys::PAGE;
        match Mapping::of_ro(vmo, map_len) {
            Ok(m) => Ok((m, len)),
            Err(e) => {
                sys::handle_close(vmo);
                Err(e)
            }
        }
    }
}

/// PCI device wrapper for `.ddrv` GPU drivers.
pub struct DrmPciDev {
    pub dev: Handle,
    pub info: DeviceInfo,
}

impl DrmPciDev {
    pub fn open(dev: Handle) -> Result<Self, i64> {
        let info = sys::device_info(dev)?;
        Ok(Self { dev, info })
    }

    pub fn enable_bus_master(&self) -> Result<(), i64> {
        let cmd = sys::config_read(self.dev, 0x04, 2)?;
        sys::config_write(self.dev, 0x04, 2, cmd | 0x06).map(|_| ())
    }

    pub fn map_bar_window(&self, bar: usize, off: u64, len: u64) -> Result<Mapping, i64> {
        if bar >= 6 || self.info.bar_size[bar] == 0 {
            return Err(sys::ERR_INVALID_ARGS);
        }
        let vmo = sys::device_map_bar(self.dev, bar as u64)?;
        match Mapping::of_range(vmo, off, len) {
            Ok(m) => Ok(m),
            Err(e) => {
                sys::handle_close(vmo);
                Err(e)
            }
        }
    }
}

// ---- Scoped C17 / C++20 `vendor/dosdrm_c` host callback bridge ----------------------------------

static SHIM_DEV: AtomicU32 = AtomicU32::new(0);
static SHIM_FW: AtomicU32 = AtomicU32::new(0);
static ALLOC_LOCK: AtomicBool = AtomicBool::new(false);

const MAX_C_ALLOCS: usize = 1024;

#[derive(Clone, Copy)]
struct AllocRec {
    addr: usize,
    map_len: u64,
    vmo: Handle,
}

static mut ALLOC_TABLE: [AllocRec; MAX_C_ALLOCS] = [AllocRec { addr: 0, map_len: 0, vmo: 0 }; MAX_C_ALLOCS];

fn lock_alloc() {
    while ALLOC_LOCK
        .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        core::hint::spin_loop();
    }
}

fn unlock_alloc() {
    ALLOC_LOCK.store(false, Ordering::Release);
}

unsafe extern "C" {
    fn dosdrm_shim_version() -> u32;
    fn dosdrm_vendor_self_test() -> i32;
}

/// Bind this `.ddrv` process's PCI device and firmware directory handles to the C/C++ shim,
/// and run the C17 + freestanding C++20 runtime self-test (`libvendor_dosdrm_c.a`).
pub fn init_and_verify_vendor_shim(dev: Handle, fw_dir: Handle) -> Result<u32, i32> {
    SHIM_DEV.store(dev, Ordering::Release);
    SHIM_FW.store(fw_dir, Ordering::Release);
    // SAFETY: `dosdrm_vendor_self_test` and `dosdrm_shim_version` are stateless/self-contained C/C++
    // functions linked from `libvendor_dosdrm_c.a` using the `dosdrm_host_*` callbacks below.
    let rc = unsafe { dosdrm_vendor_self_test() };
    if rc != 0 {
        return Err(rc);
    }
    // SAFETY: Pure constant-returning C ABI query in `libvendor_dosdrm_c.a`.
    Ok(unsafe { dosdrm_shim_version() })
}

#[unsafe(no_mangle)]
pub extern "C" fn dosdrm_host_log(msg: *const u8, len: usize) {
    if msg.is_null() || len == 0 {
        return;
    }
    let n = len.min(240);
    // SAFETY: Caller (`dosdrm_log_cstr`) verified `msg` is non-null and readable for `len` bytes.
    let bytes = unsafe { core::slice::from_raw_parts(msg, n) };
    println!("dosdrm: {}", core::str::from_utf8(bytes).unwrap_or("?"));
}

#[unsafe(no_mangle)]
pub extern "C" fn dosdrm_host_udelay(us: u32) {
    if us > 0 {
        libd::handle::sleep(u64::from(us).saturating_mul(1_000));
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn dosdrm_host_clock_ns() -> u64 {
    sys::clock_ns()
}

#[unsafe(no_mangle)]
pub extern "C" fn dosdrm_host_pci_info(
    dev_handle: u32,
    out_vendor: *mut u16,
    out_device: *mut u16,
    out_rev: *mut u8,
    out_bar_sizes: *mut u64,
) -> i32 {
    let dev = if dev_handle != 0 { dev_handle } else { SHIM_DEV.load(Ordering::Acquire) };
    let Ok(info) = sys::device_info(dev) else {
        return -5;
    };
    if !out_vendor.is_null() {
        // SAFETY: Checked non-null immediately above.
        unsafe { *out_vendor = info.vendor; }
    }
    if !out_device.is_null() {
        // SAFETY: Checked non-null immediately above.
        unsafe { *out_device = info.device; }
    }
    if !out_rev.is_null() {
        // SAFETY: Checked non-null immediately above.
        unsafe { *out_rev = info.revision; }
    }
    if !out_bar_sizes.is_null() {
        // SAFETY: Caller passes a 6-element `uint64_t[6]` array per `dosdrm_pci_get_info` contract.
        unsafe {
            let dst = core::slice::from_raw_parts_mut(out_bar_sizes, 6);
            dst.copy_from_slice(&info.bar_size);
        }
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn dosdrm_host_map_bar(
    dev_handle: u32,
    bar: u8,
    off: u64,
    len: u64,
    out_vmo: *mut u32,
    out_addr: *mut u64,
    out_len: *mut u64,
) -> i32 {
    if bar >= 6 || len == 0 || out_vmo.is_null() || out_addr.is_null() || out_len.is_null() {
        return -22;
    }
    let dev = if dev_handle != 0 { dev_handle } else { SHIM_DEV.load(Ordering::Acquire) };
    let Ok(vmo) = sys::device_map_bar(dev, u64::from(bar)) else {
        return -5;
    };
    let Ok(map) = Mapping::of_range(vmo, off, len) else {
        sys::handle_close(vmo);
        return -12;
    };
    // SAFETY: All output pointers were checked non-null above.
    unsafe {
        *out_vmo = map.vmo;
        *out_addr = map.addr;
        *out_len = map.len;
    }
    core::mem::forget(map);
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn dosdrm_host_unmap_bar(vmo: u32, addr: u64, len: u64) {
    if addr != 0 && len != 0 {
        let _ = sys::vmar_unmap(libd::root_vmar(), addr, len);
    }
    if vmo != 0 {
        sys::handle_close(vmo);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn dosdrm_host_dma_alloc(
    dev_handle: u32,
    size: u64,
    out_cpu_addr: *mut u64,
    out_dma_addr: *mut u64,
    out_vmo: *mut u32,
    out_pin: *mut u32,
    out_map_len: *mut u64,
) -> i32 {
    if size == 0
        || size > MAX_FB_BYTES
        || out_cpu_addr.is_null()
        || out_dma_addr.is_null()
        || out_vmo.is_null()
        || out_pin.is_null()
        || out_map_len.is_null()
    {
        return -22;
    }
    let dev = if dev_handle != 0 { dev_handle } else { SHIM_DEV.load(Ordering::Acquire) };
    let aligned = size.div_ceil(sys::PAGE) * sys::PAGE;
    let Ok(mut dma) = Dma::new(dev, aligned, sys::DMA_DEVICE_READ | sys::DMA_DEVICE_WRITE) else {
        return -12;
    };
    dma.map.bytes_mut().fill(0);
    let cpu_addr = dma.map.addr;
    let map_len = dma.map.len;
    let vmo = dma.map.vmo;
    let pin = dma.pin;
    let dma_addr = dma.dev_addr(0);
    core::mem::forget(dma);
    // SAFETY: All output pointers were checked non-null above.
    unsafe {
        *out_cpu_addr = cpu_addr;
        *out_dma_addr = dma_addr;
        *out_vmo = vmo;
        *out_pin = pin;
        *out_map_len = map_len;
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn dosdrm_host_dma_free(cpu_addr: u64, map_len: u64, vmo: u32, pin: u32) {
    if pin != 0 {
        sys::handle_close(pin);
    }
    if cpu_addr != 0 && map_len != 0 {
        let _ = sys::vmar_unmap(libd::root_vmar(), cpu_addr, map_len);
    }
    if vmo != 0 {
        sys::handle_close(vmo);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn dosdrm_host_alloc(size: usize) -> *mut u8 {
    if size == 0 || size > (256 << 20) {
        return core::ptr::null_mut();
    }
    let map_len = (size as u64).div_ceil(sys::PAGE) * sys::PAGE;
    let Ok(vmo) = sys::vmo_create(map_len) else {
        return core::ptr::null_mut();
    };
    let Ok(addr) = sys::vmar_map(
        libd::root_vmar(),
        sys::ANY,
        vmo,
        0,
        map_len,
        sys::RIGHT_READ | sys::RIGHT_WRITE,
    ) else {
        sys::handle_close(vmo);
        return core::ptr::null_mut();
    };
    lock_alloc();
    let mut recorded = false;
    // SAFETY: `ALLOC_TABLE` is exclusively mutated while `ALLOC_LOCK` is held.
    unsafe {
        let ptr = &raw mut ALLOC_TABLE;
        for slot in (*ptr).iter_mut() {
            if slot.addr == 0 {
                *slot = AllocRec {
                    addr: addr as usize,
                    map_len,
                    vmo,
                };
                recorded = true;
                break;
            }
        }
    }
    unlock_alloc();
    if !recorded {
        let _ = sys::vmar_unmap(libd::root_vmar(), addr, map_len);
        sys::handle_close(vmo);
        return core::ptr::null_mut();
    }
    addr as *mut u8
}

#[unsafe(no_mangle)]
pub extern "C" fn dosdrm_host_free(ptr: *mut u8, _size: usize) {
    if ptr.is_null() {
        return;
    }
    let target = ptr as usize;
    let mut found = None;
    lock_alloc();
    // SAFETY: `ALLOC_TABLE` is exclusively mutated while `ALLOC_LOCK` is held.
    unsafe {
        let tbl = &raw mut ALLOC_TABLE;
        for slot in (*tbl).iter_mut() {
            if slot.addr == target {
                found = Some(*slot);
                *slot = AllocRec { addr: 0, map_len: 0, vmo: 0 };
                break;
            }
        }
    }
    unlock_alloc();
    if let Some(rec) = found {
        let _ = sys::vmar_unmap(libd::root_vmar(), rec.addr as u64, rec.map_len);
        sys::handle_close(rec.vmo);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn dosdrm_host_pci_cfg_read(
    dev_handle: u32,
    offset: u16,
    width: u8,
    out_val: *mut u32,
) -> i32 {
    if out_val.is_null() {
        return -22;
    }
    let dev = if dev_handle != 0 { dev_handle } else { SHIM_DEV.load(Ordering::Acquire) };
    match sys::config_read(dev, u64::from(offset), u64::from(width)) {
        Ok(v) => {
            // SAFETY: `out_val` was checked non-null by `dosdrm_pci_read_config` and above.
            unsafe {
                *out_val = v as u32;
            }
            0
        }
        Err(_) => -5,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn dosdrm_host_pci_cfg_write(
    dev_handle: u32,
    offset: u16,
    width: u8,
    val: u32,
) -> i32 {
    let dev = if dev_handle != 0 { dev_handle } else { SHIM_DEV.load(Ordering::Acquire) };
    match sys::config_write(dev, u64::from(offset), u64::from(width), u64::from(val)) {
        Ok(_) => 0,
        Err(_) => -5,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn dosdrm_host_load_firmware(
    name: *const u8,
    name_len: usize,
    out_vmo: *mut u32,
    out_addr: *mut u64,
    out_map_len: *mut u64,
    out_size: *mut usize,
) -> i32 {
    if name.is_null()
        || name_len == 0
        || name_len > 255
        || out_vmo.is_null()
        || out_addr.is_null()
        || out_map_len.is_null()
        || out_size.is_null()
    {
        return -22;
    }
    let fw = FirmwareDir {
        ch: SHIM_FW.load(Ordering::Acquire),
    };
    // SAFETY: `name` is non-null and bounded by `name_len <= 255` from `dosdrm_request_firmware`.
    let rel = unsafe { core::slice::from_raw_parts(name, name_len) };
    let Ok((map, len)) = fw.load_mapped(rel) else {
        return -2;
    };
    // SAFETY: All four output pointers were checked non-null above.
    unsafe {
        *out_vmo = map.vmo;
        *out_addr = map.addr;
        *out_map_len = map.len;
        *out_size = len;
    }
    core::mem::forget(map);
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn dosdrm_host_unload_firmware(vmo: u32, addr: u64, map_len: u64) {
    if addr != 0 && map_len != 0 {
        let _ = sys::vmar_unmap(libd::root_vmar(), addr, map_len);
    }
    if vmo != 0 {
        sys::handle_close(vmo);
    }
}
