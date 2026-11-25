//! Intel Xe / Iris / Arc user-space DRM driver (`xe.ddrv`, PCI vendor `8086`, class `03.*`).
//!
//! Loaded from Ed25519-verified `sys:/bin/xe.ddrv` with read-only access to `sys:/firmware/xe/`.
//! Initializes the Ring-3 `dosdrm` C/C++ compatibility shim, GEM/GPU-VM, and timeline `syncobj`
//! subsystem while keeping display scanout safely on UEFI GOP until Intel Xe display + GuC
//! bring-up attaches native Atomic KMS pipes.

use dosdrm::gem::{GemTable, GpuVmTable, SyncobjTable};
use dosdrm::kms::{AtomicCommit, ConnectorKind, KmsState};
use dosdrm::shim::{self, DrmPciDev, FirmwareDir};
use libd::gpu::{self, KmsResourcesWire, ModeEntry};
use libd::proto;
use libd::sys::{self, Handle};
use libd::{Port, Startup, println};

use crate::gpu_drv::{self, DrmDriver, GpuAnnounce, kms_err_to_sys, mem_err_to_sys};

struct IntelXe {
    kms: KmsState,
    gem: GemTable,
    vms: GpuVmTable,
    syncobjs: SyncobjTable,
    fw_loaded: bool,
    shim_abi: u32,
}

impl DrmDriver for IntelXe {
    fn kms_get_resources(&self, res_out: &mut KmsResourcesWire, modes_out: &mut [ModeEntry]) -> usize {
        let _ = modes_out;
        *res_out = KmsResourcesWire::empty();
        res_out.connector_kind = ConnectorKind::Edp as u8;
        res_out.plane_count = 1;
        res_out.shim_abi = self.shim_abi;
        if self.fw_loaded {
            res_out.status_flags |= gpu::KMS_STATUS_FIRMWARE_LOADED;
        }
        if self.shim_abi != 0 {
            res_out.status_flags |= gpu::KMS_STATUS_VENDOR_SHIM_OK;
        }
        res_out.set_note(b"xe dosdrm ready (display on UEFI GOP)");
        0
    }

    fn gem_import(&mut self, vmo: Handle, _size: u64, _bo_flags: u32) -> Result<(u32, [u8; 16]), i64> {
        sys::handle_close(vmo);
        Err(sys::ERR_NOT_SUPPORTED)
    }

    fn gem_close(&mut self, gem_handle: u32) -> Result<(), i64> {
        self.gem.release(gem_handle).map(|_| ()).map_err(mem_err_to_sys)
    }

    fn kms_create_fb(
        &mut self,
        _gem_handle: u32,
        _width: u32,
        _height: u32,
        _pitch: u32,
        _format: u32,
        _modifier: u64,
    ) -> Result<u32, i64> {
        Err(sys::ERR_NOT_SUPPORTED)
    }

    fn kms_destroy_fb(&mut self, fb_id: u32) -> Result<(), i64> {
        self.kms.remove_fb(fb_id).ok_or(sys::ERR_OUT_OF_RANGE).map(|_| ())
    }

    fn kms_atomic_commit(&mut self, commit: &AtomicCommit) -> Result<(u64, bool), i64> {
        let _ = self.kms.validate_commit(commit).map_err(kms_err_to_sys)?;
        Err(sys::ERR_NOT_SUPPORTED)
    }

    fn vm_create(&mut self) -> Result<u32, i64> {
        self.vms.create().map_err(mem_err_to_sys)
    }

    fn vm_destroy(&mut self, vm_id: u32) -> Result<(), i64> {
        self.vms.destroy(vm_id).map_err(mem_err_to_sys)
    }

    fn syncobj_create(&mut self, initial_point: u64) -> Result<u32, i64> {
        self.syncobjs.create(initial_point).map_err(mem_err_to_sys)
    }

    fn syncobj_destroy(&mut self, syncobj: u32) -> Result<(), i64> {
        self.syncobjs.destroy(syncobj).map_err(mem_err_to_sys)
    }

    fn syncobj_signal(&mut self, syncobj: u32, point: u64) -> Result<u64, i64> {
        self.syncobjs.signal(syncobj, point).map_err(mem_err_to_sys)
    }

    fn syncobj_wait(&mut self, syncobj: u32, point: u64) -> Result<u64, i64> {
        if point == 0 {
            return self.syncobjs.query(syncobj).map_err(mem_err_to_sys);
        }
        if !self.syncobjs.is_signaled(syncobj, point).map_err(mem_err_to_sys)? {
            return Err(sys::ERR_SHOULD_WAIT);
        }
        self.syncobjs.query(syncobj).map_err(mem_err_to_sys)
    }
}

fn arch_label(device_id: u16) -> &'static str {
    match device_id >> 8 {
        0xE2 => "Intel Arc Battlemage (Xe2)",
        0x64 => "Intel Arc Lunar Lake (Xe2)",
        0x7D => "Intel Arc Meteor Lake (Xe-LPG)",
        0x56 => "Intel Arc Alchemist (Xe-HPG)",
        0xA7 | 0x46 | 0x9A => "Intel Iris Xe",
        _ => "Intel Xe Graphics",
    }
}

pub fn main(s: *const Startup) -> i32 {
    // SAFETY: `s` is the startup block pointer passed by the kernel.
    if !unsafe { libd::init(s, "xe") } {
        return -1;
    }
    let dev = libd::startup_handle(sys::TAG_DEVICE);
    let ctl = libd::startup_handle(proto::TAG_CONTROL);
    let fw = FirmwareDir::from_startup();
    let Ok(pci) = DrmPciDev::open(dev) else {
        println!("xe: device_info failed");
        return 1;
    };
    let shim_abi = shim::init_and_verify_vendor_shim(dev, fw.raw()).unwrap_or(0);
    let fw_loaded = if let Ok((vmo, len)) = fw.load_vmo(b"manifest.toml") {
        sys::handle_close(vmo);
        len > 0
    } else {
        false
    };

    let vram_bytes = pci.info.bar_size[2].max(pci.info.bar_size[0]);
    let vram_mib = (vram_bytes >> 20) as u32;
    let iommu = (pci.info.flags & sys::DEV_FLAG_IOMMU) != 0;
    let mut caps = gpu::CAP_GEM_VM | gpu::CAP_SYNCOBJ_TIMELINE;
    if iommu {
        caps |= gpu::CAP_IOMMU;
    }
    if fw_loaded {
        caps |= gpu::CAP_SYS_FIRMWARE;
    }
    let label = arch_label(pci.info.device);
    println!(
        "xe: {} ({:04x}:{:04x}) on {} ({} MiB BAR, fw={}, shim={:#x}, IOMMU={}); display kept on UEFI GOP",
        label,
        pci.info.vendor,
        pci.info.device,
        pci.info.name(),
        vram_mib,
        fw_loaded,
        shim_abi,
        iommu
    );

    let mut drv = IntelXe {
        kms: KmsState::new(),
        gem: GemTable::new(),
        vms: GpuVmTable::new(),
        syncobjs: SyncobjTable::new(),
        fw_loaded,
        shim_abi,
    };
    let Ok(port) = Port::new(32) else { return 1 };
    gpu_drv::announce(
        ctl,
        &GpuAnnounce {
            kind: gpu::KIND_INTEL_XE,
            vendor: pci.info.vendor,
            device: pci.info.device,
            vram_mib,
            width: 0,
            height: 0,
            caps,
            name: label,
        },
    );
    gpu_drv::serve_loop(ctl, &port, &mut drv)
}
