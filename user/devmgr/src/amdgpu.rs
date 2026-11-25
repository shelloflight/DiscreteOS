//! AMD Radeon RDNA / AMDGPU Ring-3 user-space DRM driver (`amdgpu.ddrv`, PCI `1002:*` class `03.*`).
//!
//! Thin Rust capability/IPC bridge over the scoped C17 `vendor/amdgpu/` (`libvendor_amdgpu.a`)
//! stack (IP Discovery, AtomBIOS, official `sys:/firmware/amdgpu/` PSP/SMU/DMCUB/GC/SDMA/MES
//! microcode, Display Core `dc`/`dml2`/`dmub`/`dsc`/`link`, GMC/MMHUB GPU VM, OSSSYS IH, and
//! GFX/SDMA/MES rings) and `dosdrm` Atomic KMS / GEM / Syncobj protocol.

use core::ffi::c_void;

use dosdrm::gem::{GemTable, GpuVmTable, SyncobjTable};
use dosdrm::kms::{self, AtomicCommit, KmsState};
use dosdrm::shim::{self, DrmPciDev, FirmwareDir, SgPin};
use dosdrm::MAX_FB_BYTES;
use libd::gpu::{self, KmsResourcesWire, ModeEntry};
use libd::proto;
use libd::sys::{self, Handle};
use libd::{Mapping, Port, Startup, println};

use crate::gpu_drv::{self, DrmDriver, GpuAnnounce, kms_err_to_sys, mem_err_to_sys};

const MAX_AMD_BOS: usize = 24;
const MAX_AMD_CTXS: usize = 16;

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct CapiMode {
    width: u32,
    height: u32,
    refresh_mhz: u32,
    pixel_clock_khz: u32,
    htotal: u16,
    vtotal: u16,
    flags: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CapiInfo {
    native_kms: u8,
    active_pipes: u8,
    connector_kind: u8,
    dp_lanes: u8,
    edid_blocks: u8,
    vrr_capable: u8,
    vrr_enabled: u8,
    hdr_capable: u8,
    hdr_enabled: u8,
    dsc_capable: u8,
    dsc_enabled: u8,
    hw_cursor: u8,
    psp_alive: u8,
    smu_alive: u8,
    dmub_alive: u8,
    ih_enabled: u8,
    vrr_min_hz: u16,
    vrr_max_hz: u16,
    dcn_version: u32,
    fw_loaded_count: u32,
    width: u32,
    height: u32,
    pitch_bytes: u32,
    refresh_mhz: u32,
    htotal: u16,
    vtotal: u16,
    dp_rate_mbps: u32,
    vblank_seq: u64,
    vram_bytes: u64,
    monitor_name: [u8; 24],
    asic_name: [u8; 40],
}

impl Default for CapiInfo {
    fn default() -> Self {
        Self {
            native_kms: 0,
            active_pipes: 0,
            connector_kind: 3,
            dp_lanes: 0,
            edid_blocks: 0,
            vrr_capable: 0,
            vrr_enabled: 0,
            hdr_capable: 0,
            hdr_enabled: 0,
            dsc_capable: 0,
            dsc_enabled: 0,
            hw_cursor: 0,
            psp_alive: 0,
            smu_alive: 0,
            dmub_alive: 0,
            ih_enabled: 0,
            vrr_min_hz: 0,
            vrr_max_hz: 0,
            dcn_version: 0,
            fw_loaded_count: 0,
            width: 0,
            height: 0,
            pitch_bytes: 0,
            refresh_mhz: 0,
            htotal: 0,
            vtotal: 0,
            dp_rate_mbps: 0,
            vblank_seq: 0,
            vram_bytes: 0,
            monitor_name: [0; 24],
            asic_name: [0; 40],
        }
    }
}

#[repr(C)]
struct CapiCommit {
    pipe_slot: u32,
    test_only: u8,
    allow_modeset: u8,
    reset_boot: u8,
    mode_changed: u8,
    mode_width: u32,
    mode_height: u32,
    mode_refresh_mhz: u32,
    vrr_changed: u8,
    vrr_enable: u8,
    hdr_changed: u8,
    hdr_enable: u8,
    primary_changed: u8,
    cursor_changed: u8,
    cursor_hot_x: u16,
    cursor_hot_y: u16,
    primary_src: *const u8,
    primary_width: u32,
    primary_height: u32,
    primary_pitch: u32,
    primary_format: u32,
    cursor_src: *const u8,
    cursor_size: u32,
    cursor_x: i32,
    cursor_y: i32,
}

unsafe extern "C" {
    fn amdgpu_capi_open(dev_handle: u32) -> *mut c_void;
    fn amdgpu_capi_close(ctx: *mut c_void);
    fn amdgpu_capi_suspend(ctx: *mut c_void) -> i32;
    fn amdgpu_capi_get_info(
        ctx: *mut c_void,
        pipe_slot: u32,
        out_info: *mut CapiInfo,
        out_modes: *mut CapiMode,
        max_modes: u32,
    ) -> u32;
    fn amdgpu_capi_atomic_commit(
        ctx: *mut c_void,
        req: *const CapiCommit,
        out_vblank_seq: *mut u64,
        out_async: *mut u8,
    ) -> i32;
    fn amdgpu_capi_poll_vblank(
        ctx: *mut c_void,
        out_pipe: *mut u32,
        out_seq: *mut u64,
        out_ts_ns: *mut u64,
        out_late: *mut u8,
    ) -> i32;
    fn amdgpu_capi_poll_hotplug(ctx: *mut c_void) -> i32;
    fn amdgpu_capi_vm_create(ctx: *mut c_void, vm_id: u32) -> i32;
    fn amdgpu_capi_vm_destroy(ctx: *mut c_void, vm_id: u32) -> i32;
    fn amdgpu_capi_vm_map(
        ctx: *mut c_void,
        vm_id: u32,
        gem_handle: u32,
        gpu_va: u64,
        size: u64,
        target_addr: u64,
        is_system: u8,
        vm_flags: u32,
    ) -> i32;
    fn amdgpu_capi_vm_unmap(ctx: *mut c_void, vm_id: u32, gpu_va: u64, size: u64) -> i32;
    fn amdgpu_capi_ring_submit(
        ctx: *mut c_void,
        engine: u32,
        vm_id: u32,
        cmd: *const u8,
        len: usize,
        out_seq: *mut u64,
    ) -> i32;
    fn amdgpu_capi_irqs(ctx: *mut c_void) -> u64;
    fn amdgpu_capi_frames(ctx: *mut c_void) -> u64;
}

fn cstr_trim(buf: &[u8]) -> &[u8] {
    let n = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    &buf[..n]
}

fn c_err_to_sys(rc: i32) -> i64 {
    match rc {
        0 => 0,
        -22 => sys::ERR_INVALID_ARGS,
        -12 | -28 => sys::ERR_NO_MEMORY,
        -2 | -34 => sys::ERR_OUT_OF_RANGE,
        -1 | -13 => sys::ERR_ACCESS_DENIED,
        -95 | -19 => sys::ERR_NOT_SUPPORTED,
        -110 => sys::ERR_TIMED_OUT,
        _ => sys::ERR_BAD_STATE,
    }
}

struct AmdBo {
    gem_handle: u32,
    vmo: Handle,
    map: Option<Mapping>,
    pin: Option<SgPin>,
    dma_addr: u64,
}

impl Drop for AmdBo {
    fn drop(&mut self) {
        if let Some(m) = self.map.take() {
            let _ = sys::vmar_unmap(libd::root_vmar(), m.addr, m.len);
        }
        // `SgPin::drop` owns and closes `vmo` when pinned; otherwise close `vmo` directly.
        if self.pin.take().is_none() && self.vmo != 0 {
            sys::handle_close(self.vmo);
        }
    }
}

#[derive(Clone, Copy)]
struct AmdCtx {
    ctx_id: u32,
    engine: u32,
    vm_id: u32,
}

struct AmdGpu {
    dev: Handle,
    capi: *mut c_void,
    scratch: Option<Mapping>,
    active_slot: usize,
    kms: KmsState,
    gem: GemTable,
    vms: GpuVmTable,
    syncobjs: SyncobjTable,
    bos: [Option<AmdBo>; MAX_AMD_BOS],
    ctxs: [Option<AmdCtx>; MAX_AMD_CTXS],
    next_ctx_id: u32,
    fw_loaded: bool,
    shim_abi: u32,
    native_kms: bool,
    last_hpd_poll_ns: u64,
}

impl AmdGpu {
    fn find_bo(&self, gem_handle: u32) -> Option<&AmdBo> {
        self.bos.iter().flatten().find(|b| b.gem_handle == gem_handle)
    }

    fn synth_uuid(gem_handle: u32, device_id: u16) -> [u8; 16] {
        let mut u = [0u8; 16];
        u[0..4].copy_from_slice(b"AMDG");
        u[4..8].copy_from_slice(&gem_handle.to_le_bytes());
        u[8..10].copy_from_slice(&0x1002u16.to_le_bytes());
        u[10..12].copy_from_slice(&device_id.to_le_bytes());
        u
    }
}

impl Drop for AmdGpu {
    fn drop(&mut self) {
        if !self.capi.is_null() {
            // SAFETY: `self.capi` was allocated by `amdgpu_capi_open` and is freed once here.
            unsafe { amdgpu_capi_close(self.capi) };
            self.capi = core::ptr::null_mut();
        }
    }
}

impl DrmDriver for AmdGpu {
    fn set_active_slot(&mut self, slot: usize) {
        self.active_slot = slot;
    }

    fn kms_get_resources(&self, res_out: &mut KmsResourcesWire, modes_out: &mut [ModeEntry]) -> usize {
        *res_out = KmsResourcesWire::empty();
        res_out.shim_abi = self.shim_abi;
        if self.fw_loaded {
            res_out.status_flags |= gpu::KMS_STATUS_FIRMWARE_LOADED;
        }
        if self.shim_abi != 0 {
            res_out.status_flags |= gpu::KMS_STATUS_VENDOR_SHIM_OK;
        }
        if self.capi.is_null() {
            res_out.connector_kind = 3;
            res_out.set_note(b"amdgpu init failed (display on UEFI GOP)");
            return 0;
        }
        let mut info = CapiInfo::default();
        let mut cmodes = [CapiMode::default(); 16];
        let cap = modes_out.len().min(16) as u32;
        // SAFETY: `self.capi` is valid for the lifetime of `self`; pointers reference stack buffers.
        let mcnt = unsafe {
            amdgpu_capi_get_info(self.capi, self.active_slot as u32, &mut info, cmodes.as_mut_ptr(), cap)
        } as usize;

        res_out.connector_id = (self.active_slot as u32) + 1;
        res_out.connector_kind = info.connector_kind;
        res_out.crtc_id = (self.active_slot as u32) + 1;
        res_out.pipe = self.active_slot as u8;
        res_out.plane_count = if info.hw_cursor != 0 { 2 } else { 1 };
        res_out.edid_blocks = info.edid_blocks;
        res_out.width = info.width;
        res_out.height = info.height;
        res_out.pitch_bytes = info.pitch_bytes;
        res_out.refresh_mhz = info.refresh_mhz;
        res_out.htotal = info.htotal;
        res_out.vtotal = info.vtotal;
        res_out.dp_lanes = info.dp_lanes;
        res_out.dp_rate_mbps = info.dp_rate_mbps;
        res_out.vrr_min_hz = info.vrr_min_hz;
        res_out.vrr_max_hz = info.vrr_max_hz;
        res_out.vblank_seq = info.vblank_seq;
        if info.fw_loaded_count > 0 {
            res_out.status_flags |= gpu::KMS_STATUS_FIRMWARE_LOADED;
        }
        if info.active_pipes > 0 {
            res_out.status_flags |= gpu::KMS_STATUS_CONNECTED | gpu::KMS_STATUS_CRTC_ACTIVE;
        }
        if info.hw_cursor != 0 {
            res_out.status_flags |= gpu::KMS_STATUS_CURSOR_PLANE;
        }
        if info.vrr_capable != 0 {
            res_out.status_flags |= gpu::KMS_STATUS_VRR_CAPABLE;
        }
        if info.vrr_enabled != 0 {
            res_out.status_flags |= gpu::KMS_STATUS_VRR_ENABLED;
        }
        if info.hdr_capable != 0 {
            res_out.status_flags |= gpu::KMS_STATUS_HDR_CAPABLE;
        }
        if info.hdr_enabled != 0 {
            res_out.status_flags |= gpu::KMS_STATUS_HDR_ENABLED;
        }
        if info.dsc_capable != 0 {
            res_out.status_flags |= gpu::KMS_STATUS_DSC_CAPABLE;
        }
        if info.dsc_enabled != 0 {
            res_out.status_flags |= gpu::KMS_STATUS_DSC_ENABLED;
        }
        let mname = cstr_trim(&info.monitor_name);
        if !mname.is_empty() {
            res_out.set_monitor(mname);
        }
        if info.native_kms != 0 {
            res_out.set_note(b"amdgpu DC/DML2 Atomic KMS");
        } else {
            res_out.set_note(b"amdgpu DC ready (no active pipe; UEFI GOP)");
        }
        for i in 0..mcnt.min(modes_out.len()) {
            modes_out[i] = ModeEntry {
                width: cmodes[i].width,
                height: cmodes[i].height,
                refresh_mhz: cmodes[i].refresh_mhz,
                pixel_clock_khz: cmodes[i].pixel_clock_khz,
                htotal: cmodes[i].htotal,
                vtotal: cmodes[i].vtotal,
                flags: cmodes[i].flags,
            };
        }
        mcnt
    }

    fn gem_import(&mut self, vmo: Handle, size: u64, bo_flags: u32) -> Result<(u32, [u8; 16]), i64> {
        if size == 0 || size > MAX_FB_BYTES || sys::vmo_size(vmo).unwrap_or(0) < size {
            sys::handle_close(vmo);
            return Err(sys::ERR_OUT_OF_RANGE);
        }
        let Some(slot) = self.bos.iter().position(Option::is_none) else {
            sys::handle_close(vmo);
            return Err(sys::ERR_NO_RESOURCES);
        };
        let is_scanout_or_cursor = (bo_flags & (gpu::BO_SCANOUT | gpu::BO_CURSOR)) != 0;
        let map_len = size.div_ceil(sys::PAGE) * sys::PAGE;
        let map = if is_scanout_or_cursor {
            match Mapping::of_ro(vmo, map_len) {
                Ok(m) => Some(m),
                Err(e) => {
                    sys::handle_close(vmo);
                    return Err(e);
                }
            }
        } else {
            None
        };
        let (pin, dma_addr) = if !is_scanout_or_cursor
            && let Some(scr) = self.scratch.as_mut()
        {
            match SgPin::pin(
                self.dev,
                scr,
                vmo,
                size,
                sys::DMA_DEVICE_READ | sys::DMA_DEVICE_WRITE,
            ) {
                Ok(p) => {
                    let first = p.runs().first().map_or(0, |&(a, _)| a);
                    (Some(p), first)
                }
                Err(e) => {
                    sys::handle_close(vmo);
                    return Err(e);
                }
            }
        } else {
            (None, 0)
        };
        let uuid = Self::synth_uuid(slot as u32 + 1, 0x7550);
        match self.gem.insert(size, bo_flags, 0, uuid) {
            Ok(gem_h) => {
                self.bos[slot] = Some(AmdBo {
                    gem_handle: gem_h,
                    vmo,
                    map,
                    pin,
                    dma_addr,
                });
                Ok((gem_h, uuid))
            }
            Err(e) => {
                drop(AmdBo { gem_handle: 0, vmo, map, pin, dma_addr });
                Err(mem_err_to_sys(e))
            }
        }
    }

    fn gem_create(&mut self, size: u64, bo_flags: u32) -> Result<(u32, Handle, [u8; 16]), i64> {
        if size == 0 || size > MAX_FB_BYTES {
            return Err(sys::ERR_INVALID_ARGS);
        }
        let aligned = size.div_ceil(sys::PAGE) * sys::PAGE;
        let vmo = sys::vmo_create(aligned)?;
        let client_vmo = match sys::handle_duplicate(vmo, sys::RIGHTS_SAME) {
            Ok(h) => h,
            Err(e) => {
                sys::handle_close(vmo);
                return Err(e);
            }
        };
        match self.gem_import(vmo, aligned, bo_flags | gpu::BO_RENDER) {
            Ok((gh, uuid)) => Ok((gh, client_vmo, uuid)),
            Err(e) => {
                sys::handle_close(client_vmo);
                Err(e)
            }
        }
    }

    fn gem_close(&mut self, gem_handle: u32) -> Result<(), i64> {
        let released = self.gem.release(gem_handle).map_err(mem_err_to_sys)?;
        if released.is_some() {
            for slot in &mut self.bos {
                if slot.as_ref().is_some_and(|b| b.gem_handle == gem_handle) {
                    *slot = None;
                }
            }
        }
        Ok(())
    }

    fn kms_create_fb(
        &mut self,
        gem_handle: u32,
        width: u32,
        height: u32,
        pitch: u32,
        format: u32,
        modifier: u64,
    ) -> Result<u32, i64> {
        let Some(bo) = self.gem.get(gem_handle) else {
            return Err(sys::ERR_OUT_OF_RANGE);
        };
        let _ = self.gem.add_ref(gem_handle);
        match self.kms.add_fb(gem_handle, width, height, pitch, format, modifier, bo.size) {
            Ok(fb_id) => Ok(fb_id),
            Err(e) => {
                let _ = self.gem.release(gem_handle);
                Err(kms_err_to_sys(e))
            }
        }
    }

    fn kms_destroy_fb(&mut self, fb_id: u32) -> Result<(), i64> {
        let Some(fb) = self.kms.remove_fb(fb_id) else {
            return Err(sys::ERR_OUT_OF_RANGE);
        };
        let _ = self.gem_close(fb.gem_handle);
        Ok(())
    }

    fn kms_atomic_commit(&mut self, commit: &AtomicCommit) -> Result<(u64, bool), i64> {
        if self.capi.is_null() || !self.native_kms {
            return Err(sys::ERR_NOT_SUPPORTED);
        }
        let mut p_src = core::ptr::null();
        let (mut p_w, mut p_h, mut p_pitch, mut p_fmt) = (0u32, 0u32, 0u32, 0u32);
        if commit.primary_changed && commit.primary_fb_id != 0 {
            let Some(fb) = self.kms.get_fb(commit.primary_fb_id) else {
                return Err(sys::ERR_OUT_OF_RANGE);
            };
            let Some(bo) = self.find_bo(fb.gem_handle) else {
                return Err(sys::ERR_OUT_OF_RANGE);
            };
            let Some(map) = bo.map.as_ref() else {
                return Err(sys::ERR_BAD_STATE);
            };
            p_src = map.addr as *const u8;
            p_w = fb.width;
            p_h = fb.height;
            p_pitch = fb.pitch;
            p_fmt = fb.format;
        }
        let mut c_src = core::ptr::null();
        let mut c_size = 0u32;
        if commit.cursor_changed && commit.cursor_fb_id != 0 {
            let Some(cfb) = self.kms.get_fb(commit.cursor_fb_id) else {
                return Err(sys::ERR_OUT_OF_RANGE);
            };
            let Some(cbo) = self.find_bo(cfb.gem_handle) else {
                return Err(sys::ERR_OUT_OF_RANGE);
            };
            let Some(cmap) = cbo.map.as_ref() else {
                return Err(sys::ERR_BAD_STATE);
            };
            c_src = cmap.addr as *const u8;
            c_size = cfb.width;
        }

        let creq = CapiCommit {
            pipe_slot: self.active_slot as u32,
            test_only: u8::from((commit.flags & kms::ATOMIC_TEST_ONLY) != 0),
            allow_modeset: u8::from((commit.flags & kms::ATOMIC_ALLOW_MODESET) != 0),
            reset_boot: u8::from((commit.flags & kms::ATOMIC_RESET_BOOT) != 0),
            mode_changed: u8::from(commit.mode_changed),
            mode_width: commit.mode_width,
            mode_height: commit.mode_height,
            mode_refresh_mhz: commit.mode_refresh_mhz,
            vrr_changed: u8::from(commit.vrr_changed),
            vrr_enable: u8::from(commit.vrr_enable),
            hdr_changed: u8::from(commit.hdr_changed),
            hdr_enable: u8::from(commit.hdr_enable),
            primary_changed: u8::from(commit.primary_changed),
            cursor_changed: u8::from(commit.cursor_changed),
            cursor_hot_x: commit.cursor_hot_x,
            cursor_hot_y: commit.cursor_hot_y,
            primary_src: p_src,
            primary_width: p_w,
            primary_height: p_h,
            primary_pitch: p_pitch,
            primary_format: p_fmt,
            cursor_src: c_src,
            cursor_size: c_size,
            cursor_x: commit.cursor_x,
            cursor_y: commit.cursor_y,
        };
        let mut seq = 0u64;
        let mut is_async = 0u8;
        // SAFETY: `self.capi` is valid; `p_src`/`c_src` point to mapped client VMOs alive for this call.
        let rc = unsafe { amdgpu_capi_atomic_commit(self.capi, &creq, &mut seq, &mut is_async) };
        if rc != 0 {
            return Err(c_err_to_sys(rc));
        }
        if (commit.flags & kms::ATOMIC_TEST_ONLY) == 0 && commit.out_syncobj != 0 {
            let _ = self.syncobjs.signal(commit.out_syncobj, commit.out_point);
        }
        Ok((seq, is_async != 0))
    }

    fn vm_create(&mut self) -> Result<u32, i64> {
        let vm_id = self.vms.create().map_err(mem_err_to_sys)?;
        if !self.capi.is_null() {
            // SAFETY: `self.capi` is valid.
            let rc = unsafe { amdgpu_capi_vm_create(self.capi, vm_id) };
            if rc != 0 {
                let _ = self.vms.destroy(vm_id);
                return Err(c_err_to_sys(rc));
            }
        }
        Ok(vm_id)
    }

    fn vm_destroy(&mut self, vm_id: u32) -> Result<(), i64> {
        self.vms.destroy(vm_id).map_err(mem_err_to_sys)?;
        if !self.capi.is_null() {
            // SAFETY: `self.capi` is valid.
            let _ = unsafe { amdgpu_capi_vm_destroy(self.capi, vm_id) };
        }
        Ok(())
    }

    fn vm_bind(
        &mut self,
        vm_id: u32,
        gem_handle: u32,
        bo_offset: u64,
        gpu_va: u64,
        size: u64,
        flags: u32,
    ) -> Result<(), i64> {
        let Some(vm) = self.vms.get_mut(vm_id) else {
            return Err(sys::ERR_OUT_OF_RANGE);
        };
        vm.bind(&self.gem, gpu_va, size, gem_handle, bo_offset, flags)
            .map_err(mem_err_to_sys)?;
        let target_addr = self.find_bo(gem_handle).map_or(0, |b| b.dma_addr.saturating_add(bo_offset));
        if !self.capi.is_null() {
            // SAFETY: `self.capi` is valid.
            let rc = unsafe {
                amdgpu_capi_vm_map(self.capi, vm_id, gem_handle, gpu_va, size, target_addr, 1, flags)
            };
            if rc != 0 {
                if let Some(vm2) = self.vms.get_mut(vm_id) {
                    let _ = vm2.unbind(gpu_va, size);
                }
                return Err(c_err_to_sys(rc));
            }
        }
        Ok(())
    }

    fn vm_unbind(&mut self, vm_id: u32, gpu_va: u64, size: u64) -> Result<(), i64> {
        let Some(vm) = self.vms.get_mut(vm_id) else {
            return Err(sys::ERR_OUT_OF_RANGE);
        };
        vm.unbind(gpu_va, size).map_err(mem_err_to_sys)?;
        if !self.capi.is_null() {
            // SAFETY: `self.capi` is valid.
            let _ = unsafe { amdgpu_capi_vm_unmap(self.capi, vm_id, gpu_va, size) };
        }
        Ok(())
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

    fn ctx_create(&mut self, engine: u32, vm_id: u32) -> Result<u32, i64> {
        let Some(slot) = self.ctxs.iter().position(Option::is_none) else {
            return Err(sys::ERR_NO_RESOURCES);
        };
        let id = self.next_ctx_id;
        self.next_ctx_id = self.next_ctx_id.wrapping_add(1).max(1);
        self.ctxs[slot] = Some(AmdCtx { ctx_id: id, engine, vm_id });
        Ok(id)
    }

    fn ctx_destroy(&mut self, ctx_id: u32) -> Result<(), i64> {
        for slot in &mut self.ctxs {
            if slot.is_some_and(|c| c.ctx_id == ctx_id) {
                *slot = None;
                return Ok(());
            }
        }
        Err(sys::ERR_OUT_OF_RANGE)
    }

    fn submit(
        &mut self,
        ctx_id: u32,
        engine: u32,
        wait_syncobj: u32,
        wait_point: u64,
        signal_syncobj: u32,
        signal_point: u64,
        cmd: &[u8],
    ) -> Result<u64, i64> {
        let Some(ctx) = self.ctxs.iter().flatten().copied().find(|c| c.ctx_id == ctx_id) else {
            return Err(sys::ERR_OUT_OF_RANGE);
        };
        if wait_syncobj != 0 && !self.syncobjs.is_signaled(wait_syncobj, wait_point).map_err(mem_err_to_sys)? {
            return Err(sys::ERR_SHOULD_WAIT);
        }
        if self.capi.is_null() {
            return Err(sys::ERR_NOT_SUPPORTED);
        }
        let eng = match if engine != 0 { engine } else { ctx.engine } {
            gpu::ENGINE_GFX => 0u32,
            gpu::ENGINE_COMPUTE => 1u32,
            gpu::ENGINE_SDMA => 2u32,
            _ => 0u32,
        };
        let mut seq = 0u64;
        // SAFETY: `self.capi` is valid; `cmd` slice is readable for `cmd.len()` bytes.
        let rc = unsafe { amdgpu_capi_ring_submit(self.capi, eng, ctx.vm_id, cmd.as_ptr(), cmd.len(), &mut seq) };
        if rc != 0 {
            return Err(c_err_to_sys(rc));
        }
        if signal_syncobj != 0 {
            let _ = self.syncobjs.signal(signal_syncobj, signal_point);
        }
        Ok(seq)
    }

    fn next_deadline_ns(&self) -> Option<u64> {
        if self.native_kms {
            Some(sys::clock_ns().saturating_add(4_000_000))
        } else {
            None
        }
    }

    fn poll_vblank(&mut self) -> Option<(usize, u64, u64, bool)> {
        if self.capi.is_null() || !self.native_kms {
            return None;
        }
        let (mut pipe, mut seq, mut ts, mut late) = (0u32, 0u64, 0u64, 0u8);
        // SAFETY: `self.capi` is valid.
        let got = unsafe { amdgpu_capi_poll_vblank(self.capi, &mut pipe, &mut seq, &mut ts, &mut late) };
        (got != 0).then_some((pipe as usize, seq, ts, late != 0))
    }

    fn poll_hotplug(&mut self) -> bool {
        if self.capi.is_null() || !self.native_kms {
            return false;
        }
        let now = sys::clock_ns();
        if now.saturating_sub(self.last_hpd_poll_ns) < 500_000_000 {
            return false;
        }
        self.last_hpd_poll_ns = now;
        // SAFETY: `self.capi` is valid.
        unsafe { amdgpu_capi_poll_hotplug(self.capi) != 0 }
    }

    fn on_suspend(&mut self) {
        if !self.capi.is_null() {
            // SAFETY: `self.capi` is valid.
            let _ = unsafe { amdgpu_capi_suspend(self.capi) };
        }
    }

    fn on_shutdown(&mut self) {
        if !self.capi.is_null() {
            // SAFETY: `self.capi` is valid; cleanly restores UEFI GOP before exit.
            unsafe { amdgpu_capi_close(self.capi) };
            self.capi = core::ptr::null_mut();
        }
    }

    fn irqs(&self) -> u64 {
        if self.capi.is_null() {
            0
        } else {
            // SAFETY: `self.capi` is valid.
            unsafe { amdgpu_capi_irqs(self.capi) }
        }
    }

    fn frames(&self) -> u64 {
        if self.capi.is_null() {
            0
        } else {
            // SAFETY: `self.capi` is valid.
            unsafe { amdgpu_capi_frames(self.capi) }
        }
    }
}

pub fn main(s: *const Startup) -> i32 {
    // SAFETY: `s` is the startup block pointer passed by the kernel.
    if !unsafe { libd::init(s, "amdgpu") } {
        return -1;
    }
    let dev = libd::startup_handle(sys::TAG_DEVICE);
    let ctl = libd::startup_handle(proto::TAG_CONTROL);
    let fw = FirmwareDir::from_startup();
    let Ok(pci) = DrmPciDev::open(dev) else {
        println!("amdgpu: device_info failed");
        return 1;
    };
    let _ = pci.enable_bus_master();
    let shim_abi = shim::init_and_verify_vendor_shim(dev, fw.raw()).unwrap_or(0);
    let fw_manifest = if let Ok((vmo, len)) = fw.load_vmo(b"manifest.toml") {
        sys::handle_close(vmo);
        len > 0
    } else {
        false
    };

    // SAFETY: `dev` is this driver's kernel-granted PCI device handle; `dosdrm::shim` is initialized.
    let capi = unsafe { amdgpu_capi_open(dev) };
    let mut info = CapiInfo::default();
    if !capi.is_null() {
        // SAFETY: `capi` is valid.
        let _ = unsafe { amdgpu_capi_get_info(capi, 0, &mut info, core::ptr::null_mut(), 0) };
    }

    let fw_loaded = fw_manifest || info.fw_loaded_count > 0;
    let vram_bytes = info.vram_bytes.max(pci.info.bar_size[0].max(pci.info.bar_size[2]));
    let vram_mib = (vram_bytes >> 20) as u32;
    let iommu = (pci.info.flags & sys::DEV_FLAG_IOMMU) != 0;
    let native = info.native_kms != 0 && info.width > 0 && info.height > 0;

    let mut caps = gpu::CAP_GEM_VM | gpu::CAP_SYNCOBJ_TIMELINE | gpu::CAP_CMD_GFX | gpu::CAP_CMD_DMA | gpu::CAP_WC;
    if iommu {
        caps |= gpu::CAP_IOMMU;
    }
    if fw_loaded {
        caps |= gpu::CAP_SYS_FIRMWARE;
    }
    if native {
        caps |= gpu::CAP_NATIVE_KMS
            | gpu::CAP_SCANOUT_2D
            | gpu::CAP_PAGE_FLIP
            | gpu::CAP_ASYNC_FLIP
            | gpu::CAP_ATOMIC_KMS;
        if info.hw_cursor != 0 {
            caps |= gpu::CAP_HW_CURSOR;
        }
        if info.edid_blocks > 0 {
            caps |= gpu::CAP_EDID;
        }
        if info.vrr_capable != 0 {
            caps |= gpu::CAP_VRR;
        }
        if info.hdr_capable != 0 {
            caps |= gpu::CAP_HDR;
        }
        if info.dsc_capable != 0 {
            caps |= gpu::CAP_DSC;
        }
    }

    let label = core::str::from_utf8(cstr_trim(&info.asic_name)).unwrap_or("AMD Radeon GPU");
    println!(
        "amdgpu: {} ({:04x}:{:04x}) on {} ({} MiB VRAM, DCN={}, fw={}, PSP={}, SMU={}, DMUB={}, pipes={}, {}x{} @ {} Hz, IOMMU={})",
        label,
        pci.info.vendor,
        pci.info.device,
        pci.info.name(),
        vram_mib,
        info.dcn_version,
        info.fw_loaded_count,
        info.psp_alive != 0,
        info.smu_alive != 0,
        info.dmub_alive != 0,
        info.active_pipes,
        info.width,
        info.height,
        info.refresh_mhz / 1000,
        iommu
    );

    let mut drv = AmdGpu {
        dev,
        capi,
        scratch: shim::alloc_sg_scratch().ok(),
        active_slot: 0,
        kms: KmsState::new(),
        gem: GemTable::new(),
        vms: GpuVmTable::new(),
        syncobjs: SyncobjTable::new(),
        bos: [const { None }; MAX_AMD_BOS],
        ctxs: [None; MAX_AMD_CTXS],
        next_ctx_id: 1,
        fw_loaded,
        shim_abi,
        native_kms: native,
        last_hpd_poll_ns: 0,
    };

    let Ok(port) = Port::new(32) else { return 1 };
    let pipes_to_announce = if native { (info.active_pipes as usize).clamp(1, gpu_drv::MAX_PIPES) } else { 1 };
    gpu_drv::announce(
        ctl,
        &GpuAnnounce {
            kind: gpu::KIND_AMD_RDNA,
            vendor: pci.info.vendor,
            device: pci.info.device,
            vram_mib,
            width: if native { info.width as u16 } else { 0 },
            height: if native { info.height as u16 } else { 0 },
            caps,
            name: label,
        },
    );
    for pipe in 1..pipes_to_announce {
        let mut pinfo = CapiInfo::default();
        if !drv.capi.is_null() {
            // SAFETY: `drv.capi` is valid.
            let _ = unsafe { amdgpu_capi_get_info(drv.capi, pipe as u32, &mut pinfo, core::ptr::null_mut(), 0) };
        }
        if pinfo.width > 0 && pinfo.height > 0 {
            gpu_drv::announce_output(
                ctl,
                &GpuAnnounce {
                    kind: gpu::KIND_AMD_RDNA,
                    vendor: pci.info.vendor,
                    device: pci.info.device,
                    vram_mib,
                    width: pinfo.width as u16,
                    height: pinfo.height as u16,
                    caps,
                    name: label,
                },
            );
        }
    }
    gpu_drv::serve_loop(ctl, &port, &mut drv)
}
