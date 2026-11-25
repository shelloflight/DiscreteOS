# Graphics, Atomic KMS, and GPU Drivers

D-OS runs every GPU driver as an unprivileged, isolated user-space process (`.ddrv`) confined inside
a per-device IOMMU domain (Intel VT-d or AMD-Vi), coordinated by `gpu.dsvc` alongside the UEFI GOP
framebuffer baseline. PCI GPU `.ddrv` binaries are loaded from Ed25519-verified `sys:/bin/*.ddrv`
once `sys:` mounts, and `devmgr` grants each GPU driver a read-only vendor-scoped directory channel
(`proto::TAG_FIRMWARE`) rooted at `sys:/firmware/<vendor>/`.

**Code:**
- `user/lib/drm` (`dosdrm`: `no_std`, `#![forbid(unsafe_code)]` core Atomic KMS state/validation &
  12-second `ModeRevertGuard`, GEM buffer objects, per-context `GpuVm` address-space allocator,
  monotonic timeline `drm_syncobj`s, EDID 1.4 / CTA-861 / DisplayID 2.0 parser up to 540+ Hz with
  CVT-RB v2 synthesis, VirtIO-GPU 1.2 2D/EDID/Cursor/UUID/Blob/VirGL/Venus codecs & CS validator,
  dirty-rect 8/10-bit WC pixel blitters, plus optional `shim` feature providing Ring-3 PCI/BAR,
  scatter-gather IOMMU DMA `SgPin`, `FirmwareDir` VMO loading, and `vendor/dosdrm_c` FFI callbacks).
- `vendor/dosdrm_c` (scoped C17 + freestanding C++20 compatibility headers & runtime compiled by
  `dbuild` with `-fcf-protection=return` and content-hashed object/archive caches in `build/vendor/`).
- `vendor/amdgpu` (upstream-aligned C17 AMD `amdgpu` core + Display Core `dc`/`dml2`/`dmub`/`dsc`
  static library `libvendor_amdgpu.a` linked into `amdgpu.ddrv`, plus host hardware simulator &
  fuzz suite in `vendor/amdgpu/test/test_amdgpu_host.c`).
- `vendor/firmware/{virtio,amdgpu,nvidia,xe}` (read-only firmware manifests and official signed
  firmware blobs packaged into `sys:/firmware/<vendor>/`, including 43 signed AMD blobs covering
  RDNA 2, RDNA 3, Ryzen 7000/9000 DCN 3.1.5 iGPUs, and RDNA 4 / RX 9070 DCN 4.0.1).
- `user/devmgr/src/{gpu_drv,virtio_gpu,amdgpu,xe,nvgpu}.rs`, `user/gpu` (`gpu.dsvc`),
  `user/lib/libd/src/gpu.rs`, `user/init/services/gpu.dman`.

**Tests:** `gpu-host`, `gpu-virtio`, `gpu-virtio-amd`, `gpu-gop`, `gpu-shell`.
The compositor and window manager built on `gpu.display` is D-AWMI ([awmi.md](awmi.md)).

## Architecture

| Component | Role |
|---|---|
| GOP framebuffer baseline (`gpu.dsvc`) | Models `platform:display` (`DISPLAY_RGB32`, write-combining BAR 0) natively through `dosdrm::kms::KmsState` + `GemTable`; maps BAR 0 lazily on first atomic primary-plane commit so text-console boots remain undisturbed. |
| `virtio-gpu.ddrv` | Modern VirtIO 1.2 GPU (PCI `1AF4:1050`, `sys:/bin/virtio-gpu.ddrv`): negotiates `F_VIRGL`, `F_EDID`, `F_RESOURCE_UUID`, `F_RESOURCE_BLOB`, and `F_CONTEXT_INIT`; verifies `sys:/firmware/virtio/` and `libvendor_dosdrm_c.a` at startup; serves full Atomic KMS (`ATOMIC_TEST_ONLY` + `ATOMIC_ALLOW_MODESET`, `CMD_SET_SCANOUT`, multi-rect primary damage, 64x64 cursor plane), IOMMU-pinned `GemTable` (`DRV_GEM_IMPORT` & `DRV_GEM_CREATE`), isolated `GpuVmTable`, timeline `SyncobjTable`, and validated VirGL/Venus command submission. |
| `amdgpu.ddrv` | AMD Radeon RDNA 2 / RDNA 3 / Ryzen 7000 & 9000 DCN 3.1.5 iGPU / RDNA 4 (RX 9070, DCN 4.0.1) user-space DRM driver (`sys:/bin/amdgpu.ddrv`, PCI `1002:*` class `03.*`): loads official signed `sys:/firmware/amdgpu/` blobs (PSP, SMU/PMFW, DMCUB, GC/MES, SDMA), parses IP Discovery v2/v4 and AtomBIOS v2.2 ROM/bytecode, runs Display Core (`dc`, `dml2`, `dmub`, VESA DSC 1.2a, DP 1.4/2.1 UHBR & HDMI 2.1 FRL link training, E-DDC EDID/DisplayID 2.0 up to 540+ Hz), supports arbitrary resolution scaling (HUBP/DSCL), 60/120/240/540+ Hz modesetting with live OTG verification and auto-rollback, FreeSync VRR, 10-bit HDR10, 64x64–256x256 hardware cursors, triple-buffered vsync flips over OSSSYS IH interrupts, multi-monitor HPD hotplug, GMC/MMHUB per-client 4-level GPU VM & GFX/SDMA/MES rings, clean GOP hand-back, and S3 suspend/resume. |
| `nvgpu.ddrv` | NVIDIA Open-GSP / `nvkms` user-space DRM driver (`sys:/bin/nvgpu.ddrv`, PCI `10DE:*` class `03.*`): loads with read-only `sys:/firmware/nvidia/`, verifies the freestanding C++20 `dosdrm` vendor runtime, initializes GEM/GPU-VM/timeline `syncobj` tables, and keeps display scanout safely on UEFI GOP until GSP-RM + `nvkms` attach native KMS pipes. |
| `xe.ddrv` | Intel Xe / Iris / Arc user-space DRM driver (`sys:/bin/xe.ddrv`, PCI `8086:*` class `03.*`): loads with read-only `sys:/firmware/xe/`, verifies the `dosdrm` C17/C++20 vendor shim, initializes GEM/GPU-VM/timeline `syncobj` tables, and keeps display scanout safely on UEFI GOP until Xe display + GuC attach native KMS pipes. |
| `gpu.dsvc` | Exposes capability-separated `gpu.query`, `gpu.display`, and `gpu.render` endpoints, enforces per-client GEM/VM/context ownership isolation, guards interactive mode switches with a 12-second `ModeRevertGuard`, and transparently reconnects adapters across driver restarts. |

## Kernel & Build Foundations

- **O(1) Large Device VMOs & WC VRAM BARs:** Device BAR VMOs store physical base and MSI-X hidden
  page ranges directly, supporting up to 64 GiB Resizable BAR apertures with zero per-page heap
  allocation; prefetchable display BARs >= 16 MiB map Write-Combining (`VMM_WC`).
- **Late `sys:/bin/*.ddrv` & Scoped Firmware Grants:** GPU `.ddrv` binaries live on `sys:/bin/`
  (signed with Ed25519 kind `"driver"`) rather than inflating `kernel.bin`, and receive only their
  own read-only `sys:/firmware/<vendor>/` directory handle.
- **Deterministic Cached Vendor C/C++ Builds:** `dbuild` compiles `vendor/*/vendor.toml` C17 and
  freestanding C++20 libraries in parallel with `-ffile-prefix-map`, `-fcf-protection=return` (CET
  shadow-stack compatible), and zero-timestamp `!<arch>` archives cached under `build/vendor/`.

## Capability Model

Services declare GPU permissions in their signed `.dman` manifest under `[grants]`:

```toml
[grants]
gpu = ["query"]                     # read-only adapter & Atomic KMS resource/connector/mode query
gpu = ["display"]                   # Atomic KMS commits, mode confirm/revert, scanout GEM import
gpu = ["render"]                    # isolated GEM BOs, GPU-VM, timeline syncobjs, context submit
```

- **No ambient authority:** processes without `grants.gpu` receive zero GPU endpoint handles.
- **Strict client & role isolation:** `gpu.query` refuses all state mutations with
  `ERR_ACCESS_DENIED`; `gpu.render` cannot alter display scanout or close `gpu.display`'s GEM
  handles; `gpu.display` cannot allocate render VMs or submit GPU command streams; closing a client
  channel automatically releases its contexts, GPU VMs, and GEM handles.

## Shell Command

The shell holds `gpu = ["query"]` and `awmi = ["admin"]` and provides:

- `gpu` (`display` alias) — list detected adapters with driver, PCI ID, active resolution, VRAM
  size, feature flags (`iommu`, `wc`, `atomic-kms`, `gem-vm`, `syncobj`, `edid`, `cursor`,
  `native`, `vrr`, `hdr`, `dsc`, `virgl3d`, `venus`, `fw`, `gsp`), and frame count.
- `gpu modes [id]` — list supported display modes, refresh rates (up to 540+ Hz), pixel clocks, and
  totals.
- `gpu display [id]` — read-only Atomic KMS topology inspection: connector (`GOP`, `Virtual`, `DP`,
  `HDMI-A`, `eDP`), CRTC/pipe/plane count, timings, link state, vblank counter, firmware/shim flags
  (`atomic-kms`, `fw-ok`, `shim-ok`, `revert-pending`), driver note, and mode list.
- `gpu mode <width> <height> <hz> [id]` — validates (`ATOMIC_TEST_ONLY`) and commits a mode switch
  via `awmi.admin` (`OP_SET_DISPLAY`), arming a 12-second automatic revert timer unless confirmed.
- `gpu confirm [id]` / `gpu revert [id]` — keep a newly applied display mode or revert immediately.
- `gpu vrr on|off [id]`, `gpu hdr on|off [id]`, `gpu scale <100-200|auto> [id]` — toggle VRR,
  10-bit HDR10 scanout, or per-output UI scale via `awmi.admin`.

## Trade-offs

- PCI GPU drivers load from `sys:/bin/` once `storaged` mounts `sys:`; bootstrap block/input/USB
  drivers remain embedded in `kernel.bin` so disk discovery and early console input have zero disk
  dependency.
- Interactive mode changes arm a 12-second `ModeRevertGuard` in `gpu.dsvc` so an out-of-range
  monitor mode automatically restores the previous working mode even if the panel loses signal.

## Tests

- `gpu-host`: `dosdrm` unit tests (EDID 1.4 / CTA-861 / DisplayID 2.0 240–540 Hz / CVT-RB v2,
  Atomic KMS validation & `ModeRevertGuard`, `GemTable` refcounting, `GpuVmSpace` 47-bit VA range
  isolation, timeline `SyncobjTable`, 8/10-bit WC blitters & `BufferAgeTracker`, VirtIO-GPU 2D/3D
  Blob/UUID/Venus codecs & VirGL validator, 16,000 fuzz rounds) plus the `vendor/amdgpu` C17 host
  simulator (validating all 43 signed AMD firmware blobs, simulating DCN 4.0.1 / 3.1.5 / 3.2 / 3.0
  end-to-end across IP Discovery, AtomBIOS, PSP/SMU/DMCUB, DML2, DSC 1.2a, DP 1.4/2.1 UHBR,
  HDMI 2.1 FRL, 240/540 Hz modeset & OTG stall rollback, VRR, HDR10, HW cursor, OSSSYS IH, HPD
  hotplug, GMC VM, GFX/SDMA/MES CS, S3 suspend/resume, and 10,000 additional fuzz rounds).
- `gpu-virtio` / `gpu-virtio-amd`: QEMU tests under Intel VT-d and AMD-Vi verifying late
  `sys:/bin/virtio-gpu.ddrv` loading, `sys:/firmware/virtio/` & C17/C++20 vendor shim self-test,
  Atomic KMS scanout & cursor plane, 12-second mode-revert guard, per-client GEM/GPU-VM/timeline
  `syncobj` isolation, VirGL CS validation, and driver crash-restart recovery.
- `gpu-gop`: UEFI QEMU test verifying the Atomic KMS GOP framebuffer baseline and role separation.
- `gpu-shell`: QEMU shell test verifying `gpu`, `gpu modes`, and `gpu display` over Atomic KMS.
